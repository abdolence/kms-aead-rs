//! Re-sealing stored values under the active key versions: the [`SealMarker`] a record carries
//! beside its encrypted fields, and [`run`], which drives an application's re-seal over the
//! records a query of that marker finds.
//!
//! A sweep is a job the application runs, a CLI or a Kubernetes Job, never a task inside the
//! library: only the application knows its tables, its pages and its write rules. It re-seals
//! after a rotation, to retire the old version, and migrates envelope values to keyring values.
//!
//! # Rotation
//!
//! A write that touches any encrypted field of a record re-seals all of them under the active
//! versions and writes `SealMarker::keyring` of their key ids, so that one query finds every
//! record a sweep still has to visit: after a randomised rotation to key id `n`, the records
//! whose `seal.randomized < n`, and likewise for deterministic versions. Once a sweep reports
//! `failed == 0` and that query returns nothing, the old version can be
//! [`retire`](crate::Keyring::retire)d.
//!
//! The re-seal reads every field with [`decrypt_with_status`](crate::Keyring::decrypt_with_status),
//! and builds its [`Resealed`] from the [`KeyTrust`] of each. A value read under a compromised
//! version is untrusted data, since whoever holds the leaked key can have forged it, and
//! re-sealing makes it read as trusted everywhere. The application decides per record before it
//! re-seals, with a quarantine field beside the marker, a comparison against a backup taken
//! before the compromise, or acceptance; [`SweepReport::resealed_from_compromised`] counts the
//! records that went through that decision.
//!
//! # Migration from envelope values
//!
//! Values that kms-aead's [`KmsAeadEnvelope`](kms_aead::KmsAeadEnvelope) wrote, per call or
//! store-less, move to keyring values in five steps:
//!
//! 1. the model gains `seal: SealMarker` with `#[serde(default)]`, or a column default, so that
//!    every record without one reads as [`SealMarker::ENVELOPE`];
//! 2. the field keeps its stored bytes, whose layout the marker names;
//! 3. reads go through the marker: [`Keyring::decrypt_envelope`](crate::Keyring::decrypt_envelope)
//!    opens an envelope value, with the AAD the application used for it, and
//!    [`Keyring::decrypt`](crate::Keyring::decrypt) a keyring value;
//! 4. a sweep over `seal.format = 'envelope'` re-seals each record as keyring values and writes
//!    its keyring marker;
//! 5. once that query returns nothing, the read path drops its envelope branch.
//!
//! Values written by kms-aead 0.29 or earlier are in layouts this call does not read: they are
//! upgraded in place first, with kms-aead's `legacy-formats` feature and
//! `KmsAeadEnvelope::upgrade_legacy_value`, which takes the value's AAD. The layout of a value
//! is always the marker's, never guessed from its bytes.

use std::fmt::Display;
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::{Stream, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use crate::errors::KeyringResult;
use crate::purpose::{optional_key_id, unreserved};
use crate::{spans, KeyId, KeyTrust, KeyringId, Purpose};

/// Which layout a record's encrypted fields are in, and the oldest key version of each purpose
/// among them, stored beside those fields as plain fields an index covers: in Firestore the
/// fields of a map, in PostgreSQL columns or a `jsonb` with an expression index, in BigQuery
/// columns.
///
/// Serialised as `{"format": "keyring", "randomized": 3, "deterministic": null, "beacon": null}`.
/// A key id is a number up to 2^32 - 1, so a SQL column holding one is a `BIGINT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealMarker {
    /// The layout of the record's encrypted fields.
    pub format: SealFormat,
    /// The oldest randomised key version among the record's fields, if any.
    #[serde(with = "optional_key_id")]
    pub randomized: Option<KeyId>,
    /// The oldest deterministic key version among the record's fields, if any.
    #[serde(with = "optional_key_id")]
    pub deterministic: Option<KeyId>,
    /// The oldest beacon key version among the record's beacons, if any.
    #[serde(with = "optional_key_id")]
    pub beacon: Option<KeyId>,
}

/// The layout of a record's encrypted fields, serialised as `"envelope"` or `"keyring"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum SealFormat {
    /// Envelope values of kms-aead, each carrying its encrypted DEK.
    Envelope,
    /// Keyring values, each carrying its key id.
    Keyring,
}

impl SealMarker {
    /// The marker of a record whose fields are envelope values: no key versions.
    pub const ENVELOPE: Self = Self {
        format: SealFormat::Envelope,
        randomized: None,
        deterministic: None,
        beacon: None,
    };

    /// The marker of a record whose fields are keyring values and beacons under `key_ids`, the
    /// [`key_id`](crate::Encrypted::key_id)s of its values and beacons.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`](crate::KeyringError::ReservedKeyId) for a reserved key
    /// id, which no version has.
    pub fn keyring(key_ids: impl IntoIterator<Item = KeyId>) -> KeyringResult<Self> {
        let mut marker = Self {
            format: SealFormat::Keyring,
            randomized: None,
            deterministic: None,
            beacon: None,
        };
        for key_id in key_ids {
            let oldest = match Purpose::of(unreserved(key_id)?) {
                Purpose::Randomized => &mut marker.randomized,
                Purpose::Deterministic => &mut marker.deterministic,
                Purpose::Beacon => &mut marker.beacon,
            };
            *oldest = Some(oldest.map_or(key_id, |oldest| {
                std::cmp::min_by_key(oldest, key_id, |key_id| key_id.as_u32())
            }));
        }
        Ok(marker)
    }
}

/// [`SealMarker::ENVELOPE`], the marker of a record stored before markers existed, so that
/// `#[serde(default)]` reads such a record as envelope values.
impl Default for SealMarker {
    fn default() -> Self {
        Self::ENVELOPE
    }
}

/// What the re-seal of one candidate did.
#[derive(Debug)]
pub enum Outcome {
    /// The record's fields were sealed again under the active versions.
    Resealed(Resealed),
    /// The record needed no re-seal by the time it was read, or a concurrent write won.
    Skipped,
}

/// A re-sealed record, built from the [`KeyTrust`] of every field the re-seal read, so that a
/// record with any field from a compromised version counts as one. A record of envelope values,
/// which name no key version, is built from no trust.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resealed {
    from_compromised: bool,
}

impl<'a> FromIterator<&'a KeyTrust> for Resealed {
    fn from_iter<I: IntoIterator<Item = &'a KeyTrust>>(trusts: I) -> Self {
        Self {
            from_compromised: trusts
                .into_iter()
                .any(|trust| matches!(trust, KeyTrust::Compromised(_))),
        }
    }
}

/// The counts of a sweep. Every candidate is counted once in `scanned` and once in `resealed`,
/// `skipped` or `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SweepReport {
    /// The candidates visited.
    pub scanned: u64,
    /// The records re-sealed.
    pub resealed: u64,
    /// The records among `resealed` with a field read from a compromised version.
    pub resealed_from_compromised: u64,
    /// The records the re-seal skipped.
    pub skipped: u64,
    /// The records whose re-seal returned an error.
    pub failed: u64,
}

/// Runs `reseal` over every candidate of `candidates`, with at most `concurrency` re-seals in
/// flight, and counts what they did. A candidate is whatever the application identifies a record
/// by, such as its id or its key columns.
///
/// A re-seal that fails does not stop the sweep: it is counted in `failed` and logged at `WARN`
/// with the candidate's `Display` and the error's code, never a value, so a candidate's
/// `Display` names the record and nothing else. The sweep opens a `Keyring sweep` span for
/// `keyring_id`, which carries the counts once it ends.
pub async fn run<T, C, F, Fut>(
    keyring_id: &KeyringId,
    candidates: C,
    concurrency: NonZeroUsize,
    mut reseal: F,
) -> SweepReport
where
    T: Display,
    C: Stream<Item = T>,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = KeyringResult<Outcome>>,
{
    let span = spans::sweep(keyring_id);
    let report = async {
        let mut report = SweepReport::default();
        let mut outcomes = pin!(candidates
            .map(|candidate| {
                // Formatted before `reseal` takes the candidate, for the log line of a failure.
                let shown = candidate.to_string();
                let outcome = reseal(candidate);
                async move { (shown, outcome.await) }
            })
            .buffer_unordered(concurrency.get()));
        while let Some((candidate, outcome)) = outcomes.next().await {
            report.scanned += 1;
            match outcome {
                Ok(Outcome::Resealed(resealed)) => {
                    report.resealed += 1;
                    if resealed.from_compromised {
                        report.resealed_from_compromised += 1;
                    }
                }
                Ok(Outcome::Skipped) => report.skipped += 1,
                Err(error) => {
                    report.failed += 1;
                    spans::sweep_failed(keyring_id, &candidate, &error);
                }
            }
        }
        report
    }
    .instrument(span.clone())
    .await;
    spans::record_sweep(&span, &report);
    report
}

#[cfg(test)]
mod tests {
    use futures_util::stream;
    use jiff::Timestamp;
    use serde_json::json;

    use super::*;
    use crate::test_support::{TestResult, TENANT};
    use crate::{Compromise, KeyringError};

    const DETERMINISTIC: u32 = 1 << 31;
    const BEACON: u32 = 1 << 30;

    #[test]
    fn marker_of_fields_takes_the_oldest_ordinal_per_purpose() -> TestResult {
        let key_ids = [
            3,
            DETERMINISTIC | 5,
            BEACON | 3,
            1,
            DETERMINISTIC | 2,
            BEACON | 2,
            4,
        ]
        .into_iter()
        .map(KeyId::new)
        .collect::<Vec<_>>();

        assert_eq!(
            SealMarker::keyring(key_ids)?,
            SealMarker {
                format: SealFormat::Keyring,
                randomized: Some(KeyId::new(1)),
                deterministic: Some(KeyId::new(DETERMINISTIC | 2)),
                beacon: Some(KeyId::new(BEACON | 2)),
            }
        );
        assert_eq!(
            SealMarker::keyring([KeyId::new(7)])?,
            SealMarker {
                format: SealFormat::Keyring,
                randomized: Some(KeyId::new(7)),
                deterministic: None,
                beacon: None,
            }
        );
        Ok(())
    }

    #[test]
    fn a_marker_of_a_reserved_key_id_is_refused() {
        assert!(matches!(
            SealMarker::keyring([KeyId::new(1), KeyId::new(0)]),
            Err(KeyringError::ReservedKeyId)
        ));
    }

    #[test]
    fn a_marker_is_stored_as_plain_fields() -> TestResult {
        let marker = SealMarker::keyring([
            KeyId::new(2),
            KeyId::new(DETERMINISTIC | 1),
            KeyId::new(BEACON | 1),
        ])?;
        let stored = json!({
            "format": "keyring",
            "randomized": 2,
            "deterministic": 2147483649u32,
            "beacon": 1073741825u32,
        });

        assert_eq!(serde_json::to_value(marker)?, stored);
        assert_eq!(serde_json::from_value::<SealMarker>(stored)?, marker);
        assert_eq!(
            serde_json::to_value(SealMarker::ENVELOPE)?,
            json!({"format": "envelope", "randomized": null, "deterministic": null, "beacon": null})
        );
        assert!(serde_json::from_value::<SealMarker>(
            json!({"format": "keyring", "randomized": 0, "deterministic": null})
        )
        .is_err());
        Ok(())
    }

    #[tokio::test]
    async fn run_counts_scanned_resealed_skipped_failed() {
        let report = run(
            &TENANT,
            stream::iter(["1", "2", "3", "4", "5", "6"]),
            NonZeroUsize::MIN.saturating_add(1),
            |candidate| async move {
                match candidate {
                    "3" => Ok(Outcome::Skipped),
                    "4" | "5" => Err(KeyringError::RecordMissing(TENANT)),
                    _ => Ok(Outcome::Resealed(
                        [&KeyTrust::Trusted].into_iter().collect(),
                    )),
                }
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 6,
                resealed: 3,
                resealed_from_compromised: 0,
                skipped: 1,
                failed: 2,
            }
        );
    }

    #[tokio::test]
    async fn resealed_from_compromised_is_counted() {
        let report = run(
            &TENANT,
            stream::iter(["trusted", "one-compromised", "all-compromised", "skipped"]),
            NonZeroUsize::MIN,
            |candidate| async move {
                let compromised =
                    KeyTrust::Compromised(Compromise::new(Timestamp::UNIX_EPOCH, None));
                let trusts = match candidate {
                    "trusted" => vec![KeyTrust::Trusted, KeyTrust::Trusted],
                    "one-compromised" => vec![KeyTrust::Trusted, compromised],
                    "all-compromised" => vec![compromised],
                    _ => return Ok(Outcome::Skipped),
                };
                Ok(Outcome::Resealed(trusts.iter().collect()))
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 4,
                resealed: 3,
                resealed_from_compromised: 2,
                skipped: 1,
                failed: 0,
            }
        );
    }

    #[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
    mod with_backend {
        use std::sync::{Mutex, PoisonError};

        use kms_aead::{AeadAlgorithm, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions};

        use super::*;
        use crate::test_support::{email_of, TestBackend, TestKeyring, TestProvider};
        use crate::testing::MemoryKeyringStore;
        use crate::{EntityId, EntityKind, FieldName, FieldSpec, KeyringOptions, KeyringPolicy};

        const ALICE: &str = "alice@example.com";
        const ALICE_PHONE: &str = "+44 20 7946 0000";
        const PHONE: FieldSpec = FieldSpec::new(
            EntityKind::from_static("user"),
            FieldName::from_static("phone"),
        );
        /// The AAD an application gave its envelope values.
        const ENVELOPE_AAD: &[u8] = b"users:42:email";

        async fn keyring(provider: TestProvider) -> KeyringResult<TestKeyring<MemoryKeyringStore>> {
            TestKeyring::create(
                MemoryKeyringStore::new(),
                provider,
                TENANT,
                KeyringPolicy::new(),
                KeyringOptions::new().with_watch(false),
            )
            .await
        }

        #[tokio::test]
        async fn reseal_receives_the_trust_of_every_field() -> TestResult {
            let keyring = keyring(TestProvider::new("tenant-42-kek")?).await?;
            let email_aad = email_of("42")?;
            let phone_aad = PHONE.aad(&EntityId::try_from("42")?);
            let email = keyring.encrypt(&email_aad, &ALICE.to_string()).await?;
            keyring.mark_compromised(email.key_id(), None).await?;
            let phone = keyring
                .encrypt(&phone_aad, &ALICE_PHONE.to_string())
                .await?;
            let seen = Mutex::new(Vec::new());

            let report = run(
                &TENANT,
                stream::iter(["42"]),
                NonZeroUsize::MIN,
                |_| async {
                    let email = keyring.decrypt_with_status(&email_aad, &email).await?;
                    let phone = keyring.decrypt_with_status(&phone_aad, &phone).await?;
                    let trusts = [email.trust, phone.trust];
                    seen.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend(trusts.iter().cloned());
                    Ok(Outcome::Resealed(trusts.iter().collect()))
                },
            )
            .await;

            let seen = seen.into_inner().unwrap_or_else(PoisonError::into_inner);
            assert!(matches!(
                seen.as_slice(),
                [KeyTrust::Compromised(_), KeyTrust::Trusted]
            ));
            assert_eq!(report.resealed, 1);
            assert_eq!(report.resealed_from_compromised, 1);
            Ok(())
        }

        #[tokio::test]
        async fn a_store_less_value_opens_through_the_keyring() -> TestResult {
            let provider = TestProvider::new("tenant-42-kek")?;
            let envelope = KmsAeadEnvelope::<TestProvider, TestBackend>::with_options(
                provider.clone(),
                KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
            )?;
            let values = [
                envelope.encrypt(ENVELOPE_AAD, &ALICE.to_string()).await?,
                envelope.encrypt(ENVELOPE_AAD, &ALICE.to_string()).await?,
            ];
            let keyring = keyring(provider).await?;

            for value in &values {
                let opened = keyring
                    .decrypt_envelope(ENVELOPE_AAD, value, AeadAlgorithm::Aes256Gcm)
                    .await?;
                assert_eq!(opened, ALICE);
            }
            Ok(())
        }
    }
}
