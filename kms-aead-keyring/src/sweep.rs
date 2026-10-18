//! Re-sealing stored values under the active key versions: the [`SealMarker`] a record carries
//! beside its encrypted fields, and [`run`], which drives an application's re-seal over the
//! records a query of that marker finds.
//!
//! A sweep is a job the application runs, a CLI or a Kubernetes Job, never a task inside the
//! library: only the application knows its tables, its pages and its write rules. It re-seals
//! after a rotation, to retire the old version, and migrates envelope values to keyring values.
//!
//! # The seal marker
//!
//! A keyring record counts a seal epoch, which moves on by one with every administrative write
//! that makes a version active: the creation of the keyring, at epoch 1, `KeyringAdmin::promote`,
//! and `KeyringAdmin::mark_compromised` when it puts a new version in place of the active one.
//! [`KeyringRecord::seal_marker`](crate::KeyringRecord::seal_marker) returns it as a
//! [`SealMarker`], 5 bytes that order as the epochs do.
//!
//! A write that touches any encrypted field of a record re-seals all of them under the active
//! versions and stores the marker beside them, in the same write. It reads the marker before it
//! seals the first field, so that the marker never names a newer epoch than the versions the
//! fields are under. The records a sweep still has to visit are then those whose marker is below
//! the current one: `seal < $1` on one indexed field, in Firestore, PostgreSQL and BigQuery
//! alike, and `<` on a [`SealMarker`] in Rust.
//!
//! The query also matches a record with nothing to re-seal: after a rotation of a purpose the
//! record holds no value of, such as a beacon rotation for a record without beacons, its marker
//! is below the current one all the same. [`Keyring::reseal`](crate::Keyring::reseal) returns
//! `None` for a value under the active version without decrypting it or calling the KMS, so the
//! re-seal writes the current marker alone, conditional on the record as it read it, and
//! returns [`ResealOutcome::Skipped`]. Such a record matches once.
//!
//! Each process stamps the epoch of the record it caches. A process that has not refreshed its
//! record since a promotion seals under the previous version and stamps the previous epoch, so
//! its writes stay below the current marker and the next sweep visits them. Once a sweep reports
//! `failed == 0`, and the query returns nothing after every process has had time to refresh its
//! record, the administrative job can retire the old version with `KeyringAdmin::retire`.
//!
//! The re-seal reads every field with [`decrypt_with_trust`](crate::Keyring::decrypt_with_trust),
//! as `reseal` does, and reports in [`ResealOutcome::Resealed`] whether the
//! [`KeyTrust`](crate::KeyTrust) of any of them is compromised. A value read under a compromised
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
//! 1. the model gains `seal: SealMarker`, and a record without one reads as
//!    [`SealMarker::ENVELOPE`], epoch 0: through `#[serde(default)]`, or a column default of its
//!    bytes, `01 00 00 00 00`;
//! 2. the field keeps its stored bytes, whose layout the marker names: envelope values under
//!    `ENVELOPE`, keyring values under any other marker, since the epochs of a keyring start at 1;
//! 3. reads go through the marker: [`Keyring::decrypt_envelope_for_migration`](crate::Keyring::decrypt_envelope_for_migration)
//!    opens an envelope value, with the AAD the application used for it, and
//!    [`Keyring::decrypt`](crate::Keyring::decrypt) a keyring value;
//! 4. the sweep's query, `seal < $1`, finds every envelope record too, and the re-seal seals it
//!    as keyring values and writes the current marker;
//! 5. once no record holds `ENVELOPE`, the read path drops its envelope branch.
//!
//! A query never matches a record whose marker is missing: an inequality filter of Firestore
//! skips a document without the field, and `<` in SQL is never true on `NULL`. A PostgreSQL
//! column added with a default gives every existing row the default. Firestore documents and
//! BigQuery rows written before the marker get `ENVELOPE` written into them first, or the
//! migration scans them once instead of querying.
//!
//! Values written by kms-aead 0.29 or earlier are in layouts this call does not read: they are
//! upgraded in place first, with kms-aead's `legacy-formats` feature and
//! `KmsAeadEnvelope::upgrade_legacy_value`, which takes the value's AAD. The layout of a value
//! is always the marker's, never guessed from its bytes.
//!
//! # Cancellation
//!
//! A job runner may cancel [`run`] and start it again over the same marker query. A sweep keeps
//! no state of its own beyond the counts of its report: a cancelled run drops the re-seals in
//! flight, at most `concurrency` of them, and its counts, and its span closes without them.
//!
//! It leaves no half-written record, provided the re-seal writes a record's fields and its
//! [`SealMarker`] in one conditional write: a cancelled write either committed, and the marker
//! moved, or did not, and the record is as it was. The keyring calls of a re-seal, `encrypt`
//! and `decrypt`, cache keys and write nothing to the store. The marker is the sweep's progress:
//! the records re-sealed before the cancellation no longer match the query, and the next run
//! visits the rest.

use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::{Stream, StreamExt};
use tracing::Instrument;

use crate::errors::{KeyringError, KeyringResult};
use crate::{spans, KeyringId};

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "serde")]
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// The seal epoch of a keyring at the time a record's encrypted fields were sealed, stored beside
/// those fields: the marker version `0x01`, then the epoch as a big-endian `u32`, 5 bytes in all.
///
/// Markers compare in the order of their epochs, and so do their bytes, in every store that
/// compares bytes as unsigned and from the first: a Firestore `bytes` value, a PostgreSQL `BYTEA`
/// and a BigQuery `BYTES`. The records a sweep still has to visit are then one range of one
/// indexed field, the markers below
/// [`KeyringRecord::seal_marker`](crate::KeyringRecord::seal_marker).
///
/// Epoch 0 is [`ENVELOPE`](Self::ENVELOPE), the marker of a record of envelope values, below the
/// marker of every keyring, whose epochs start at 1.
///
/// Stored bytes become a marker only through `TryFrom<Vec<u8>>`, which checks the version and
/// the length. `Debug` and `Display` show the epoch. The `serde` feature serialises a marker as
/// bytes and deserialises it through `TryFrom<Vec<u8>>`, and the `postgres` and `sqlx` features
/// store it as `BYTEA` and read it through `TryFrom<Vec<u8>>` too.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SealMarker([u8; 5]);

impl SealMarker {
    /// The marker of a record whose fields are envelope values, written before the record had a
    /// marker: epoch 0, the bytes `01 00 00 00 00`.
    pub const ENVELOPE: Self = Self::of_epoch(0);

    /// The first byte of every marker, the version of its layout.
    const VERSION: u8 = 0x01;

    /// The marker of `epoch`.
    pub(crate) const fn of_epoch(epoch: u32) -> Self {
        let [first, second, third, fourth] = epoch.to_be_bytes();
        Self([Self::VERSION, first, second, third, fourth])
    }

    /// The epoch this marker names.
    pub(crate) fn epoch(self) -> u32 {
        let [_, epoch @ ..] = self.0;
        u32::from_be_bytes(epoch)
    }

    /// The marker of the epoch after this one, or `None` past 2^32 - 1.
    #[cfg(feature = "admin")]
    pub(crate) fn next(self) -> Option<Self> {
        self.epoch().checked_add(1).map(Self::of_epoch)
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.0
    }

    /// The bytes to store, taking the marker.
    pub fn into_value(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Reads stored bytes as a marker.
///
/// # Errors
///
/// [`KeyringError::InvalidSealMarker`] for bytes that are not 5 long or do not start with the
/// version `0x01`.
impl TryFrom<Vec<u8>> for SealMarker {
    type Error = KeyringError;

    fn try_from(bytes: Vec<u8>) -> KeyringResult<Self> {
        match <[u8; 5]>::try_from(bytes) {
            Ok(bytes @ [Self::VERSION, ..]) => Ok(Self(bytes)),
            _ => Err(KeyringError::InvalidSealMarker),
        }
    }
}

/// [`SealMarker::ENVELOPE`], so that `#[serde(default)]` reads a record stored before it had a
/// marker as envelope values.
impl Default for SealMarker {
    fn default() -> Self {
        Self::ENVELOPE
    }
}

/// The epoch, such as `SealMarker { epoch: 3 }`.
impl Debug for SealMarker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealMarker")
            .field("epoch", &self.epoch())
            .finish()
    }
}

/// The epoch, such as `3`.
impl Display for SealMarker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.epoch(), f)
    }
}

/// What the re-seal of one candidate did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResealOutcome {
    /// The record's fields were sealed again under the active versions.
    Resealed {
        /// Whether any field the re-seal read came from a compromised version, with
        /// [`KeyTrust::Compromised`](crate::KeyTrust::Compromised): `false` for a record of
        /// envelope values, which name no key version.
        from_compromised: bool,
    },
    /// No field of the record needed a re-seal by the time it was read, and at most its marker
    /// was written, or a concurrent write won.
    Skipped,
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
/// A re-seal returns the application's own error type `E`, so that an error of its table is
/// returned as it is. The keyring's calls inside it, such as
/// [`Keyring::reseal`](crate::Keyring::reseal), return a
/// [`KeyringError`], which `?` converts into `E` through a `From` impl the
/// application gives its error; `E` is `KeyringError` itself for a re-seal that has no other
/// errors.
///
/// A re-seal that fails does not stop the sweep: it is counted in `failed` and logged at `WARN`
/// with the candidate's `Display` and the error's `Display`. The report keeps counts only; an
/// application that wants the errors themselves records them inside `reseal`. Both texts are the
/// application's own and go to the log as they are, so they name the record and the failure and
/// carry no value, secret or personal data. The sweep opens a `Keyring sweep` span for
/// `keyring_id`, which carries the counts once it ends.
pub async fn run<T, C, F, Fut, E>(
    keyring_id: &KeyringId,
    candidates: C,
    concurrency: NonZeroUsize,
    mut reseal: F,
) -> SweepReport
where
    T: Display,
    C: Stream<Item = T>,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<ResealOutcome, E>>,
    E: Display,
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
                Ok(ResealOutcome::Resealed { from_compromised }) => {
                    report.resealed += 1;
                    if from_compromised {
                        report.resealed_from_compromised += 1;
                    }
                }
                Ok(ResealOutcome::Skipped) => report.skipped += 1,
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
    use std::io;

    use futures_util::stream;
    use proptest::prelude::*;

    use super::*;
    use crate::test_support::{TestResult, TENANT};

    /// Epochs on either side of every byte boundary of the big-endian layout.
    const BYTE_BOUNDARIES: [u32; 8] = [0, 1, 255, 256, 65_535, 65_536, 16_777_216, u32::MAX];

    fn epoch() -> impl Strategy<Value = u32> {
        prop_oneof![any::<u32>(), proptest::sample::select(&BYTE_BOUNDARIES[..])]
    }

    #[test]
    fn a_marker_is_the_version_byte_and_the_big_endian_epoch() {
        assert_eq!(SealMarker::ENVELOPE.value(), [0x01, 0, 0, 0, 0]);
        assert_eq!(
            SealMarker::of_epoch(0x0102_0304).value(),
            [0x01, 0x01, 0x02, 0x03, 0x04]
        );
    }

    proptest! {
        #[test]
        fn markers_and_their_bytes_order_as_their_epochs(earlier in epoch(), later in epoch()) {
            let (first, second) = (SealMarker::of_epoch(earlier), SealMarker::of_epoch(later));
            prop_assert_eq!(first.cmp(&second), earlier.cmp(&later));
            prop_assert_eq!(first.value().cmp(second.value()), earlier.cmp(&later));
        }
    }

    #[test]
    fn bytes_of_another_version_or_length_are_refused() -> TestResult {
        for malformed in [
            vec![],
            vec![0x01, 0, 0, 7],
            vec![0x01, 0, 0, 0, 7, 0],
            vec![0x00, 0, 0, 0, 7],
            vec![0x02, 0, 0, 0, 7],
        ] {
            assert!(matches!(
                SealMarker::try_from(malformed),
                Err(KeyringError::InvalidSealMarker)
            ));
        }
        assert_eq!(
            SealMarker::try_from(vec![0x01, 0, 0, 1, 2])?,
            SealMarker::of_epoch(258)
        );
        assert_eq!(
            SealMarker::try_from(SealMarker::ENVELOPE.into_value())?,
            SealMarker::ENVELOPE
        );
        Ok(())
    }

    #[tokio::test]
    async fn run_counts_scanned_resealed_skipped_failed_with_the_applications_errors() {
        let report = run(
            &TENANT,
            stream::iter(["1", "2", "3", "4", "5", "6"]),
            NonZeroUsize::MIN.saturating_add(1),
            |candidate| async move {
                match candidate {
                    "3" => Ok(ResealOutcome::Skipped),
                    "4" => Err(io::Error::other("the users table is unavailable")),
                    "5" => Err(io::Error::other(KeyringError::RecordMissing(TENANT))),
                    "6" => Ok(ResealOutcome::Resealed {
                        from_compromised: true,
                    }),
                    _ => Ok(ResealOutcome::Resealed {
                        from_compromised: false,
                    }),
                }
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 6,
                resealed: 3,
                resealed_from_compromised: 1,
                skipped: 1,
                failed: 2,
            }
        );
    }

    #[cfg(all(
        feature = "admin",
        any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
    ))]
    mod with_backend {
        use std::collections::BTreeMap;
        use std::sync::{Mutex, PoisonError};

        use kms_aead::formats::Randomized;
        #[cfg(feature = "deterministic")]
        use kms_aead::DeterministicAlgorithm;
        use kms_aead::{
            AeadAlgorithm, BeaconAlgorithm, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
        };

        use super::*;
        use crate::test_support::{
            email_of, TestAdmin, TestBackend, TestKeyring, TestProvider, TestRegistry,
        };
        use crate::testing::MemoryKeyringStore;
        use crate::{
            Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, KeyringAlgorithms,
            KeyringRegistryOptions, Purpose,
        };

        const ALICE: &str = "alice@example.com";
        const ALICE_PHONE: &str = "+44 20 7946 0000";
        #[cfg(feature = "deterministic")]
        const EMAIL: FieldSpec = FieldSpec::new(
            EntityKind::from_static("user"),
            FieldName::from_static("email"),
        );
        const PHONE: FieldSpec = FieldSpec::new(
            EntityKind::from_static("user"),
            FieldName::from_static("phone"),
        );
        /// The AAD an application gave its envelope values.
        const ENVELOPE_AAD: &[u8] = b"users:42:email";

        async fn keyring_admin(
            provider: TestProvider,
        ) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
            TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(provider, TENANT, KeyringAlgorithms::new())
            .await
        }

        /// The users table of an application, by user id.
        type Users = Mutex<BTreeMap<&'static str, UserRow>>;

        #[derive(Clone)]
        struct UserRow {
            email: Encrypted<String, Randomized>,
            seal: SealMarker,
        }

        /// Writes `user` as an application does: the marker read first, then the email sealed
        /// under the active version.
        async fn write_user(
            keyring: &TestKeyring<MemoryKeyringStore>,
            users: &Users,
            user: &'static str,
        ) -> KeyringResult<()> {
            let seal = keyring.record().seal_marker();
            let email = keyring
                .encrypt(&email_of(user)?, &ALICE.to_string())
                .await?;
            users
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(user, UserRow { email, seal });
            Ok(())
        }

        /// The users whose marker is below the keyring's: the sweep's query.
        fn behind(keyring: &TestKeyring<MemoryKeyringStore>, users: &Users) -> Vec<&'static str> {
            let current = keyring.record().seal_marker();
            users
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|(_, row)| row.seal < current)
                .map(|(user, _)| *user)
                .collect()
        }

        /// One sweep over the users [`behind`] finds, re-sealing each email as an application
        /// does and writing the marker read before the re-seal.
        async fn sweep(keyring: &TestKeyring<MemoryKeyringStore>, users: &Users) -> SweepReport {
            let candidates = behind(keyring, users);
            run(
                &TENANT,
                stream::iter(candidates),
                NonZeroUsize::MIN,
                |user| async move {
                    let row = users
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(user)
                        .cloned();
                    let Some(row) = row else {
                        return Ok(ResealOutcome::Skipped);
                    };
                    let seal = keyring.record().seal_marker();
                    let (email, outcome) =
                        match keyring.reseal(&email_of(user)?, &row.email).await? {
                            Some(resealed) => (
                                resealed.value,
                                ResealOutcome::Resealed {
                                    from_compromised: matches!(
                                        resealed.trust,
                                        KeyTrust::Compromised(_)
                                    ),
                                },
                            ),
                            None => (row.email, ResealOutcome::Skipped),
                        };
                    users
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .insert(user, UserRow { email, seal });
                    Ok::<ResealOutcome, KeyringError>(outcome)
                },
            )
            .await
        }

        fn email_in(users: &Users, user: &str) -> Option<Encrypted<String, Randomized>> {
            users
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(user)
                .map(|row| row.email.clone())
        }

        #[tokio::test]
        async fn run_writes_the_marker_alone_when_a_beacon_rotation_leaves_the_value_current(
        ) -> TestResult {
            let admin = TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
            )
            .await?;
            let keyring = admin.keyring();
            let users = Users::default();
            write_user(keyring, &users, "42").await?;
            let email = email_in(&users, "42").ok_or("the user is written")?;
            admin.promote(admin.rotate(Purpose::Beacon).await?).await?;

            let report = sweep(keyring, &users).await;

            assert_eq!(
                report,
                SweepReport {
                    scanned: 1,
                    resealed: 0,
                    resealed_from_compromised: 0,
                    skipped: 1,
                    failed: 0,
                }
            );
            assert!(behind(keyring, &users).is_empty());
            let kept = email_in(&users, "42").ok_or("the sweep keeps the user")?;
            assert_eq!(kept.value(), email.value());
            Ok(())
        }

        #[tokio::test]
        async fn run_reseals_a_value_under_a_decrypt_only_version_above_the_active_one(
        ) -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let users = Users::default();
            let first = keyring
                .record()
                .active(Purpose::Randomized)
                .map(|version| version.id())
                .ok_or("a new keyring has an active randomised version")?;
            let pending = admin.rotate(Purpose::Randomized).await?;
            let replacement = admin
                .mark_compromised(first, None)
                .await?
                .ok_or("the compromised active version is replaced")?
                .current;
            assert!(replacement.as_u32() > pending.as_u32());
            write_user(keyring, &users, "42").await?;
            admin.promote(pending).await?;

            let report = sweep(keyring, &users).await;

            assert_eq!(
                report,
                SweepReport {
                    scanned: 1,
                    resealed: 1,
                    resealed_from_compromised: 0,
                    skipped: 0,
                    failed: 0,
                }
            );
            assert!(behind(keyring, &users).is_empty());
            admin.retire(replacement).await?;
            let email = email_in(&users, "42").ok_or("the sweep keeps the user")?;
            assert_eq!(email.key_id(), pending);
            assert_eq!(keyring.decrypt(&email_of("42")?, &email).await?, ALICE);
            Ok(())
        }

        #[tokio::test]
        async fn reseal_receives_the_trust_of_every_field() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let email_aad = email_of("42")?;
            let phone_aad = PHONE.aad(&EntityId::try_from("42")?);
            let email = keyring.encrypt(&email_aad, &ALICE.to_string()).await?;
            admin.mark_compromised(email.key_id(), None).await?;
            let phone = keyring
                .encrypt(&phone_aad, &ALICE_PHONE.to_string())
                .await?;
            let seen = Mutex::new(Vec::new());

            let report = run(
                &TENANT,
                stream::iter(["42"]),
                NonZeroUsize::MIN,
                |_| async {
                    let email = keyring.decrypt_with_trust(&email_aad, &email).await?;
                    let phone = keyring.decrypt_with_trust(&phone_aad, &phone).await?;
                    let trusts = [email.trust, phone.trust];
                    seen.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend(trusts.iter().cloned());
                    Ok::<ResealOutcome, KeyringError>(ResealOutcome::Resealed {
                        from_compromised: trusts
                            .iter()
                            .any(|trust| matches!(trust, KeyTrust::Compromised(_))),
                    })
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
        async fn reseal_moves_only_a_value_behind_the_active_version() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let aad = email_of("42")?;
            let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
            assert!(keyring.reseal(&aad, &old).await?.is_none());

            let rotation = admin
                .promote(admin.rotate(Purpose::Randomized).await?)
                .await?;
            let resealed = keyring
                .reseal(&aad, &old)
                .await?
                .ok_or("a value under the previous version is re-sealed")?;

            assert_eq!(resealed.value.key_id(), rotation.current);
            assert_eq!(resealed.trust, KeyTrust::Trusted);
            assert_eq!(keyring.decrypt(&aad, &resealed.value).await?, ALICE);
            assert!(keyring.reseal(&aad, &resealed.value).await?.is_none());
            Ok(())
        }

        #[tokio::test]
        async fn reseal_reports_the_trust_of_a_compromised_value() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let aad = email_of("42")?;
            let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
            let rotation = admin
                .mark_compromised(old.key_id(), None)
                .await?
                .ok_or("the compromised active version is replaced")?;

            let resealed = keyring
                .reseal(&aad, &old)
                .await?
                .ok_or("a value under the compromised version is re-sealed")?;

            assert!(matches!(resealed.trust, KeyTrust::Compromised(_)));
            assert_eq!(resealed.value.key_id(), rotation.current);
            Ok(())
        }

        #[cfg(feature = "deterministic")]
        #[tokio::test]
        async fn reseal_deterministic_moves_only_a_value_behind_the_active_version() -> TestResult {
            let admin = TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
            )
            .await?;
            let keyring = admin.keyring();
            let aad = EMAIL.deterministic_aad();
            let old = keyring
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?;
            assert!(keyring.reseal_deterministic(&aad, &old).await?.is_none());

            let rotation = admin
                .promote(admin.rotate(Purpose::Deterministic).await?)
                .await?;
            let resealed = keyring
                .reseal_deterministic(&aad, &old)
                .await?
                .ok_or("a value under the previous version is re-sealed")?;

            assert_eq!(resealed.trust, KeyTrust::Trusted);
            assert_eq!(
                resealed.value,
                keyring
                    .encrypt_deterministic(&aad, &ALICE.to_string())
                    .await?
            );
            assert_eq!(resealed.value.key_id(), rotation.current);
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
            let admin = keyring_admin(provider).await?;
            let keyring = admin.keyring();

            for value in &values {
                let opened = keyring
                    .decrypt_envelope_for_migration(ENVELOPE_AAD, value, AeadAlgorithm::Aes256Gcm)
                    .await?;
                assert_eq!(opened, ALICE);
            }
            Ok(())
        }
    }
}
