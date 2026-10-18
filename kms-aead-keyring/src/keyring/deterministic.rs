//! The deterministic calls of [`Keyring`], which run AES-SIV and so need the `deterministic`
//! feature.

use std::cmp::Reverse;

use kms_aead::cache::DekCacheOutcome;
use kms_aead::formats::Deterministic;
use kms_aead::{
    AeadBackend, DeterministicCipher, Encrypted, EncryptedDataEncryptionKey,
    KmsAeadEncryptionProvider, Plaintext,
};

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::spans;
use crate::store::KeyringStore;
use crate::{
    Decrypted, DeterministicAad, KeyAlgorithm, KeyId, KeyTrust, KeyVersion, Keyring, KeyringRecord,
    Purpose,
};

/// Deterministic fields: equal plaintexts under one version give equal values, so that a data
/// store finds a row by an encrypted column.
///
/// A deterministic column leaks which rows hold equal values and how often each value occurs,
/// to anyone who reads the column, without any key. Without a nonce, a leaked key lets its
/// holder test guesses against the whole column offline. It fits fields that are queried and
/// have high entropy, such as emails and external ids, and never low-cardinality fields, such
/// as a status or a country, whose values the frequencies give away. A value opens in any row of
/// the same kind and field (see [`DeterministicAad`]), so a deterministic field never decides
/// identity or authorization on its own.
impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// Seals `value` with `aad` under the active deterministic version: the same `value` and
    /// `aad` give the same bytes until that version is rotated. The column it goes into leaks
    /// equality and frequency; see the leaks above.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the keyring has no deterministic version, or lost
    /// it to a `mark_compromised` whose new key could not be wrapped; [`KeyringError::Interop`]
    /// when sealing breaks the [`Interop`](crate::Interop) requirement `aad` carries;
    /// [`KeyringError::Kms`] with code `INVALID_PLAINTEXT` when the value does not encode; and
    /// the provider's error when the version's key is not in the
    /// [`DekCache`](kms_aead::cache::DekCache) and cannot be unwrapped.
    pub async fn encrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T, Deterministic>> {
        let span = spans::encrypt(self.id(), Purpose::Deterministic, None);
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let (version, dek) = record.active_dek(Purpose::Deterministic).ok_or_else(|| {
                KeyringError::no_active_version(self.id(), Purpose::Deterministic)
            })?;
            spans::record_sealing_version(version);
            self.check_interop(aad.interop, version)?;
            let (sealed, outcome) = self.seal_cached(&record, version, dek, aad, value).await?;
            spans::record_dek_cache(outcome);
            Ok(sealed)
        })
        .await
    }

    /// Opens `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), with [`KeyringError::KeyPurposeMismatch`] for a value whose
    /// key id is randomized.
    pub async fn decrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<T> {
        let key_id = KeyId::try_from(value)?;
        spans::in_span(spans::decrypt(self.id(), key_id), async {
            let (record, reload) = self.cache.find(key_id).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, key_id)?;
            self.apply_read_policy(version, compromise)?;
            let cipher = self.deterministic_cipher(version)?;
            let (opened, outcome) = self
                .with_cached_key(&record, key_id, dek, |key| {
                    cipher.decrypt_field(&aad.bytes, value, key)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(opened?)
        })
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy, as
    /// [`decrypt_with_status`](Self::decrypt_with_status) does for randomized values. A
    /// compromised version's key is unwrapped through the provider, never through the
    /// [`DekCache`](kms_aead::cache::DekCache).
    ///
    /// # Errors
    ///
    /// As [`decrypt_deterministic`](Self::decrypt_deterministic), without
    /// `KeyVersionCompromised`.
    pub async fn decrypt_deterministic_with_status<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<Decrypted<T>> {
        let key_id = KeyId::try_from(value)?;
        spans::in_span(spans::decrypt(self.id(), key_id), async {
            let (record, reload) = self.cache.find(key_id).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, key_id)?;
            let cipher = self.deterministic_cipher(version)?;
            let open = |key: &_| cipher.decrypt_field(&aad.bytes, value, key);
            let (opened, trust) = match compromise {
                None => {
                    let (opened, outcome) =
                        self.with_cached_key(&record, key_id, dek, open).await?;
                    spans::record_dek_cache(outcome);
                    (opened?, KeyTrust::Trusted)
                }
                Some(compromise) => (
                    self.with_uncached_key(dek, open).await??,
                    KeyTrust::Compromised(compromise.clone()),
                ),
            };
            Ok(Decrypted {
                value: opened,
                key_id,
                trust,
            })
        })
        .await
    }

    /// `value` sealed with `aad` under every deterministic version that decrypts, pending, active
    /// or decrypt-only, compromised ones included, newest first: the `IN` list of an equality
    /// query, which finds the rows sealed before a rotation as well as after it. Retired and
    /// destroyed versions give no probe. A compromised version's key is unwrapped for each
    /// call, never through the [`DekCache`](kms_aead::cache::DekCache).
    ///
    /// A query that sends the list links the values of one plaintext across the versions for
    /// whoever reads the query, so a rotation does not unlink a value's history from that reader.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Interop`], before any unwrap, when sealing under any of the versions
    /// breaks the [`Interop`](crate::Interop) requirement `aad` carries; [`KeyringError::Kms`]
    /// with code `INVALID_PLAINTEXT` when the value does not encode; and the provider's error
    /// when a version's key cannot be unwrapped.
    pub async fn equality_probes<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<Vec<Encrypted<T, Deterministic>>> {
        // One span for every version's probe, so it records no field of a single version: no
        // key id, algorithm or DEK cache outcome.
        let span = spans::encrypt(self.id(), Purpose::Deterministic, None);
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let mut versions = record
                .versions()
                .iter()
                .filter(|version| version.key_id().purpose() == Purpose::Deterministic)
                .filter_map(|version| {
                    let (dek, compromise) = version.readable_dek()?;
                    Some(
                        self.check_interop(aad.interop, version)
                            .map(|()| (version, dek, compromise)),
                    )
                })
                .collect::<KeyringResult<Vec<_>>>()?;
            versions.sort_by_key(|(version, ..)| Reverse(version.key_id()));
            let mut probes = Vec::with_capacity(versions.len());
            for (version, dek, compromise) in versions {
                probes.push(match compromise {
                    None => self.seal_cached(&record, version, dek, aad, value).await?.0,
                    Some(_) => {
                        let cipher = self.deterministic_cipher(version)?;
                        self.with_uncached_key(dek, |key| {
                            cipher.encrypt_field(version.key_id().into(), &aad.bytes, value, key)
                        })
                        .await??
                    }
                });
            }
            Ok(probes)
        })
        .await
    }

    fn deterministic_cipher(&self, version: &KeyVersion) -> KeyringResult<DeterministicCipher<B>> {
        match version.algorithm() {
            KeyAlgorithm::Deterministic(algorithm) => Ok(DeterministicCipher::new(algorithm)?),
            KeyAlgorithm::Randomized(_) | KeyAlgorithm::Beacon(_) => {
                Err(KeyringError::record_invalid(
                    self.id(),
                    RecordInvalidReason::PurposeMismatch(version.key_id()),
                ))
            }
        }
    }

    /// Seals `value` with `aad` under `version` of `record`, whose wrapped key is `dek`, with the
    /// key through the [`DekCache`](kms_aead::cache::DekCache), and returns where the key came
    /// from.
    async fn seal_cached<T: Plaintext>(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<(Encrypted<T, Deterministic>, DekCacheOutcome)> {
        let cipher = self.deterministic_cipher(version)?;
        let (sealed, outcome) = self
            .with_cached_key(record, version.key_id(), dek, |key| {
                cipher.encrypt_field(version.key_id().into(), &aad.bytes, value, key)
            })
            .await?;
        Ok((sealed?, outcome))
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use kms_aead::{DeterministicAlgorithm, KekProvider, ValueStruct};

    use crate::errors::InteropRequirement;
    use crate::test_support::{email_of, TestKeyring, TestProvider, TestResult, TENANT};
    use crate::testing::MemoryKeyringStore;
    use crate::{
        EntityKind, FieldName, FieldSpec, Interop, KeyId, KeyTrust, KeyringError, KeyringOptions,
        KeyringPolicy, KeyringResult, Purpose,
    };

    const EMAIL: FieldSpec = FieldSpec::new(
        EntityKind::from_static("user"),
        FieldName::from_static("email"),
    );

    const ALICE: &str = "alice@example.com";

    /// A keyring with an AES-SIV version beside the randomized one.
    async fn deterministic_keyring(
        provider: TestProvider,
    ) -> KeyringResult<TestKeyring<MemoryKeyringStore>> {
        TestKeyring::create(
            MemoryKeyringStore::new(),
            provider,
            TENANT,
            KeyringPolicy::new().with_deterministic_algorithm(DeterministicAlgorithm::Aes256Siv),
            KeyringOptions::new().with_watch(false),
        )
        .await
    }

    #[tokio::test]
    async fn equal_plaintexts_give_equal_values_under_one_version() -> TestResult {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let aad = EMAIL.deterministic_aad();
        let alice = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;

        assert_eq!(
            keyring
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?,
            alice
        );
        assert_ne!(
            keyring
                .encrypt_deterministic(&aad, &"bob@example.com".to_string())
                .await?,
            alice
        );
        assert_eq!(KeyId::try_from(&alice)?, KeyId::try_from(0x8000_0001)?);
        assert_eq!(alice.value().len(), 5 + 16 + ALICE.len());
        assert_eq!(keyring.decrypt_deterministic(&aad, &alice).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn probes_cover_every_decrypting_version_newest_first_with_the_pending_one() -> TestResult
    {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let aad = EMAIL.deterministic_aad();
        let first = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        keyring
            .promote(keyring.rotate(Purpose::Deterministic).await?)
            .await?;
        let pending = keyring.rotate(Purpose::Deterministic).await?;

        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes
                .iter()
                .map(KeyId::try_from)
                .collect::<KeyringResult<Vec<_>>>()?,
            [
                pending,
                KeyId::try_from(0x8000_0002)?,
                KeyId::try_from(0x8000_0001)?,
            ]
        );
        assert_eq!(
            probes[1],
            keyring
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?
        );
        assert_eq!(probes[2], first);
        Ok(())
    }

    #[tokio::test]
    async fn probes_refuse_a_field_whose_interop_the_keyring_breaks() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let keyring = deterministic_keyring(provider.clone()).await?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        let probes = keyring
            .equality_probes(
                &EMAIL.with_interop(Interop::BigQuery).deterministic_aad(),
                &ALICE.to_string(),
            )
            .await;

        assert!(matches!(
            probes,
            Err(KeyringError::Interop(error))
                if error.requirement == InteropRequirement::Kek(KekProvider::Local)
        ));
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps);
        keyring
            .equality_probes(&EMAIL.deterministic_aad(), &ALICE.to_string())
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn retired_versions_give_no_probe() -> TestResult {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let aad = EMAIL.deterministic_aad();
        keyring
            .promote(keyring.rotate(Purpose::Deterministic).await?)
            .await?;
        let first = KeyId::try_from(0x8000_0001)?;
        let current = [KeyId::try_from(0x8000_0002)?];

        keyring.retire(first).await?;
        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes
                .iter()
                .map(KeyId::try_from)
                .collect::<KeyringResult<Vec<_>>>()?,
            current
        );

        keyring.destroy(first).await?;
        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes
                .iter()
                .map(KeyId::try_from)
                .collect::<KeyringResult<Vec<_>>>()?,
            current
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_probe_under_a_compromised_version_is_listed() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let keyring = deterministic_keyring(provider.clone()).await?;
        let aad = EMAIL.deterministic_aad();
        let first = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        keyring
            .mark_compromised(KeyId::try_from(&first)?, None)
            .await?;

        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes
                .iter()
                .map(KeyId::try_from)
                .collect::<KeyringResult<Vec<_>>>()?,
            [KeyId::try_from(0x8000_0002)?, KeyId::try_from(&first)?]
        );
        assert_eq!(probes[1], first);

        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);
        keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            provider.calls.unwraps.load(Ordering::SeqCst),
            unwraps + 1,
            "the compromised key is unwrapped for each call, and never cached"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_deterministic_read_under_a_compromised_version_follows_the_read_policy() -> TestResult
    {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let aad = EMAIL.deterministic_aad();
        let value = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        let key_id = KeyId::try_from(&value)?;
        keyring.mark_compromised(key_id, None).await?;

        assert!(matches!(
            keyring.decrypt_deterministic(&aad, &value).await,
            Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == key_id
        ));
        let decrypted = keyring
            .decrypt_deterministic_with_status(&aad, &value)
            .await?;
        assert_eq!(decrypted.value, ALICE);
        assert_eq!(decrypted.key_id, key_id);
        assert!(matches!(decrypted.trust, KeyTrust::Compromised(_)));
        Ok(())
    }

    /// The deterministic AAD holds no entity id, so a value copied from user 42's row into user 7's
    /// opens there, where the randomized twin, bound to its row, does not.
    #[tokio::test]
    async fn a_deterministic_value_opens_in_another_row() -> TestResult {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let deterministic = keyring
            .encrypt_deterministic(&EMAIL.deterministic_aad(), &ALICE.to_string())
            .await?;
        let randomized = keyring
            .encrypt(&email_of("42")?, &ALICE.to_string())
            .await?;

        assert_eq!(
            keyring
                .decrypt_deterministic(&EMAIL.deterministic_aad(), &deterministic)
                .await?,
            ALICE
        );
        assert!(matches!(
            keyring.decrypt(&email_of("7")?, &randomized).await,
            Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
        ));
        Ok(())
    }
}
