//! The deterministic calls of [`Sealer`] and [`Keyring`], which run AES-SIV and so need the
//! `deterministic` feature.

use std::cmp::Reverse;

use kms_aead::backends::AeadBackend;
use kms_aead::cache::DekCacheOutcome;
use kms_aead::formats::Deterministic;
use kms_aead::{
    DeterministicCipher, Encrypted, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider,
    Plaintext,
};

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::record_cache::VersionLookup;
use crate::spans;
use crate::store::KeyringStore;
use crate::{
    Decrypted, DeterministicAad, KeyAlgorithm, KeyTrust, KeyVersion, Keyring, KeyringRecord,
    Purpose, Resealed, Sealer,
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
/// identity or authorisation on its own.
impl<S, P, B> Sealer<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// Seals `value` with `aad` under the record's active deterministic version: the same `value`
    /// and `aad` give the same bytes until that version is rotated. The column it goes into leaks
    /// equality and frequency; see the leaks above.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the record has no deterministic version, or lost
    /// it to a `mark_compromised` whose new key could not be encrypted; [`KeyringError::Interop`]
    /// when sealing breaks the [`Interop`](crate::Interop) requirement `aad` carries;
    /// [`KeyringError::KmsAead`] with code `INVALID_PLAINTEXT` when the value does not encode; and
    /// the provider's error when the version's key is not in the
    /// [`DekCache`](kms_aead::cache::DekCache) and cannot be decrypted.
    pub async fn encrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T, Deterministic>> {
        let keyring = self.keyring;
        let span = spans::encrypt(keyring.id(), Purpose::Deterministic, None);
        spans::in_span(span, async {
            let (version, encrypted_dek) = self
                .record
                .active_dek(Purpose::Deterministic)
                .ok_or_else(|| {
                    KeyringError::no_active_version(keyring.id(), Purpose::Deterministic)
                })?;
            spans::record_sealing_version(version);
            keyring.check_interop(aad.interop, version)?;
            let (sealed, outcome) = keyring
                .seal_cached(&self.record, version, encrypted_dek, aad, value)
                .await?;
            spans::record_dek_cache(outcome);
            Ok(sealed)
        })
        .await
    }

    /// `value` sealed again with `aad` under the record's active deterministic version, with the
    /// trust of the version it was read under, or `None` when it is under that version already,
    /// by the rule [`reseal`](Self::reseal) follows for randomised values: only a version older
    /// than the sealer's is sealed again, and a version pending in the sealer's record or missing
    /// from it fails with [`KeyringError::SealerOutdated`]. Once no value is left under the old
    /// version, it is retired, and the equality queries of [`Keyring::deterministic_probes`] drop
    /// its probe.
    ///
    /// # Errors
    ///
    /// As `reseal`, with the errors of
    /// [`Keyring::decrypt_deterministic_with_trust`] and
    /// [`encrypt_deterministic`](Self::encrypt_deterministic).
    pub async fn reseal_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<Option<Resealed<T, Deterministic>>> {
        let key_id = Purpose::Deterministic.check(value.key_id())?;
        if self.is_current(key_id).await? {
            return Ok(None);
        }
        let decrypted = self
            .keyring
            .decrypt_deterministic_with_trust(aad, value)
            .await?;
        Ok(Some(Resealed {
            value: self.encrypt_deterministic(aad, &decrypted.value).await?,
            trust: decrypted.trust,
        }))
    }
}

/// The reads and probes of deterministic fields; see [`Sealer::encrypt_deterministic`] for what
/// a deterministic column leaks.
impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// Opens `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), with [`KeyringError::KeyPurposeMismatch`] for a value whose
    /// key id is randomised.
    pub async fn decrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<T> {
        let key_id = Purpose::Deterministic.check(value.key_id())?;
        spans::in_span(
            spans::decrypt(self.id(), Purpose::Deterministic, key_id),
            async {
                let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
                spans::record_reload(reload);
                let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                self.apply_read_policy(version, compromise)?;
                let cipher = self.deterministic_cipher(version)?;
                let (opened, outcome) = self
                    .with_cached_dek(&record, key_id, encrypted_dek, |dek| {
                        cipher.decrypt(&aad.bytes, value, dek)
                    })
                    .await?;
                spans::record_dek_cache(outcome);
                Ok(opened?)
            },
        )
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy, as
    /// [`decrypt_with_trust`](Self::decrypt_with_trust) does for randomised values. A
    /// compromised version's key is decrypted through the provider, never through the
    /// [`DekCache`](kms_aead::cache::DekCache).
    ///
    /// # Errors
    ///
    /// As [`decrypt_deterministic`](Self::decrypt_deterministic), without
    /// `KeyVersionCompromised`.
    pub async fn decrypt_deterministic_with_trust<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<Decrypted<T>> {
        let key_id = Purpose::Deterministic.check(value.key_id())?;
        spans::in_span(
            spans::decrypt(self.id(), Purpose::Deterministic, key_id),
            async {
                let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
                spans::record_reload(reload);
                let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                let cipher = self.deterministic_cipher(version)?;
                let open = |dek: &_| cipher.decrypt(&aad.bytes, value, dek);
                let (opened, trust) = match compromise {
                    None => {
                        let (opened, outcome) = self
                            .with_cached_dek(&record, key_id, encrypted_dek, open)
                            .await?;
                        spans::record_dek_cache(outcome);
                        (opened?, KeyTrust::Trusted)
                    }
                    Some(compromise) => (
                        self.with_uncached_dek(encrypted_dek, open).await??,
                        KeyTrust::Compromised(compromise.clone()),
                    ),
                };
                Ok(Decrypted {
                    value: opened,
                    key_id,
                    trust,
                })
            },
        )
        .await
    }

    /// `value` sealed with `aad` under every deterministic version that decrypts, pending, active
    /// or decrypt-only, compromised ones included, newest first: the `IN` list of an equality
    /// query, which finds the rows sealed before a rotation as well as after it. Retired and
    /// destroyed versions give no probe. A compromised version's key is decrypted for each
    /// call, never through the [`DekCache`](kms_aead::cache::DekCache).
    ///
    /// A query that sends the list links the values of one plaintext across the versions for
    /// whoever reads the query, so a rotation does not unlink a value's history from that reader.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Interop`], before any decryption, when sealing under any of the versions
    /// breaks the [`Interop`](crate::Interop) requirement `aad` carries; [`KeyringError::KmsAead`]
    /// with code `INVALID_PLAINTEXT` when the value does not encode; and the provider's error
    /// when a version's key cannot be decrypted.
    pub async fn deterministic_probes<T: Plaintext>(
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
                .filter(|version| version.algorithm().purpose() == Purpose::Deterministic)
                .filter_map(|version| {
                    let (encrypted_dek, compromise) = version.readable_dek()?;
                    Some(
                        self.check_interop(aad.interop, version)
                            .map(|()| (version, encrypted_dek, compromise)),
                    )
                })
                .collect::<KeyringResult<Vec<_>>>()?;
            versions.sort_by_key(|(version, ..)| Reverse(version.id().as_u32()));
            let mut probes = Vec::with_capacity(versions.len());
            for (version, encrypted_dek, compromise) in versions {
                probes.push(match compromise {
                    None => {
                        self.seal_cached(&record, version, encrypted_dek, aad, value)
                            .await?
                            .0
                    }
                    Some(_) => {
                        let cipher = self.deterministic_cipher(version)?;
                        self.with_uncached_dek(encrypted_dek, |dek| {
                            cipher.encrypt(version.id(), &aad.bytes, value, dek)
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
                    RecordInvalidReason::PurposeMismatch(version.id()),
                ))
            }
        }
    }

    /// Seals `value` with `aad` under `version` of `record`, whose encrypted DEK is
    /// `encrypted_dek`, with the key through the [`DekCache`](kms_aead::cache::DekCache), and
    /// returns where the key came from.
    async fn seal_cached<T: Plaintext>(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        encrypted_dek: &EncryptedDataEncryptionKey,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<(Encrypted<T, Deterministic>, DekCacheOutcome)> {
        let cipher = self.deterministic_cipher(version)?;
        let (sealed, outcome) = self
            .with_cached_dek(record, version.id(), encrypted_dek, |dek| {
                cipher.encrypt(version.id(), &aad.bytes, value, dek)
            })
            .await?;
        Ok((sealed?, outcome))
    }
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use kms_aead::{DeterministicAlgorithm, KekProvider};

    use crate::errors::InteropRequirement;
    use crate::test_support::{
        email_of, TestAdmin, TestProvider, TestRegistry, TestResult, TENANT,
    };
    use crate::testing::MemoryKeyringStore;
    use crate::{
        EntityKind, FieldName, FieldSpec, Interop, KeyId, KeyTrust, KeyringAlgorithms,
        KeyringError, KeyringRegistryOptions, KeyringResult, Purpose,
    };

    const EMAIL: FieldSpec = FieldSpec::new(
        EntityKind::from_static("user"),
        FieldName::from_static("email"),
    );

    const ALICE: &str = "alice@example.com";

    /// A keyring with an AES-SIV version beside the randomised one.
    async fn deterministic_keyring(
        provider: TestProvider,
    ) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
        TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(
            provider,
            TENANT,
            KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
        )
        .await
    }

    #[tokio::test]
    async fn equal_plaintexts_give_equal_values_under_one_version() -> TestResult {
        let admin = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let aad = EMAIL.deterministic_aad();
        let alice = keyring
            .sealer()
            .await
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;

        assert_eq!(
            keyring
                .sealer()
                .await
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?,
            alice
        );
        assert_ne!(
            keyring
                .sealer()
                .await
                .encrypt_deterministic(&aad, &"bob@example.com".to_string())
                .await?,
            alice
        );
        assert_eq!(alice.key_id(), KeyId::new(0x8000_0001));
        assert_eq!(alice.value().len(), 5 + 16 + ALICE.len());
        assert_eq!(keyring.decrypt_deterministic(&aad, &alice).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn probes_cover_every_decrypting_version_newest_first_with_the_pending_one() -> TestResult
    {
        let admin = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let aad = EMAIL.deterministic_aad();
        let first = keyring
            .sealer()
            .await
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        admin
            .promote(admin.rotate(Purpose::Deterministic).await?)
            .await?;
        let pending = admin.rotate(Purpose::Deterministic).await?;

        let probes = keyring
            .deterministic_probes(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(
            probes
                .iter()
                .map(|probe| probe.key_id())
                .collect::<Vec<_>>(),
            [pending, KeyId::new(0x8000_0002), KeyId::new(0x8000_0001),]
        );
        assert_eq!(
            probes[1],
            keyring
                .sealer()
                .await
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?
        );
        assert_eq!(probes[2], first);
        Ok(())
    }

    #[tokio::test]
    async fn probes_refuse_a_field_whose_interop_the_keyring_breaks() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let admin = deterministic_keyring(provider.clone()).await?;
        let keyring = admin.keyring();
        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);

        let probes = keyring
            .deterministic_probes(
                &EMAIL.with_interop(Interop::BigQuery).deterministic_aad(),
                &ALICE.to_string(),
            )
            .await;

        assert!(matches!(
            probes,
            Err(KeyringError::Interop(error))
                if error.requirement == InteropRequirement::Kek(KekProvider::Local)
        ));
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions
        );
        keyring
            .deterministic_probes(&EMAIL.deterministic_aad(), &ALICE.to_string())
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn retired_versions_give_no_probe() -> TestResult {
        let admin = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let aad = EMAIL.deterministic_aad();
        admin
            .promote(admin.rotate(Purpose::Deterministic).await?)
            .await?;
        let first = KeyId::new(0x8000_0001);
        let current = [KeyId::new(0x8000_0002)];

        admin.retire(first).await?;
        let probes = keyring
            .deterministic_probes(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(
            probes
                .iter()
                .map(|probe| probe.key_id())
                .collect::<Vec<_>>(),
            current
        );

        admin.destroy(first).await?;
        let probes = keyring
            .deterministic_probes(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(
            probes
                .iter()
                .map(|probe| probe.key_id())
                .collect::<Vec<_>>(),
            current
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_probe_under_a_compromised_version_is_listed() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let admin = deterministic_keyring(provider.clone()).await?;
        let keyring = admin.keyring();
        let aad = EMAIL.deterministic_aad();
        let first = keyring
            .sealer()
            .await
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        admin.mark_compromised(first.key_id(), None).await?;

        let probes = keyring
            .deterministic_probes(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(
            probes
                .iter()
                .map(|probe| probe.key_id())
                .collect::<Vec<_>>(),
            [KeyId::new(0x8000_0002), first.key_id()]
        );
        assert_eq!(probes[1], first);

        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);
        keyring
            .deterministic_probes(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions + 1,
            "the compromised key is decrypted for each call, and never cached"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_deterministic_read_under_a_compromised_version_follows_the_read_policy() -> TestResult
    {
        let admin = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let aad = EMAIL.deterministic_aad();
        let value = keyring
            .sealer()
            .await
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        let key_id = value.key_id();
        admin.mark_compromised(key_id, None).await?;

        assert!(matches!(
            keyring.decrypt_deterministic(&aad, &value).await,
            Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == key_id
        ));
        let decrypted = keyring
            .decrypt_deterministic_with_trust(&aad, &value)
            .await?;
        assert_eq!(decrypted.value, ALICE);
        assert_eq!(decrypted.key_id, key_id);
        assert!(matches!(decrypted.trust, KeyTrust::Compromised(_)));
        Ok(())
    }

    /// The deterministic AAD holds no entity id, so a value copied from user 42's row into user 7's
    /// opens there, where the randomised twin, bound to its row, does not.
    #[tokio::test]
    async fn a_deterministic_value_opens_in_another_row() -> TestResult {
        let admin = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let deterministic = keyring
            .sealer()
            .await
            .encrypt_deterministic(&EMAIL.deterministic_aad(), &ALICE.to_string())
            .await?;
        let randomized = keyring
            .sealer()
            .await
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
            Err(KeyringError::KmsAead(error)) if error.code() == "DECRYPT"
        ));
        Ok(())
    }
}
