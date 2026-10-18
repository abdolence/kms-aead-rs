//! The deterministic calls of [`Keyring`], which run AES-SIV and so need the `deterministic`
//! feature.

use std::cmp::Reverse;

use kms_aead::cache::{DekCache, DekCacheOutcome};
use kms_aead::{
    DeterministicCipher, DeterministicCipherText, DeterministicDataEncryptionKey,
    EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, ValueStruct,
};
use secret_vault_value::SecretValue;

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::spans;
use crate::store::KeyringStore;
use crate::{
    Decrypted, Deterministic, DeterministicAad, Encrypted, KeyAlgorithm, KeyTrust, KeyVersion,
    Keyring, KeyringRecord, Plaintext, Purpose,
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
impl<S, P> Keyring<S, P>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
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
    /// [`KeyringError::Plaintext`] when the value does not encode; and the provider's error
    /// when the version's key is not in the [`DekCache`] and cannot be unwrapped.
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
            let plaintext = value.to_plaintext()?;
            let (sealed, outcome) = self
                .seal_cached(&record, version, dek, aad, &plaintext)
                .await?;
            spans::record_dek_cache(outcome);
            Ok(Encrypted::new(version.key_id(), sealed.value()))
        })
        .await
    }

    /// Opens `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt).
    pub async fn decrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<T> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            self.apply_read_policy(version, compromise)?;
            let cipher = self.deterministic_cipher(version)?;
            let body = DeterministicCipherText::from(value.body().to_vec());
            let (plaintext, outcome) = self
                .with_cached_key(&record, version.key_id(), dek, async |cache, binding| {
                    cache
                        .with_deterministic_key(
                            &self.provider,
                            cipher.algorithm(),
                            dek,
                            binding,
                            |key| cipher.decrypt_value(&aad.bytes, &body, key),
                        )
                        .await
                })
                .await?;
            spans::record_dek_cache(outcome);
            T::from_plaintext(plaintext?)
        })
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy, as
    /// [`decrypt_with_status`](Self::decrypt_with_status) does for randomized values. A
    /// compromised version's key is unwrapped through the provider, never through the
    /// [`DekCache`].
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), without `KeyVersionCompromised`.
    pub async fn decrypt_deterministic_with_status<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<Decrypted<T>> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            let cipher = self.deterministic_cipher(version)?;
            let body = DeterministicCipherText::from(value.body().to_vec());
            let open =
                |key: &DeterministicDataEncryptionKey| cipher.decrypt_value(&aad.bytes, &body, key);
            let (plaintext, trust) = match compromise {
                None => {
                    let (plaintext, outcome) = self
                        .with_cached_key(&record, version.key_id(), dek, async |cache, binding| {
                            cache
                                .with_deterministic_key(
                                    &self.provider,
                                    cipher.algorithm(),
                                    dek,
                                    binding,
                                    open,
                                )
                                .await
                        })
                        .await?;
                    spans::record_dek_cache(outcome);
                    (plaintext?, KeyTrust::Trusted)
                }
                Some(compromise) => {
                    let plaintext = self.with_uncached_key(version, dek, &cipher, open).await?;
                    spans::record_dek_cache_bypassed();
                    (plaintext?, KeyTrust::Compromised(compromise.clone()))
                }
            };
            Ok(Decrypted {
                value: T::from_plaintext(plaintext)?,
                key_id: version.key_id(),
                trust,
            })
        })
        .await
    }

    /// `value` sealed with `aad` under every deterministic version that still decrypts, active
    /// or decrypt-only, compromised ones included, newest first: the `IN` list of an equality
    /// query, which finds the rows sealed before a rotation as well as after it. Retired and
    /// destroyed versions give no probe. A compromised version's key is unwrapped for each
    /// call, never through the [`DekCache`].
    ///
    /// A query that sends the list links the values of one plaintext across the versions for
    /// whoever reads the query, so a rotation does not unlink a value's history from that reader.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Interop`], before any unwrap, when sealing under any of the versions
    /// breaks the [`Interop`](crate::Interop) requirement `aad` carries;
    /// [`KeyringError::Plaintext`] when the value does not encode; and the provider's error when
    /// a version's key cannot be unwrapped.
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
            let plaintext = value.to_plaintext()?;
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
                let sealed = match compromise {
                    None => {
                        self.seal_cached(&record, version, dek, aad, &plaintext)
                            .await?
                            .0
                    }
                    Some(_) => {
                        let cipher = self.deterministic_cipher(version)?;
                        self.with_uncached_key(version, dek, &cipher, |key| {
                            cipher.encrypt_value(&aad.bytes, &plaintext, key)
                        })
                        .await??
                    }
                };
                probes.push(Encrypted::new(version.key_id(), sealed.value()));
            }
            Ok(probes)
        })
        .await
    }

    fn deterministic_cipher(&self, version: &KeyVersion) -> KeyringResult<DeterministicCipher> {
        match version.algorithm() {
            KeyAlgorithm::Deterministic(algorithm) => Ok(DeterministicCipher::new(algorithm)?),
            KeyAlgorithm::Randomized(_) => Err(KeyringError::record_invalid(
                self.id(),
                RecordInvalidReason::PurposeMismatch(version.key_id()),
            )),
        }
    }

    /// Seals `plaintext` with `aad` under `version` of `record`, whose wrapped key is `dek`, with
    /// the key through the [`DekCache`], and returns where the key came from.
    async fn seal_cached(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        aad: &DeterministicAad,
        plaintext: &SecretValue,
    ) -> KeyringResult<(DeterministicCipherText, DekCacheOutcome)> {
        let cipher = self.deterministic_cipher(version)?;
        let (sealed, outcome) = self
            .with_cached_key(record, version.key_id(), dek, async |cache, binding| {
                cache
                    .with_deterministic_key(
                        &self.provider,
                        cipher.algorithm(),
                        dek,
                        binding,
                        |key| cipher.encrypt_value(&aad.bytes, plaintext, key),
                    )
                    .await
            })
            .await?;
        Ok((sealed?, outcome))
    }

    /// Runs `use_key` with the key of `version`, which the provider unwraps for this call only
    /// and which never enters the [`DekCache`].
    async fn with_uncached_key<T>(
        &self,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        cipher: &DeterministicCipher,
        use_key: impl FnOnce(&DeterministicDataEncryptionKey) -> T,
    ) -> KeyringResult<T> {
        let binding = self.cache.binding(version.key_id())?;
        let (result, _) = DekCache::disabled()
            .with_deterministic_key(
                &self.provider,
                cipher.algorithm(),
                dek,
                binding.as_ref(),
                use_key,
            )
            .await?;
        Ok(result)
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use kms_aead::{
        DataEncryptionKey, DeterministicAlgorithm, KekProvider, KmsAeadEncryptionProvider,
    };
    use secret_vault_value::SecretValue;
    use serde_json::json;

    use crate::errors::InteropRequirement;
    use crate::store::{KeyringStore, MemoryKeyringStore};
    use crate::testing::{email_of, TestProvider, TestResult, TENANT, TEST_BACKEND};
    use crate::{
        Deterministic, DeterministicAad, Encrypted, EntityKind, FieldName, FieldSpec, Interop,
        KeyId, KeyTrust, Keyring, KeyringError, KeyringOptions, KeyringPolicy, KeyringRecord,
        KeyringResult, Purpose,
    };

    const EMAIL: FieldSpec = FieldSpec::new(
        EntityKind::from_static("user"),
        FieldName::from_static("email"),
    );

    const ALICE: &str = "alice@example.com";

    /// A keyring with an AES-SIV version beside the randomized one.
    async fn deterministic_keyring(
        provider: TestProvider,
    ) -> KeyringResult<Keyring<MemoryKeyringStore, TestProvider>> {
        Keyring::create(
            MemoryKeyringStore::new(),
            provider,
            TEST_BACKEND,
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
        assert_eq!(alice.key_id(), KeyId::try_from(0x8000_0001)?);
        assert_eq!(alice.as_bytes().len(), 5 + 16 + ALICE.len());
        assert_eq!(keyring.decrypt_deterministic(&aad, &alice).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn probes_cover_every_decrypting_version_newest_first() -> TestResult {
        let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let aad = EMAIL.deterministic_aad();
        let first = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        keyring.rotate(Purpose::Deterministic).await?;
        keyring.rotate(Purpose::Deterministic).await?;

        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
            [
                KeyId::try_from(0x8000_0003)?,
                KeyId::try_from(0x8000_0002)?,
                KeyId::try_from(0x8000_0001)?,
            ]
        );
        assert_eq!(
            probes[0],
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
        keyring.rotate(Purpose::Deterministic).await?;
        let first = KeyId::try_from(0x8000_0001)?;
        let current = [KeyId::try_from(0x8000_0002)?];

        keyring.retire(first).await?;
        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
            current
        );

        keyring.destroy(first).await?;
        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
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
        keyring.mark_compromised(first.key_id(), None).await?;

        let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
        assert_eq!(
            probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
            [KeyId::try_from(0x8000_0002)?, first.key_id()]
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
        keyring.mark_compromised(value.key_id(), None).await?;

        assert!(matches!(
            keyring.decrypt_deterministic(&aad, &value).await,
            Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == value.key_id()
        ));
        let decrypted = keyring
            .decrypt_deterministic_with_status(&aad, &value)
            .await?;
        assert_eq!(decrypted.value, ALICE);
        assert_eq!(decrypted.key_id, value.key_id());
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

    /// The empty plaintext sealed by tink-java's AES-SIV with the TINK prefix: key id 0x44556677,
    /// the bytes 0 to 63 as the 64-byte key, and one associated-data item, the byte 0xFF. From
    /// `testCreateForEncryptConstructorForDecrypt_tinkPrefix` in
    /// <https://github.com/tink-crypto/tink-java/blob/eadd2736490b50d80b3117a5586ffe0985c9207e/src/test/java/com/google/crypto/tink/subtle/AesSivTest.java#L396-L424>.
    const TINK_DETERMINISTIC_VALUE: [u8; 21] = [
        0x01, 0x44, 0x55, 0x66, 0x77, 0x1b, 0xc4, 0x9c, 0x6a, 0x89, 0x4e, 0xf5, 0x74, 0x4a, 0x0a,
        0x01, 0xd4, 0x66, 0x08, 0xcb, 0xcc,
    ];

    /// Tink's key id has bit 31 clear, which is a randomized id here, so the value is read under
    /// the deterministic version 2^31 + 1 holding Tink's key: the rest of the bytes are Tink's.
    #[tokio::test]
    async fn a_deterministic_value_sealed_by_tink_decrypts() -> TestResult {
        assert!(matches!(
            Encrypted::<Vec<u8>, Deterministic>::try_from(TINK_DETERMINISTIC_VALUE.to_vec()),
            Err(KeyringError::KeyPurposeMismatch(_))
        ));
        let key_id = KeyId::try_from(0x8000_0001)?;
        let mut bytes = TINK_DETERMINISTIC_VALUE.to_vec();
        bytes[1..5].copy_from_slice(&0x8000_0001u32.to_be_bytes());
        let value = Encrypted::<Vec<u8>, Deterministic>::try_from(bytes)?;

        let memory = MemoryKeyringStore::new();
        let provider = TestProvider::new("tink-kek")?;
        let tink_key = DataEncryptionKey::from(SecretValue::from((0u8..64).collect::<Vec<_>>()));
        let wrapped = provider
            .encrypt_data_encryption_key(&tink_key, Some(&TENANT.dek_binding(key_id)?))
            .await?;
        let document = json!({
            "schema": 1,
            "id": "tenant-42",
            "kek": { "provider": "local", "key": "tink-kek" },
            "algorithms": { "randomized": "aes-256-gcm", "deterministic": "aes-256-siv" },
            "versions": [{
                "key_id": 0x8000_0001u32,
                "algorithm": "aes-256-siv",
                "state": "active",
                "compromised": null,
                "created_at": "2026-01-10T09:00:00Z",
                "state_changed_at": "2026-01-10T09:00:00Z",
                "wrapped_dek": STANDARD.encode(wrapped.to_bytes()?),
            }],
            "created_at": "2026-01-10T09:00:00Z",
            "updated_at": "2026-01-10T09:00:00Z",
        });
        let record = KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())?;
        memory.compare_and_swap(&record, None).await?;
        let keyring = Keyring::open(
            memory,
            provider,
            TEST_BACKEND,
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
        .await?;
        let aad = DeterministicAad {
            bytes: vec![0xFF],
            interop: Interop::None,
        };

        assert_eq!(
            keyring.decrypt_deterministic(&aad, &value).await?,
            Vec::<u8>::new()
        );
        assert_eq!(
            keyring
                .encrypt_deterministic(&aad, &Vec::<u8>::new())
                .await?,
            value
        );
        Ok(())
    }
}
