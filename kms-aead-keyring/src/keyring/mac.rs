//! The MAC calls of [`Encryptor`] and [`Keyring`]: MACs under the MAC versions.

use kms_aead::backends::AeadBackend;
use kms_aead::mac::{Authenticator, Mac, WithMac};
use kms_aead::{DataEncryptionKey, KmsAeadDecryptionProvider, KmsAeadResult, Signable};

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::record_cache::VersionLookup;
use crate::spans;
use crate::store::KeyringStore;
use crate::{Encryptor, KeyAlgorithm, KeyId, KeyTrust, KeyVersion, Keyring, Purpose};

/// A verified MAC: the version that verified it and whether that version is trusted, as
/// [`Decrypted`](crate::Decrypted) reports them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct MacVerified {
    /// The version that verified the MAC.
    pub key_id: KeyId,
    /// Whether the version is compromised.
    pub trust: KeyTrust,
}

/// MACs under the keyring's MAC versions: an HMAC of a [`Signable`] value's pre-image, computed
/// under the active version and verified under the version the MAC names.
///
/// A MAC proves that the bytes are unchanged since a holder of the version's key computed it, and
/// nothing about which holder. The payload type of `T` is in the pre-image, so one version serves
/// every type an application authenticates. Every call runs kms-aead's [`Authenticator`], which
/// records its own metrics, so the keyring adds none.
impl<S, P, B> Encryptor<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// The MAC of `value` under the record's active MAC version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the record has no active MAC version;
    /// [`KeyringError::KmsAead`] with code `INVALID_PAYLOAD` when the value has no payload; and
    /// the provider's error when the version's key is not in the
    /// [`DekCache`](kms_aead::cache::DekCache) and cannot be decrypted.
    pub async fn mac<T: Signable>(&self, value: &T) -> KeyringResult<Mac<T>> {
        self.with_active_mac(|authenticator, key_id, dek| authenticator.mac(key_id, value, dek))
            .await
    }

    /// The MAC of `value`, joined with its payload, under the record's active MAC version.
    ///
    /// # Errors
    ///
    /// As [`mac`](Self::mac).
    pub async fn mac_attached<T: Signable>(&self, value: &T) -> KeyringResult<WithMac<T>> {
        self.with_active_mac(|authenticator, key_id, dek| {
            authenticator.mac_attached(key_id, value, dek)
        })
        .await
    }

    /// Runs `compute` with the authenticator, id and key of the record's active MAC version.
    async fn with_active_mac<R>(
        &self,
        compute: impl FnOnce(&Authenticator<B>, KeyId, &DataEncryptionKey) -> KmsAeadResult<R>,
    ) -> KeyringResult<R> {
        let keyring = self.keyring;
        spans::in_span(spans::mac(keyring.id()), async {
            let (version, encrypted_dek) = self
                .record
                .active_dek(Purpose::Mac)
                .ok_or_else(|| KeyringError::no_active_version(keyring.id(), Purpose::Mac))?;
            spans::record_encrypting_version(version);
            let authenticator = keyring.authenticator(version)?;
            let (computed, outcome) = keyring
                .with_cached_dek(&self.record, version.id(), encrypted_dek, |dek| {
                    compute(&authenticator, version.id(), dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(computed?)
        })
        .await
    }
}

/// Whether a read under a compromised version is refused by the keyring's policy or reported.
#[derive(Clone, Copy)]
enum CompromisedReads {
    Apply,
    Report,
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// Verifies `mac` for `value` under the version its key id names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy, and returns that
    /// version's id.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::ReservedKeyId`] and [`KeyringError::KeyPurposeMismatch`], before any
    ///   store or KMS call, when the MAC's key id is reserved or of another purpose;
    /// - [`KeyringError::KeyVersionUnknown`] when the record has no such version, also after one
    ///   reload, as for [`decrypt`](Self::decrypt);
    /// - [`KeyringError::KeyVersionRetired`] and [`KeyringError::KeyVersionDestroyed`];
    /// - [`KeyringError::KeyVersionCompromised`] under
    ///   [`CompromisedReadPolicy::Block`](crate::CompromisedReadPolicy::Block), before any
    ///   decryption;
    /// - [`KeyringError::KmsAead`] with code `MAC_INVALID` when the tag does not match, or is not
    ///   the length of the version's algorithm, `INVALID_PAYLOAD` when the value has no payload,
    ///   and the provider's error when the key cannot be decrypted.
    pub async fn verify_mac<T: Signable>(&self, value: &T, mac: &Mac<T>) -> KeyringResult<KeyId> {
        let (_, verified) = self
            .with_mac_version(
                mac.key_id(),
                CompromisedReads::Apply,
                |authenticator, dek| authenticator.verify(value, mac, dek),
            )
            .await?;
        Ok(verified.key_id)
    }

    /// As [`verify_mac`](Self::verify_mac), without the read policy: reports whether the version
    /// is compromised, as [`decrypt_with_trust`](Self::decrypt_with_trust) does. A compromised
    /// version's key is decrypted for each call, never through the
    /// [`DekCache`](kms_aead::cache::DekCache). A MAC under a compromised version can have been
    /// forged by whoever holds the leaked key.
    ///
    /// # Errors
    ///
    /// As [`verify_mac`](Self::verify_mac), without `KeyVersionCompromised`.
    pub async fn verify_mac_with_trust<T: Signable>(
        &self,
        value: &T,
        mac: &Mac<T>,
    ) -> KeyringResult<MacVerified> {
        let (_, verified) = self
            .with_mac_version(
                mac.key_id(),
                CompromisedReads::Report,
                |authenticator, dek| authenticator.verify(value, mac, dek),
            )
            .await?;
        Ok(verified)
    }

    /// Verifies the payload of `with_mac` under the version its key id names and decodes
    /// it, in that order, applying the read policy as [`verify_mac`](Self::verify_mac) does.
    ///
    /// # Errors
    ///
    /// As [`verify_mac`](Self::verify_mac), and `INVALID_PAYLOAD` when the verified bytes are not
    /// a `T`.
    pub async fn verify_with_mac<T: Signable>(&self, with_mac: &WithMac<T>) -> KeyringResult<T> {
        let (verified, _) = self
            .with_mac_version(
                with_mac.key_id(),
                CompromisedReads::Apply,
                |authenticator, dek| authenticator.verify_with_mac(with_mac, dek),
            )
            .await?;
        Ok(verified)
    }

    /// Runs `verify` with the authenticator and key of the MAC version `key_id`, under the span
    /// `Keyring verify mac`, and returns its result and the version's id and trust.
    async fn with_mac_version<R>(
        &self,
        key_id: KeyId,
        reads: CompromisedReads,
        verify: impl FnOnce(&Authenticator<B>, &DataEncryptionKey) -> KmsAeadResult<R>,
    ) -> KeyringResult<(R, MacVerified)> {
        let key_id = Purpose::Mac.check(key_id)?;
        spans::in_span(spans::verify_mac(self.id(), key_id), async {
            let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
            spans::record_reload(reload);
            let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
            let authenticator = self.authenticator(version)?;
            if matches!(reads, CompromisedReads::Apply) {
                self.apply_read_policy(version, compromise)?;
            }
            let verified = match (compromise, reads) {
                (Some(_), CompromisedReads::Report) => {
                    self.with_uncached_dek(encrypted_dek, |dek| verify(&authenticator, dek))
                        .await?
                }
                _ => {
                    let (verified, outcome) = self
                        .with_cached_dek(&record, key_id, encrypted_dek, |dek| {
                            verify(&authenticator, dek)
                        })
                        .await?;
                    spans::record_dek_cache(outcome);
                    verified
                }
            };
            let trust = compromise.map_or(KeyTrust::Trusted, |compromise| {
                KeyTrust::Compromised(compromise.clone())
            });
            Ok((
                verified?,
                MacVerified {
                    key_id: version.id(),
                    trust,
                },
            ))
        })
        .await
    }

    fn authenticator(&self, version: &KeyVersion) -> KeyringResult<Authenticator<B>> {
        match version.algorithm() {
            KeyAlgorithm::Mac(algorithm) => Ok(Authenticator::new(algorithm)?),
            KeyAlgorithm::Randomized(_)
            | KeyAlgorithm::Deterministic(_)
            | KeyAlgorithm::Beacon(_) => Err(KeyringError::record_invalid(
                self.id(),
                RecordInvalidReason::PurposeMismatch(version.id()),
            )),
        }
    }
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use kms_aead::{KmsAeadResult, SignableType, SignedPayloadType};

    use super::*;
    use crate::errors::KeyVersionError;
    use crate::test_support::{TestAdmin, TestProvider, TestRegistry, TestResult, TENANT};
    use crate::testing::MemoryKeyringStore;
    use crate::{KeyAlgorithm, KeyringAlgorithms, KeyringRegistryOptions, MacAlgorithm};

    #[derive(Debug, PartialEq, Eq)]
    struct Invoice(Vec<u8>);

    impl SignableType for Invoice {
        const PAYLOAD_TYPE: SignedPayloadType =
            SignedPayloadType::from_static("application/vnd.example.invoice+json");
    }

    impl Signable for Invoice {
        fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
            Ok(self.0.clone())
        }

        fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
            Ok(Invoice(payload))
        }
    }

    const FIRST_MAC: KeyId = KeyId::new(0xC000_0001);

    fn test_invoice() -> Invoice {
        Invoice(br#"{"number":"INV-1042","total_cents":12500}"#.to_vec())
    }

    /// A keyring whose MAC purpose uses `algorithm`, with its first MAC version active.
    async fn mac_keyring(algorithm: MacAlgorithm) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
        TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new().with_mac(algorithm),
        )
        .await
    }

    async fn rotate_mac(admin: &TestAdmin<MemoryKeyringStore>) -> KeyringResult<KeyId> {
        let staged = admin.rotate(Purpose::Mac).await?;
        admin.promote_now(staged).await?;
        Ok(staged)
    }

    #[tokio::test]
    async fn an_hmac_sha512_mac_verifies_through_a_cold_dek_cache() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let admin = TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(provider.clone(), TENANT, KeyringAlgorithms::new())
        .await?;
        let keyring = admin.keyring();
        let staged = admin
            .change_algorithm(KeyAlgorithm::Mac(MacAlgorithm::HmacSha512))
            .await?;
        admin.promote_now(staged).await?;
        assert_eq!(staged, FIRST_MAC);

        let encryptor = keyring.encryptor().await;
        let mac = encryptor.mac(&test_invoice()).await?;
        let with_mac = encryptor.mac_attached(&test_invoice()).await?;
        assert_eq!(mac.key_id(), FIRST_MAC);
        assert_eq!(mac.raw().len(), 64);
        keyring.dek_cache().clear();

        assert_eq!(keyring.verify_mac(&test_invoice(), &mac).await?, FIRST_MAC);
        keyring.dek_cache().clear();
        assert_eq!(keyring.verify_with_mac(&with_mac).await?, test_invoice());
        let altered = Invoice(br#"{"number":"INV-1042","total_cents":99900}"#.to_vec());
        let refused = keyring.verify_mac(&altered, &mac).await.err();
        assert_eq!(
            refused.as_ref().map(KeyringError::code),
            Some("MAC_INVALID")
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_older_version_verifies_after_a_rotation_and_a_reencryption() -> TestResult {
        let admin = mac_keyring(MacAlgorithm::HmacSha256).await?;
        let keyring = admin.keyring();
        let old = keyring.encryptor().await.mac(&test_invoice()).await?;

        let second = rotate_mac(&admin).await?;
        admin.reencrypt_deks().await?;
        keyring.dek_cache().clear();

        let new = keyring.encryptor().await.mac(&test_invoice()).await?;
        assert_eq!(new.key_id(), second);
        assert_eq!(keyring.verify_mac(&test_invoice(), &old).await?, FIRST_MAC);
        assert_eq!(keyring.verify_mac(&test_invoice(), &new).await?, second);
        Ok(())
    }

    #[tokio::test]
    async fn a_retired_or_destroyed_version_is_refused() -> TestResult {
        let admin = mac_keyring(MacAlgorithm::HmacSha256).await?;
        let keyring = admin.keyring();
        let mac = keyring.encryptor().await.mac(&test_invoice()).await?;
        let with_mac = keyring
            .encryptor()
            .await
            .mac_attached(&test_invoice())
            .await?;
        rotate_mac(&admin).await?;

        admin.retire(FIRST_MAC).await?;
        assert!(matches!(
            keyring.verify_mac(&test_invoice(), &mac).await,
            Err(KeyringError::KeyVersionRetired(_))
        ));
        assert!(matches!(
            keyring.verify_mac_with_trust(&test_invoice(), &mac).await,
            Err(KeyringError::KeyVersionRetired(_))
        ));
        assert!(matches!(
            keyring.verify_with_mac(&with_mac).await,
            Err(KeyringError::KeyVersionRetired(_))
        ));

        admin.destroy(FIRST_MAC).await?;
        assert!(matches!(
            keyring.verify_mac(&test_invoice(), &mac).await,
            Err(KeyringError::KeyVersionDestroyed(KeyVersionError { key_id, .. })) if key_id == FIRST_MAC
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_compromised_version_follows_the_read_policy() -> TestResult {
        let admin = mac_keyring(MacAlgorithm::HmacSha256).await?;
        let keyring = admin.keyring();
        let mac = keyring.encryptor().await.mac(&test_invoice()).await?;

        let rotation = admin
            .mark_compromised(FIRST_MAC, Some("key leaked".to_string()))
            .await?;

        assert!(matches!(
            keyring.verify_mac(&test_invoice(), &mac).await,
            Err(KeyringError::KeyVersionCompromised(_))
        ));
        let verified = keyring.verify_mac_with_trust(&test_invoice(), &mac).await?;
        assert_eq!(verified.key_id, FIRST_MAC);
        assert!(matches!(verified.trust, KeyTrust::Compromised(_)));
        let replacement = keyring.encryptor().await.mac(&test_invoice()).await?;
        assert_eq!(
            Some(replacement.key_id()),
            rotation.map(|rotation| rotation.current)
        );
        let verified = keyring
            .verify_mac_with_trust(&test_invoice(), &replacement)
            .await?;
        assert_eq!(verified.trust, KeyTrust::Trusted);
        Ok(())
    }

    #[tokio::test]
    async fn a_key_id_of_another_purpose_or_an_unknown_version_is_refused() -> TestResult {
        let admin = mac_keyring(MacAlgorithm::HmacSha256).await?;
        let keyring = admin.keyring();
        let tagged = |key_id: u32| {
            Mac::<Invoice>::try_from([&[0x01][..], &key_id.to_be_bytes(), &[7; 32]].concat())
        };

        assert!(matches!(
            keyring.verify_mac(&test_invoice(), &tagged(1)?).await,
            Err(KeyringError::KeyPurposeMismatch(error)) if error.expected == Purpose::Mac
        ));
        assert!(matches!(
            keyring
                .verify_mac(&test_invoice(), &tagged(0xC000_0000)?)
                .await,
            Err(KeyringError::ReservedKeyId(_))
        ));
        assert!(matches!(
            keyring
                .verify_mac(&test_invoice(), &tagged(0xC000_0009)?)
                .await,
            Err(KeyringError::KeyVersionUnknown(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn a_keyring_without_a_mac_version_has_no_active_one() -> TestResult {
        let admin = TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;

        let encryptor = admin.keyring().encryptor().await;

        assert!(matches!(
            encryptor.mac(&test_invoice()).await,
            Err(KeyringError::NoActiveVersion(_))
        ));
        assert!(matches!(
            encryptor.mac_attached(&test_invoice()).await,
            Err(KeyringError::NoActiveVersion(_))
        ));
        Ok(())
    }
}
