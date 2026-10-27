//! The keyset exports: a keyring's versions as a Tink keyset encrypted by the keyring's KEK, for
//! BigQuery's `KEYS.KEYSET_CHAIN` or for Tink's own keyset readers.

use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use kms_aead::backends::AeadBackend;
use kms_aead::cache::DekCache;
use kms_aead::formats::{TinkKeyType, TinkKeyset};
#[cfg(feature = "bigquery-export")]
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{DataEncryptionKey, EncryptedDataEncryptionKey, KmsAeadDecryptionProvider};

#[cfg(feature = "bigquery-export")]
use crate::encodings::BigQuery;
use crate::encodings::{KeysetEncoding, Tink};
use crate::errors::{InteropRequirement, KeyVersionError, KeyringError, KeyringResult};
use crate::purpose::unreserved_key_id;
use crate::record_signing::MaybeRecordSigner;
use crate::spans::{self, LoadReason};
use crate::store::KeyringStore;
use crate::sweep::EncryptionMarker;
use crate::{Interop, KeyId, KeyVersionState, KeyringAdmin, KeyringRecord, Purpose};

/// The versions a keyset export holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetSelection {
    /// Every version of the purpose that decrypts and is not compromised, the pending one included,
    /// with the active version as the primary: the keyset of a query that reads a column. BigQuery
    /// and Tink decrypt a value under the key its prefix names, so one keyset reads the values of
    /// every version it holds.
    Readable(Purpose),
    /// The one version, as the primary, also when it is compromised, and never a pending one:
    /// the keyset of `DETERMINISTIC_ENCRYPT` for the probe of one version, since BigQuery
    /// encrypts under the primary, and of a read through a compromised version.
    Single(KeyId),
}

impl KeysetSelection {
    /// The purpose of the selected versions.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`] for `Single` of a reserved key id.
    fn purpose(self) -> KeyringResult<Purpose> {
        match self {
            KeysetSelection::Readable(purpose) => Ok(purpose),
            KeysetSelection::Single(key_id) => Ok(Purpose::of(unreserved_key_id(key_id)?)),
        }
    }
}

/// A Tink keyset of a keyring's versions, encrypted by the keyring's KEK with no additional
/// authenticated data, in the encoding `E` of the export that made it.
///
/// The bytes are a KMS ciphertext. They decrypt nothing without the KMS key's decrypt right, which
/// a principal that reads with them needs anyway. A keyset is a copy of the record at the time of
/// the export: after a rotation, a `Readable` keyset does not read the values of the new version
/// until it is exported again.
///
/// `Debug` shows the key URI, the encoding and the key ids, never the encrypted keyset.
#[derive(Clone)]
pub struct EncryptedKeyset<E: KeysetEncoding> {
    bytes: Vec<u8>,
    key_uri: String,
    key_ids: Vec<KeyId>,
    encryption_marker: EncryptionMarker,
    /// Tags the bytes with the encoding of the export that made them; holds no `E`.
    encoding: PhantomData<E>,
}

impl<E: KeysetEncoding> EncryptedKeyset<E> {
    /// The encrypted keyset, as a `BYTES` column, a query parameter or a file holds it.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The encrypted keyset, taking the export.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The key ids of the versions in the keyset, in ascending order.
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }

    /// The encryption marker of the record the keyset was exported from. The primary of a
    /// `Readable` keyset is that record's active version of the purpose, so a statement that
    /// encrypts values under the keyset, such as a sweep's `AEAD.ENCRYPT` in BigQuery, stores this
    /// marker beside them, as a write stores the marker of its [`Encryptor`](crate::Encryptor)'s
    /// record.
    pub fn encryption_marker(&self) -> EncryptionMarker {
        self.encryption_marker
    }

    /// Tink's key URI of the KMS key that encrypts the keyset, such as
    /// `gcp-kms://projects/…/cryptoKeys/…` or `aws-kms://arn:aws:kms:…`: the first argument of
    /// `KEYS.KEYSET_CHAIN`, and the URI of the KMS client a Tink keyset reader takes.
    pub fn key_uri(&self) -> &str {
        &self.key_uri
    }
}

impl<E: KeysetEncoding> Debug for EncryptedKeyset<E> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedKeyset")
            .field("encoding", &E::INTEROP)
            .field("key_uri", &self.key_uri)
            .field("key_ids", &self.key_ids)
            .field("encryption_marker", &self.encryption_marker)
            .finish_non_exhaustive()
    }
}

/// The BigQuery export, which exists for keyrings on a Cloud KMS key alone: `KEYS.KEYSET_CHAIN`
/// decrypts with Cloud KMS only.
#[cfg(feature = "bigquery-export")]
impl<S: KeyringStore, B: AeadBackend> KeyringAdmin<S, GcpKmsProvider, B> {
    /// The versions `selection` names as a Tink keyset encrypted by the keyring's KMS key, for
    /// BigQuery's `KEYS.KEYSET_CHAIN` in the KMS key's location. An administrative call: it
    /// decrypts every selected key through the provider, never through the
    /// [`DekCache`](kms_aead::cache::DekCache), and encrypts the keyset, so it needs the KMS key's
    /// encrypt and decrypt rights, and the process holds the selected keys for the duration of
    /// the call only.
    ///
    /// The versions are selected from the record read from the store for this call, checked
    /// forward-only as a revalidation is, and taken as the cached record: a version another
    /// process flagged compromised is never exported as readable.
    ///
    /// The keys inside are the versions' own keys. The keyset never decrypts as a version's key:
    /// what the KMS decrypts from it is a serialised keyset, which is no serialised Tink key.
    ///
    /// A query binds the export as two parameters, never as SQL text:
    /// `KEYS.KEYSET_CHAIN(@kms_key, @keyset)`, with [`key_uri`](EncryptedKeyset::key_uri) a
    /// `STRING` parameter and [`value`](EncryptedKeyset::value) a `BYTES` one.
    ///
    /// # Errors
    ///
    /// - the store's errors, [`KeyringError::RecordMissing`], [`KeyringError::RecordInvalid`]
    ///   and [`KeyringError::RecordRegressed`], from the read of the record;
    /// - [`KeyringError::ReservedKeyId`], before any store or KMS call, for `Single` of a
    ///   reserved key id;
    /// - [`KeyringError::NoActiveVersion`] for `Readable` of a purpose with no active version;
    /// - [`KeyringError::KeyVersionUnknown`], [`KeyringError::KeyVersionRetired`] and
    ///   [`KeyringError::KeyVersionDestroyed`] for `Single` of a version that does not decrypt,
    ///   and [`KeyringError::KeyVersionPending`] for `Single` of a pending version;
    /// - [`KeyringError::ExportAlgorithmUnsupported`], before any KMS call, for a selected
    ///   version whose algorithm is not AES-256-GCM or AES-SIV;
    /// - the provider's errors, among them Cloud KMS's limit of 64 KiB of plaintext, which a
    ///   keyset reaches at several hundred versions.
    pub async fn export_bigquery_keyset(
        &self,
        selection: KeysetSelection,
    ) -> KeyringResult<EncryptedKeyset<BigQuery>> {
        self.export_keyset(selection).await
    }
}

impl<S, P, B, R> KeyringAdmin<S, P, B, R>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
    R: MaybeRecordSigner,
{
    /// The versions `selection` names as Tink's encrypted keyset, encrypted by the keyring's KEK:
    /// the bytes Tink's keyset readers take with the KMS client of
    /// [`key_uri`](EncryptedKeyset::key_uri), `KeysetHandle.read` in Java, `keyset.Read` in Go and
    /// `tink.read_keyset_handle` in Python. An administrative call, with the same versions, the
    /// same fresh read of the record and the same rights as `export_bigquery_keyset`, on a KEK in
    /// any KMS that Tink has a client for: Cloud KMS, AWS KMS by key ARN, and Vault Transit in
    /// Tink for Go.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::Interop`] with [`Interop::Tink`](crate::Interop::Tink) and
    ///   [`InteropRequirement::Kek`], before any store or KMS call, for a KEK without a Tink key
    ///   URI: an Azure, local or application's own KEK, or an AWS key named without its ARN, and
    ///   for an asymmetric KEK, which Tink's KMS clients do not decrypt with;
    /// - [`KeyringError::ExportAlgorithmUnsupported`], before any KMS call, for a selected
    ///   version of ChaCha20-Poly1305, which Tink for Python and C++ do not read in a keyset, or
    ///   of a beacon or a MAC;
    /// - the errors of the selection and of the provider, as `export_bigquery_keyset` has them.
    pub async fn export_tink_keyset(
        &self,
        selection: KeysetSelection,
    ) -> KeyringResult<EncryptedKeyset<Tink>> {
        self.export_keyset(selection).await
    }

    /// The body of both exports, on any provider so that the unit tests run the BigQuery one on
    /// a local KMS that reports a Cloud KMS key.
    async fn export_keyset<E: KeysetEncoding>(
        &self,
        selection: KeysetSelection,
    ) -> KeyringResult<EncryptedKeyset<E>> {
        let keyring = &self.keyring;
        spans::in_span(spans::export(keyring.id(), selection.purpose()?), async {
            let interop = E::INTEROP;
            let kek = keyring.provider.kek();
            let key_uri = interop
                .key_uri(kek)
                .filter(|_| !keyring.is_asymmetric_kek(&keyring.record()))
                .ok_or_else(|| {
                    KeyringError::interop(
                        keyring.id(),
                        interop,
                        InteropRequirement::Kek(kek.provider().clone()),
                    )
                })?;
            // The store's record rather than the cached one, so that a version another process
            // flagged compromised since this process last refreshed is never exported.
            let record = keyring.cache.reload(LoadReason::Export).await?;
            let (primary, versions) = self.exported_versions(&record, selection, interop)?;
            let mut keyset = TinkKeyset::new(primary);
            for (key_id, key_type, encrypted_dek) in &versions {
                // Uncached, so that the export leaves no key in the cache of a process that
                // serves no reads under it.
                let (added, _) = DekCache::disabled()
                    .with_dek(&keyring.provider, encrypted_dek, |dek| {
                        keyset.add_key(*key_id, *key_type, dek)
                    })
                    .await?;
                added?;
            }
            let bytes = match interop {
                Interop::BigQuery => {
                    let keyset_dek = DataEncryptionKey::from(keyset.to_bytes());
                    // Zeroises the keys inside the keyset before the KMS round trip, so that the
                    // serialised keyset is the one copy left while it is encrypted.
                    drop(keyset);
                    keyring
                        .provider
                        .encrypt_data_encryption_key(&keyset_dek)
                        .await?
                        .into_value()
                }
                Interop::Tink => keyset.into_encrypted_bytes(&keyring.provider).await?,
            };
            spans::record_versions(versions.len());
            Ok(EncryptedKeyset {
                bytes,
                key_uri,
                key_ids: versions.iter().map(|(key_id, _, _)| *key_id).collect(),
                encryption_marker: record.encryption_marker(),
                encoding: PhantomData,
            })
        })
        .await
    }

    /// The primary and the versions of `selection` in `record`, each with its Tink key type in
    /// the keyset `interop` reads, and its encrypted DEK.
    fn exported_versions<'r>(
        &self,
        record: &'r KeyringRecord,
        selection: KeysetSelection,
        interop: Interop,
    ) -> KeyringResult<(KeyId, Vec<ExportedVersion<'r>>)> {
        let keyring = &self.keyring;
        let (primary, versions): (KeyId, Vec<_>) = match selection {
            KeysetSelection::Readable(purpose) => {
                let primary = record
                    .active(purpose)
                    .ok_or_else(|| KeyringError::no_active_version(keyring.id(), purpose))?;
                let versions = record
                    .versions()
                    .iter()
                    .filter(|version| version.algorithm().purpose() == purpose)
                    .filter_map(|version| match version.readable_dek() {
                        Some((encrypted_dek, None)) => Some((version, encrypted_dek)),
                        _ => None,
                    })
                    .collect();
                (primary.id(), versions)
            }
            KeysetSelection::Single(key_id) => {
                let version = record
                    .version(key_id)
                    .ok_or_else(|| KeyringError::key_version_unknown(keyring.id(), key_id))?;
                if version.state() == KeyVersionState::Pending {
                    return Err(KeyringError::KeyVersionPending(KeyVersionError {
                        keyring: keyring.id().clone(),
                        key_id,
                    }));
                }
                let (encrypted_dek, _) = version
                    .readable_dek()
                    .ok_or_else(|| keyring.unreadable(version))?;
                (key_id, vec![(version, encrypted_dek)])
            }
        };
        let versions = versions
            .into_iter()
            .map(|(version, encrypted_dek)| {
                let key_type = interop.key_type(version.algorithm()).ok_or_else(|| {
                    KeyringError::ExportAlgorithmUnsupported(KeyVersionError {
                        keyring: keyring.id().clone(),
                        key_id: version.id(),
                    })
                })?;
                Ok((version.id(), key_type, encrypted_dek))
            })
            .collect::<KeyringResult<_>>()?;
        Ok((primary, versions))
    }
}

/// A selected version: its key id, its Tink key type and its encrypted DEK.
type ExportedVersion<'r> = (KeyId, TinkKeyType, &'r EncryptedDataEncryptionKey);

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use kms_aead::formats::{Bare, Envelope};
    use kms_aead::{AeadAlgorithm, BeaconAlgorithm, Encrypted, KmsProvider};
    use secret_vault_value::SecretValue;

    use super::*;
    use crate::encodings::BigQuery;
    use crate::errors::{InteropError, KeyVersionError};
    use crate::test_support::{
        email_of, TestAdmin, TestKeyring, TestProvider, TestRegistry, TestResult, TENANT,
    };
    use crate::testing::MemoryKeyringStore;
    use crate::{
        Interop, KeyAlgorithm, KeyVersion, KeyringAlgorithms, KeyringRegistryOptions, MacAlgorithm,
    };

    /// A keyring on `provider` with one version of each purpose `algorithms` names.
    async fn keyring_admin(
        provider: TestProvider,
        algorithms: KeyringAlgorithms,
    ) -> KeyringResult<(TestAdmin<MemoryKeyringStore>, TestProvider)> {
        let admin = TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(provider.clone(), TENANT, algorithms)
        .await?;
        Ok((admin, provider))
    }

    /// The keyset of `keyring`'s randomised versions `key_ids` with `primary` as the primary, as
    /// an export of them writes it.
    async fn keyset_of(
        keyring: &TestKeyring<MemoryKeyringStore>,
        provider: &TestProvider,
        primary: u32,
        key_ids: &[u32],
    ) -> Result<SecretValue, Box<dyn std::error::Error>> {
        let record = keyring.record();
        let mut keyset = TinkKeyset::new(KeyId::new(primary));
        for key_id in key_ids {
            let key_id = KeyId::new(*key_id);
            let encrypted_dek = record
                .version(key_id)
                .and_then(KeyVersion::encrypted_dek)
                .ok_or("the version holds no key")?;
            let (added, _) = DekCache::disabled()
                .with_dek(provider, encrypted_dek, |dek| {
                    keyset.add_key(key_id, TinkKeyType::AesGcm, dek)
                })
                .await?;
            added?;
        }
        Ok(keyset.to_bytes())
    }

    #[tokio::test]
    async fn export_refuses_a_version_of_another_algorithm() -> TestResult {
        let (admin, provider) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        admin
            .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
            .await?;
        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);

        let readable = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await;
        let first = admin
            .export_keyset::<BigQuery>(KeysetSelection::Single(KeyId::new(1)))
            .await?;

        assert!(matches!(
            readable,
            Err(KeyringError::ExportAlgorithmUnsupported(KeyVersionError { key_id, .. }))
                if key_id == KeyId::new(2)
        ));
        assert_eq!(first.key_ids(), [KeyId::new(1)]);
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions + 1
        );
        Ok(())
    }

    #[tokio::test]
    async fn readable_omits_compromised_versions() -> TestResult {
        let (admin, provider) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        let keyring = admin.keyring();
        for _ in 0..2 {
            admin
                .promote_now(admin.rotate(Purpose::Randomized).await?)
                .await?;
        }
        admin.mark_compromised(KeyId::new(2), None).await?;

        let exported = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                exported.value().to_vec(),
            ))
            .await?;

        assert_eq!(exported.key_ids(), [KeyId::new(1), KeyId::new(3)]);
        assert_eq!(
            *keyset.value(),
            keyset_of(keyring, &provider, 3, &[1, 3]).await?
        );
        Ok(())
    }

    #[test]
    fn debug_leaves_out_the_encrypted_keyset() -> TestResult {
        let marker = [0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE];
        let keyset = EncryptedKeyset::<Tink> {
            bytes: marker.to_vec(),
            key_uri: "gcp-kms://projects/p/cryptoKeys/k".to_string(),
            key_ids: vec![KeyId::new(1)],
            encryption_marker: EncryptionMarker::of_epoch(1),
            encoding: PhantomData,
        };

        let debug = format!("{keyset:?}");

        assert!(!debug.contains("192, 255, 238"), "{debug}");
        Ok(())
    }

    #[tokio::test]
    async fn readable_follows_a_compromise_by_another_process() -> TestResult {
        let store = MemoryKeyringStore::new();
        let provider = TestProvider::cloud_kms()?;
        let options = KeyringRegistryOptions::new().with_watch(false);
        let exporter = TestRegistry::new(store.clone(), options.clone())?
            .create(provider.clone(), TENANT, KeyringAlgorithms::new())
            .await?;
        let administrator = TestRegistry::new(store, options)?
            .admin(provider.clone(), TENANT)
            .await?;
        let leaked = KeyId::new(1);
        administrator.mark_compromised(leaked, None).await?;

        let exported = exporter
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                exported.value().to_vec(),
            ))
            .await?;

        assert_eq!(exported.key_ids(), [KeyId::new(2)]);
        assert_eq!(
            *keyset.value(),
            keyset_of(exporter.keyring(), &provider, 2, &[2]).await?
        );
        assert_eq!(
            exported.encryption_marker(),
            administrator.keyring().record().encryption_marker()
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_does_not_populate_the_cache() -> TestResult {
        let (admin, provider) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        let keyring = admin.keyring();
        let aad = email_of("42")?;
        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);

        admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        keyring
            .encryptor()
            .await
            .encrypt(&aad, &"alice@example.com".to_string())
            .await?;
        admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;

        // One decryption per export, and one for the encryption, which found the cache empty.
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions + 3
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_exported_keyset_does_not_decrypt_as_an_envelope_key() -> TestResult {
        let (admin, provider) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        let keyring = admin.keyring();
        let exported = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        let value = Encrypted::<SecretValue, Envelope>::join(
            &Encrypted::<SecretValue, Bare>::try_from(vec![0; 32])?,
            &EncryptedDataEncryptionKey::new(exported.value().to_vec()),
        )?;
        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);

        for _ in 0..2 {
            let decrypted = keyring
                .decrypt_envelope_for_migration(b"users:42:email", &value, AeadAlgorithm::Aes256Gcm)
                .await;
            assert!(matches!(
                decrypted,
                Err(KeyringError::KmsAead(error)) if error.code() == "INVALID_KEY_FORMAT"
            ));
        }

        // Each call decrypts again: the keyset was never cached as a key.
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions + 2
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_pending_version_is_readable_and_never_the_primary() -> TestResult {
        let (admin, provider) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        let keyring = admin.keyring();
        let staged = admin.rotate(Purpose::Randomized).await?;

        let exported = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                exported.value().to_vec(),
            ))
            .await?;
        assert_eq!(exported.key_ids(), [KeyId::new(1), staged]);
        assert_eq!(
            *keyset.value(),
            keyset_of(keyring, &provider, 1, &[1, staged.as_u32()]).await?
        );
        assert!(matches!(
            admin
                .export_keyset::<BigQuery>(KeysetSelection::Single(staged))
                .await,
            Err(KeyringError::KeyVersionPending(KeyVersionError { key_id, .. })) if key_id == staged
        ));
        Ok(())
    }

    #[tokio::test]
    async fn beacon_keys_are_never_exported() -> TestResult {
        let algorithms = KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256);
        let (admin, _) = keyring_admin(TestProvider::cloud_kms()?, algorithms).await?;

        let exported = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Beacon))
            .await;

        assert!(matches!(
            exported,
            Err(KeyringError::ExportAlgorithmUnsupported(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn mac_keys_are_never_exported() -> TestResult {
        let algorithms = KeyringAlgorithms::new().with_mac(MacAlgorithm::HmacSha256);
        let (admin, _) = keyring_admin(TestProvider::cloud_kms()?, algorithms).await?;

        let mac_selection = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Mac))
            .await;
        let single = admin
            .export_keyset::<BigQuery>(KeysetSelection::Single(KeyId::new(0xC000_0001)))
            .await;
        let randomized = admin
            .export_keyset::<BigQuery>(KeysetSelection::Readable(Purpose::Randomized))
            .await?;

        assert!(matches!(
            mac_selection,
            Err(KeyringError::ExportAlgorithmUnsupported(_))
        ));
        assert!(matches!(
            single,
            Err(KeyringError::ExportAlgorithmUnsupported(_))
        ));
        assert_eq!(randomized.key_ids(), [KeyId::new(1)]);
        Ok(())
    }

    #[tokio::test]
    async fn single_of_a_destroyed_version_fails() -> TestResult {
        let (admin, _) =
            keyring_admin(TestProvider::cloud_kms()?, KeyringAlgorithms::new()).await?;
        let first = KeyId::new(1);
        admin
            .promote_now(admin.rotate(Purpose::Randomized).await?)
            .await?;
        admin.retire(first).await?;
        admin.destroy(first).await?;

        let result = admin
            .export_keyset::<BigQuery>(KeysetSelection::Single(first))
            .await;

        assert!(matches!(
            result,
            Err(KeyringError::KeyVersionDestroyed(KeyVersionError { key_id, .. })) if key_id == first
        ));
        Ok(())
    }

    #[tokio::test]
    async fn tink_export_refuses_a_kek_without_a_tink_key_uri() -> TestResult {
        let (admin, provider) = keyring_admin(
            TestProvider::new("tenant-42-kek")?,
            KeyringAlgorithms::new(),
        )
        .await?;
        let encryptions = provider.calls.encryptions.load(Ordering::SeqCst);
        let decryptions = provider.calls.decryptions.load(Ordering::SeqCst);

        let exported = admin
            .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
            .await;

        assert!(matches!(
            exported,
            Err(KeyringError::Interop(InteropError {
                interop: Interop::Tink,
                requirement: InteropRequirement::Kek(KmsProvider::Local),
                ..
            }))
        ));
        assert_eq!(
            provider.calls.encryptions.load(Ordering::SeqCst),
            encryptions
        );
        assert_eq!(
            provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions
        );
        Ok(())
    }

    #[tokio::test]
    async fn tink_export_selects_the_versions_of_the_bigquery_export() -> TestResult {
        let algorithms = KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256);
        let (admin, _) = keyring_admin(TestProvider::cloud_kms()?, algorithms).await?;
        for _ in 0..2 {
            admin
                .promote_now(admin.rotate(Purpose::Randomized).await?)
                .await?;
        }
        let compromised = KeyId::new(2);
        admin.mark_compromised(compromised, None).await?;
        let pending = admin.rotate(Purpose::Randomized).await?;
        let cases = [
            (
                KeysetSelection::Readable(Purpose::Randomized),
                Ok(vec![KeyId::new(1), KeyId::new(3), pending]),
            ),
            (KeysetSelection::Single(compromised), Ok(vec![compromised])),
            (KeysetSelection::Single(pending), Err("KEY_VERSION_PENDING")),
            (
                KeysetSelection::Readable(Purpose::Beacon),
                Err("EXPORT_ALGORITHM_UNSUPPORTED"),
            ),
        ];

        for (selection, expected) in cases {
            let bigquery = admin.export_keyset::<BigQuery>(selection).await;
            let tink = admin.export_keyset::<Tink>(selection).await;
            for key_ids in [
                bigquery
                    .as_ref()
                    .map(|keyset| keyset.key_ids().to_vec())
                    .map_err(KeyringError::code),
                tink.as_ref()
                    .map(|keyset| keyset.key_ids().to_vec())
                    .map_err(KeyringError::code),
            ] {
                assert_eq!(key_ids, expected, "{selection:?}");
            }
        }
        Ok(())
    }
}
