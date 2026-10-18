//! The keyset exports: a keyring's versions as a Tink keyset wrapped by the keyring's KEK, for
//! BigQuery's `KEYS.KEYSET_CHAIN` or for Tink's own keyset readers.

use std::fmt::{Debug, Formatter, Write};

use kms_aead::cache::DekCache;
use kms_aead::formats::{TinkKeyType, TinkKeyset};
#[cfg(feature = "bigquery-export")]
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{
    AeadAlgorithm, AeadBackend, DataEncryptionKey, DeterministicAlgorithm,
    EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider, ValueStruct,
};

use crate::errors::{InteropRequirement, KeyVersionError, KeyringError, KeyringResult};
use crate::spans;
use crate::store::KeyringStore;
use crate::{Interop, KeyAlgorithm, KeyId, KeyVersionState, Keyring, KeyringRecord, Purpose};

/// The versions a keyset export holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetSelection {
    /// Every version of the purpose that decrypts and is not compromised, the pending one
    /// included, with the active version as the primary: the keyset of a query that reads a
    /// column. BigQuery and Tink open a value under the key its prefix names, so one keyset reads
    /// the values of every version it holds.
    Readable(Purpose),
    /// The one version, as the primary, also when it is compromised, and never a pending one:
    /// the keyset of `DETERMINISTIC_ENCRYPT` for the probe of one version, since BigQuery
    /// encrypts under the primary, and of a read through a compromised version.
    Single(KeyId),
}

impl KeysetSelection {
    fn purpose(self) -> Purpose {
        match self {
            KeysetSelection::Readable(purpose) => purpose,
            KeysetSelection::Single(key_id) => key_id.purpose(),
        }
    }
}

/// How the bytes of a [`WrappedKeyset`] wrap the keyset, which decides its reader.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum KeysetEncoding {
    /// The KMS ciphertext of the serialized `Keyset`, with no associated data: the
    /// `first_level_keyset` of BigQuery's `KEYS.KEYSET_CHAIN`, which unwraps with Cloud KMS only
    /// and reads AES-256-GCM and AES-SIV keys only.
    BigQuery,
    /// Tink's `EncryptedKeyset` message around that ciphertext, which Tink's keyset readers take
    /// with the KMS client of the KEK's Tink key URI. Its keys are the ones every Tink language
    /// reads in a keyset: AES-GCM, AES-GCM-SIV and AES-SIV.
    Tink,
}

impl KeysetEncoding {
    /// The reader of a field whose values this encoding's keyset reads.
    fn interop(self) -> Interop {
        match self {
            KeysetEncoding::BigQuery => Interop::BigQuery,
            KeysetEncoding::Tink => Interop::Tink,
        }
    }

    /// The Tink key type the reader reads `algorithm`'s keys as, or `None` for an algorithm it
    /// does not implement.
    pub(crate) fn key_type(self, algorithm: KeyAlgorithm) -> Option<TinkKeyType> {
        match algorithm {
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm) => Some(TinkKeyType::AesGcm),
            KeyAlgorithm::Randomized(
                algorithm @ (AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256GcmSiv),
            ) if self == KeysetEncoding::Tink => Some(algorithm.into()),
            KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv) => {
                Some(TinkKeyType::AesSiv)
            }
            KeyAlgorithm::Randomized(_)
            | KeyAlgorithm::Deterministic(_)
            | KeyAlgorithm::Beacon(_) => None,
        }
    }

    /// Tink's key URI of `kek`, or `None` for a KEK the reader does not unwrap with.
    pub(crate) fn key_uri(self, kek: &KekRef) -> Option<String> {
        let key_uri = kek.tink_key_uri();
        match self {
            KeysetEncoding::BigQuery => key_uri.filter(|_| *kek.provider() == KekProvider::Gcp),
            KeysetEncoding::Tink => key_uri,
        }
    }
}

/// A Tink keyset of a keyring's versions, wrapped by the keyring's KEK with no additional
/// authenticated data, in the encoding of the export that made it.
///
/// The bytes are a KMS ciphertext. They open nothing without the KMS key's decrypt right, which a
/// principal that reads with them needs anyway. A keyset is a copy of the record at the time of
/// the export: after a rotation, a `Readable` keyset does not read the values of the new version
/// until it is exported again.
///
/// `Debug` shows the key URI, the encoding and the key ids, never the wrapped keyset.
#[derive(Clone)]
pub struct WrappedKeyset {
    bytes: Vec<u8>,
    encoding: KeysetEncoding,
    key_uri: String,
    key_ids: Vec<KeyId>,
}

impl WrappedKeyset {
    /// The wrapped keyset, as a `BYTES` column, a query parameter or a file holds it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The versions in the keyset, in ascending order.
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }

    /// The keyset of `export_bigquery_keyset` as a GoogleSQL bytes literal, `b'\x0a\x24…'`, for
    /// the second argument of `KEYS.KEYSET_CHAIN`, which takes a literal or a query parameter.
    /// `None` for the keyset of [`export_tink_keyset`](Keyring::export_tink_keyset), which
    /// `KEYS.KEYSET_CHAIN` does not read.
    pub fn to_sql_literal(&self) -> Option<String> {
        if self.encoding != KeysetEncoding::BigQuery {
            return None;
        }
        let mut literal = String::with_capacity(3 + 4 * self.bytes.len());
        literal.push_str("b'");
        for byte in &self.bytes {
            // Writing to a `String` cannot fail.
            let _ = write!(literal, "\\x{byte:02x}");
        }
        literal.push('\'');
        Some(literal)
    }

    /// Tink's key URI of the KMS key that wraps the keyset, such as
    /// `gcp-kms://projects/…/cryptoKeys/…` or `aws-kms://arn:aws:kms:…`: the first argument of
    /// `KEYS.KEYSET_CHAIN`, and the URI of the KMS client a Tink keyset reader takes.
    pub fn key_uri(&self) -> &str {
        &self.key_uri
    }
}

impl Debug for WrappedKeyset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKeyset")
            .field("encoding", &self.encoding)
            .field("key_uri", &self.key_uri)
            .field("key_ids", &self.key_ids)
            .finish_non_exhaustive()
    }
}

/// The BigQuery export, which exists for keyrings on a Cloud KMS key alone: `KEYS.KEYSET_CHAIN`
/// unwraps with Cloud KMS only.
#[cfg(feature = "bigquery-export")]
impl<S: KeyringStore, B: AeadBackend> Keyring<S, GcpKmsProvider, B> {
    /// The versions `selection` names as a Tink keyset wrapped by the keyring's KMS key, for
    /// BigQuery's `KEYS.KEYSET_CHAIN` in the KMS key's location. An administrative call: it
    /// unwraps every selected key through the provider, never through the
    /// [`DekCache`](kms_aead::cache::DekCache), and wraps the keyset, so it needs the KMS key's
    /// encrypt and decrypt rights, and the process holds the selected keys for the duration of
    /// the call only.
    ///
    /// The versions are selected from the record read from the store for this call, checked
    /// forward-only as a revalidation is, and taken as the cached record: a version another
    /// process flagged compromised is never exported as readable.
    ///
    /// The keys inside are the versions' own keys. The keyset never opens as a version's key:
    /// what the KMS unwraps from it is a serialized keyset, which is no serialized Tink key.
    ///
    /// # Errors
    ///
    /// - the store's errors, [`KeyringError::RecordMissing`], [`KeyringError::RecordInvalid`]
    ///   and [`KeyringError::RecordRegressed`], from the read of the record;
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
    ) -> KeyringResult<WrappedKeyset> {
        self.export_keyset(selection, KeysetEncoding::BigQuery)
            .await
    }
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// The versions `selection` names as Tink's encrypted keyset, wrapped by the keyring's KEK:
    /// the bytes Tink's keyset readers take with the KMS client of
    /// [`key_uri`](WrappedKeyset::key_uri), `KeysetHandle.read` in Java, `keyset.Read` in Go and
    /// `tink.read_keyset_handle` in Python. An administrative call, with the same versions, the
    /// same fresh read of the record and the same rights as `export_bigquery_keyset`, on a KEK in
    /// any KMS that Tink has a client for: Cloud KMS, AWS KMS by key ARN, and Vault Transit in
    /// Tink for Go.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::Interop`] with [`Interop::Tink`] and [`InteropRequirement::Kek`],
    ///   before any store or KMS call, for a KEK without a Tink key URI: an Azure, local or
    ///   application's own KEK, or an AWS key named without its ARN;
    /// - [`KeyringError::ExportAlgorithmUnsupported`], before any KMS call, for a selected
    ///   version of ChaCha20-Poly1305, which Tink for Python and C++ do not read in a keyset, or
    ///   of a beacon;
    /// - the errors of the selection and of the provider, as `export_bigquery_keyset` has them.
    pub async fn export_tink_keyset(
        &self,
        selection: KeysetSelection,
    ) -> KeyringResult<WrappedKeyset> {
        self.export_keyset(selection, KeysetEncoding::Tink).await
    }

    /// The body of both exports, on any provider so that the unit tests run the BigQuery one on
    /// a local KMS that reports a Cloud KMS key.
    async fn export_keyset(
        &self,
        selection: KeysetSelection,
        encoding: KeysetEncoding,
    ) -> KeyringResult<WrappedKeyset> {
        spans::in_span(spans::export(self.id(), selection.purpose()), async {
            let kek = self.provider.kek();
            let key_uri = encoding.key_uri(kek).ok_or_else(|| {
                KeyringError::interop(
                    self.id(),
                    encoding.interop(),
                    InteropRequirement::Kek(kek.provider().clone()),
                )
            })?;
            // The store's record rather than the cached one, so that a version another process
            // flagged compromised since this process last refreshed is never exported.
            let record = self.cache.reload("export").await?;
            let (primary, versions) = self.exported_versions(&record, selection, encoding)?;
            let mut keyset = TinkKeyset::new(primary.into());
            for (key_id, key_type, dek) in &versions {
                // Uncached, so that the export leaves no key in the cache of a process that
                // serves no reads under it.
                let (added, _) = DekCache::disabled()
                    .with_key(&self.provider, dek, |key| {
                        keyset.add_key((*key_id).into(), *key_type, key)
                    })
                    .await?;
                added?;
            }
            let bytes = match encoding {
                KeysetEncoding::BigQuery => {
                    let plaintext = DataEncryptionKey::from(keyset.to_bytes());
                    // Zeroizes the keys inside the keyset before the KMS round trip, so that the
                    // serialized keyset is the one copy left while it is wrapped.
                    drop(keyset);
                    self.provider
                        .encrypt_data_encryption_key(&plaintext)
                        .await?
                        .into_value()
                }
                KeysetEncoding::Tink => keyset.to_encrypted_bytes(&self.provider).await?,
            };
            spans::record_versions(versions.len());
            Ok(WrappedKeyset {
                bytes,
                encoding,
                key_uri,
                key_ids: versions.iter().map(|(key_id, _, _)| *key_id).collect(),
            })
        })
        .await
    }

    /// The primary and the versions of `selection` in `record`, each with its Tink key type in
    /// `encoding` and its wrapped key.
    fn exported_versions<'r>(
        &self,
        record: &'r KeyringRecord,
        selection: KeysetSelection,
        encoding: KeysetEncoding,
    ) -> KeyringResult<(KeyId, Vec<ExportedVersion<'r>>)> {
        let (primary, versions): (KeyId, Vec<_>) = match selection {
            KeysetSelection::Readable(purpose) => {
                let primary = record
                    .active(purpose)
                    .ok_or_else(|| KeyringError::no_active_version(self.id(), purpose))?;
                let versions = record
                    .versions()
                    .iter()
                    .filter(|version| version.key_id().purpose() == purpose)
                    .filter_map(|version| match version.readable_dek() {
                        Some((dek, None)) => Some((version, dek)),
                        _ => None,
                    })
                    .collect();
                (primary.key_id(), versions)
            }
            KeysetSelection::Single(key_id) => {
                let version = record
                    .version(key_id)
                    .ok_or_else(|| KeyringError::key_version_unknown(self.id(), key_id))?;
                if version.state() == KeyVersionState::Pending {
                    return Err(KeyringError::KeyVersionPending(KeyVersionError {
                        keyring: self.id().clone(),
                        key_id,
                    }));
                }
                let (dek, _) = version
                    .readable_dek()
                    .ok_or_else(|| self.unreadable(version))?;
                (key_id, vec![(version, dek)])
            }
        };
        let versions = versions
            .into_iter()
            .map(|(version, dek)| {
                let key_type = encoding.key_type(version.algorithm()).ok_or_else(|| {
                    KeyringError::ExportAlgorithmUnsupported(KeyVersionError {
                        keyring: self.id().clone(),
                        key_id: version.key_id(),
                    })
                })?;
                Ok((version.key_id(), key_type, dek))
            })
            .collect::<KeyringResult<_>>()?;
        Ok((primary, versions))
    }
}

/// A selected version: its key id, its Tink key type and its wrapped key.
type ExportedVersion<'r> = (KeyId, TinkKeyType, &'r EncryptedDataEncryptionKey);

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use kms_aead::{AeadAlgorithm, BeaconAlgorithm, CipherText, CipherTextWithEncryptedKey};
    use secret_vault_value::SecretValue;

    use super::*;
    use crate::errors::{InteropError, KeyVersionError};
    use crate::test_support::{email_of, TestKeyring, TestProvider, TestResult, TENANT};
    use crate::testing::MemoryKeyringStore;
    use crate::{KeyAlgorithm, KeyVersion, KeyringOptions, KeyringPolicy};

    /// A keyring on `provider` with one version of each purpose the policy names.
    async fn keyring(
        provider: TestProvider,
        policy: KeyringPolicy,
    ) -> KeyringResult<(TestKeyring<MemoryKeyringStore>, TestProvider)> {
        let keyring = TestKeyring::create(
            MemoryKeyringStore::new(),
            provider.clone(),
            TENANT,
            policy,
            KeyringOptions::new().with_watch(false),
        )
        .await?;
        Ok((keyring, provider))
    }

    /// The keyset of `keyring`'s randomized versions `key_ids` with `primary` as the primary, as
    /// an export of them writes it.
    async fn keyset_of(
        keyring: &TestKeyring<MemoryKeyringStore>,
        provider: &TestProvider,
        primary: u32,
        key_ids: &[u32],
    ) -> Result<SecretValue, Box<dyn std::error::Error>> {
        let record = keyring.record();
        let mut keyset = TinkKeyset::new(KeyId::try_from(primary)?.into());
        for key_id in key_ids {
            let key_id = KeyId::try_from(*key_id)?;
            let dek = record
                .version(key_id)
                .and_then(KeyVersion::wrapped_dek)
                .ok_or("the version holds no key")?;
            let (added, _) = DekCache::disabled()
                .with_key(provider, dek, |key| {
                    keyset.add_key(key_id.into(), TinkKeyType::AesGcm, key)
                })
                .await?;
            added?;
        }
        Ok(keyset.to_bytes())
    }

    #[tokio::test]
    async fn export_refuses_a_version_of_another_algorithm() -> TestResult {
        let (keyring, provider) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        keyring
            .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
            .await?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        let readable = keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await;
        let first = keyring
            .export_keyset(
                KeysetSelection::Single(KeyId::try_from(1)?),
                KeysetEncoding::BigQuery,
            )
            .await?;

        assert!(matches!(
            readable,
            Err(KeyringError::ExportAlgorithmUnsupported(KeyVersionError { key_id, .. }))
                if key_id == KeyId::try_from(2)?
        ));
        assert_eq!(first.key_ids(), [KeyId::try_from(1)?]);
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps + 1);
        Ok(())
    }

    #[tokio::test]
    async fn readable_omits_compromised_versions() -> TestResult {
        let (keyring, provider) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        for _ in 0..2 {
            keyring
                .promote(keyring.rotate(Purpose::Randomized).await?)
                .await?;
        }
        keyring.mark_compromised(KeyId::try_from(2)?, None).await?;

        let wrapped = keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                wrapped.as_bytes().to_vec(),
            ))
            .await?;

        assert_eq!(
            wrapped.key_ids(),
            [KeyId::try_from(1)?, KeyId::try_from(3)?]
        );
        assert_eq!(
            *keyset.value(),
            keyset_of(&keyring, &provider, 3, &[1, 3]).await?
        );
        Ok(())
    }

    #[test]
    fn debug_leaves_out_the_wrapped_keyset() -> TestResult {
        let marker = [0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE];
        let keyset = WrappedKeyset {
            bytes: marker.to_vec(),
            encoding: KeysetEncoding::Tink,
            key_uri: "gcp-kms://projects/p/cryptoKeys/k".to_string(),
            key_ids: vec![KeyId::try_from(1)?],
        };

        let debug = format!("{keyset:?}");

        assert!(!debug.contains("192, 255, 238"), "{debug}");
        Ok(())
    }

    #[tokio::test]
    async fn readable_follows_a_compromise_by_another_process() -> TestResult {
        let (exporter, provider) =
            keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        let administrator = TestKeyring::open(
            exporter.cache.store().clone(),
            provider.clone(),
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
        .await?;
        let leaked = KeyId::try_from(1)?;
        administrator.mark_compromised(leaked, None).await?;

        let wrapped = exporter
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                wrapped.as_bytes().to_vec(),
            ))
            .await?;

        assert_eq!(wrapped.key_ids(), [KeyId::try_from(2)?]);
        assert_eq!(
            *keyset.value(),
            keyset_of(&exporter, &provider, 2, &[2]).await?
        );
        Ok(())
    }

    #[tokio::test]
    async fn export_does_not_populate_the_cache() -> TestResult {
        let (keyring, provider) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        let aad = email_of("42")?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;
        keyring
            .encrypt(&aad, &"alice@example.com".to_string())
            .await?;
        keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;

        // One unwrap per export, and one for the encrypt, which found the cache empty.
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps + 3);
        Ok(())
    }

    #[tokio::test]
    async fn an_exported_keyset_does_not_open_as_an_envelope_key() -> TestResult {
        let (keyring, provider) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        let wrapped = keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;
        let value = CipherTextWithEncryptedKey::join(
            &CipherText(vec![0; 32]),
            &EncryptedDataEncryptionKey::new(wrapped.as_bytes().to_vec()),
        )?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        for _ in 0..2 {
            let opened = keyring
                .decrypt_envelope_value(b"users:42:email", &value, AeadAlgorithm::Aes256Gcm)
                .await;
            assert!(matches!(
                opened,
                Err(KeyringError::Kms(error)) if error.code() == "INVALID_KEY_FORMAT"
            ));
        }

        // Each call unwraps again: the keyset was never cached as a key.
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps + 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_pending_version_is_readable_and_never_the_primary() -> TestResult {
        let (keyring, provider) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        let staged = keyring.rotate(Purpose::Randomized).await?;

        let wrapped = keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Randomized),
                KeysetEncoding::BigQuery,
            )
            .await?;
        let keyset = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                wrapped.as_bytes().to_vec(),
            ))
            .await?;
        assert_eq!(wrapped.key_ids(), [KeyId::try_from(1)?, staged]);
        assert_eq!(
            *keyset.value(),
            keyset_of(&keyring, &provider, 1, &[1, staged.as_u32()]).await?
        );
        assert!(matches!(
            keyring
                .export_keyset(KeysetSelection::Single(staged), KeysetEncoding::BigQuery)
                .await,
            Err(KeyringError::KeyVersionPending(KeyVersionError { key_id, .. })) if key_id == staged
        ));
        Ok(())
    }

    #[tokio::test]
    async fn beacon_keys_are_never_exported() -> TestResult {
        let policy = KeyringPolicy::new().with_beacon_algorithm(BeaconAlgorithm::HmacSha256);
        let (keyring, _) = keyring(TestProvider::cloud_kms()?, policy).await?;

        let exported = keyring
            .export_keyset(
                KeysetSelection::Readable(Purpose::Beacon),
                KeysetEncoding::BigQuery,
            )
            .await;

        assert!(matches!(
            exported,
            Err(KeyringError::ExportAlgorithmUnsupported(_))
        ));
        Ok(())
    }

    #[tokio::test]
    async fn single_of_a_destroyed_version_fails() -> TestResult {
        let (keyring, _) = keyring(TestProvider::cloud_kms()?, KeyringPolicy::new()).await?;
        let first = KeyId::try_from(1)?;
        keyring
            .promote(keyring.rotate(Purpose::Randomized).await?)
            .await?;
        keyring.retire(first).await?;
        keyring.destroy(first).await?;

        let result = keyring
            .export_keyset(KeysetSelection::Single(first), KeysetEncoding::BigQuery)
            .await;

        assert!(matches!(
            result,
            Err(KeyringError::KeyVersionDestroyed(KeyVersionError { key_id, .. })) if key_id == first
        ));
        Ok(())
    }

    #[tokio::test]
    async fn tink_export_refuses_a_kek_without_a_tink_key_uri() -> TestResult {
        let (keyring, provider) =
            keyring(TestProvider::new("tenant-42-kek")?, KeyringPolicy::new()).await?;
        let wraps = provider.calls.wraps.load(Ordering::SeqCst);
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        let exported = keyring
            .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
            .await;

        assert!(matches!(
            exported,
            Err(KeyringError::Interop(InteropError {
                interop: Interop::Tink,
                requirement: InteropRequirement::Kek(KekProvider::Local),
                ..
            }))
        ));
        assert_eq!(provider.calls.wraps.load(Ordering::SeqCst), wraps);
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps);
        Ok(())
    }

    #[tokio::test]
    async fn tink_export_selects_the_versions_of_the_bigquery_export() -> TestResult {
        let policy = KeyringPolicy::new().with_beacon_algorithm(BeaconAlgorithm::HmacSha256);
        let (keyring, _) = keyring(TestProvider::cloud_kms()?, policy).await?;
        for _ in 0..2 {
            keyring
                .promote(keyring.rotate(Purpose::Randomized).await?)
                .await?;
        }
        let compromised = KeyId::try_from(2)?;
        keyring.mark_compromised(compromised, None).await?;
        let pending = keyring.rotate(Purpose::Randomized).await?;
        let cases = [
            (
                KeysetSelection::Readable(Purpose::Randomized),
                Ok(vec![KeyId::try_from(1)?, KeyId::try_from(3)?, pending]),
            ),
            (KeysetSelection::Single(compromised), Ok(vec![compromised])),
            (KeysetSelection::Single(pending), Err("KEY_VERSION_PENDING")),
            (
                KeysetSelection::Readable(Purpose::Beacon),
                Err("EXPORT_ALGORITHM_UNSUPPORTED"),
            ),
        ];

        for (selection, expected) in cases {
            for encoding in [KeysetEncoding::BigQuery, KeysetEncoding::Tink] {
                let exported = keyring.export_keyset(selection, encoding).await;
                assert_eq!(
                    exported
                        .as_ref()
                        .map(|keyset| keyset.key_ids().to_vec())
                        .map_err(KeyringError::code),
                    expected,
                    "{selection:?} {encoding:?}"
                );
                if let Ok(keyset) = exported {
                    assert_eq!(
                        keyset.to_sql_literal().is_some(),
                        encoding == KeysetEncoding::BigQuery
                    );
                }
            }
        }
        Ok(())
    }
}
