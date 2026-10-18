//! The BigQuery keyset export: a keyring's versions as a Tink keyset that BigQuery's
//! `KEYS.KEYSET_CHAIN` reads, wrapped by the keyring's Cloud KMS key.

use std::fmt::{Debug, Formatter, Write};

use kms_aead::cache::DekCache;
use kms_aead::formats::{TinkKeyType, TinkKeyset};
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{
    AeadAlgorithm, AeadBackend, DataEncryptionKey, DeterministicAlgorithm,
    EncryptedDataEncryptionKey, KekRef, KmsAeadEncryptionProvider, ValueStruct,
};

use crate::errors::{KeyVersionError, KeyringError, KeyringResult};
use crate::spans;
use crate::store::KeyringStore;
use crate::{KeyAlgorithm, KeyId, KeyVersion, KeyVersionState, Keyring, KeyringRecord, Purpose};

/// The versions a keyset export holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeysetSelection {
    /// Every version of the purpose that decrypts and is not compromised, the pending one
    /// included, with the active version as the primary: the keyset of a query that reads a
    /// column. BigQuery opens a value under the key its prefix names, so one keyset reads the
    /// values of every version it holds.
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

/// A Tink keyset of a keyring's versions, wrapped by the keyring's Cloud KMS key with no
/// additional authenticated data: the `first_level_keyset` of BigQuery's `KEYS.KEYSET_CHAIN`.
///
/// The bytes are a Cloud KMS ciphertext. They open nothing without the KMS key's decrypt right,
/// which a principal that queries with them needs anyway. A keyset is a copy of the record at the
/// time of the export: after a rotation, a `Readable` keyset does not read the values of the new
/// version until it is exported again.
///
/// `Debug` shows the KMS key and the key ids, never the wrapped keyset.
#[derive(Clone)]
pub struct WrappedKeyset {
    bytes: Vec<u8>,
    kek: KekRef,
    key_ids: Vec<KeyId>,
}

impl WrappedKeyset {
    /// The wrapped keyset, as a `BYTES` column or query parameter holds it.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The versions in the keyset, in ascending order.
    pub fn key_ids(&self) -> &[KeyId] {
        &self.key_ids
    }

    /// The keyset as a GoogleSQL bytes literal, `b'\x0a\x24…'`, for the second argument of
    /// `KEYS.KEYSET_CHAIN`, which takes a literal or a query parameter.
    pub fn to_sql_literal(&self) -> String {
        let mut literal = String::with_capacity(3 + 4 * self.bytes.len());
        literal.push_str("b'");
        for byte in &self.bytes {
            // Writing to a `String` cannot fail.
            let _ = write!(literal, "\\x{byte:02x}");
        }
        literal.push('\'');
        literal
    }

    /// `gcp-kms://projects/…/cryptoKeys/…`, the KMS key that wraps the keyset, as the first
    /// argument of `KEYS.KEYSET_CHAIN` names it.
    pub fn kms_resource_name(&self) -> String {
        format!("gcp-kms://{}", self.kek.key())
    }
}

impl Debug for WrappedKeyset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WrappedKeyset")
            .field("kek", &self.kek)
            .field("key_ids", &self.key_ids)
            .finish_non_exhaustive()
    }
}

/// The export, which exists for keyrings on a Cloud KMS key alone: `KEYS.KEYSET_CHAIN` unwraps
/// with Cloud KMS only.
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
        self.export_keyset(selection).await
    }
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// The body of [`export_bigquery_keyset`](Keyring::export_bigquery_keyset), on any provider
    /// so that the unit tests run it on a local KMS.
    pub(super) async fn export_keyset(
        &self,
        selection: KeysetSelection,
    ) -> KeyringResult<WrappedKeyset> {
        spans::in_span(spans::export(self.id(), selection.purpose()), async {
            // The store's record rather than the cached one, so that a version another process
            // flagged compromised since this process last refreshed is never exported.
            let record = self.cache.reload("export").await?;
            let (primary, versions) = self.exported_versions(&record, selection)?;
            let mut keyset = TinkKeyset::new(primary.as_u32());
            for (key_id, key_type, dek) in &versions {
                // Uncached, so that the export leaves no key in the cache of a process that
                // serves no reads under it.
                DekCache::disabled()
                    .with_key(&self.provider, dek, |key| {
                        keyset.add_key(key_id.as_u32(), *key_type, key)
                    })
                    .await?;
            }
            let plaintext = DataEncryptionKey::from(keyset.to_bytes());
            // Zeroizes the keys inside the keyset before the KMS round trip, so that the
            // serialized keyset is the one copy left while it is wrapped.
            drop(keyset);
            let wrapped = self
                .provider
                .encrypt_data_encryption_key(&plaintext)
                .await?;
            spans::record_versions(versions.len());
            Ok(WrappedKeyset {
                bytes: wrapped.into_value(),
                kek: self.provider.kek().clone(),
                key_ids: versions.iter().map(|(key_id, _, _)| *key_id).collect(),
            })
        })
        .await
    }

    /// The primary and the versions of `selection` in `record`, each with its Tink key type and
    /// its wrapped key.
    fn exported_versions<'r>(
        &self,
        record: &'r KeyringRecord,
        selection: KeysetSelection,
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
            .map(|(version, dek)| Ok((version.key_id(), self.tink_key_type(version)?, dek)))
            .collect::<KeyringResult<_>>()?;
        Ok((primary, versions))
    }

    /// The Tink key type of `version`, or `ExportAlgorithmUnsupported` for an algorithm BigQuery
    /// does not read.
    fn tink_key_type(&self, version: &KeyVersion) -> KeyringResult<TinkKeyType> {
        match version.algorithm() {
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm) => Ok(TinkKeyType::AesGcm),
            KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv) => {
                Ok(TinkKeyType::AesSiv)
            }
            _ => Err(KeyringError::ExportAlgorithmUnsupported(KeyVersionError {
                keyring: self.id().clone(),
                key_id: version.key_id(),
            })),
        }
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

    use kms_aead::{CipherText, CipherTextWithEncryptedKey};
    use secret_vault_value::SecretValue;

    use super::*;
    use crate::errors::KeyVersionError;
    use crate::test_support::{email_of, TestKeyring, TestProvider, TestResult, TENANT};
    use crate::testing::MemoryKeyringStore;
    use crate::{KeyringOptions, KeyringPolicy};

    // The keysets below were written by tinkey 1.14.0, from
    // https://storage.googleapis.com/tinkey/tinkey-1.14.0.tar.gz:
    //
    //   tinkey create-keyset --key-template AES256_GCM --out-format json --out gcm1.json
    //   tinkey add-key --key-template AES256_GCM --in gcm1.json --in-format json \
    //     --out-format json --out gcm2.json
    //   tinkey convert-keyset --in gcm2.json --in-format json --out gcm2.bin --out-format binary
    //   tinkey create-keyset --key-template AES256_SIV --out-format json --out siv.json
    //   tinkey convert-keyset --in siv.json --in-format json --out siv.bin --out-format binary
    //
    // The keys are the `key_value` fields of the keys' `value`, read from the JSON keysets.

    /// `gcm2.bin`: two AES-256-GCM keys, 412113711 the primary and 2776353560.
    const TINKEY_AES_GCM_KEYSET: [u8; 210] = [
        0x08, 0xaf, 0xb6, 0xc1, 0xc4, 0x01, 0x12, 0x64, 0x0a, 0x58, 0x0a, 0x30, 0x74, 0x79, 0x70,
        0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f,
        0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
        0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x47, 0x63, 0x6d, 0x4b, 0x65, 0x79,
        0x12, 0x22, 0x1a, 0x20, 0x26, 0x9f, 0x89, 0x22, 0xaf, 0xa5, 0xdd, 0xac, 0xf8, 0x0e, 0x5c,
        0xab, 0x8a, 0x6e, 0x02, 0x8b, 0xfe, 0xc2, 0x0a, 0x63, 0x3b, 0xfd, 0x13, 0xf5, 0x86, 0x50,
        0x30, 0xb9, 0x67, 0x97, 0xbc, 0x7f, 0x18, 0x01, 0x10, 0x01, 0x18, 0xaf, 0xb6, 0xc1, 0xc4,
        0x01, 0x20, 0x01, 0x12, 0x64, 0x0a, 0x58, 0x0a, 0x30, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74, 0x69,
        0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x47, 0x63, 0x6d, 0x4b, 0x65, 0x79, 0x12, 0x22, 0x1a,
        0x20, 0x41, 0xcc, 0xbb, 0x34, 0x57, 0xc4, 0xbe, 0x99, 0x79, 0x08, 0x7c, 0x27, 0x9c, 0x5b,
        0x86, 0x8f, 0xe1, 0x56, 0x4e, 0xf8, 0xad, 0x6f, 0x0d, 0x01, 0xd6, 0xd5, 0xbd, 0x62, 0x49,
        0xe3, 0x44, 0x71, 0x18, 0x01, 0x10, 0x01, 0x18, 0x98, 0x96, 0xef, 0xab, 0x0a, 0x20, 0x01,
    ];

    const TINKEY_AES_GCM_PRIMARY: u32 = 412_113_711;
    const TINKEY_AES_GCM_PRIMARY_KEY: [u8; 32] = [
        0x26, 0x9f, 0x89, 0x22, 0xaf, 0xa5, 0xdd, 0xac, 0xf8, 0x0e, 0x5c, 0xab, 0x8a, 0x6e, 0x02,
        0x8b, 0xfe, 0xc2, 0x0a, 0x63, 0x3b, 0xfd, 0x13, 0xf5, 0x86, 0x50, 0x30, 0xb9, 0x67, 0x97,
        0xbc, 0x7f,
    ];
    const TINKEY_AES_GCM_SECOND: u32 = 2_776_353_560;
    const TINKEY_AES_GCM_SECOND_KEY: [u8; 32] = [
        0x41, 0xcc, 0xbb, 0x34, 0x57, 0xc4, 0xbe, 0x99, 0x79, 0x08, 0x7c, 0x27, 0x9c, 0x5b, 0x86,
        0x8f, 0xe1, 0x56, 0x4e, 0xf8, 0xad, 0x6f, 0x0d, 0x01, 0xd6, 0xd5, 0xbd, 0x62, 0x49, 0xe3,
        0x44, 0x71,
    ];

    /// `siv.bin`: one AES-SIV key, 767014583.
    const TINKEY_AES_SIV_KEYSET: [u8; 141] = [
        0x08, 0xb7, 0xed, 0xde, 0xed, 0x02, 0x12, 0x84, 0x01, 0x0a, 0x78, 0x0a, 0x30, 0x74, 0x79,
        0x70, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63,
        0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
        0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x53, 0x69, 0x76, 0x4b, 0x65,
        0x79, 0x12, 0x42, 0x12, 0x40, 0x02, 0x88, 0xd5, 0x3a, 0xa1, 0x86, 0x0f, 0xae, 0x9d, 0xe2,
        0x05, 0xc8, 0x9f, 0x88, 0x69, 0x27, 0xa5, 0x19, 0xe4, 0xbf, 0x33, 0x74, 0xa5, 0xc4, 0x85,
        0x88, 0xb7, 0xa0, 0xf1, 0x26, 0x28, 0x69, 0x3a, 0xa2, 0x2d, 0x60, 0x41, 0x15, 0xb8, 0xb4,
        0x4a, 0x0a, 0xfb, 0x77, 0xe1, 0x25, 0x0e, 0x4a, 0x57, 0x29, 0x5d, 0x44, 0xab, 0x1d, 0xd2,
        0xf9, 0xcc, 0x68, 0x89, 0x76, 0xc8, 0x32, 0xc7, 0xfd, 0x18, 0x01, 0x10, 0x01, 0x18, 0xb7,
        0xed, 0xde, 0xed, 0x02, 0x20, 0x01,
    ];

    const TINKEY_AES_SIV: u32 = 767_014_583;
    const TINKEY_AES_SIV_KEY: [u8; 64] = [
        0x02, 0x88, 0xd5, 0x3a, 0xa1, 0x86, 0x0f, 0xae, 0x9d, 0xe2, 0x05, 0xc8, 0x9f, 0x88, 0x69,
        0x27, 0xa5, 0x19, 0xe4, 0xbf, 0x33, 0x74, 0xa5, 0xc4, 0x85, 0x88, 0xb7, 0xa0, 0xf1, 0x26,
        0x28, 0x69, 0x3a, 0xa2, 0x2d, 0x60, 0x41, 0x15, 0xb8, 0xb4, 0x4a, 0x0a, 0xfb, 0x77, 0xe1,
        0x25, 0x0e, 0x4a, 0x57, 0x29, 0x5d, 0x44, 0xab, 0x1d, 0xd2, 0xf9, 0xcc, 0x68, 0x89, 0x76,
        0xc8, 0x32, 0xc7, 0xfd,
    ];

    /// A keyring on a local KMS with one version of each purpose the policy names.
    async fn keyring(
        policy: KeyringPolicy,
    ) -> KeyringResult<(TestKeyring<MemoryKeyringStore>, TestProvider)> {
        let provider = TestProvider::new("tenant-42-kek")?;
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

    #[test]
    fn keysets_are_the_ones_tinkey_writes() {
        let mut aes_gcm = TinkKeyset::new(TINKEY_AES_GCM_PRIMARY);
        aes_gcm.add_key(
            TINKEY_AES_GCM_PRIMARY,
            TinkKeyType::AesGcm,
            &DataEncryptionKey::from(SecretValue::from(TINKEY_AES_GCM_PRIMARY_KEY.to_vec())),
        );
        aes_gcm.add_key(
            TINKEY_AES_GCM_SECOND,
            TinkKeyType::AesGcm,
            &DataEncryptionKey::from(SecretValue::from(TINKEY_AES_GCM_SECOND_KEY.to_vec())),
        );
        let mut aes_siv = TinkKeyset::new(TINKEY_AES_SIV);
        aes_siv.add_key(
            TINKEY_AES_SIV,
            TinkKeyType::AesSiv,
            &DataEncryptionKey::from(SecretValue::from(TINKEY_AES_SIV_KEY.to_vec())),
        );

        assert_eq!(
            *aes_gcm.to_bytes().ref_sensitive_value(),
            TINKEY_AES_GCM_KEYSET
        );
        assert_eq!(
            *aes_siv.to_bytes().ref_sensitive_value(),
            TINKEY_AES_SIV_KEYSET
        );
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
        let mut keyset = TinkKeyset::new(primary);
        for key_id in key_ids {
            let dek = record
                .version(KeyId::try_from(*key_id)?)
                .and_then(KeyVersion::wrapped_dek)
                .ok_or("the version holds no key")?;
            DekCache::disabled()
                .with_key(provider, dek, |key| {
                    keyset.add_key(*key_id, TinkKeyType::AesGcm, key)
                })
                .await?;
        }
        Ok(keyset.to_bytes())
    }

    #[tokio::test]
    async fn export_refuses_a_version_of_another_algorithm() -> TestResult {
        let (keyring, provider) = keyring(KeyringPolicy::new()).await?;
        keyring
            .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
            .await?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        let readable = keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
            .await;
        let first = keyring
            .export_keyset(KeysetSelection::Single(KeyId::try_from(1)?))
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
        let (keyring, provider) = keyring(KeyringPolicy::new()).await?;
        for _ in 0..2 {
            keyring
                .promote(keyring.rotate(Purpose::Randomized).await?)
                .await?;
        }
        keyring.mark_compromised(KeyId::try_from(2)?, None).await?;

        let wrapped = keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
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
            kek: KekRef::new(
                kms_aead::KekProvider::Gcp,
                "projects/p/cryptoKeys/k".to_string(),
            ),
            key_ids: vec![KeyId::try_from(1)?],
        };

        let debug = format!("{keyset:?}");

        assert!(!debug.contains("192, 255, 238"), "{debug}");
        Ok(())
    }

    #[tokio::test]
    async fn readable_follows_a_compromise_by_another_process() -> TestResult {
        let (exporter, provider) = keyring(KeyringPolicy::new()).await?;
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
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
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
        let (keyring, provider) = keyring(KeyringPolicy::new()).await?;
        let aad = email_of("42")?;
        let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);

        keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
            .await?;
        keyring
            .encrypt(&aad, &"alice@example.com".to_string())
            .await?;
        keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
            .await?;

        // One unwrap per export, and one for the encrypt, which found the cache empty.
        assert_eq!(provider.calls.unwraps.load(Ordering::SeqCst), unwraps + 3);
        Ok(())
    }

    #[tokio::test]
    async fn an_exported_keyset_does_not_open_as_an_envelope_key() -> TestResult {
        let (keyring, provider) = keyring(KeyringPolicy::new()).await?;
        let wrapped = keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
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
        let (keyring, provider) = keyring(KeyringPolicy::new()).await?;
        let staged = keyring.rotate(Purpose::Randomized).await?;

        let wrapped = keyring
            .export_keyset(KeysetSelection::Readable(Purpose::Randomized))
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
            keyring.export_keyset(KeysetSelection::Single(staged)).await,
            Err(KeyringError::KeyVersionPending(KeyVersionError { key_id, .. })) if key_id == staged
        ));
        Ok(())
    }

    #[tokio::test]
    async fn single_of_a_destroyed_version_fails() -> TestResult {
        let (keyring, _) = keyring(KeyringPolicy::new()).await?;
        let first = KeyId::try_from(1)?;
        keyring
            .promote(keyring.rotate(Purpose::Randomized).await?)
            .await?;
        keyring.retire(first).await?;
        keyring.destroy(first).await?;

        let result = keyring.export_keyset(KeysetSelection::Single(first)).await;

        assert!(matches!(
            result,
            Err(KeyringError::KeyVersionDestroyed(KeyVersionError { key_id, .. })) if key_id == first
        ));
        Ok(())
    }
}
