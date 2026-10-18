use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroU32;
use std::path::Path;

use async_trait::async_trait;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::aead_cipher::AeadKeyBytesOps;
use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::formats::local_kms::LocalEncryptedDek;
use crate::spans::{self, kms};
use crate::{
    AeadAlgorithm, AeadBackend, AeadCipher, DataEncryptionKey, EncryptedDataEncryptionKey,
    KekProvider, KekRef, KmsAeadEncryptionProvider, KmsAeadResult,
};

/// The name of a local key encryption key: 1 to 255 bytes of ASCII alphanumerics, `-`, `_` and
/// `.`.
///
/// It is the `key` of the provider's [`KekRef`], and every encrypted DEK records it, so two local
/// KEKs never share an id: a cache of decrypted keys is keyed by it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalKekId(String);

impl TryFrom<String> for LocalKekId {
    type Error = KmsAeadError;

    /// # Errors
    ///
    /// `INVALID_LOCAL_KEK_ID` when the id is empty, longer than 255 bytes, or holds another
    /// character.
    fn try_from(value: String) -> KmsAeadResult<Self> {
        let valid = (1..=usize::from(u8::MAX)).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if valid {
            Ok(Self(value))
        } else {
            Err(KmsAeadSystemError::create(
                "INVALID_LOCAL_KEK_ID",
                &format!(
                    "A local KEK id of {} bytes is not 1 to 255 ASCII alphanumerics, '-', '_' or '.'",
                    value.len()
                ),
            ))
        }
    }
}

impl Display for LocalKekId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The version of a local key encryption key. The highest version a [`LocalKmsProvider`] holds
/// encrypts new keys; every version it holds decrypts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalKekVersion(pub(crate) NonZeroU32);

impl From<NonZeroU32> for LocalKekVersion {
    fn from(version: NonZeroU32) -> Self {
        Self(version)
    }
}

/// The version in decimal, as the `key_version` span field records it.
impl Display for LocalKekVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One version of a local key encryption key: 32 bytes for AES-256-GCM, zeroised on drop.
/// `Debug` shows the version and where the key came from, never the key.
pub struct LocalKek {
    version: LocalKekVersion,
    material: SecretValue,
    /// `ephemeral`, `file`, `env` or `secret`, for the log line of the provider.
    source: &'static str,
}

impl LocalKek {
    /// The largest KEK file read: the 44 characters of the base64 and room for whitespace, small
    /// enough that a wrong path is refused before its content is read into memory.
    const MAX_FILE_LEN: usize = 256;

    /// A KEK the application already holds: one an operator unseals with their own tool
    /// (systemd-creds, a TPM, sops, age), or a credential the init system passes, such as a
    /// file systemd's `LoadCredential` places in `$CREDENTIALS_DIRECTORY`. The recommended form
    /// on a host.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_LENGTH` when `material` is not 32 bytes.
    pub fn from_secret(version: LocalKekVersion, material: SecretValue) -> KmsAeadResult<Self> {
        Self::new(version, material, "secret", "the secret")
    }

    /// Reads the standard base64 of the 32 bytes from the environment variable `variable`.
    /// Trailing whitespace is allowed.
    ///
    /// The variable stays in the process environment for the life of the process: the same
    /// user can read it through `/proc/<pid>/environ`, and every child process inherits it.
    /// On a host, prefer [`from_secret`](Self::from_secret) with a credential the init system
    /// passes, such as systemd's `LoadCredential`.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_SOURCE` when the variable is not set or is not standard base64, and
    /// `LOCAL_KEK_LENGTH` when it does not decode to 32 bytes. The error names the variable,
    /// never its value.
    pub fn from_env(version: LocalKekVersion, variable: &str) -> KmsAeadResult<Self> {
        let origin = format!("the environment variable {variable}");
        let encoded = std::env::var_os(variable).ok_or_else(|| {
            KmsAeadSystemError::create("LOCAL_KEK_SOURCE", &format!("{origin} is not set"))
        })?;
        let material = Self::decode(SecretValue::new(encoded.into_encoded_bytes()), &origin)?;
        Self::new(version, material, "env", &origin)
    }

    /// Reads the standard base64 of the 32 bytes from the file at `path`. Trailing whitespace,
    /// such as an editor's final newline, is allowed. A symbolic link is followed.
    ///
    /// The opened file must be a regular file of at most 256 bytes; both are checked on the
    /// opened file before it is read, so a file swapped in after the open is never read. No
    /// permission or ownership check runs: restricting who can read or replace the file is the
    /// operator's job. Opening a FIFO blocks until a writer opens it.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_SOURCE` when the file cannot be read, is not a regular file or is not standard
    /// base64, and `LOCAL_KEK_LENGTH` when it is larger than 256 bytes or does not decode to 32
    /// bytes. The error names the path, never the content.
    pub fn from_file(version: LocalKekVersion, path: &Path) -> KmsAeadResult<Self> {
        let origin = format!("the file {}", path.display());
        let unreadable = |error: std::io::Error| {
            KmsAeadSystemError::create(
                "LOCAL_KEK_SOURCE",
                &format!("Unable to read {origin}: {error}"),
            )
        };

        let file = File::open(path).map_err(unreadable)?;
        let metadata = file.metadata().map_err(unreadable)?;
        if !metadata.is_file() {
            return Err(KmsAeadSystemError::create(
                "LOCAL_KEK_SOURCE",
                &format!("{origin} is not a regular file"),
            ));
        }
        let len = usize::try_from(metadata.len())
            .ok()
            .filter(|len| *len <= Self::MAX_FILE_LEN)
            .ok_or_else(|| {
                KmsAeadSystemError::create(
                    "LOCAL_KEK_LENGTH",
                    &format!("{origin} is larger than {} bytes", Self::MAX_FILE_LEN),
                )
            })?;
        let mut encoded = SecretValue::new(Vec::with_capacity(len));
        // Reading at most the length the file had when opened keeps the buffer from growing,
        // which would leave a copy of the key in freed memory.
        file.take(metadata.len())
            .read_to_end(encoded.ref_sensitive_value_mut())
            .map_err(unreadable)?;
        let material = Self::decode(encoded, &origin)?;
        Self::new(version, material, "file", &origin)
    }

    fn new(
        version: LocalKekVersion,
        material: SecretValue,
        source: &'static str,
        origin: &str,
    ) -> KmsAeadResult<Self> {
        let len = material.ref_sensitive_value().len();
        let expected = AeadAlgorithm::Aes256Gcm.key_len();
        if len == expected {
            Ok(Self {
                version,
                material,
                source,
            })
        } else {
            Err(KmsAeadSystemError::create(
                "LOCAL_KEK_LENGTH",
                &format!("The local KEK from {origin} is {len} bytes, not {expected}"),
            ))
        }
    }

    /// Decodes standard base64 with trailing whitespace allowed. Every copy of the text is
    /// zeroised: `encoded` on drop, and the trimmed copy by `from_base64_str`.
    fn decode(encoded: SecretValue, origin: &str) -> KmsAeadResult<SecretValue> {
        let invalid = || {
            KmsAeadSystemError::create(
                "LOCAL_KEK_SOURCE",
                &format!("{origin} does not hold standard base64"),
            )
        };
        let text = encoded.sensitive_value_to_str().map_err(|_| invalid())?;
        SecretValue::from_base64_str(text.trim_end().to_string()).map_err(|_| invalid())
    }
}

impl std::fmt::Debug for LocalKek {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKek")
            .field("version", &self.version)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Encrypts data encryption keys with a key encryption key (KEK) the process holds, with
/// AES-256-GCM on the backend `B`: for development and tests without a cloud KMS, and for
/// single-host installs where the operator protects the KEK.
///
/// kms-aead builds one only when the application calls one of its constructors; no provider
/// falls back to it. Each constructor logs one `INFO` event naming the KEK id, its versions and
/// where each version came from (`ephemeral`, `file`, `env` or `secret`).
///
/// # Encrypted keys
///
/// The highest version encrypts, and every version the provider holds decrypts, so a new KEK
/// version can be added while the keys encrypted under the older ones stay readable. The encrypted
/// key, the bytes of the [`EncryptedDataEncryptionKey`], is
///
/// ```text
/// [0x01][i: u8][KEK id: i bytes][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]
/// ```
///
/// with the header up to the version as the associated data, so neither the id nor the version
/// can be changed. A decryption refuses a key encrypted under another KEK id before it opens it.
///
/// # Limits
///
/// - No IAM, no audit log and no HSM. Protecting the KEK, at rest and in backups, is the
///   operator's job, and so are the permissions and ownership of a KEK file:
///   [`LocalKek::from_file`] does not check them.
/// - Every DEK encryption is one AES-256-GCM encryption with a random 96-bit nonce, so a KEK
///   version is safe for about 2^32 encryptions. With the per-call envelope every value costs one
///   encryption: a host sealing 1,000 values per second spends 2^32 encryptions in 50 days. Reuse
///   each data encryption key for many values instead, and add a new KEK version before the
///   budget is spent.
/// - Crypto-shredding means destroying every copy of the KEK, backups included.
/// - Keys encrypted by a local KEK cannot be exported to BigQuery, which decrypts with Cloud KMS.
///
/// # Errors
///
/// An encryption fails with `RANDOM_GENERATOR` when the backend's CSPRNG fails. A decryption fails
/// with `LOCAL_ENCRYPTED_DEK_FORMAT` when the key is not in the layout above,
/// `LOCAL_KEK_ID_MISMATCH` when it was encrypted under another KEK id, `LOCAL_KEK_UNKNOWN_VERSION`
/// when the provider does not hold its version, and `DECRYPT` when it is not authentic under that
/// version.
#[derive(Debug)]
pub struct LocalKmsProvider<B> {
    /// Its key is the KEK id, which every encrypted DEK records.
    kek: KekRef,
    /// The material of each KEK version.
    keks: BTreeMap<LocalKekVersion, SecretValue>,
    cipher: AeadCipher<B>,
}

impl<B: AeadBackend> LocalKmsProvider<B> {
    /// A provider for the KEK `id` with the versions in `keks`, encrypting on the backend `B`. The
    /// highest version encrypts; every version listed decrypts.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when `keks` is empty or lists a version twice.
    pub fn new(id: LocalKekId, keks: Vec<LocalKek>) -> KmsAeadResult<Self> {
        let cipher = AeadCipher::new(AeadAlgorithm::Aes256Gcm)?;
        let mut sources = Vec::with_capacity(keks.len());
        let mut by_version = BTreeMap::new();
        for kek in keks {
            if by_version.insert(kek.version, kek.material).is_some() {
                return Err(KmsAeadSystemError::create(
                    "LOCAL_KEK_VERSIONS",
                    &format!("The local KEK {id} lists version {} twice", kek.version),
                ));
            }
            sources.push((kek.version, kek.source));
        }
        if by_version.is_empty() {
            return Err(KmsAeadSystemError::create(
                "LOCAL_KEK_VERSIONS",
                &format!("The local KEK {id} has no version"),
            ));
        }

        sources.sort();
        let versions = sources
            .iter()
            .map(|(version, source)| format!("{version} ({source})"))
            .collect::<Vec<_>>()
            .join(", ");
        kms::local_kek_loaded(&id, &versions);

        Ok(Self {
            kek: KekRef::new(KekProvider::Local, id.to_string()),
            keks: by_version,
            cipher,
        })
    }

    /// A provider with one random version-1 KEK from the CSPRNG of the backend `B`, which lives
    /// as long as the provider: the keys it encrypts cannot be decrypted once the process exits.
    /// For tests.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn ephemeral(id: LocalKekId) -> KmsAeadResult<Self> {
        let kek = LocalKek {
            version: LocalKekVersion(NonZeroU32::MIN),
            material: B::generate_random_bytes(AeadAlgorithm::Aes256Gcm.key_len())?,
            source: "ephemeral",
        };
        Self::new(id, vec![kek])
    }
}

#[async_trait]
impl<B: AeadBackend> KmsAeadEncryptionProvider for LocalKmsProvider<B> {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(&self.kek), async {
            let (&version, material) = self.keks.last_key_value().ok_or_else(|| {
                KmsAeadSystemError::create(
                    "LOCAL_KEK_VERSIONS",
                    &format!("The local KEK {} has no version", self.kek.key()),
                )
            })?;
            kms::record_key_version(&version.to_string());
            let header = LocalEncryptedDek::header(self.kek.key(), version)?;
            let encrypted_dek = kms::timed(async {
                self.cipher.seal(
                    &header,
                    &header,
                    dek.value().ref_sensitive_value(),
                    material.ref_sensitive_value(),
                )
            })
            .await?;
            Ok(EncryptedDataEncryptionKey::new(encrypted_dek))
        })
        .await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::decrypt_span(&self.kek), async {
            let layout = LocalEncryptedDek::split(encrypted_dek.value()).ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "LOCAL_ENCRYPTED_DEK_FORMAT",
                    "The encrypted DEK is not in the layout of the local KMS",
                )
            })?;
            if layout.kek_id != self.kek.key().as_bytes() {
                return Err(KmsAeadEncryptionError::create(
                    "LOCAL_KEK_ID_MISMATCH",
                    &format!(
                        "The key was encrypted under another local KEK than {}",
                        self.kek.key()
                    ),
                ));
            }
            let version = layout.kek_version;
            kms::record_key_version(&version.to_string());
            let material = self.keks.get(&version).ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "LOCAL_KEK_UNKNOWN_VERSION",
                    &format!("The local KEK {} has no version {version}", self.kek.key()),
                )
            })?;
            let key = kms::timed(async {
                self.cipher.open(
                    layout.header,
                    layout.sealed,
                    0,
                    material.ref_sensitive_value(),
                )
            })
            .await?;
            Ok(DataEncryptionKey::from(key))
        })
        .await
    }
}

#[cfg(test)]
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
mod tests {
    use super::*;
    use crate::formats::Bare;
    use crate::test_provider::{renderings, TestBackend};
    use crate::Encrypted;

    const ORDERS: &str = "orders";
    const KEK_MATERIAL: [u8; 32] = [0x42; 32];
    const DEK_MATERIAL: [u8; 32] = [0x11; 32];

    /// Encrypted by Python's `cryptography` AES-GCM under [`KEK_MATERIAL`], KEK id `golden`,
    /// version 7 and nonce `[0x24; 12]`, from [`DEK_MATERIAL`].
    const GOLDEN_ENCRYPTED_DEK: &str = "0106676f6c64656e000000072424242424242424242424240480d550f8d7d72f37f933bbac2382b77dea2261a7ba417ca1b5dd4b47d4f602e5d1e6bd40e6d7891cd8fbc8d68e3a18";

    #[tokio::test]
    async fn an_encrypted_dek_decrypts_to_the_same_key() -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from(ORDERS.to_string())?,
            vec![LocalKek::from_secret(
                LocalKekVersion::from(NonZeroU32::MIN),
                SecretValue::new(KEK_MATERIAL.to_vec()),
            )?],
        )?;
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));

        let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;

        assert_eq!(
            provider.decrypt_data_encryption_key(&encrypted_dek).await?,
            dek
        );
        assert_eq!(*provider.kek(), KekRef::new(KekProvider::Local, ORDERS));
        Ok(())
    }

    #[tokio::test]
    async fn the_header_is_the_associated_data() -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from(ORDERS.to_string())?,
            vec![LocalKek::from_secret(
                LocalKekVersion::from(NonZeroU32::MIN),
                SecretValue::new(KEK_MATERIAL.to_vec()),
            )?],
        )?;
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));

        let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;

        let (header, sealed) = encrypted_dek.value().split_at(2 + ORDERS.len() + 4);
        let opened: SecretValue = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?
            .decrypt_bare(
                header,
                &Encrypted::<SecretValue, Bare>::try_from(sealed.to_vec())?,
                &DataEncryptionKey::from(SecretValue::new(KEK_MATERIAL.to_vec())),
            )?;
        assert_eq!(DataEncryptionKey::from(opened), dek);
        Ok(())
    }

    #[tokio::test]
    async fn the_highest_version_encrypts_and_every_version_decrypts() -> KmsAeadResult<()> {
        let [v1, v2, v3] = [1, 2, 3].map(|v| LocalKekVersion::from(NonZeroU32::new(v).unwrap()));
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));
        let old = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from(ORDERS.to_string())?,
            vec![LocalKek::from_secret(
                v1,
                SecretValue::new(KEK_MATERIAL.to_vec()),
            )?],
        )?;
        let old_encrypted_dek = old.encrypt_data_encryption_key(&dek).await?;
        let rotated = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from(ORDERS.to_string())?,
            vec![
                LocalKek::from_secret(v3, SecretValue::new(vec![0x43; 32]))?,
                LocalKek::from_secret(v1, SecretValue::new(KEK_MATERIAL.to_vec()))?,
                LocalKek::from_secret(v2, SecretValue::new(vec![0x44; 32]))?,
            ],
        )?;

        let new_encrypted_dek = rotated.encrypt_data_encryption_key(&dek).await?;

        assert_eq!(&new_encrypted_dek.value()[8..12], [0, 0, 0, 3]);
        for encrypted_dek in [old_encrypted_dek, new_encrypted_dek] {
            assert_eq!(
                rotated.decrypt_data_encryption_key(&encrypted_dek).await?,
                dek
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_golden_encrypted_dek_decrypts() -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from("golden".to_string())?,
            vec![LocalKek::from_secret(
                LocalKekVersion::from(NonZeroU32::new(7).unwrap()),
                SecretValue::new(KEK_MATERIAL.to_vec()),
            )?],
        )?;
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));
        let golden = hex::decode(GOLDEN_ENCRYPTED_DEK).unwrap();

        assert_eq!(
            provider
                .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(golden.clone()))
                .await?,
            dek
        );

        let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;
        assert_eq!(&encrypted_dek.value()[..12], &golden[..12]);
        assert_eq!(encrypted_dek.value().len(), 12 + 12 + 32 + 16);
        Ok(())
    }

    #[tokio::test]
    async fn a_flipped_header_byte_fails_to_decrypt() -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from("golden".to_string())?,
            [7, 6]
                .map(|version| {
                    LocalKek::from_secret(
                        LocalKekVersion::from(NonZeroU32::new(version).unwrap()),
                        SecretValue::new(KEK_MATERIAL.to_vec()),
                    )
                })
                .into_iter()
                .collect::<KmsAeadResult<_>>()?,
        )?;
        let golden = hex::decode(GOLDEN_ENCRYPTED_DEK).unwrap();

        for index in 0..12 {
            for flip in [0x01, 0x80] {
                let mut encrypted_dek = golden.clone();
                encrypted_dek[index] ^= flip;
                let encrypted_dek = EncryptedDataEncryptionKey::new(encrypted_dek);
                assert!(
                    provider
                        .decrypt_data_encryption_key(&encrypted_dek)
                        .await
                        .is_err(),
                    "byte {index} flipped by {flip:#04x}"
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_dek_encrypted_under_another_kek_id_is_refused() -> KmsAeadResult<()> {
        let [orders, invoices] = [ORDERS, "invoices"].map(|id| {
            LocalKmsProvider::<TestBackend>::new(
                LocalKekId::try_from(id.to_string())?,
                vec![LocalKek::from_secret(
                    LocalKekVersion::from(NonZeroU32::MIN),
                    SecretValue::new(KEK_MATERIAL.to_vec()),
                )?],
            )
        });
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));
        let encrypted_dek = orders?.encrypt_data_encryption_key(&dek).await?;

        let result = invoices?.decrypt_data_encryption_key(&encrypted_dek).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "LOCAL_KEK_ID_MISMATCH"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_edek_encrypted_under_another_key_fails_to_decrypt() -> KmsAeadResult<()> {
        let [original, impostor] = [KEK_MATERIAL, [0x43; 32]].map(|material| {
            LocalKmsProvider::<TestBackend>::new(
                LocalKekId::try_from(ORDERS.to_string())?,
                vec![LocalKek::from_secret(
                    LocalKekVersion::from(NonZeroU32::MIN),
                    SecretValue::new(material.to_vec()),
                )?],
            )
        });
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));
        let encrypted_dek = impostor?.encrypt_data_encryption_key(&dek).await?;

        let result = original?.decrypt_data_encryption_key(&encrypted_dek).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "DECRYPT"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_version_the_provider_does_not_hold_is_refused() -> KmsAeadResult<()> {
        let [rotated, old] = [2, 1].map(|version| {
            LocalKmsProvider::<TestBackend>::new(
                LocalKekId::try_from(ORDERS.to_string())?,
                vec![LocalKek::from_secret(
                    LocalKekVersion::from(NonZeroU32::new(version).unwrap()),
                    SecretValue::new(KEK_MATERIAL.to_vec()),
                )?],
            )
        });
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));
        let encrypted_dek = rotated?.encrypt_data_encryption_key(&dek).await?;

        let result = old?.decrypt_data_encryption_key(&encrypted_dek).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "LOCAL_KEK_UNKNOWN_VERSION"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_truncated_encrypted_dek_is_refused() -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from("golden".to_string())?,
            vec![LocalKek::from_secret(
                LocalKekVersion::from(NonZeroU32::new(7).unwrap()),
                SecretValue::new(KEK_MATERIAL.to_vec()),
            )?],
        )?;
        let golden = hex::decode(GOLDEN_ENCRYPTED_DEK).unwrap();

        for len in [0, 1, 2, 8, 11] {
            let encrypted_dek = EncryptedDataEncryptionKey::new(golden[..len].to_vec());
            let result = provider.decrypt_data_encryption_key(&encrypted_dek).await;
            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_ENCRYPTED_DEK_FORMAT"),
                "{len} bytes: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn invalid_keks_fail_with_their_codes() -> KmsAeadResult<()> {
        let v1 = LocalKekVersion::from(NonZeroU32::MIN);
        let orders = LocalKekId::try_from(ORDERS.to_string())?;

        let short = LocalKek::from_secret(v1, SecretValue::new(vec![0x42; 16]));
        assert!(
            matches!(&short, Err(e) if e.code() == "LOCAL_KEK_LENGTH"),
            "{short:?}"
        );
        let unset = LocalKek::from_env(v1, "KMS_AEAD_LOCAL_KEK_TEST_UNSET_VARIABLE");
        assert!(
            matches!(&unset, Err(e) if e.code() == "LOCAL_KEK_SOURCE"),
            "{unset:?}"
        );
        let no_version = LocalKmsProvider::<TestBackend>::new(orders.clone(), Vec::new());
        assert!(
            matches!(&no_version, Err(e) if e.code() == "LOCAL_KEK_VERSIONS"),
            "{no_version:?}"
        );
        let twice = LocalKmsProvider::<TestBackend>::new(
            orders,
            vec![
                LocalKek::from_secret(v1, SecretValue::new(KEK_MATERIAL.to_vec()))?,
                LocalKek::from_secret(v1, SecretValue::new(vec![0x43; 32]))?,
            ],
        );
        assert!(
            matches!(&twice, Err(e) if e.code() == "LOCAL_KEK_VERSIONS"),
            "{twice:?}"
        );
        Ok(())
    }

    #[test]
    fn local_kek_id_is_1_to_255_ascii_alphanumerics_dashes_underscores_and_dots() {
        assert!(LocalKekId::try_from("a".repeat(255)).is_ok());
        assert!(LocalKekId::try_from("orders-kek_v2.prod".to_string()).is_ok());
        for invalid in [
            String::new(),
            "a".repeat(256),
            "a/b".into(),
            "a b".into(),
            "é".into(),
        ] {
            let result = LocalKekId::try_from(invalid.clone());
            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_LOCAL_KEK_ID"),
                "{invalid:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_ephemeral_provider_round_trips() -> KmsAeadResult<()> {
        let provider =
            LocalKmsProvider::<TestBackend>::ephemeral(LocalKekId::try_from("tests".to_string())?)?;
        let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));

        let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;

        assert_eq!(
            provider.decrypt_data_encryption_key(&encrypted_dek).await?,
            dek
        );
        Ok(())
    }

    #[test]
    fn debug_prints_no_key_material() -> KmsAeadResult<()> {
        let [v1, v2] = [1, 2].map(|v| LocalKekVersion::from(NonZeroU32::new(v).unwrap()));
        let provider = LocalKmsProvider::<TestBackend>::new(
            LocalKekId::try_from(ORDERS.to_string())?,
            vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x5A; 32]))?],
        )?;
        let kek = LocalKek::from_secret(v2, SecretValue::new(vec![0x5A; 32]))?;

        let printed = format!("{provider:?} {kek:?}");

        for rendering in renderings(&[0x5A; 32]) {
            assert!(!printed.contains(&rendering), "{printed}");
        }
        Ok(())
    }

    mod files {
        use std::fs;
        use std::path::PathBuf;

        use super::*;

        const KEK_BASE64: &str = "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI=";

        /// A directory of its own under the system temp directory, removed on drop.
        struct TestDir(PathBuf);

        impl TestDir {
            fn new(test: &str) -> Self {
                let path = std::env::temp_dir()
                    .join(format!("kms-aead-local-kek-{}-{test}", std::process::id()));
                fs::create_dir(&path).unwrap();
                Self(path)
            }

            fn file(&self, name: &str, content: &str) -> PathBuf {
                let path = self.0.join(name);
                fs::write(&path, content).unwrap();
                path
            }
        }

        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        #[tokio::test]
        async fn a_kek_file_encrypts_and_decrypts() -> KmsAeadResult<()> {
            let dir = TestDir::new("round-trip");
            let path = dir.file("kek", KEK_BASE64);
            let v1 = LocalKekVersion::from(NonZeroU32::MIN);
            let from_file = LocalKmsProvider::<TestBackend>::new(
                LocalKekId::try_from(ORDERS.to_string())?,
                vec![LocalKek::from_file(v1, &path)?],
            )?;
            let from_secret = LocalKmsProvider::<TestBackend>::new(
                LocalKekId::try_from(ORDERS.to_string())?,
                vec![LocalKek::from_secret(
                    v1,
                    SecretValue::new(KEK_MATERIAL.to_vec()),
                )?],
            )?;
            let dek = DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()));

            let encrypted_dek = from_file.encrypt_data_encryption_key(&dek).await?;

            assert_eq!(
                from_secret
                    .decrypt_data_encryption_key(&encrypted_dek)
                    .await?,
                dek
            );
            Ok(())
        }

        #[test]
        fn a_trailing_newline_is_accepted() {
            let dir = TestDir::new("newline");
            let path = dir.file("kek", &format!("{KEK_BASE64}\n"));

            assert!(LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path).is_ok());
        }

        #[test]
        fn a_file_that_is_not_base64_is_refused() {
            let dir = TestDir::new("base64");
            let path = dir.file("kek", "not base64!");

            let result = LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path);

            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_KEK_SOURCE"),
                "{result:?}"
            );
        }

        #[test]
        fn a_file_of_another_length_is_refused() {
            let dir = TestDir::new("length");
            let path = dir.file("kek", "QkJCQg==");

            let result = LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path);

            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_KEK_LENGTH"),
                "{result:?}"
            );
        }

        #[test]
        fn a_directory_is_refused() {
            let dir = TestDir::new("directory");
            let path = dir.0.clone();

            let result = LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path);

            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_KEK_SOURCE"),
                "{result:?}"
            );
        }

        #[test]
        fn a_missing_file_is_refused() {
            let dir = TestDir::new("missing");
            let path = dir.0.join("kek");

            let result = LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path);

            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_KEK_SOURCE"),
                "{result:?}"
            );
        }

        #[test]
        fn a_file_larger_than_the_cap_is_refused() {
            let dir = TestDir::new("large");
            let path = dir.file(
                "kek",
                &format!("{KEK_BASE64}{}", " ".repeat(LocalKek::MAX_FILE_LEN)),
            );

            let result = LocalKek::from_file(LocalKekVersion::from(NonZeroU32::MIN), &path);

            assert!(
                matches!(&result, Err(e) if e.code() == "LOCAL_KEK_LENGTH"),
                "{result:?}"
            );
        }
    }
}
