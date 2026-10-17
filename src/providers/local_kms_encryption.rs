use std::collections::BTreeMap;
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Read;
use std::num::NonZeroU32;
use std::path::Path;

use async_trait::async_trait;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::spans::{self, kms};
use crate::{
    AeadAlgorithm, AeadBackend, AeadCipher, Cipher, CipherText, DataEncryptionKey,
    EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider, KmsAeadResult,
    KmsKeyVersion,
};

/// The first byte of a wrapped key: the version of its layout.
const WRAPPED_KEY_LAYOUT: u8 = 0x01;

/// The name of a local key encryption key: 1 to 255 bytes of ASCII alphanumerics, `-`, `_` and
/// `.`.
///
/// It is the `key` of the provider's [`KekRef`], and every wrapped key records it, so two local
/// KEKs never share an id: a cache of unwrapped keys is keyed by it.
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

impl LocalKekId {
    /// `[0x01][i][KEK id][KEK version]`: the start of a wrapped key and its associated data.
    fn wrapped_key_header(&self, version: LocalKekVersion) -> KmsAeadResult<Vec<u8>> {
        let id = self.0.as_bytes();
        let id_len = u8::try_from(id.len()).map_err(|_| {
            KmsAeadSystemError::create(
                "INVALID_LOCAL_KEK_ID",
                "A local KEK id is longer than 255 bytes",
            )
        })?;
        let mut header = Vec::with_capacity(2 + id.len() + 4);
        header.push(WRAPPED_KEY_LAYOUT);
        header.push(id_len);
        header.extend_from_slice(id);
        header.extend_from_slice(&version.0.get().to_be_bytes());
        Ok(header)
    }
}

impl Display for LocalKekId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The version of a local key encryption key. The highest version a [`LocalKmsProvider`] holds
/// wraps new keys; every version it holds unwraps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalKekVersion(NonZeroU32);

impl From<NonZeroU32> for LocalKekVersion {
    fn from(version: NonZeroU32) -> Self {
        Self(version)
    }
}

/// The version in decimal, as [`EncryptedDataEncryptionKey::key_version`] records it.
impl Display for LocalKekVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One version of a local key encryption key: 32 bytes for AES-256-GCM, zeroized on drop.
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
    /// such as an editor's final newline, is allowed.
    ///
    /// On Unix the file is opened without blocking and the opened file is checked, so it cannot
    /// be swapped between the check and the read: it must be a regular file, owned by the
    /// effective user or by root, with no permission for group or others (`mode & 0o077 == 0`),
    /// as OpenSSH requires of a private key. A symbolic link is followed, and the file it points
    /// to is checked. On other platforms no type, owner or permission check runs.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_FILE_PERMISSIONS` when a check fails, `LOCAL_KEK_SOURCE` when the file cannot
    /// be read or is not standard base64, and `LOCAL_KEK_LENGTH` when it is larger than 256
    /// bytes or does not decode to 32 bytes. The error names the path, never the content.
    pub fn from_file(version: LocalKekVersion, path: &Path) -> KmsAeadResult<Self> {
        let origin = format!("the file {}", path.display());
        let unreadable = |error: std::io::Error| {
            KmsAeadSystemError::create(
                "LOCAL_KEK_SOURCE",
                &format!("Unable to read {origin}: {error}"),
            )
        };

        // Without `O_NONBLOCK`, opening a FIFO blocks until a writer opens it.
        #[cfg(unix)]
        let file = {
            use rustix::fs::{Mode, OFlags};
            let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
            File::from(
                rustix::fs::open(path, flags, Mode::empty())
                    .map_err(|errno| unreadable(errno.into()))?,
            )
        };
        #[cfg(not(unix))]
        let file = File::open(path).map_err(unreadable)?;
        let metadata = file.metadata().map_err(unreadable)?;
        #[cfg(unix)]
        check_opened_file(&metadata, path, rustix::process::geteuid().as_raw())?;

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
    /// zeroized: `encoded` on drop, and the trimmed copy by `from_base64_str`.
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

/// Refuses an opened KEK file that is not a regular file, is owned by neither `effective_user`
/// nor root, or grants any permission to group or others: a file another user owns is a KEK
/// that user wrote, and one they can write can be replaced by a key they hold.
#[cfg(unix)]
fn check_opened_file(
    metadata: &std::fs::Metadata,
    path: &Path,
    effective_user: u32,
) -> KmsAeadResult<()> {
    use std::os::unix::fs::MetadataExt;

    let refusal = if !metadata.is_file() {
        Some("is not a regular file")
    } else if metadata.uid() != effective_user && metadata.uid() != 0 {
        Some("is owned by neither the effective user nor root")
    } else if metadata.mode() & 0o077 != 0 {
        Some("grants a permission to group or others")
    } else {
        None
    };
    match refusal {
        Some(reason) => Err(KmsAeadSystemError::create(
            "LOCAL_KEK_FILE_PERMISSIONS",
            &format!("The file {} {reason}", path.display()),
        )),
        None => Ok(()),
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

/// Wraps data encryption keys with a key encryption key (KEK) the process holds, with
/// AES-256-GCM on the backend it is built with: for development and tests without a cloud KMS,
/// and for single-host installs where the operator protects the KEK.
///
/// kms-aead builds one only when the application calls one of its constructors; no provider
/// falls back to it. Each constructor logs one `INFO` event naming the KEK id, its versions and
/// where each version came from (`ephemeral`, `file`, `env` or `secret`).
///
/// # Wrapped keys
///
/// The highest version wraps, and every version the provider holds unwraps, so a new KEK
/// version can be added while the keys wrapped under the older ones stay readable. The
/// [`EncryptedDataEncryptionKey`] records the version in decimal as its key version. The
/// wrapped key is
///
/// ```text
/// [0x01][i: u8][KEK id: i bytes][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]
/// ```
///
/// with the header up to the version as the associated data, so neither the id nor the version
/// can be changed. An unwrap refuses a key wrapped under another KEK id before it opens it.
///
/// # Limits
///
/// - No IAM, no audit log and no HSM. Protecting the KEK, at rest and in backups, is the
///   operator's job.
/// - Every wrap is one AES-256-GCM encryption with a random 96-bit nonce, so a KEK version is
///   safe for about 2^32 wraps. With the per-call envelope every value costs one wrap: a host
///   sealing 1,000 values per second spends 2^32 wraps in 50 days. Wrap once per data
///   encryption key instead, and add a new KEK version before the budget is spent.
/// - Crypto-shredding means destroying every copy of the KEK, backups included.
/// - Keys wrapped by a local KEK cannot be exported to BigQuery, which unwraps with Cloud KMS.
///
/// # Errors
///
/// A wrap fails with `ENCRYPTION` when the backend's CSPRNG fails. An unwrap fails with
/// `LOCAL_WRAPPED_KEY_FORMAT` when the key is not in the layout above, `LOCAL_KEK_ID_MISMATCH`
/// when it was wrapped under another KEK id, `LOCAL_KEK_UNKNOWN_VERSION` when the provider does
/// not hold its version, and `DECRYPT` when it is not authentic under that version.
#[derive(Debug)]
pub struct LocalKmsProvider {
    id: LocalKekId,
    kek: KekRef,
    keks: BTreeMap<LocalKekVersion, DataEncryptionKey>,
    cipher: AeadCipher,
}

impl LocalKmsProvider {
    /// A provider for the KEK `id` with the versions in `keks`, wrapping on `backend`. The
    /// highest version wraps; every version listed unwraps.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when `keks` is empty or lists a version twice.
    pub fn new(id: LocalKekId, keks: Vec<LocalKek>, backend: AeadBackend) -> KmsAeadResult<Self> {
        let cipher = AeadCipher::new(backend, AeadAlgorithm::Aes256Gcm)?;
        let mut sources = Vec::with_capacity(keks.len());
        let mut by_version = BTreeMap::new();
        for kek in keks {
            if by_version
                .insert(kek.version, DataEncryptionKey::from(kek.material))
                .is_some()
            {
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
            id,
            keks: by_version,
            cipher,
        })
    }

    /// A provider with one random version-1 KEK from the CSPRNG of `backend`, which lives as
    /// long as the provider: the keys it wraps cannot be unwrapped once the process exits. For
    /// tests.
    ///
    /// # Errors
    ///
    /// `ENCRYPTION` when the CSPRNG fails.
    pub fn ephemeral(id: LocalKekId, backend: AeadBackend) -> KmsAeadResult<Self> {
        let material = AeadCipher::new(backend, AeadAlgorithm::Aes256Gcm)?
            .generate_data_encryption_key()?
            .value()
            .clone();
        let kek = LocalKek {
            version: LocalKekVersion(NonZeroU32::MIN),
            material,
            source: "ephemeral",
        };
        Self::new(id, vec![kek], backend)
    }

    /// Splits `[0x01][i][KEK id][KEK version]` off a wrapped key and checks the id, before
    /// anything is opened. Returns the header, which is the associated data, the version and
    /// the sealed key.
    fn read_header<'w>(
        &self,
        wrapped: &'w [u8],
    ) -> KmsAeadResult<(&'w [u8], LocalKekVersion, &'w [u8])> {
        let malformed = || {
            KmsAeadEncryptionError::create(
                "LOCAL_WRAPPED_KEY_FORMAT",
                "The wrapped key is not in the layout of the local KMS",
            )
        };
        let [WRAPPED_KEY_LAYOUT, id_len, rest @ ..] = wrapped else {
            return Err(malformed());
        };
        let (id, rest) = rest
            .split_at_checked(usize::from(*id_len))
            .ok_or_else(malformed)?;
        if id != self.id.0.as_bytes() {
            return Err(KmsAeadEncryptionError::create(
                "LOCAL_KEK_ID_MISMATCH",
                &format!(
                    "The key was wrapped under another local KEK than {}",
                    self.id
                ),
            ));
        }
        let (version, sealed) = rest.split_first_chunk::<4>().ok_or_else(malformed)?;
        let version = NonZeroU32::new(u32::from_be_bytes(*version))
            .map(LocalKekVersion)
            .ok_or_else(malformed)?;
        Ok((&wrapped[..wrapped.len() - sealed.len()], version, sealed))
    }
}

#[async_trait]
impl KmsAeadEncryptionProvider for LocalKmsProvider {
    fn kek(&self) -> KekRef {
        self.kek.clone()
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::wrap_span(&self.kek), async {
            let (&version, kek) = self.keks.last_key_value().ok_or_else(|| {
                KmsAeadSystemError::create(
                    "LOCAL_KEK_VERSIONS",
                    &format!("The local KEK {} has no version", self.id),
                )
            })?;
            let mut wrapped = self.id.wrapped_key_header(version)?;
            let sealed =
                kms::timed(async { self.cipher.seal(&wrapped, encryption_key.value(), kek) })
                    .await?;
            wrapped.extend_from_slice(sealed.value());
            let key_version = KmsKeyVersion::try_from(version.to_string())?;
            let encrypted_key = EncryptedDataEncryptionKey::new(wrapped, Some(key_version));
            kms::record_wrap(&encrypted_key);
            Ok(encrypted_key)
        })
        .await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let span = kms::unwrap_span(&self.kek, encrypted_key.key_version());
        spans::in_span(span, async {
            let (header, version, sealed) = self.read_header(encrypted_key.wrapped())?;
            let kek = self.keks.get(&version).ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "LOCAL_KEK_UNKNOWN_VERSION",
                    &format!("The local KEK {} has no version {version}", self.id),
                )
            })?;
            let sealed = CipherText::from(sealed.to_vec());
            let key = kms::timed(async { self.cipher.open(header, &sealed, kek) }).await?;
            Ok(DataEncryptionKey::from(key))
        })
        .await
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::test_provider::TEST_BACKEND;

    const KEK_MATERIAL: [u8; 32] = [0x42; 32];
    const DEK_MATERIAL: [u8; 32] = [0x11; 32];

    /// Wrapped by Python's `cryptography` AES-GCM under [`KEK_MATERIAL`], KEK id `golden`,
    /// version 7 and nonce `[0x24; 12]`, from [`DEK_MATERIAL`].
    const GOLDEN_WRAPPED_KEY: &str = "0106676f6c64656e000000072424242424242424242424240480d550f8d7d72f37f933bbac2382b77dea2261a7ba417ca1b5dd4b47d4f602e5d1e6bd40e6d7891cd8fbc8d68e3a18";

    fn kek_id(id: &str) -> LocalKekId {
        LocalKekId::try_from(id.to_string()).unwrap()
    }

    fn version(version: u32) -> LocalKekVersion {
        LocalKekVersion::from(NonZeroU32::new(version).unwrap())
    }

    fn kek(kek_version: u32, material: [u8; 32]) -> LocalKek {
        LocalKek::from_secret(version(kek_version), SecretValue::new(material.to_vec())).unwrap()
    }

    fn dek() -> DataEncryptionKey {
        DataEncryptionKey::from(SecretValue::new(DEK_MATERIAL.to_vec()))
    }

    fn error_code<T: std::fmt::Debug>(result: KmsAeadResult<T>) -> String {
        result.unwrap_err().code().to_string()
    }

    #[tokio::test]
    async fn a_wrapped_key_unwraps_to_the_same_key() {
        let provider =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();

        let wrapped = provider.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(wrapped.key_version().unwrap().as_str(), "1");
        assert_eq!(
            provider
                .decrypt_data_encryption_key(&wrapped)
                .await
                .unwrap(),
            dek()
        );
        assert_eq!(provider.kek(), KekRef::new(KekProvider::Local, "orders"));
    }

    #[tokio::test]
    async fn the_highest_version_wraps_and_every_version_unwraps() {
        let old = LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
            .unwrap();
        let wrapped_by_old = old.encrypt_data_encryption_key(&dek()).await.unwrap();
        let rotated = LocalKmsProvider::new(
            kek_id("orders"),
            vec![kek(3, [0x43; 32]), kek(1, KEK_MATERIAL), kek(2, [0x44; 32])],
            TEST_BACKEND,
        )
        .unwrap();

        let wrapped_by_new = rotated.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(wrapped_by_new.key_version().unwrap().as_str(), "3");
        for wrapped in [wrapped_by_old, wrapped_by_new] {
            assert_eq!(
                rotated.decrypt_data_encryption_key(&wrapped).await.unwrap(),
                dek()
            );
        }
    }

    #[tokio::test]
    async fn the_golden_wrapped_key_unwraps() {
        let provider =
            LocalKmsProvider::new(kek_id("golden"), vec![kek(7, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let golden =
            EncryptedDataEncryptionKey::new(hex::decode(GOLDEN_WRAPPED_KEY).unwrap(), None);

        assert_eq!(
            provider.decrypt_data_encryption_key(&golden).await.unwrap(),
            dek()
        );

        let wrapped = provider.encrypt_data_encryption_key(&dek()).await.unwrap();
        let header = &hex::decode(GOLDEN_WRAPPED_KEY).unwrap()[..12];
        assert_eq!(&wrapped.wrapped()[..12], header);
        assert_eq!(wrapped.wrapped().len(), 12 + 12 + 32 + 16);
    }

    #[tokio::test]
    async fn a_flipped_header_byte_fails_to_unwrap() {
        let provider = LocalKmsProvider::new(
            kek_id("golden"),
            vec![kek(7, KEK_MATERIAL), kek(6, KEK_MATERIAL)],
            TEST_BACKEND,
        )
        .unwrap();
        let golden = hex::decode(GOLDEN_WRAPPED_KEY).unwrap();

        for index in 0..12 {
            for flip in [0x01, 0x80] {
                let mut wrapped = golden.clone();
                wrapped[index] ^= flip;
                let wrapped = EncryptedDataEncryptionKey::new(wrapped, None);
                assert!(
                    provider
                        .decrypt_data_encryption_key(&wrapped)
                        .await
                        .is_err(),
                    "byte {index} flipped by {flip:#04x}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_key_wrapped_under_another_kek_id_is_refused() {
        let orders =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let invoices =
            LocalKmsProvider::new(kek_id("invoices"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let wrapped = orders.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(
            error_code(invoices.decrypt_data_encryption_key(&wrapped).await),
            "LOCAL_KEK_ID_MISMATCH"
        );
    }

    #[tokio::test]
    async fn an_edek_wrapped_under_another_key_fails_to_unwrap() {
        let original =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let impostor =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(1, [0x43; 32])], TEST_BACKEND)
                .unwrap();
        let wrapped = impostor.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(
            error_code(original.decrypt_data_encryption_key(&wrapped).await),
            "DECRYPT"
        );
    }

    #[tokio::test]
    async fn a_version_the_provider_does_not_hold_is_refused() {
        let rotated =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(2, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let old = LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
            .unwrap();
        let wrapped = rotated.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(
            error_code(old.decrypt_data_encryption_key(&wrapped).await),
            "LOCAL_KEK_UNKNOWN_VERSION"
        );
    }

    #[tokio::test]
    async fn a_truncated_wrapped_key_is_refused() {
        let provider =
            LocalKmsProvider::new(kek_id("golden"), vec![kek(7, KEK_MATERIAL)], TEST_BACKEND)
                .unwrap();
        let golden = hex::decode(GOLDEN_WRAPPED_KEY).unwrap();

        for len in [0, 1, 2, 8, 11] {
            let wrapped = EncryptedDataEncryptionKey::new(golden[..len].to_vec(), None);
            assert_eq!(
                error_code(provider.decrypt_data_encryption_key(&wrapped).await),
                "LOCAL_WRAPPED_KEY_FORMAT",
                "{len} bytes"
            );
        }
    }

    #[test]
    fn invalid_keks_fail_with_their_codes() {
        let short = SecretValue::new(vec![0x42; 16]);
        assert_eq!(
            error_code(LocalKek::from_secret(version(1), short)),
            "LOCAL_KEK_LENGTH"
        );
        assert_eq!(
            error_code(LocalKek::from_env(
                version(1),
                "KMS_AEAD_LOCAL_KEK_TEST_UNSET_VARIABLE"
            )),
            "LOCAL_KEK_SOURCE"
        );
        assert_eq!(
            error_code(LocalKmsProvider::new(
                kek_id("orders"),
                Vec::new(),
                TEST_BACKEND
            )),
            "LOCAL_KEK_VERSIONS"
        );
        assert_eq!(
            error_code(LocalKmsProvider::new(
                kek_id("orders"),
                vec![kek(1, KEK_MATERIAL), kek(1, [0x43; 32])],
                TEST_BACKEND,
            )),
            "LOCAL_KEK_VERSIONS"
        );
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
            assert_eq!(
                error_code(LocalKekId::try_from(invalid.clone())),
                "INVALID_LOCAL_KEK_ID",
                "{invalid:?}"
            );
        }
    }

    #[tokio::test]
    async fn an_ephemeral_provider_round_trips() {
        let provider = LocalKmsProvider::ephemeral(kek_id("tests"), TEST_BACKEND).unwrap();

        let wrapped = provider.encrypt_data_encryption_key(&dek()).await.unwrap();

        assert_eq!(
            provider
                .decrypt_data_encryption_key(&wrapped)
                .await
                .unwrap(),
            dek()
        );
    }

    /// The forms in which a key could reach a log line.
    fn renderings(material: &[u8]) -> Vec<String> {
        let base64 = SecretValue::new(material.to_vec())
            .as_sensitive_base64_str()
            .to_string();
        vec![
            hex::encode(material),
            hex::encode_upper(material),
            base64,
            format!("{material:?}"),
        ]
    }

    #[test]
    fn debug_prints_no_key_material() {
        let provider =
            LocalKmsProvider::new(kek_id("orders"), vec![kek(1, [0x5A; 32])], TEST_BACKEND)
                .unwrap();
        let printed = format!("{provider:?} {:?}", kek(2, [0x5A; 32]));

        for rendering in renderings(&[0x5A; 32]) {
            assert!(!printed.contains(&rendering), "{printed}");
        }
    }

    #[cfg(unix)]
    mod files {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;
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

            fn file(&self, name: &str, content: &str, mode: u32) -> PathBuf {
                let path = self.0.join(name);
                fs::write(&path, content).unwrap();
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                path
            }
        }

        impl Drop for TestDir {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }

        fn effective_user() -> u32 {
            rustix::process::geteuid().as_raw()
        }

        #[tokio::test]
        async fn a_kek_file_wraps_and_unwraps() {
            let dir = TestDir::new("round-trip");
            let path = dir.file("kek", KEK_BASE64, 0o600);
            let from_file = LocalKmsProvider::new(
                kek_id("orders"),
                vec![LocalKek::from_file(version(1), &path).unwrap()],
                TEST_BACKEND,
            )
            .unwrap();
            let from_secret =
                LocalKmsProvider::new(kek_id("orders"), vec![kek(1, KEK_MATERIAL)], TEST_BACKEND)
                    .unwrap();

            let wrapped = from_file.encrypt_data_encryption_key(&dek()).await.unwrap();

            assert_eq!(
                from_secret
                    .decrypt_data_encryption_key(&wrapped)
                    .await
                    .unwrap(),
                dek()
            );
        }

        #[test]
        fn a_trailing_newline_is_accepted() {
            let dir = TestDir::new("newline");
            let path = dir.file("kek", &format!("{KEK_BASE64}\n"), 0o600);

            assert!(LocalKek::from_file(version(1), &path).is_ok());
        }

        #[test]
        fn group_or_other_permissions_are_refused() {
            let dir = TestDir::new("modes");
            for mode in [0o640, 0o604] {
                let path = dir.file(&format!("kek-{mode:o}"), KEK_BASE64, mode);
                assert_eq!(
                    error_code(LocalKek::from_file(version(1), &path)),
                    "LOCAL_KEK_FILE_PERMISSIONS",
                    "{mode:o}"
                );
            }
        }

        #[test]
        fn a_file_that_is_not_base64_is_refused() {
            let dir = TestDir::new("base64");
            let path = dir.file("kek", "not base64!", 0o600);

            assert_eq!(
                error_code(LocalKek::from_file(version(1), &path)),
                "LOCAL_KEK_SOURCE"
            );
        }

        #[test]
        fn a_file_of_another_length_is_refused() {
            let dir = TestDir::new("length");
            let path = dir.file("kek", "QkJCQg==", 0o600);

            assert_eq!(
                error_code(LocalKek::from_file(version(1), &path)),
                "LOCAL_KEK_LENGTH"
            );
        }

        #[test]
        fn a_missing_file_is_refused() {
            let dir = TestDir::new("missing");

            assert_eq!(
                error_code(LocalKek::from_file(version(1), &dir.0.join("kek"))),
                "LOCAL_KEK_SOURCE"
            );
        }

        #[test]
        fn a_file_larger_than_the_cap_is_refused() {
            let dir = TestDir::new("large");
            let padded = format!("{KEK_BASE64}{}", " ".repeat(LocalKek::MAX_FILE_LEN));
            let path = dir.file("kek", &padded, 0o600);

            assert_eq!(
                error_code(LocalKek::from_file(version(1), &path)),
                "LOCAL_KEK_LENGTH"
            );
        }

        /// Opening a FIFO with no writer blocks, so the read runs on its own thread and a
        /// regression fails on the timeout instead of hanging the suite.
        #[test]
        fn a_fifo_is_refused_without_blocking() {
            let dir = TestDir::new("fifo");
            let path = dir.0.join("kek");
            let owner_only = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
            rustix::fs::mkfifoat(rustix::fs::CWD, &path, owner_only).unwrap();

            let (sender, receiver) = std::sync::mpsc::channel();
            let fifo = path.clone();
            std::thread::spawn(move || {
                let _ = sender.send(error_code(LocalKek::from_file(version(1), &fifo)));
            });

            assert_eq!(
                receiver
                    .recv_timeout(std::time::Duration::from_secs(5))
                    .expect("from_file blocked on the FIFO"),
                "LOCAL_KEK_FILE_PERMISSIONS"
            );
        }

        #[test]
        fn a_symlink_to_a_group_readable_file_is_refused() {
            let dir = TestDir::new("symlink");
            let target = dir.file("target", KEK_BASE64, 0o640);
            let link = dir.0.join("kek");
            std::os::unix::fs::symlink(&target, &link).unwrap();

            assert_eq!(
                error_code(LocalKek::from_file(version(1), &link)),
                "LOCAL_KEK_FILE_PERMISSIONS"
            );
        }

        /// The process cannot open a 0600 file another user owns unless it runs as root, so the
        /// check is given another effective user when the tests do not run as root.
        #[test]
        fn a_file_owned_by_another_user_is_refused() {
            let dir = TestDir::new("owner");
            let path = dir.file("kek", KEK_BASE64, 0o600);
            let effective_user = if effective_user() == 0 {
                std::os::unix::fs::chown(&path, Some(65534), None).unwrap();
                0
            } else {
                effective_user() + 1
            };
            let file = File::open(&path).unwrap();

            assert_eq!(
                error_code(check_opened_file(
                    &file.metadata().unwrap(),
                    &path,
                    effective_user
                )),
                "LOCAL_KEK_FILE_PERMISSIONS"
            );
        }
    }
}
