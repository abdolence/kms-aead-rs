use crate::errors::KmsAeadEncryptionError;
use crate::*;
use async_trait::*;
use secret_vault_value::SecretValue;
use std::fmt::{Display, Formatter};

/// A trait that defines the encryption and decryption of a value using a data encryption key
/// and additional authenticated data (AEAD).
#[async_trait]
pub trait AeadEncryption<Aad> {
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;
}

/// A trait that defines the envelope encryption and decryption of a value using
/// a data encryption key (DEK), a key encryption key (KEK) from KMS providers,
/// and additional authenticated data (AEAD).
#[async_trait]
pub trait KmsAeadEnvelopeEncryption<Aad> {
    /// Encrypts the plain text using a new data encryption key.
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey>;

    /// Decrypts the cipher text using the cipher text with corresponding encrypted data encryption key.
    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Encrypts the plain text using the provided data encryption key.
    async fn encrypt_value_with_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Encrypts the plain text using the provided encrypted data encryption key.
    async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Decrypts the cipher text using the provided encrypted data encryption key.
    async fn decrypt_value_with_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        data_encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Decrypts the cipher text using the provided encrypted data encryption key.
    async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Generates a new data encryption key and encrypts it using the KMS provider.
    async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>;
}

/// Wraps and unwraps data encryption keys with a key encryption key (KEK) held by a KMS.
///
/// Applications may implement it, for a KMS of their own or as a wrapper around another
/// provider, such as a cache. A wrapper returns the inner provider's [`kek`](Self::kek).
#[async_trait]
pub trait KmsAeadEncryptionProvider {
    /// The KEK this provider wraps with and names to the KMS on every unwrap, so that a key
    /// wrapped under another KEK fails at the KMS and never yields a data encryption key.
    fn kek(&self) -> KekRef;

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>;

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey>;

    /// `len` random bytes from the KMS's own generator, for a provider configured to use it.
    /// `Ok(None)` means the caller generates the key with its crypto backend.
    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        let _ = len;
        Ok(None)
    }
}

/// `len` bytes from the KMS generator of `provider`, or `None` when it does not use one. The
/// one place that checks the length the KMS returned, for every kind of key.
pub(crate) async fn checked_key_material<P>(
    provider: &P,
    len: usize,
) -> KmsAeadResult<Option<SecretValue>>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    match provider.generate_key_material(len).await? {
        Some(material) if material.ref_sensitive_value().len() != len => {
            Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!(
                    "The KMS generator returned {} bytes for a key of {len} bytes",
                    material.ref_sensitive_value().len()
                ),
            ))
        }
        material => Ok(material),
    }
}

/// A KMS key: the `provider` and `key` values of the KMS spans, as a type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KekRef {
    provider: KekProvider,
    key: String,
}

impl KekRef {
    pub fn new(provider: KekProvider, key: impl Into<String>) -> Self {
        Self {
            provider,
            key: key.into(),
        }
    }

    pub fn provider(&self) -> &KekProvider {
        &self.provider
    }

    /// The key as the provider names it: the GCP CryptoKey name, the AWS key ARN or id,
    /// `<vault URL>/keys/<name>` for Azure, `<mount>/keys/<name>` for Vault Transit, the local
    /// KEK id.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// `<provider>:<key>`.
impl Display for KekRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.provider.name(), self.key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KekProvider {
    Gcp,
    Aws,
    Azure,
    VaultTransit,
    Local,
    /// An application's own provider, named by the application.
    Other(String),
}

impl KekProvider {
    /// The value of the `provider` span field.
    pub(crate) fn name(&self) -> &str {
        match self {
            KekProvider::Gcp => "gcp",
            KekProvider::Aws => "aws",
            KekProvider::Azure => "azure",
            KekProvider::VaultTransit => "vault_transit",
            KekProvider::Local => "local",
            KekProvider::Other(name) => name,
        }
    }
}
