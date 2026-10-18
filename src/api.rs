use crate::errors::KmsAeadEncryptionError;
use crate::*;
use async_trait::*;
use secret_vault_value::SecretValue;
use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

/// Authenticated encryption with associated data (AEAD) under a data encryption key the caller
/// holds, implemented by [`AeadCipher`].
///
/// `aad` is authenticated but not encrypted: a value opens only with the AAD it was sealed with.
#[async_trait]
pub trait AeadEncryption<Aad> {
    /// Seals `plain_text` with `encryption_key` and a fresh random nonce, so that sealing the same
    /// input twice gives different cipher texts.
    ///
    /// # Errors
    ///
    /// [`AeadCipher`] fails with `INVALID_KEY_LENGTH` when the key does not have the length of
    /// its algorithm, `ENCRYPTION` when the random nonce cannot be generated, and `ENCRYPT_KEY`
    /// or `ENCRYPT` when the backend refuses the key or fails to seal.
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Opens a cipher text sealed by [`encrypt_value`](Self::encrypt_value) with the same key
    /// and AAD.
    ///
    /// # Errors
    ///
    /// [`AeadCipher`] fails with `INVALID_KEY_LENGTH` when the key does not have the length of
    /// its algorithm, `INVALID_CIPHERTEXT` when the value is shorter than a nonce and a tag,
    /// `DECRYPT_KEY` when the backend refuses the key, and `DECRYPT` when the value is not
    /// authentic under the key, the nonce and the AAD.
    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;
}

/// Envelope encryption: AEAD under a data encryption key (DEK), with the DEK wrapped by a key
/// encryption key (KEK) that a KMS holds. Implemented by [`KmsAeadEnvelope`].
///
/// Every method returns the errors of [`AeadEncryption`] for the AEAD step and the errors of the
/// [`KmsAeadEncryptionProvider`] for the KMS step, with the codes the KMS provider reports.
#[async_trait]
pub trait KmsAeadEnvelopeEncryption<Aad> {
    /// Encrypts `plain_text` under a new DEK, or under the reused DEK of a store-less
    /// [`KmsAeadEnvelope`], and returns it with the wrapped DEK in one
    /// [`CipherTextWithEncryptedKey`]. A new DEK costs one KMS call to wrap it, and one more for
    /// the key material when the provider uses the KMS generator. A reused DEK costs one KMS
    /// unwrap per TTL of the envelope's [`DekCache`](crate::cache::DekCache).
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
    /// material of the wrong length, and `INVALID_CIPHER_TEXT_FORMAT` when the wrapped key is
    /// longer than 65,535 bytes.
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey>;

    /// Unwraps the DEK stored in `cipher_text`, through the envelope's
    /// [`DekCache`](crate::cache::DekCache), and opens the value with it.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, `UNKNOWN_CIPHER_TEXT_LAYOUT`,
    /// `INVALID_CIPHER_TEXT_FORMAT` or `INVALID_KEY_VERSION` when `cipher_text` cannot be read
    /// (see [`CipherTextWithEncryptedKey::separate`]).
    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Encrypts `plain_text` under a plaintext DEK the caller holds, such as one from
    /// [`generate_new_dek`](Self::generate_new_dek), without calling the KMS.
    async fn encrypt_value_with_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Unwraps `dek`, through the envelope's [`DekCache`](crate::cache::DekCache), and encrypts
    /// `plain_text` under it. The caller stores the wrapped DEK beside the returned cipher text.
    async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Opens `cipher_text` with a plaintext DEK the caller holds, without calling the KMS.
    async fn decrypt_value_with_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        data_encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Unwraps `encrypted_data_encryption_key`, through the envelope's
    /// [`DekCache`](crate::cache::DekCache), and opens `cipher_text` with it.
    async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Generates a new DEK, from the KMS generator when the provider uses one and from the
    /// backend's CSPRNG otherwise, and wraps it with the KMS.
    ///
    /// # Errors
    ///
    /// Besides the KMS errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material
    /// of the wrong length, and `ENCRYPTION` when the backend's CSPRNG fails.
    async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>;
}

/// Wraps and unwraps data encryption keys with a key encryption key (KEK) held by a KMS.
///
/// Applications may implement it, for a KMS of their own or as a wrapper around another
/// provider, such as a cache. A wrapper returns the inner provider's [`kek`](Self::kek).
///
/// An implementation's errors carry no key material in any form, plaintext or wrapped, in
/// `Display` or `Debug`.
#[async_trait]
pub trait KmsAeadEncryptionProvider {
    /// The KEK this provider wraps with and names to the KMS on every unwrap, so that a key
    /// wrapped under another KEK fails at the KMS and never yields a data encryption key.
    ///
    /// Two providers return equal values only when they address the same key of the same KMS:
    /// a cache of unwrapped keys may be keyed by it.
    fn kek(&self) -> KekRef;

    /// Wraps `encryption_key` with the KEK, recording the KEK version that wrapped it when the
    /// KMS reports one.
    ///
    /// # Errors
    ///
    /// The error the KMS returned, with the provider's code: the KMS's own error code where it
    /// has one, such as `NotFoundException` from AWS KMS or `VAULT_STATUS_403` from Vault.
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>;

    /// Unwraps `encrypted_key` with the KEK. The request names the configured KEK, so a key
    /// wrapped under another KEK is refused by the KMS.
    ///
    /// # Errors
    ///
    /// As [`encrypt_data_encryption_key`](Self::encrypt_data_encryption_key).
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey>;

    /// `len` random bytes from the KMS's own generator, for a provider configured to use it.
    /// `Ok(None)` means the caller generates the key with its crypto backend, which is what the
    /// default implementation returns. The caller checks the length and fails with
    /// `INVALID_KEY_LENGTH` when the KMS returned another one.
    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        let _ = len;
        Ok(None)
    }
}

/// Sealing and opening for the crate's own callers. It is crate-private so that these operations
/// stay off the public API of [`AeadCipher`] and can change in any release.
pub(crate) trait Cipher {
    /// Seals `plain_text` under `key`, authenticating `aad`.
    fn seal(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Opens a value [`seal`](Self::seal) sealed under `key` and `aad`, into a buffer the
    /// returned `SecretValue` owns, so that no other copy of the plaintext exists.
    fn open(
        &self,
        aad: &[u8],
        cipher_text: &CipherText,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;
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

/// A key encryption key: the KMS that holds it and the key's name there. It is also the
/// `provider` and `key` value of the KMS spans.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KekRef {
    provider: KekProvider,
    key: String,
}

impl KekRef {
    /// A KEK named `key` in the KMS `provider`. An application's own provider passes
    /// [`KekProvider::Other`] and a key name that identifies the key across every KMS instance
    /// it may address.
    pub fn new(provider: KekProvider, key: impl Into<String>) -> Self {
        Self {
            provider,
            key: key.into(),
        }
    }

    /// The KMS that holds the key.
    pub fn provider(&self) -> &KekProvider {
        &self.provider
    }

    /// The key as the provider names it: the GCP CryptoKey name; the AWS key or alias ARN, or
    /// the configured key id when no region is known; `<vault URL>/keys/<name>` for Azure;
    /// `<vault address>/<namespace>/<mount>/keys/<name>` for Vault Transit, without the
    /// namespace segment when none is set.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// `<provider>:<key>`.
impl Display for KekRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.provider, self.key)
    }
}

/// The KMS that holds a key encryption key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KekProvider {
    /// Google Cloud KMS.
    Gcp,
    /// AWS Key Management Service.
    Aws,
    /// Azure Key Vault or Managed HSM.
    Azure,
    /// The Transit secrets engine of HashiCorp Vault.
    HcVaultTransit,
    /// A KEK held by the application itself.
    Local,
    /// An application's own provider, named by the application.
    Other(String),
}

/// `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of [`KekProvider::Other`]: the
/// values of the `/kms_aead/provider` span field.
impl Display for KekProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KekProvider::Gcp => "gcp",
            KekProvider::Aws => "aws",
            KekProvider::Azure => "azure",
            KekProvider::HcVaultTransit => "hc_vault_transit",
            KekProvider::Local => "local",
            KekProvider::Other(name) => name,
        })
    }
}

/// Reads what `Display` writes: a built-in name is its variant, and any other name is
/// [`KekProvider::Other`].
impl FromStr for KekProvider {
    type Err = Infallible;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(match name {
            "gcp" => KekProvider::Gcp,
            "aws" => KekProvider::Aws,
            "azure" => KekProvider::Azure,
            "hc_vault_transit" => KekProvider::HcVaultTransit,
            "local" => KekProvider::Local,
            other => KekProvider::Other(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_parses_back_and_another_name_is_other() {
        for provider in [
            KekProvider::Gcp,
            KekProvider::Aws,
            KekProvider::Azure,
            KekProvider::HcVaultTransit,
            KekProvider::Local,
            KekProvider::Other("orders-hsm".to_string()),
        ] {
            assert_eq!(provider.to_string().parse(), Ok(provider));
        }
    }
}
