use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use async_trait::async_trait;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
use crate::{DataEncryptionKey, DekBinding, EncryptedDataEncryptionKey, KmsAeadResult};

/// Wraps and unwraps data encryption keys with a key encryption key (KEK) held by a KMS.
///
/// Applications may implement it, for a KMS of their own or as a wrapper around another
/// provider, such as a cache. A wrapper returns the inner provider's [`kek`](Self::kek).
///
/// An implementation's errors carry no key material in any form, plaintext or wrapped, in
/// `Display` or `Debug`. A provider that calls a KMS hands the plaintext key to the KMS SDK or
/// HTTP client, which keeps copies of it in request and response buffers that kms-aead cannot
/// zeroize.
#[async_trait]
pub trait KmsAeadEncryptionProvider {
    /// The KEK this provider wraps with and names to the KMS on every unwrap, so that a key
    /// wrapped under another KEK fails at the KMS and never yields a data encryption key.
    ///
    /// Two providers return equal values only when they address the same key of the same KMS:
    /// a cache of unwrapped keys may be keyed by it.
    fn kek(&self) -> &KekRef;

    /// Wraps `encryption_key` with the KEK, recording the KEK version that wrapped it when the
    /// KMS reports one. With `Some(binding)`, the KMS authenticates the binding with the wrapped
    /// key, and only an unwrap that names the same binding opens it. A provider whose KMS
    /// cannot bind fails with `Some` and never wraps unbound in its place. `None` wraps unbound.
    ///
    /// # Errors
    ///
    /// The error the KMS returned, with the provider's code: the KMS's own error code where it
    /// has one, such as `NotFoundException` from AWS KMS or `VAULT_STATUS_403` from Vault.
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>;

    /// Unwraps `encrypted_key` with the KEK, naming the configured KEK and `binding` to the
    /// KMS, which refuses a key wrapped under another KEK or another binding, or wrapped
    /// unbound when `binding` is `Some`.
    ///
    /// # Errors
    ///
    /// As [`encrypt_data_encryption_key`](Self::encrypt_data_encryption_key).
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
        binding: Option<&DekBinding>,
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
