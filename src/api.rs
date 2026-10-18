use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use async_trait::async_trait;
use secret_vault_value::SecretValue;

use crate::providers::KmsKeyVersion;
use crate::{DataEncryptionKey, EncryptedDataEncryptionKey, KmsAeadResult};

/// Encrypts and decrypts data encryption keys with a key encryption key (KEK) held by a KMS.
///
/// Applications may implement it, for a KMS of their own or as a wrapper around another
/// provider, such as a cache. A wrapper returns the inner provider's [`kek`](Self::kek) and
/// [`key_version`](Self::key_version).
///
/// An implementation's errors carry no key material in any form, plaintext or encrypted, in
/// `Display` or `Debug`. A provider that calls a KMS hands the plaintext key to the KMS SDK or
/// HTTP client, which keeps copies of it in request and response buffers that kms-aead cannot
/// zeroise.
#[async_trait]
pub trait KmsAeadEncryptionProvider {
    /// The KEK this provider encrypts with and names to the KMS on every decryption, so that a key
    /// encrypted under another KEK fails at the KMS and never yields a data encryption key.
    ///
    /// Two providers return equal values only when they address the same key of the same KMS:
    /// a cache of decrypted keys may be keyed by it.
    fn kek(&self) -> &KekRef;

    /// Encrypts `dek` with the KEK, recording the KEK version that encrypted it when the
    /// KMS reports one.
    ///
    /// # Errors
    ///
    /// The error the KMS returned, with the provider's code: the KMS's own error code where it
    /// has one, such as `NotFoundException` from AWS KMS or `VAULT_STATUS_403` from Vault.
    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>;

    /// Decrypts `encrypted_dek` with the KEK. The request names the configured KEK, so a key
    /// encrypted under another KEK is refused by the KMS.
    ///
    /// # Errors
    ///
    /// As [`encrypt_data_encryption_key`](Self::encrypt_data_encryption_key).
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey>;

    /// `len` random bytes from the KMS's own generator, for a provider configured to use it.
    /// `Ok(None)` means the caller generates the key with its crypto backend, which is what the
    /// default implementation returns. The caller checks the length and fails with
    /// `INVALID_KEY_LENGTH` when the KMS returned another one.
    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        let _ = len;
        Ok(None)
    }

    /// The version of the KEK that encrypted `encrypted_dek`, read from the bytes this provider
    /// returned, without a KMS call, so that a sweep after a KEK rotation finds the stored keys
    /// that still need an older version.
    ///
    /// `None` means the provider's encrypted DEKs name no version that can be read. That is what
    /// the default implementation returns, and what the GCP and AWS providers return: their KMS
    /// ciphertexts are opaque. The local, Azure and Vault Transit providers read the version from
    /// their bytes.
    ///
    /// # Errors
    ///
    /// The provider's error for bytes it refuses to decrypt, such as `AZURE_ENCRYPTED_DEK_FORMAT`.
    fn key_version(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Option<KmsKeyVersion>> {
        let _ = encrypted_dek;
        Ok(None)
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

    /// The key URI Tink's KMS clients address this KEK by: `gcp-kms://<CryptoKey name>` for GCP,
    /// `aws-kms://<key or alias ARN>` for AWS and `hcvault://<host>/<namespace>/<mount>/keys/<name>`
    /// for Vault Transit, without the namespace segment when none is set. The Vault URI keeps
    /// the host of the address only, so it does not address a key behind an address with a path
    /// of its own, such as a proxy's.
    ///
    /// `None` for a KEK that no Tink KMS client addresses: an AWS key named without a region,
    /// which has no ARN, and the Azure, local and an application's own KEKs.
    pub fn tink_key_uri(&self) -> Option<String> {
        match self.provider {
            KekProvider::Gcp => Some(format!("gcp-kms://{}", self.key)),
            KekProvider::Aws if self.key.starts_with("arn:") => {
                Some(format!("aws-kms://{}", self.key))
            }
            KekProvider::HcVaultTransit => self
                .key
                .split_once("://")
                .map(|(_, location)| format!("hcvault://{location}")),
            _ => None,
        }
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
    /// An application's own provider, named by the application. The name is never one of the
    /// built-in names above, which [`FromStr`] reads as their own variants.
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

/// A built-in name is its variant, and any other name is [`KekProvider::Other`]. It reads back
/// what `Display` writes for every value but an `Other` holding a built-in name, which reads back
/// as that name's variant.
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

    #[test]
    fn tink_key_uris_are_the_ones_tink_kms_clients_take() {
        let crypto_key =
            "projects/orders-project/locations/europe-north1/keyRings/orders/cryptoKeys/email";
        let key_arn =
            "arn:aws:kms:eu-north-1:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        let keks = [
            (
                KekRef::new(KekProvider::Gcp, crypto_key),
                Some(format!("gcp-kms://{crypto_key}")),
            ),
            (
                KekRef::new(KekProvider::Aws, key_arn),
                Some(format!("aws-kms://{key_arn}")),
            ),
            // A key named without a region, which has no ARN.
            (KekRef::new(KekProvider::Aws, "alias/orders"), None),
            (
                KekRef::new(
                    KekProvider::HcVaultTransit,
                    "https://vault.example.com:8200/tenant-a/transit/keys/orders",
                ),
                Some("hcvault://vault.example.com:8200/tenant-a/transit/keys/orders".to_string()),
            ),
            (
                KekRef::new(
                    KekProvider::Azure,
                    "https://orders.vault.azure.net/keys/orders",
                ),
                None,
            ),
            (KekRef::new(KekProvider::Local, "orders"), None),
            (
                KekRef::new(KekProvider::Other("orders-hsm".to_string()), "orders"),
                None,
            ),
        ];
        for (kek, key_uri) in keks {
            assert_eq!(kek.tink_key_uri(), key_uri, "{kek}");
        }
    }
}
