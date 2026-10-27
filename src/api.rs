use std::convert::Infallible;
use std::fmt::{Display, Formatter};
use std::future::Future;
use std::str::FromStr;

use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

use crate::{DataEncryptionKey, EncryptedDataEncryptionKey, KmsAeadResult};

/// Encrypts data encryption keys (DEKs) with a key encryption key (KEK) held by a KMS: the half
/// of a provider that writes. [`KmsAeadDecryptionProvider`] adds the half that reads.
///
/// A provider that implements this trait alone encrypts and never decrypts, such as
/// [`PublicKeyKekProvider`](crate::providers::PublicKeyKekProvider), which holds the public half
/// of an asymmetric KEK: an envelope over it has the calls that encrypt and none that decrypts a
/// DEK or decrypts a value, and no keyring opens over it. Every other built-in provider implements
/// both traits.
///
/// Applications may implement it, for a KMS of their own or as a wrapper around another
/// provider, such as a cache. A wrapper returns the inner provider's [`kek`](Self::kek), and
/// implements [`KmsAeadDecryptionProvider`] where the inner provider does.
///
/// Write each method that returns a future as an `async fn`. Its future must be `Send`, so that
/// an envelope or a keyring runs on a multi-threaded runtime. Envelopes and keyrings are generic
/// over their provider: the trait has no `dyn` form.
///
/// An implementation's errors carry no key material in any form, plaintext or encrypted, in
/// `Display` or `Debug`. A provider that calls a KMS hands the plaintext key to the KMS SDK or
/// HTTP client, which keeps copies of it in request and response buffers that kms-aead cannot
/// zeroise.
pub trait KmsAeadEncryptionProvider: Send + Sync {
    /// The KEK this provider encrypts with. A provider that decrypts names it to the KMS on every
    /// decryption, so that a key encrypted under another KEK fails at the KMS and never yields a
    /// data encryption key.
    ///
    /// Two providers return equal values only when they address the same key of the same KMS:
    /// a cache of decrypted keys may be keyed by it.
    fn kek(&self) -> &KekRef;

    /// Encrypts `dek` with the KEK. The result carries the KEK version the KMS's response names,
    /// set with [`with_kek_version`](EncryptedDataEncryptionKey::with_kek_version), and none when
    /// the response names none.
    ///
    /// # Errors
    ///
    /// The error the KMS returned, with the provider's code: the KMS's own error code where it
    /// has one, such as `NotFoundException` from AWS KMS or `VAULT_STATUS_403` from Vault.
    fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> impl Future<Output = KmsAeadResult<EncryptedDataEncryptionKey>> + Send;

    /// `len` random bytes from the KMS's own generator, for a provider configured to use it.
    /// `Ok(None)` means the caller generates the key with its crypto backend, which is what the
    /// default implementation returns. The caller checks the length and fails with
    /// `INVALID_KEY_LENGTH` when the KMS returned another one.
    fn generate_key_material(
        &self,
        len: usize,
    ) -> impl Future<Output = KmsAeadResult<Option<SecretValue>>> + Send {
        let _ = len;
        std::future::ready(Ok(None))
    }

    /// Whether this provider encrypts DEKs with the public half of an asymmetric KEK, so that a
    /// keyring refuses the BigQuery and Tink exports and the `Interop` fields its KEK cannot
    /// serve. `false` by default; an application's own provider that encrypts with a public key
    /// returns `true`.
    fn encrypts_with_public_key(&self) -> bool {
        false
    }
}

/// Decrypts the data encryption keys that its [`KmsAeadEncryptionProvider`] half, or another
/// provider of the same KEK, encrypted: the half of a provider that reads. The envelope's calls
/// that decrypt a DEK or a value need it, and so does every keyring.
///
/// The rules of [`KmsAeadEncryptionProvider`] hold for it: an `async fn` with a `Send` future,
/// and no key material in an error.
pub trait KmsAeadDecryptionProvider: KmsAeadEncryptionProvider {
    /// Decrypts `encrypted_dek` with the KEK. The request names the configured KEK, so a key
    /// encrypted under another KEK is refused by the KMS.
    ///
    /// # Errors
    ///
    /// As [`encrypt_data_encryption_key`](KmsAeadEncryptionProvider::encrypt_data_encryption_key).
    fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> impl Future<Output = KmsAeadResult<DataEncryptionKey>> + Send;
}

/// A key encryption key: the KMS that holds it and the key's name there. It is also the
/// `provider` and `key` value of the KMS spans.
///
/// serde reads and writes it as the object `{"provider": "gcp", "key": "projects/…"}`, the
/// provider by its [`Display`] name, the form a keyring record stores it in.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KekRef {
    provider: KmsProvider,
    key: String,
}

impl KekRef {
    /// A KEK named `key` in the KMS `provider`. An application's own provider passes
    /// [`KmsProvider::Other`] and a key name that identifies the key across every KMS instance
    /// it may address.
    pub fn new(provider: KmsProvider, key: impl Into<String>) -> Self {
        Self {
            provider,
            key: key.into(),
        }
    }

    /// The KMS that holds the key.
    pub fn provider(&self) -> &KmsProvider {
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
            KmsProvider::Gcp => Some(format!("gcp-kms://{}", self.key)),
            KmsProvider::Aws if self.key.starts_with("arn:") => {
                Some(format!("aws-kms://{}", self.key))
            }
            KmsProvider::HcVaultTransit => self
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

/// The KMS that holds a key: a key encryption key, or a signing key.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum KmsProvider {
    /// Google Cloud KMS.
    Gcp,
    /// AWS Key Management Service.
    Aws,
    /// Azure Key Vault or Managed HSM.
    Azure,
    /// The Transit secrets engine of HashiCorp Vault.
    HcVaultTransit,
    /// A key held by the application itself.
    Local,
    /// An application's own provider, named by the application. The name is never one of the
    /// built-in names above, which [`FromStr`] reads as their own variants.
    #[serde(untagged)]
    Other(String),
}

/// `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of [`KmsProvider::Other`]: the
/// values of the `/kms_aead/provider` span field.
impl Display for KmsProvider {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KmsProvider::Gcp => "gcp",
            KmsProvider::Aws => "aws",
            KmsProvider::Azure => "azure",
            KmsProvider::HcVaultTransit => "hc_vault_transit",
            KmsProvider::Local => "local",
            KmsProvider::Other(name) => name,
        })
    }
}

/// A built-in name is its variant, and any other name is [`KmsProvider::Other`]. It reads back
/// what `Display` writes for every value but an `Other` holding a built-in name, which reads back
/// as that name's variant.
impl FromStr for KmsProvider {
    type Err = Infallible;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Ok(match name {
            "gcp" => KmsProvider::Gcp,
            "aws" => KmsProvider::Aws,
            "azure" => KmsProvider::Azure,
            "hc_vault_transit" => KmsProvider::HcVaultTransit,
            "local" => KmsProvider::Local,
            other => KmsProvider::Other(other.to_string()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_parses_back_and_another_name_is_other() {
        for provider in [
            KmsProvider::Gcp,
            KmsProvider::Aws,
            KmsProvider::Azure,
            KmsProvider::HcVaultTransit,
            KmsProvider::Local,
            KmsProvider::Other("orders-hsm".to_string()),
        ] {
            assert_eq!(provider.to_string().parse(), Ok(provider));
        }
    }

    #[test]
    fn a_kek_is_the_object_of_its_provider_name_and_key() {
        for (kek, json) in [
            (
                KekRef::new(KmsProvider::Gcp, "orders"),
                r#"{"provider":"gcp","key":"orders"}"#,
            ),
            (
                KekRef::new(KmsProvider::Aws, "orders"),
                r#"{"provider":"aws","key":"orders"}"#,
            ),
            (
                KekRef::new(KmsProvider::Azure, "orders"),
                r#"{"provider":"azure","key":"orders"}"#,
            ),
            (
                KekRef::new(
                    KmsProvider::HcVaultTransit,
                    "https://vault:8200/transit/keys/orders",
                ),
                r#"{"provider":"hc_vault_transit","key":"https://vault:8200/transit/keys/orders"}"#,
            ),
            (
                KekRef::new(KmsProvider::Local, "orders"),
                r#"{"provider":"local","key":"orders"}"#,
            ),
            (
                KekRef::new(KmsProvider::Other("orders-hsm".to_string()), "orders"),
                r#"{"provider":"orders-hsm","key":"orders"}"#,
            ),
        ] {
            assert_eq!(serde_json::to_string(&kek).unwrap(), json);
            assert_eq!(serde_json::from_str::<KekRef>(json).unwrap(), kek);
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
                KekRef::new(KmsProvider::Gcp, crypto_key),
                Some(format!("gcp-kms://{crypto_key}")),
            ),
            (
                KekRef::new(KmsProvider::Aws, key_arn),
                Some(format!("aws-kms://{key_arn}")),
            ),
            // A key named without a region, which has no ARN.
            (KekRef::new(KmsProvider::Aws, "alias/orders"), None),
            (
                KekRef::new(
                    KmsProvider::HcVaultTransit,
                    "https://vault.example.com:8200/tenant-a/transit/keys/orders",
                ),
                Some("hcvault://vault.example.com:8200/tenant-a/transit/keys/orders".to_string()),
            ),
            (
                KekRef::new(
                    KmsProvider::Azure,
                    "https://orders.vault.azure.net/keys/orders",
                ),
                None,
            ),
            (KekRef::new(KmsProvider::Local, "orders"), None),
            (
                KekRef::new(KmsProvider::Other("orders-hsm".to_string()), "orders"),
                None,
            ),
        ];
        for (kek, key_uri) in keks {
            assert_eq!(kek.tink_key_uri(), key_uri, "{kek}");
        }
    }
}
