use rsb_derive::*;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use azure_core::credentials::TokenCredential;
use azure_core::http::RequestContent;
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, KeyClientWrapKeyOptions, KeyOperationParameters,
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use std::sync::Arc;

use crate::spans::{self, kms};
use secret_vault_value::SecretValue;

/// A Key Vault or Managed HSM key that wraps data encryption keys. Available with the
/// `azure-kms-encryption-base` feature.
///
/// Without `key_version` the latest version wraps new keys. Each encrypted key records the
/// version that wrapped it, and unwrapping uses that recorded version, so keys wrapped before a
/// rotation still unwrap afterwards.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AzureKmsKeyRef {
    /// Vault URL, such as `https://my-vault.vault.azure.net`.
    pub vault_url: String,
    /// The key name: `0-9`, `a-z`, `A-Z` and `-`.
    pub key_name: String,
    /// The version that wraps new keys. Without one, the latest version wraps them.
    pub key_version: Option<KmsKeyVersion>,
}

/// Options for [`AzureKmsProvider`].
#[derive(Debug, Clone, Builder)]
pub struct AzureKmsProviderOptions {
    /// Wrap algorithm, which must suit the key type: `RsaOaep256` for RSA keys, `A256Kw` for
    /// Managed HSM AES keys. `RsaOaep` (SHA-1) is accepted for existing keys; `Rsa1_5` and
    /// unknown algorithms are rejected. Encrypted keys do not record the algorithm, so it stays
    /// fixed for the life of the key.
    #[default = "EncryptionAlgorithm::RsaOaep256"]
    pub algorithm: EncryptionAlgorithm,

    /// Client settings passed to the Azure SDK, such as a custom HTTP transport or retry policy.
    pub client_options: Option<KeyClientOptions>,
}

/// Wraps and unwraps data encryption keys with an Azure Key Vault key. Available with the
/// `azure-kms-encryption-base` feature.
///
/// A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
/// `AZURE_STATUS_<status>` when the response has none. A server error or a rate limit is a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError), any other status an
/// [`EncryptionError`](crate::errors::KmsAeadError::EncryptionError).
///
/// Unwrapping needs the key version recorded in [`EncryptedDataEncryptionKey::key_version`].
/// Store an encrypted key with [`EncryptedDataEncryptionKey::to_bytes`] or
/// [`EncryptedDataEncryptionKey::to_hex_string`] and read it back with `TryFrom<&[u8]>` or
/// [`EncryptedDataEncryptionKey::try_from_hex_string`], which keep the version Azure needs to
/// unwrap after a rotation.
pub struct AzureKmsProvider {
    client: KeyClient,
    azure_key_ref: AzureKmsKeyRef,
    options: AzureKmsProviderOptions,
    kek: KekRef,
}

impl AzureKmsProvider {
    /// Uses the key at `kms_key_ref` with any Azure credential, for example one from
    /// `azure_identity`, and the default options. No request is made until the first key is
    /// wrapped or unwrapped.
    ///
    /// # Errors
    ///
    /// As [`with_options`](Self::with_options).
    pub fn new(
        kms_key_ref: &AzureKmsKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, AzureKmsProviderOptions::new(), credential)
    }

    /// As [`new`](Self::new), with `options`.
    ///
    /// # Errors
    ///
    /// A [`SystemError`](crate::errors::KmsAeadError::SystemError): `AZURE_KEY_NAME` when the key
    /// name holds characters Key Vault does not allow in it, `AZURE_WRAP_ALGORITHM` when the
    /// algorithm is `Rsa1_5` or unknown, and `AZURE_VAULT_URL` when the vault URL is not an
    /// HTTP(S) URL.
    pub fn with_options(
        kms_key_ref: &AzureKmsKeyRef,
        options: AzureKmsProviderOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        // The SDK substitutes the name and version into the request path without escaping,
        // so a `/` or `?` in either would address a different resource. `KmsKeyVersion`
        // admits only alphanumerics.
        if !is_key_vault_name(&kms_key_ref.key_name) {
            return Err(KmsAeadSystemError::create(
                "AZURE_KEY_NAME",
                &format!(
                    "Azure Key Vault key names allow only 0-9, a-z, A-Z and -: {:?}",
                    kms_key_ref.key_name
                ),
            ));
        }

        if let EncryptionAlgorithm::Rsa1_5 | EncryptionAlgorithm::UnknownValue(_) =
            options.algorithm
        {
            return Err(KmsAeadSystemError::create(
                "AZURE_WRAP_ALGORITHM",
                &format!(
                    "Azure Key Vault wrap algorithm {} is not supported",
                    options.algorithm
                ),
            ));
        }

        let client = KeyClient::new(
            &kms_key_ref.vault_url,
            credential,
            options.client_options.clone(),
        )
        .map_err(|e| {
            KmsAeadSystemError::create(
                "AZURE_VAULT_URL",
                &format!(
                    "Invalid Azure Key Vault URL {:?}: {e}",
                    kms_key_ref.vault_url
                ),
            )
        })?;

        Ok(Self {
            client,
            azure_key_ref: kms_key_ref.clone(),
            options,
            kek: KekRef::new(
                KekProvider::Azure,
                format!(
                    "{}/keys/{}",
                    kms_key_ref.vault_url.trim_end_matches('/'),
                    kms_key_ref.key_name
                ),
            ),
        })
    }

    fn key_operation(
        &self,
        value: Vec<u8>,
    ) -> KmsAeadResult<RequestContent<KeyOperationParameters>> {
        RequestContent::try_from(KeyOperationParameters {
            algorithm: Some(self.options.algorithm.clone()),
            value: Some(value),
            ..Default::default()
        })
        .map_err(KmsAeadError::from_azure_error)
    }
}

fn is_key_vault_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[async_trait]
impl KmsAeadEncryptionProvider for AzureKmsProvider {
    fn kek(&self) -> KekRef {
        self.kek.clone()
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::wrap_span(&self.kek), async {
            let parameters =
                self.key_operation(encryption_key.value().ref_sensitive_value().clone())?;
            let wrapped = kms::timed(
                self.client.wrap_key(
                    &self.azure_key_ref.key_name,
                    parameters,
                    Some(KeyClientWrapKeyOptions {
                        key_version: self
                            .azure_key_ref
                            .key_version
                            .as_ref()
                            .map(KmsKeyVersion::to_string),
                        ..Default::default()
                    }),
                ),
            )
            .await
            .and_then(|response| response.into_model())
            .map_err(KmsAeadError::from_azure_error)?;

            let key_version = wrapped
                .resource_id()
                .map_err(KmsAeadError::from_azure_error)?
                .version
                .ok_or_else(|| {
                    KmsAeadEncryptionError::create(
                        "AZURE_KEY_VERSION",
                        "Azure Key Vault returned a wrapped key without the key version",
                    )
                })?;
            let wrapped_bytes = wrapped.result.ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "AZURE_WRAPPED_KEY",
                    "Azure Key Vault returned no wrapped key",
                )
            })?;
            let encrypted_key = EncryptedDataEncryptionKey::new(
                wrapped_bytes,
                Some(KmsKeyVersion::try_from(key_version)?),
            );
            kms::record_wrap(&encrypted_key);
            Ok(encrypted_key)
        })
        .await
    }

    /// Unwraps with the configured key name and the key version the encrypted key records, so
    /// that Key Vault refuses a key wrapped under another key and accepts one wrapped under an
    /// earlier version of this one.
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let span = kms::unwrap_span(&self.kek, encrypted_key.key_version());
        spans::in_span(span, async {
            let key_version = encrypted_key.key_version().ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "AZURE_KEY_VERSION_MISSING",
                    "The encrypted data encryption key records no Azure Key Vault key version",
                )
            })?;

            let parameters = self.key_operation(encrypted_key.wrapped().to_vec())?;
            let unwrapped = kms::timed(self.client.unwrap_key(
                &self.azure_key_ref.key_name,
                key_version.as_str(),
                parameters,
                None,
            ))
            .await
            .and_then(|response| response.into_model())
            .map_err(KmsAeadError::from_azure_error)?;

            let key = unwrapped.result.ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "AZURE_UNWRAPPED_KEY",
                    "Azure Key Vault returned no unwrapped key",
                )
            })?;
            Ok(DataEncryptionKey::from(SecretValue::new(key)))
        })
        .await
    }
}
