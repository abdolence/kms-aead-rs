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
use tracing::*;

use crate::ring_encryption::RingAeadEncryption;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

/// A Key Vault or Managed HSM key that wraps data encryption keys.
///
/// Without `key_version` the latest version wraps new keys. Each encrypted key records the
/// version that wrapped it, and unwrapping uses that recorded version, so keys wrapped before a
/// rotation still unwrap afterwards.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AzureKmsKeyRef {
    /// Vault URL, such as `https://my-vault.vault.azure.net`.
    pub vault_url: String,
    pub key_name: String,
    pub key_version: Option<KmsKeyVersion>,
}

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

/// Wraps and unwraps data encryption keys with an Azure Key Vault key.
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
}

impl AzureKmsProvider {
    /// Uses the key at `kms_key_ref` with any Azure credential, for example one from
    /// `azure_identity`. No request is made until the first key is wrapped or unwrapped.
    pub fn new(
        kms_key_ref: &AzureKmsKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, AzureKmsProviderOptions::new(), credential)
    }

    /// Fails with a system error when the vault URL is not an HTTP(S) URL, when the key name
    /// holds characters Key Vault does not allow in it, or when the algorithm is `Rsa1_5` or
    /// unknown.
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

        debug!(
            "Initialising Azure Key Vault envelope encryption for {}/keys/{}",
            kms_key_ref.vault_url, kms_key_ref.key_name
        );

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
        })
    }

    fn key_operation(
        &self,
        value: Vec<u8>,
    ) -> KmsAeadResult<RequestContent<KeyOperationParameters>> {
        Ok(RequestContent::try_from(KeyOperationParameters {
            algorithm: Some(self.options.algorithm.clone()),
            value: Some(value),
            ..Default::default()
        })?)
    }
}

fn is_key_vault_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[async_trait]
impl KmsAeadRingEncryptionProvider for AzureKmsProvider {
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let parameters =
            self.key_operation(encryption_key.value().ref_sensitive_value().clone())?;
        let wrapped = self
            .client
            .wrap_key(
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
            )
            .await?
            .into_model()?;

        let key_version = wrapped.resource_id()?.version.ok_or_else(|| {
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
        Ok(EncryptedDataEncryptionKey::new(
            wrapped_bytes,
            Some(KmsKeyVersion::try_from(key_version)?),
        ))
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let key_version = encrypted_key.key_version().ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "AZURE_KEY_VERSION_MISSING",
                "The encrypted data encryption key records no Azure Key Vault key version",
            )
        })?;

        let parameters = self.key_operation(encrypted_key.wrapped().to_vec())?;
        let unwrapped = self
            .client
            .unwrap_key(
                &self.azure_key_ref.key_name,
                key_version.as_str(),
                parameters,
                None,
            )
            .await?
            .into_model()?;

        let key = unwrapped.result.ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "AZURE_UNWRAPPED_KEY",
                "Azure Key Vault returned no unwrapped key",
            )
        })?;
        Ok(DataEncryptionKey::from(SecretValue::new(key)))
    }

    async fn generate_encryption_key(
        &self,
        aead_encryption: &RingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey> {
        aead_encryption.generate_data_encryption_key()
    }
}
