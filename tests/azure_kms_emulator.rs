//! Tests against the Lowkey Vault Key Vault emulator. They are ignored by default; to run them:
//!
//! ```sh
//! docker run --rm -d --name lowkey-vault -p 8443:8443 docker.io/nagyesta/lowkey-vault:7.3.112
//! AZURE_KEY_VAULT_EMULATOR_URL=https://localhost:8443 \
//!   cargo test --features azure-kms-encryption --test azure_kms_emulator -- --ignored
//! ```

use azure_core::http::{ClientOptions, RequestContent, Transport};
use azure_security_keyvault_keys::models::{
    CreateKeyParameters, EncryptionAlgorithm, KeyOperation, KeyOperationParameters, KeyType,
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use kms_aead::errors::KmsAeadError;
use kms_aead::providers::{
    AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions, KmsKeyVersion,
};
use kms_aead::*;
use secret_vault_value::SecretValue;
use std::error::Error;
use std::sync::Arc;

mod common;
use common::{Backend, FixedTokenCredential};

const EMULATOR_URL_ENV: &str = "AZURE_KEY_VAULT_EMULATOR_URL";

type TestResult<T> = Result<T, Box<dyn Error>>;

struct Emulator {
    vault_url: String,
    client: KeyClient,
}

impl Emulator {
    fn connect() -> TestResult<Self> {
        let vault_url = std::env::var(EMULATOR_URL_ENV)
            .map_err(|_| format!("{EMULATOR_URL_ENV} must point at a Lowkey Vault"))?;
        let client = KeyClient::new(
            &vault_url,
            Arc::new(FixedTokenCredential),
            Some(Self::client_options()?),
        )?;
        Ok(Self { vault_url, client })
    }

    /// The emulator serves a self-signed certificate and names itself, not a Key Vault domain,
    /// as the authentication challenge resource.
    fn client_options() -> TestResult<KeyClientOptions> {
        common::install_crypto_provider();
        let http_client = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()?;
        Ok(KeyClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(Arc::new(http_client))),
                ..Default::default()
            },
            verify_challenge_resource: Some(false),
            ..Default::default()
        })
    }

    /// Creates a new RSA version of `key_name`, creating the key if it does not exist, and
    /// returns that version.
    async fn create_rsa_key_version(&self, key_name: &str) -> TestResult<KmsKeyVersion> {
        let parameters = CreateKeyParameters {
            kty: Some(KeyType::Rsa),
            key_size: Some(2048),
            // Lowkey Vault checks the encrypt and decrypt operations on wrap and unwrap.
            key_ops: Some(vec![
                KeyOperation::WrapKey,
                KeyOperation::UnwrapKey,
                KeyOperation::Encrypt,
                KeyOperation::Decrypt,
            ]),
            ..Default::default()
        };
        let key = self
            .client
            .create_key(key_name, RequestContent::try_from(parameters)?, None)
            .await?
            .into_model()?;
        let version = key
            .resource_id()?
            .version
            .ok_or("Lowkey Vault returned a key id without a version")?;
        Ok(KmsKeyVersion::try_from(version)?)
    }

    /// Lowkey Vault wraps only with an explicit key version.
    async fn encryption(
        &self,
        key_name: &str,
        key_version: KmsKeyVersion,
    ) -> TestResult<KmsAeadEnvelope<AzureKmsProvider, Backend>> {
        let key_ref = AzureKmsKeyRef::new(self.vault_url.clone(), key_name.to_string())
            .with_key_version(key_version);
        let provider = AzureKmsProvider::with_options(
            &key_ref,
            AzureKmsProviderOptions::new().with_client_options(Self::client_options()?),
            Arc::new(FixedTokenCredential),
        )?;
        Ok(KmsAeadEnvelope::new(provider)?)
    }
}

/// Emulator state outlives a test run, so every run uses fresh key names.
fn unique_name(prefix: &str) -> TestResult<String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    Ok(format!("{prefix}-{nanos}"))
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn value_encrypted_before_key_rotation_decrypts_after_it() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-wrapping-key")?;
    let first_version = emulator.create_rsa_key_version(&key_name).await?;
    let aad = b"test-aad";

    let cipher_text = emulator
        .encryption(&key_name, first_version.clone())
        .await?
        .encrypt_value(aad, &SecretValue::from("test-secret"))
        .await?;
    let (_, encrypted_key) = cipher_text.separate()?;
    let key_version = first_version.as_str().as_bytes();
    assert_eq!(
        encrypted_key.value()[2..2 + key_version.len()],
        *key_version
    );

    let rotated_version = emulator.create_rsa_key_version(&key_name).await?;
    let decrypted = emulator
        .encryption(&key_name, rotated_version)
        .await?
        .decrypt_value(aad, &cipher_text)
        .await?;

    assert_eq!(decrypted.as_sensitive_str(), "test-secret");
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn value_encrypted_with_another_key_fails_to_decrypt() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-wrapping-key")?;
    let other_key_name = unique_name("other-key")?;
    let key_version = emulator.create_rsa_key_version(&key_name).await?;
    let other_key_version = emulator.create_rsa_key_version(&other_key_name).await?;
    let aad = b"test-aad";

    let cipher_text = emulator
        .encryption(&other_key_name, other_key_version)
        .await?
        .encrypt_value(aad, &SecretValue::from("test-secret"))
        .await?;
    let result = emulator
        .encryption(&key_name, key_version)
        .await?
        .decrypt_value(aad, &cipher_text)
        .await;

    assert!(matches!(result, Err(KmsAeadError::EncryptionError(_))));
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn key_vault_wraps_the_raw_dek_and_the_value_round_trips() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-wrapping-key")?;
    let key_version = emulator.create_rsa_key_version(&key_name).await?;
    let encryption = emulator.encryption(&key_name, key_version.clone()).await?;
    let aad = b"test-aad";

    let (dek, encrypted_dek) = encryption.generate_new_dek().await?;
    let cipher_text =
        encryption.encrypt_value_with_dek(aad, &SecretValue::from("test-secret"), &dek)?;
    let decrypted = encryption
        .decrypt_value(
            aad,
            &CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?,
        )
        .await?;
    // The provider's bytes are `[0x01][k: u8][key version: k][Key Vault wrapped key]`.
    let wrapped = &encrypted_dek.value()[2 + key_version.as_str().len()..];
    let parameters = KeyOperationParameters {
        algorithm: Some(EncryptionAlgorithm::RsaOaep256),
        value: Some(wrapped.to_vec()),
        ..Default::default()
    };
    let unwrapped = emulator
        .client
        .unwrap_key(
            &key_name,
            key_version.as_str(),
            RequestContent::try_from(parameters)?,
            None,
        )
        .await?
        .into_model()?
        .result;

    assert_eq!(
        unwrapped.as_deref(),
        Some(dek.value().ref_sensitive_value().as_slice())
    );
    assert_eq!(decrypted.as_sensitive_str(), "test-secret");
    Ok(())
}
