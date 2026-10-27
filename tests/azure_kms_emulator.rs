//! Tests against the Lowkey Vault Key Vault emulator. They are ignored by default; to run them:
//!
//! ```sh
//! docker run --rm -d --name lowkey-vault -p 8443:8443 docker.io/nagyesta/lowkey-vault:7.3.112
//! AZURE_KEY_VAULT_EMULATOR_URL=https://localhost:8443 \
//!   cargo test --features azure-kms-encryption,aws-lc --test azure_kms_emulator -- --ignored
//! ```

use azure_core::http::{ClientOptions, RequestContent, RetryOptions, Transport};
use azure_security_keyvault_keys::models::{
    CreateKeyParameters, CurveName, EncryptionAlgorithm, KeyAttributes,
    KeyClientUpdateKeyPropertiesOptions, KeyOperation, KeyOperationParameters, KeyType,
    UpdateKeyPropertiesParameters,
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::Envelope;
use kms_aead::providers::{
    AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions, AzureKmsSigningKeyRef,
    AzureKmsSigningProvider, KmsKeyVersion,
};
use kms_aead::signing::{Signer, Verifier, VerifyingKeySet};
use kms_aead::*;
use secret_vault_value::SecretValue;
use std::error::Error;
use std::sync::Arc;

mod common;
#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
use common::RsaBackend;
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
    /// as the authentication challenge resource. It answers some refusals with a 500, which the
    /// SDK would retry for over a minute.
    fn client_options() -> TestResult<KeyClientOptions> {
        common::install_crypto_provider();
        let http_client = reqwest::Client::builder()
            .tls_danger_accept_invalid_certs(true)
            .build()?;
        Ok(KeyClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(Arc::new(http_client))),
                retry: RetryOptions::none(),
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
            // Lowkey Vault checks the encrypt and decrypt operations on wrapKey and unwrapKey.
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

    /// Creates a new EC P-256 version of `key_name` that signs, creating the key if it does not
    /// exist, and returns that version.
    async fn create_ec_key_version(&self, key_name: &str) -> TestResult<KmsKeyVersion> {
        let parameters = CreateKeyParameters {
            kty: Some(KeyType::Ec),
            curve: Some(CurveName::P256),
            key_ops: Some(vec![KeyOperation::Sign, KeyOperation::Verify]),
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

    fn signing_provider(
        &self,
        key_name: &str,
        version: KmsKeyVersion,
    ) -> TestResult<AzureKmsSigningProvider> {
        Ok(AzureKmsSigningProvider::with_client_options(
            &AzureKmsSigningKeyRef::new(self.vault_url.clone(), key_name.to_string(), version),
            Some(Self::client_options()?),
            Arc::new(FixedTokenCredential),
        )?)
    }

    fn provider(&self, key_ref: &AzureKmsKeyRef) -> TestResult<AzureKmsProvider> {
        Ok(AzureKmsProvider::with_options(
            key_ref,
            AzureKmsProviderOptions::new().with_client_options(Self::client_options()?),
            Arc::new(FixedTokenCredential),
        )?)
    }

    /// Lowkey Vault encrypts only with an explicit key version.
    async fn encryption(
        &self,
        key_name: &str,
        kek_version: KmsKeyVersion,
    ) -> TestResult<KmsAeadEnvelope<AzureKmsProvider, Backend>> {
        let key_ref = AzureKmsKeyRef::new(self.vault_url.clone(), key_name.to_string())
            .with_kek_version(kek_version);
        let provider = self.provider(&key_ref)?;
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
    let key_name = unique_name("dek-encrypting-key")?;
    let first_version = emulator.create_rsa_key_version(&key_name).await?;
    let aad = b"test-aad";

    let cipher_text: Encrypted<SecretValue, Envelope> = emulator
        .encryption(&key_name, first_version.clone())
        .await?
        .encrypt(aad, &SecretValue::from("test-secret"))
        .await?;
    let (_, encrypted_dek) = cipher_text.separate()?;
    let kek_version = first_version.as_str().as_bytes();
    assert_eq!(
        encrypted_dek.value()[2..2 + kek_version.len()],
        *kek_version
    );

    let rotated_version = emulator.create_rsa_key_version(&key_name).await?;
    let decrypted: SecretValue = emulator
        .encryption(&key_name, rotated_version)
        .await?
        .decrypt(aad, &cipher_text)
        .await?;

    assert_eq!(decrypted.as_sensitive_str(), "test-secret");
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn encrypt_reports_the_key_version_that_encrypted() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-encrypting-key")?;
    let first_version = emulator.create_rsa_key_version(&key_name).await?;
    let rotated_version = emulator.create_rsa_key_version(&key_name).await?;

    for kek_version in [first_version, rotated_version] {
        let encryption = emulator.encryption(&key_name, kek_version.clone()).await?;

        let (_, encrypted_dek) = encryption.generate_encrypted_dek().await?;

        assert_eq!(encrypted_dek.kek_version(), Some(&kek_version));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn a_reencrypted_value_decrypts_with_the_old_key_version_disabled() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-encrypting-key")?;
    let first_version = emulator.create_rsa_key_version(&key_name).await?;
    let aad = b"test-aad";
    let value: Encrypted<SecretValue, Envelope> = emulator
        .encryption(&key_name, first_version.clone())
        .await?
        .encrypt(aad, &SecretValue::from("test-secret"))
        .await?;
    let rotated_version = emulator.create_rsa_key_version(&key_name).await?;
    let rotated = emulator.encryption(&key_name, rotated_version).await?;

    let reencrypted = rotated.reencrypt_dek(&value).await?;

    let disabled = UpdateKeyPropertiesParameters {
        key_attributes: Some(KeyAttributes {
            enabled: Some(false),
            ..Default::default()
        }),
        ..Default::default()
    };
    emulator
        .client
        .update_key_properties(
            &key_name,
            RequestContent::try_from(disabled)?,
            Some(KeyClientUpdateKeyPropertiesOptions {
                key_version: Some(first_version.to_string()),
                ..Default::default()
            }),
        )
        .await?;
    let decrypted: SecretValue = rotated.decrypt(aad, &reencrypted).await?;
    assert_eq!(decrypted.as_sensitive_str(), "test-secret");
    // Key Vault refuses a disabled version with 403 Forbidden, and Lowkey Vault with a 500.
    let before_reencryption: KmsAeadResult<SecretValue> = rotated.decrypt(aad, &value).await;
    assert!(before_reencryption.is_err(), "{before_reencryption:?}");
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn value_encrypted_with_another_key_fails_to_decrypt() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-encrypting-key")?;
    let other_key_name = unique_name("other-key")?;
    let kek_version = emulator.create_rsa_key_version(&key_name).await?;
    let other_key_version = emulator.create_rsa_key_version(&other_key_name).await?;
    let aad = b"test-aad";

    let cipher_text: Encrypted<SecretValue, Envelope> = emulator
        .encryption(&other_key_name, other_key_version)
        .await?
        .encrypt(aad, &SecretValue::from("test-secret"))
        .await?;
    let result = emulator
        .encryption(&key_name, kek_version)
        .await?
        .decrypt(aad, &cipher_text)
        .await;

    assert!(matches!(result, Err(KmsAeadError::EncryptionError(_))));
    Ok(())
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn key_vault_encrypts_the_raw_dek_and_the_value_round_trips() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-encrypting-key")?;
    let kek_version = emulator.create_rsa_key_version(&key_name).await?;
    let encryption = emulator.encryption(&key_name, kek_version.clone()).await?;
    let aad = b"test-aad";

    let (dek, encrypted_dek) = encryption.generate_encrypted_dek().await?;
    let bare = encryption.encrypt_with_dek(aad, &SecretValue::from("test-secret"), &dek)?;
    let decrypted: SecretValue = encryption
        .decrypt(aad, &Encrypted::join(&bare, &encrypted_dek)?)
        .await?;
    // The provider's bytes are `[0x01][k: u8][key version: k][Key Vault encrypted DEK]`.
    let wrapped = &encrypted_dek.value()[2 + kek_version.as_str().len()..];
    let parameters = KeyOperationParameters {
        algorithm: Some(EncryptionAlgorithm::RsaOaep256),
        value: Some(wrapped.to_vec()),
        ..Default::default()
    };
    let unwrapped = emulator
        .client
        .unwrap_key(
            &key_name,
            kek_version.as_str(),
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

#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn key_vault_unwraps_what_its_public_key_wraps() -> TestResult<()> {
    use kms_aead::providers::PublicKeyKekProvider;
    let emulator = Emulator::connect()?;
    let key_name = unique_name("dek-encrypting-key")?;
    let kek_version = emulator.create_rsa_key_version(&key_name).await?;
    let provider = emulator.provider(&AzureKmsKeyRef::new(
        emulator.vault_url.clone(),
        key_name.clone(),
    ))?;
    let aad = b"test-aad";

    let public_key = provider.public_key(None).await?;
    let producer = KmsAeadEnvelope::<_, RsaBackend>::new(PublicKeyKekProvider::<RsaBackend>::new(
        public_key.clone(),
    )?)?;
    let encrypted: Encrypted<SecretValue, Envelope> = producer
        .encrypt(aad, &SecretValue::from("test-secret"))
        .await?;
    let reader = KmsAeadEnvelope::<_, RsaBackend>::new(provider)?;
    let decrypted: SecretValue = reader.decrypt(aad, &encrypted).await?;

    assert_eq!(public_key.kek(), reader.provider().kek());
    assert_eq!(public_key.kek_version(), Some(&kek_version));
    assert_eq!(decrypted.as_sensitive_str(), "test-secret");
    Ok(())
}

struct Invoice(Vec<u8>);

impl SignableType for Invoice {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.invoice+json");
}

impl Signable for Invoice {
    fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
        Ok(self.0.clone())
    }

    fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
        Ok(Invoice(payload))
    }
}

#[tokio::test]
#[ignore = "needs the Lowkey Vault emulator, see the module docs"]
async fn each_key_version_signs_values_that_verify_with_its_own_public_key() -> TestResult<()> {
    let emulator = Emulator::connect()?;
    let key_name = unique_name("signing-key")?;
    let first_version = emulator.create_ec_key_version(&key_name).await?;
    let second_version = emulator.create_ec_key_version(&key_name).await?;
    let first =
        Signer::<_, Backend>::new(emulator.signing_provider(&key_name, first_version)?).await?;
    let second =
        Signer::<_, Backend>::new(emulator.signing_provider(&key_name, second_version)?).await?;
    let verifier = Verifier::<Backend>::new(VerifyingKeySet::new([
        first.verifying_key().clone(),
        second.verifying_key().clone(),
    ])?)?;
    let invoice = Invoice(br#"{"number":"INV-1042","total_cents":12500}"#.to_vec());

    for signer in [&first, &second] {
        let signature = signer.sign(&invoice).await?;

        assert_eq!(
            verifier.verify(&invoice, &signature)?,
            signer.verifying_key()
        );
    }
    assert_ne!(first.verifying_key(), second.verifying_key());
    Ok(())
}
