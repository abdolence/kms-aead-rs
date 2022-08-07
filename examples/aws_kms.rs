use kms_aead::providers::{AwsKmsProvider, AwsKmsProviderOptions};
use kms_aead::*;
use secret_vault_value::SecretValue;

pub fn config_env_var(name: &str) -> Result<String, String> {
    std::env::var(name).map_err(|e| format!("{}: {}", name, e))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("kms_aead=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let aws_account_id = config_env_var("ACCOUNT_ID")?;
    let aws_key_id: String = config_env_var("KMS_KEY_ID")?;

    let kms_ref = kms_aead::providers::AwsKmsKeyRef::new(aws_account_id, aws_key_id);

    let encryption: KmsAeadRingEnvelopeEncryption<AwsKmsProvider> =
        kms_aead::KmsAeadRingEnvelopeEncryption::new(
            providers::AwsKmsProvider::with_options(
                &kms_ref,
                AwsKmsProviderOptions::new().with_use_kms_random_gen(true),
            )
            .await?,
        )
        .await?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = "test-aad".to_string();

    let (encrypted_value, session_key) = encryption
        .encrypt_value_with_current_key(&test_aad, &secret_value)
        .await?;

    println!(
        "Encrypted to {:?} with session key: {:?}",
        encrypted_value,
        session_key.to_hex_string()
    );

    let (secret_value, _) = encryption
        .decrypt_value_with_current_key(&test_aad, &encrypted_value)
        .await?;

    println!(
        "We have our secret back: {}",
        secret_value.sensitive_value_to_str().unwrap() == "test-secret"
    );

    Ok(())
}
