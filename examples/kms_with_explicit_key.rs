use kms_aead::providers::AwsKmsProvider;
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

    // Building the vault
    let encryption: KmsAeadRingEncryption<AwsKmsProvider> =
        kms_aead::KmsAeadRingEncryption::new(providers::AwsKmsProvider::new(&kms_ref).await?)
            .await?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = "test-aad".to_string();

    let (encrypted_value, session_key) = encryption
        .encrypt_value_with_new_session_key(&test_aad, &secret_value)
        .await?;

    println!(
        "Encrypted to {:?} with session key: {:?}",
        encrypted_value,
        session_key.to_hex_string()
    );

    let secret_value = encryption
        .decrypt_value_with_session_key(&test_aad, &encrypted_value, &session_key)
        .await?;

    println!(
        "We have our secret back: {}",
        secret_value.sensitive_value_to_str().unwrap() == "test-secret"
    );

    Ok(())
}
