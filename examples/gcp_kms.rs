use kms_aead::providers::GcpKmsProviderOptions;
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

    let google_project_id = config_env_var("PROJECT_ID")?;
    let google_project_location = config_env_var("PROJECT_LOCATION")?;
    let google_kms_key_ring = config_env_var("KMS_KEY_RING")?;
    let google_kms_key = config_env_var("KMS_KEY")?;

    let kms_ref = kms_aead::providers::GcpKmsKeyRef::new(
        google_project_id,
        google_project_location,
        google_kms_key_ring,
        google_kms_key,
    );

    let encryption = kms_aead::KmsAeadRingEncryption::new(
        kms_aead::providers::GcpKmsProvider::new(&kms_ref).await?,
    )
    .await?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = "test-aad".to_string();

    let (encrypted_value, session_key) = encryption.encrypt_value(&test_aad, &secret_value).await?;

    println!(
        "Encrypted to {:?} with session key: {:?}",
        encrypted_value,
        session_key.to_hex_string()
    );

    let (secret_value, _) = encryption
        .decrypt_value(&test_aad, &encrypted_value)
        .await?;

    println!(
        "We have our secret back: {}",
        secret_value.sensitive_value_to_str().unwrap() == "test-secret"
    );

    Ok(())
}
