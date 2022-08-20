use kms_aead::ring_encryption::RingAeadEncryption;
use kms_aead::*;
use secret_vault_value::SecretValue;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("kms_aead=debug")
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    let encryption: RingAeadEncryption = RingAeadEncryption::new()?;
    let key = encryption.generate_data_encryption_key()?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = "test-aad".to_string();

    let cipher_text = encryption
        .encrypt_value(&test_aad, &secret_value, &key)
        .await?;

    println!("Encrypted to {:?}", cipher_text.to_hex_string());

    let secret_value = encryption
        .decrypt_value(&test_aad, &cipher_text, &key)
        .await?;

    println!(
        "We have our secret back: {}",
        secret_value.sensitive_value_to_str().unwrap() == "test-secret"
    );

    Ok(())
}
