use kms_aead::providers::{HcVaultTransitKeyRef, HcVaultTransitProvider};
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

    // VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE and VAULT_CACERT are read by the provider
    let key_ref = HcVaultTransitKeyRef::new(config_env_var("VAULT_TRANSIT_KEY")?);

    let encryption =
        KmsAeadEnvelope::new(HcVaultTransitProvider::new(&key_ref)?, AeadBackend::Ring).await?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = "test-aad".to_string();

    let cipher_text = encryption.encrypt_value(&test_aad, &secret_value).await?;

    println!("Encrypted to {:?}", cipher_text.to_hex_string());

    let secret_value = encryption.decrypt_value(&test_aad, &cipher_text).await?;

    println!(
        "We have our secret back: {}",
        secret_value.sensitive_value_to_str().unwrap() == "test-secret"
    );

    Ok(())
}
