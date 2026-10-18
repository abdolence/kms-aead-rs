use kms_aead::backends::AwsLc;
use kms_aead::formats::Envelope;
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
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

    let kms_ref = AzureKmsKeyRef::new(config_env_var("VAULT_URL")?, config_env_var("KEY_NAME")?);

    // Azure CLI or Azure Developer CLI credentials for local runs;
    // use `azure_identity::ManagedIdentityCredential` in Azure deployments
    let credential = azure_identity::DeveloperToolsCredential::new(None)?;

    let envelope = KmsAeadEnvelope::<AzureKmsProvider, AwsLc>::new(AzureKmsProvider::new(
        &kms_ref, credential,
    )?)?;

    let secret_value = SecretValue::from("test-secret");
    let test_aad = b"test-aad";

    let cipher_text: Encrypted<SecretValue, Envelope> =
        envelope.encrypt(test_aad, &secret_value).await?;

    println!("Encrypted to {}", cipher_text.to_hex_string());

    let decrypted: SecretValue = envelope.decrypt(test_aad, &cipher_text).await?;
    assert_eq!(decrypted, secret_value);

    println!("Decrypted to the original value");

    Ok(())
}
