//! Prints the spans kms-aead opens, with their fields, for an encryption and a decryption on the
//! local KMS. It needs no KMS and no credentials.
//!
//! Run with `cargo run --example tracing --features ring`.

use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;
use tracing_subscriber::fmt::format::FmtSpan;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // The crate records each call's mode, algorithm, backend and KMS key as fields of its spans
    // at debug level; closing a span prints them, with the KMS call nested in the envelope call.
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter("kms_aead=debug")
        .with_span_events(FmtSpan::CLOSE)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // An ephemeral KEK lives as long as the process, so nothing it encrypts outlives this run.
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
    let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

    let aad = b"orders/1042";
    let secret = SecretValue::from("4111 1111 1111 1111");
    let encrypted: Encrypted<SecretValue, Envelope> = envelope.encrypt(aad, &secret).await?;
    let decrypted: SecretValue = envelope.decrypt(aad, &encrypted).await?;
    assert_eq!(decrypted, secret);
    Ok(())
}
