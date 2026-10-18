//! kms-aead against Tink's `KmsEnvelopeAead` on a Cloud KMS key and an AWS KMS key. `encrypt`
//! writes one value per KMS and algorithm for `python -I tests/tink_interop.py decrypt`, and
//! `decrypt` reads what `python -I tests/tink_interop.py encrypt` writes. The script lists the
//! commands and the variables that name the keys.

use std::io::BufRead;

use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider, GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{
    AeadAlgorithm, AwsLc, CipherTextWithEncryptedKey, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadEnvelopeOptions, KmsAeadResult, ValueStruct,
};
use secret_vault_value::SecretValue;
use serde_json::{json, Value};

const ALGORITHMS: [AeadAlgorithm; 4] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
    AeadAlgorithm::ChaCha20Poly1305,
];

#[tokio::main]
async fn main() -> KmsAeadResult<()> {
    let variable = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"));
    let gcp_key = GcpKmsKeyRef::new(
        variable("PROJECT_ID"),
        variable("PROJECT_LOCATION"),
        variable("KMS_KEY_RING"),
        variable("KMS_KEY"),
    );
    let aws_key = AwsKmsKeyRef::new(variable("ACCOUNT_ID"), variable("KMS_KEY_ID"));

    match std::env::args().nth(1).as_deref() {
        Some("encrypt") => {
            for algorithm in ALGORITHMS {
                encrypt("gcp", GcpKmsProvider::new(&gcp_key).await?, algorithm).await?;
                encrypt("aws", AwsKmsProvider::new(&aws_key).await?, algorithm).await?;
            }
        }
        Some("decrypt") => {
            let mut failures = 0;
            for line in std::io::stdin().lock().lines() {
                let case: Value = serde_json::from_str(&line.expect("stdin is readable"))
                    .expect("each line is a JSON object");
                let field = |name: &str| case[name].as_str().expect("the field is a string");
                let algorithm: AeadAlgorithm = field("algorithm").parse()?;
                let aad = hex::decode(field("aad")).expect("aad is hex");
                let value = CipherTextWithEncryptedKey::from(
                    hex::decode(field("value")).expect("value is hex"),
                );
                let decrypted = match field("kms") {
                    "gcp" => {
                        decrypt(
                            GcpKmsProvider::new(&gcp_key).await?,
                            algorithm,
                            &aad,
                            &value,
                        )
                        .await?
                    }
                    _ => {
                        decrypt(
                            AwsKmsProvider::new(&aws_key).await?,
                            algorithm,
                            &aad,
                            &value,
                        )
                        .await?
                    }
                };
                let expected = hex::decode(field("plain_text")).expect("plain_text is hex");
                if *decrypted.ref_sensitive_value() == expected {
                    println!("{} {algorithm}: ok", field("kms"));
                } else {
                    println!("{} {algorithm}: another plain text", field("kms"));
                    failures += 1;
                }
            }
            std::process::exit(if failures == 0 { 0 } else { 1 });
        }
        _ => eprintln!("usage: tink_interop encrypt|decrypt"),
    }
    Ok(())
}

async fn encrypt<P>(kms: &str, provider: P, algorithm: AeadAlgorithm) -> KmsAeadResult<()>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    let envelope = KmsAeadEnvelope::<P, AwsLc>::with_options(
        provider,
        KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
    )?;
    let aad = format!("orders/{kms}/{algorithm}");
    let plain_text = format!("sealed by kms-aead {}", env!("CARGO_PKG_VERSION"));
    let value = envelope
        .encrypt_value(aad.as_bytes(), &SecretValue::from(plain_text.as_str()))
        .await?;
    println!(
        "{}",
        json!({
            "kms": kms,
            "algorithm": algorithm.to_string(),
            "aad": hex::encode(aad),
            "plain_text": hex::encode(plain_text),
            "value": hex::encode(value.value()),
        })
    );
    Ok(())
}

async fn decrypt<P>(
    provider: P,
    algorithm: AeadAlgorithm,
    aad: &[u8],
    value: &CipherTextWithEncryptedKey,
) -> KmsAeadResult<SecretValue>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    KmsAeadEnvelope::<P, AwsLc>::with_options(
        provider,
        KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
    )?
    .decrypt_value(aad, value)
    .await
}
