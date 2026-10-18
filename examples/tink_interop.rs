//! kms-aead's typed fields against Tink's `KmsEnvelopeAead` on a Cloud KMS key and an AWS KMS
//! key. `encrypt` writes one `Encrypted<String, Envelope>` per KMS and algorithm for
//! `python -I tests/tink_interop.py decrypt`, and `decrypt` reads what
//! `python -I tests/tink_interop.py encrypt` writes. The script lists the commands and the
//! variables that name the keys; a KMS whose variables are not set is skipped.

use std::io::BufRead;

use kms_aead::formats::Envelope;
use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider, GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{
    AeadAlgorithm, AwsLc, Encrypted, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadEnvelopeOptions, KmsAeadResult, ValueStruct,
};
use serde_json::{json, Value};

const ALGORITHMS: [AeadAlgorithm; 4] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
    AeadAlgorithm::ChaCha20Poly1305,
];

#[tokio::main]
async fn main() -> KmsAeadResult<()> {
    let variable = |name: &str| std::env::var(name).ok();
    let required = |name: &str| variable(name).unwrap_or_else(|| panic!("{name} is not set"));
    let gcp_key = variable("PROJECT_ID").map(|project_id| {
        GcpKmsKeyRef::new(
            project_id,
            required("PROJECT_LOCATION"),
            required("KMS_KEY_RING"),
            required("KMS_KEY"),
        )
    });
    let aws_key =
        variable("KMS_KEY_ID").map(|key_id| AwsKmsKeyRef::new(required("ACCOUNT_ID"), key_id));

    match std::env::args().nth(1).as_deref() {
        Some("encrypt") => {
            for algorithm in ALGORITHMS {
                if let Some(gcp_key) = &gcp_key {
                    encrypt("gcp", GcpKmsProvider::new(gcp_key).await?, algorithm).await?;
                }
                if let Some(aws_key) = &aws_key {
                    encrypt("aws", AwsKmsProvider::new(aws_key).await?, algorithm).await?;
                }
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
                let value = Encrypted::<String, Envelope>::try_from(
                    hex::decode(field("value")).expect("value is hex"),
                )?;
                let decrypted = match (field("kms"), &gcp_key, &aws_key) {
                    ("gcp", Some(gcp_key), _) => {
                        let provider = GcpKmsProvider::new(gcp_key).await?;
                        decrypt(provider, algorithm, &aad, &value).await?
                    }
                    ("aws", _, Some(aws_key)) => {
                        let provider = AwsKmsProvider::new(aws_key).await?;
                        decrypt(provider, algorithm, &aad, &value).await?
                    }
                    (kms, _, _) => {
                        println!("{kms} {algorithm}: skipped, its key is not configured");
                        continue;
                    }
                };
                let expected = hex::decode(field("plain_text")).expect("plain_text is hex");
                if decrypted.as_bytes() == expected {
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
    let value: Encrypted<String, Envelope> =
        envelope.encrypt_field(aad.as_bytes(), &plain_text).await?;
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
    value: &Encrypted<String, Envelope>,
) -> KmsAeadResult<String>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    KmsAeadEnvelope::<P, AwsLc>::with_options(
        provider,
        KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
    )?
    .decrypt_field(aad, value)
    .await
}
