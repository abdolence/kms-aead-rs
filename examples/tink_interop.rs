//! kms-aead's typed fields against Tink on a Cloud KMS key and an AWS KMS key, both ways:
//!
//! - `encrypt` writes one `Encrypted<Message, Envelope>` per KMS and algorithm, which
//!   `python -I tests/tink_interop.py decrypt` opens with Tink's `KmsEnvelopeAead`;
//! - `export` writes a keyset of one new key per KMS and algorithm, encrypted by the KMS key, and
//!   an `Encrypted<Message, Randomized>` of the key, which
//!   `python -I tests/tink_interop.py read-keysets` opens with the keyset;
//! - `decrypt` reads what `python -I tests/tink_interop.py encrypt` and `read-keysets` write.
//!
//! The script lists the commands and the variables that name the keys; a KMS whose variables are
//! not set is skipped.

use std::io::BufRead;

use kms_aead::cache::DekCache;
use kms_aead::formats::{Envelope, Randomized, TinkKeyType, TinkKeyset};
use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider, GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{
    AeadAlgorithm, AeadCipher, AwsLc, Encrypted, EncryptedDataEncryptionKey, KeyId,
    KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadEnvelopeOptions, KmsAeadResult, Plaintext,
    ValueStruct,
};
use secret_vault_value::SecretValue;
use serde_json::{json, Value};

/// The text each side seals for the other, an application newtype stored as the UTF-8 bytes of
/// its string, as Tink's side writes and reads it.
struct Message(String);

impl Plaintext for Message {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Message)
    }
}

const ALGORITHMS: [AeadAlgorithm; 4] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
    AeadAlgorithm::ChaCha20Poly1305,
];

/// The id of the one key of every exported keyset.
const EXPORTED_KEY_ID: KeyId = KeyId::new(1042);

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
        Some("export") => {
            for algorithm in ALGORITHMS {
                if let Some(gcp_key) = &gcp_key {
                    export("gcp", GcpKmsProvider::new(gcp_key).await?, algorithm).await?;
                }
                if let Some(aws_key) = &aws_key {
                    export("aws", AwsKmsProvider::new(aws_key).await?, algorithm).await?;
                }
            }
        }
        Some("decrypt") => {
            let mut failures = 0;
            for line in std::io::stdin().lock().lines() {
                let case: Value = serde_json::from_str(&line.expect("stdin is readable"))
                    .expect("each line is a JSON object");
                let kms = case["kms"].as_str().expect("kms is a string");
                let algorithm = case["algorithm"].as_str().expect("algorithm is a string");
                let decrypted = match (kms, &gcp_key, &aws_key) {
                    ("gcp", Some(gcp_key), _) => {
                        decrypt(GcpKmsProvider::new(gcp_key).await?, &case).await?
                    }
                    ("aws", _, Some(aws_key)) => {
                        decrypt(AwsKmsProvider::new(aws_key).await?, &case).await?
                    }
                    _ => {
                        println!("{kms} {algorithm}: skipped, its key is not configured");
                        continue;
                    }
                };
                let expected = hex_field(&case, "plain_text");
                if decrypted.0.as_bytes() == expected {
                    println!("{kms} {algorithm}: ok");
                } else {
                    println!("{kms} {algorithm}: another plain text");
                    failures += 1;
                }
            }
            std::process::exit(if failures == 0 { 0 } else { 1 });
        }
        _ => eprintln!("usage: tink_interop encrypt|export|decrypt"),
    }
    Ok(())
}

fn hex_field(case: &Value, name: &str) -> Vec<u8> {
    let field = case[name].as_str().expect("the field is a string");
    hex::decode(field).expect("the field is hex")
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
    let message = Message(format!("sealed by kms-aead {}", env!("CARGO_PKG_VERSION")));
    let value: Encrypted<Message, Envelope> =
        envelope.encrypt_field(aad.as_bytes(), &message).await?;
    println!(
        "{}",
        json!({
            "kms": kms,
            "algorithm": algorithm.to_string(),
            "aad": hex::encode(aad),
            "plain_text": hex::encode(&message.0),
            "value": hex::encode(value.value()),
        })
    );
    Ok(())
}

/// A keyset of a new key, encrypted by `provider` for Tink, with a value of the key and the key
/// encrypted by `provider`, from which `decrypt` opens the value Tink seals with the keyset.
async fn export<P>(kms: &str, provider: P, algorithm: AeadAlgorithm) -> KmsAeadResult<()>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    let cipher = AeadCipher::<AwsLc>::new(algorithm)?;
    let (key, encrypted_dek) = cipher.generate_dek(&provider).await?;
    let mut keyset = TinkKeyset::new(EXPORTED_KEY_ID);
    keyset.add_key(EXPORTED_KEY_ID, TinkKeyType::from(algorithm), &key)?;
    let aad = format!("orders/{kms}/{algorithm}");
    let message = Message(format!("sealed by kms-aead {}", env!("CARGO_PKG_VERSION")));
    let value = cipher.encrypt_field(EXPORTED_KEY_ID, aad.as_bytes(), &message, &key)?;
    println!(
        "{}",
        json!({
            "kms": kms,
            "algorithm": algorithm.to_string(),
            "key_uri": provider.kek().tink_key_uri(),
            "keyset": hex::encode(keyset.into_encrypted_bytes(&provider).await?),
            "encrypted_dek": encrypted_dek.to_hex_string(),
            "aad": hex::encode(aad),
            "plain_text": hex::encode(&message.0),
            "value": hex::encode(value.value()),
        })
    );
    Ok(())
}

/// The value of `case`: a Tink envelope, or with `encrypted_dek` a value of that key.
async fn decrypt<P>(provider: P, case: &Value) -> KmsAeadResult<Message>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    let algorithm: AeadAlgorithm = case["algorithm"]
        .as_str()
        .expect("algorithm is a string")
        .parse()?;
    let aad = hex_field(case, "aad");
    let value = hex_field(case, "value");
    match case["encrypted_dek"].as_str() {
        None => {
            KmsAeadEnvelope::<P, AwsLc>::with_options(
                provider,
                KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
            )?
            .decrypt_field(&aad, &Encrypted::<Message, Envelope>::try_from(value)?)
            .await
        }
        Some(encrypted_dek) => {
            let cipher = AeadCipher::<AwsLc>::new(algorithm)?;
            let value = Encrypted::<Message, Randomized>::try_from(value)?;
            let encrypted_dek = EncryptedDataEncryptionKey::try_from_hex_string(encrypted_dek)?;
            let (decrypted, _) = DekCache::disabled()
                .with_key(&provider, &encrypted_dek, |key| {
                    cipher.decrypt_field(&aad, &value, key)
                })
                .await?;
            decrypted
        }
    }
}
