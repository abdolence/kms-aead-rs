//! Keyring keysets read by Tink: for each KMS whose key is configured and each algorithm Tink
//! for Python reads, a keyring seals a value, rotates, and exports its `Readable` keyset with
//! `export_tink_keyset`. Each keyset is one JSON line, which kms-aead's
//! `tests/tink_interop.py read-keysets` reads with `KeysetHandle.read`, opening the value sealed
//! before the rotation, under the keyset's other key.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example tink_export --features ci-tink,aws-lc \
//!     | python -I tests/tink_interop.py read-keysets
//! ```
//!
//! The keys are the ones the script names: PROJECT_ID, PROJECT_LOCATION, KMS_KEY_RING and
//! KMS_KEY for Cloud KMS, and KMS_KEY_ID, the key ARN, with ACCOUNT_ID for AWS KMS. A KMS whose
//! variables are not set is skipped.

use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider, GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadAlgorithm, AwsLc, KmsAeadEncryptionProvider, ValueStruct};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    encodings, EntityId, EntityKind, FieldName, FieldSpec, Interop, Keyring, KeyringId,
    KeyringOptions, KeyringPolicy, KeysetSelection, Purpose, WrappedKeyset,
};
use serde_json::json;

type ExampleResult = Result<(), Box<dyn std::error::Error>>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::Tink);

const ALGORITHMS: [AeadAlgorithm; 3] = [
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
];

#[tokio::main]
async fn main() -> ExampleResult {
    let variable = |name: &str| std::env::var(name).ok();
    let required = |name: &str| variable(name).ok_or(format!("{name} is not set"));
    for algorithm in ALGORITHMS {
        if let Some(project_id) = variable("PROJECT_ID") {
            let key_ref = GcpKmsKeyRef::new(
                project_id,
                required("PROJECT_LOCATION")?,
                required("KMS_KEY_RING")?,
                required("KMS_KEY")?,
            );
            export("gcp", GcpKmsProvider::new(&key_ref).await?, algorithm).await?;
        }
        if let Some(key_id) = variable("KMS_KEY_ID") {
            let key_ref = AwsKmsKeyRef::new(required("ACCOUNT_ID")?, key_id);
            export("aws", AwsKmsProvider::new(&key_ref).await?, algorithm).await?;
        }
    }
    Ok(())
}

async fn export<P>(kms: &str, provider: P, algorithm: AeadAlgorithm) -> ExampleResult
where
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
{
    let keyring = Keyring::<MemoryKeyringStore, P, AwsLc>::create(
        MemoryKeyringStore::new(),
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringPolicy::new().with_randomized_algorithm(algorithm),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let plain_text = format!("sealed by kms-aead-keyring {}", env!("CARGO_PKG_VERSION"));
    let value = keyring.encrypt(&aad, &plain_text).await?;
    keyring
        .promote(keyring.rotate(Purpose::Randomized).await?)
        .await?;
    let keyset: WrappedKeyset<encodings::Tink> = keyring
        .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    println!(
        "{}",
        json!({
            "kms": kms,
            "algorithm": algorithm.to_string(),
            "key_uri": keyset.key_uri(),
            "keyset": hex(keyset.as_bytes()),
            "aad": hex(aad.as_bytes()),
            "plain_text": hex(plain_text.as_bytes()),
            "value": hex(value.value()),
        })
    );
    Ok(())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
