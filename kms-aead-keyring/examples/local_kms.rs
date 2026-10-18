//! A keyring on the memory store with a local KEK: encrypts a field, rotates, and reads the
//! value written before the rotation. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example local_kms --features ring
//! ```

use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadResult, Ring};
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, Plaintext, Purpose,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

/// The application's email type, sealed as the UTF-8 of the address.
#[derive(Debug)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("orders-kek".to_string())?)?;
    let keyring = Keyring::<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>::open_or_create(
        MemoryKeyringStore::new(),
        provider,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new(),
    )
    .await?;

    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let alice = Email("alice@example.com".to_string());

    let before = keyring.encrypt(&aad, &alice).await?;
    let rotation = keyring.rotate(Purpose::Randomized).await?;
    let after = keyring.encrypt(&aad, &alice).await?;

    match rotation.previous {
        Some(previous) => println!(
            "rotated from key version {previous} to {}",
            rotation.current
        ),
        None => println!("created key version {}", rotation.current),
    }
    for value in [before, after] {
        let Email(email) = keyring.decrypt(&aad, &value).await?;
        println!("value under {}: {email}", KeyId::try_from(&value)?);
    }
    Ok(())
}
