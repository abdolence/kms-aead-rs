//! A keyring on the memory store with a local KEK: the administrative handle creates the keyring
//! and stages and promotes a new key version, and the application's handle encrypts a field and
//! reads the value written before the rotation. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example local_kms --features ring,admin
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Purpose,
    Rotation,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

/// The application's email type, sealed as the UTF-8 of the address.
#[derive(Debug, Clone)]
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
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("orders-kek".to_string())?)?;
    let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(provider, TENANT, KeyringAlgorithms::new())
        .await?;
    // An application opens its own handle with `registry.open`, under a second copy of the KEK;
    // the ephemeral KEK has none, so this one shares the administrative handle's.
    let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let alice = Email("alice@example.com".to_string());

    let before: Encrypted<Email, Randomized> = keyring.sealer().await.encrypt(&aad, &alice).await?;
    let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
    println!("staged key version {}", staged.as_u32());
    // One process, so no other has to see the staged version first; a fleet waits out the
    // record TTL and calls `promote`
    let rotation: Rotation = admin.promote_now(staged).await?;
    let after: Encrypted<Email, Randomized> = keyring.sealer().await.encrypt(&aad, &alice).await?;

    match rotation.previous {
        Some(previous) => println!(
            "promoted key version {} over {}",
            rotation.current.as_u32(),
            previous.as_u32()
        ),
        None => println!("promoted key version {}", rotation.current.as_u32()),
    }
    for value in [before, after] {
        let Email(email) = keyring.decrypt(&aad, &value).await?;
        println!("value under {}: {email}", value.key_id().as_u32());
    }
    registry.shutdown().await?;
    Ok(())
}
