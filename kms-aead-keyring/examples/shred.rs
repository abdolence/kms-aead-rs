//! Crypto-shreds a keyring on the memory store with a local KEK: a value encrypted before the shred
//! can no longer be decrypted, because the keyring's record, and with it every encrypted key, is
//! gone. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example shred --features ring,admin
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyringAlgorithms, KeyringId,
    KeyringRegistry, KeyringRegistryOptions,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let kek = LocalKekId::try_from("tenants-kek".to_string())?;
    let admin = registry
        .create(
            LocalKmsProvider::<Ring>::ephemeral(kek)?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring = admin.keyring();

    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let email = SecretValue::from("alice@example.com");
    let encrypted: Encrypted<SecretValue, Randomized> =
        keyring.encryptor().await.encrypt(&aad, &email).await?;
    let decrypted: SecretValue = keyring.decrypt(&aad, &encrypted).await?;
    assert_eq!(decrypted, email);
    println!(
        "encrypted and decrypted a value under key version {}",
        encrypted.key_id().as_u32()
    );

    admin.dangerously_shred().await?;
    println!("shredded keyring {TENANT}");

    // The keyring's handles still hold the record with every version destroyed.
    match keyring.decrypt::<SecretValue>(&aad, &encrypted).await {
        Ok(_) => return Err("a shredded value decrypted".into()),
        Err(error) => println!("the open handle refuses the value: {}", error.code()),
    }

    // A new open reads the store, which holds no record any more.
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenants-kek".to_string())?)?;
    match registry.open(provider, TENANT).await {
        Ok(_) => return Err("a shredded keyring opened".into()),
        Err(error) => println!("opening the keyring fails: {}", error.code()),
    }

    registry.shutdown(None).await;
    Ok(())
}
