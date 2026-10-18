//! A keyring on the memory store with a local KEK: encrypts a field, rotates, and reads the
//! value written before the rotation. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example local_kms --features ring
//! ```

use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions, KeyringPolicy,
    Purpose,
};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let backend = AeadBackend::Ring;
    let provider =
        LocalKmsProvider::ephemeral(LocalKekId::try_from("orders-kek".to_string())?, backend)?;
    let keyring = Keyring::open_or_create(
        MemoryKeyringStore::new(),
        provider,
        backend,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new(),
    )
    .await?;

    let aad = EMAIL.aad(&EntityId::try_from("42")?);

    let before = keyring
        .encrypt(&aad, &"alice@example.com".to_string())
        .await?;
    let rotation = keyring.rotate(Purpose::Randomized).await?;
    let after = keyring
        .encrypt(&aad, &"alice@example.com".to_string())
        .await?;

    match rotation.previous {
        Some(previous) => println!(
            "rotated from key version {previous} to {}",
            rotation.current
        ),
        None => println!("created key version {}", rotation.current),
    }
    println!(
        "value under {}: {}",
        before.key_id(),
        keyring.decrypt(&aad, &before).await?
    );
    println!(
        "value under {}: {}",
        after.key_id(),
        keyring.decrypt(&aad, &after).await?
    );
    Ok(())
}
