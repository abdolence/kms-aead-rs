//! Signs a keyring's record with a local Ed25519 key and opens it under
//! `RecordSignaturePolicy::Required`, which refuses a record that carries no signature. The memory
//! store is shared by two registries, one that reads and signs and one that writes an unsigned
//! record, as a writer without the signing key would. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example record_signing --features ring,admin
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{
    LocalKekId, LocalKmsProvider, LocalSigningKeyName, LocalSigningProvider,
};
use kms_aead::signing::{Signer, SigningAlgorithm, VerifyingKeySet};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, RecordSignaturePolicy,
};

const SIGNED_TENANT: KeyringId = KeyringId::from_static("tenant-42");
const UNSIGNED_TENANT: KeyringId = KeyringId::from_static("tenant-43");

/// An ephemeral KEK differs on every call. Opening a keyring checks the KEK's name against the
/// record and decrypts nothing, so a fresh one is enough here.
fn local_kek() -> Result<LocalKmsProvider<Ring>, Box<dyn std::error::Error>> {
    Ok(LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from(
        "tenants-kek".to_string(),
    )?)?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let signer = Signer::<_, Ring>::new(LocalSigningProvider::<Ring>::ephemeral(
        LocalSigningKeyName::try_from("records".to_string())?,
        SigningAlgorithm::Ed25519,
    )?)
    .await?;
    // The verifying keys come from the application's configuration, never from the store.
    let trusted = VerifyingKeySet::new([signer.verifying_key().clone()])?;
    let signing_key_id = signer.verifying_key().key_id().as_u32();

    let store = MemoryKeyringStore::new();
    let registry = KeyringRegistry::<_, Ring>::new(
        store.clone(),
        KeyringRegistryOptions::new()
            .with_record_signatures(RecordSignaturePolicy::Required(trusted)),
    )?;

    let admin = registry
        .create_signed(
            local_kek()?,
            signer,
            SIGNED_TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    println!("created {SIGNED_TENANT}, signed with key id {signing_key_id}");
    drop(admin);

    let reopened = registry.open(local_kek()?, SIGNED_TENANT).await?;
    println!(
        "reopened {} under Required: the signature verified",
        reopened.id()
    );

    // A writer with store access and no signing key leaves an unsigned record.
    let unsigned_registry = KeyringRegistry::<_, Ring>::new(store, KeyringRegistryOptions::new())?;
    unsigned_registry
        .create(local_kek()?, UNSIGNED_TENANT, KeyringAlgorithms::new())
        .await?;
    match registry.open(local_kek()?, UNSIGNED_TENANT).await {
        Ok(_) => return Err("an unsigned record was opened under Required".into()),
        Err(error) => println!("opening {UNSIGNED_TENANT} refused: {}", error.code()),
    }

    registry.shutdown(None).await;
    unsigned_registry.shutdown(None).await;
    Ok(())
}
