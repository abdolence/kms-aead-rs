//! A keyring with a MAC version on the memory store and a local KEK: computes the MAC of a
//! payload, verifies it, and shows that verification fails once the payload changes. Needs no
//! cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example mac --features ring,admin
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    JsonEncoded, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    MacAlgorithm, SignableType, SignedPayloadType,
};
use serde::{Deserialize, Serialize};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");

/// A webhook body, authenticated as the JSON it serialises to through [`JsonEncoded`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct WebhookBody {
    event: String,
    order_id: u64,
}

impl SignableType for WebhookBody {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.webhook");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("hooks-kek".to_string())?)?;
    let admin = registry
        .create(
            provider,
            TENANT,
            KeyringAlgorithms::new().with_mac(MacAlgorithm::HmacSha256),
        )
        .await?;
    let keyring = admin.keyring();

    let body = JsonEncoded::new(WebhookBody {
        event: "order.paid".into(),
        order_id: 1042,
    });
    let mac = keyring.encryptor().await.mac(&body).await?;
    println!(
        "MAC under key version {}: {} bytes",
        mac.key_id().as_u32(),
        mac.value().len()
    );

    let verified = keyring.verify_mac(&body, &mac).await?;
    println!("verified under key version {}", verified.as_u32());

    let tampered = JsonEncoded::new(WebhookBody {
        order_id: 9999,
        ..body.0.clone()
    });
    match keyring.verify_mac(&tampered, &mac).await {
        Ok(_) => return Err("a changed payload verified".into()),
        Err(error) => println!("changed payload refused: {}", error.code()),
    }

    registry.shutdown(None).await;
    Ok(())
}
