[![Cargo](https://img.shields.io/crates/v/kms-aead-keyring.svg)](https://crates.io/crates/kms-aead-keyring)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)

# kms-aead-keyring

Field encryption with a keyring, over [kms-aead](https://crates.io/crates/kms-aead). A keyring is
the record of one scope's key versions, such as a tenant's, kept in a keyring store. Each version
is a data encryption key wrapped by a KEK in a KMS.

The library provides:

- values in Tink's wire format, with a 4-byte key id instead of a wrapped key, which Tink and
  BigQuery read too;
- no KMS call on write, and one unwrap per key version per cache TTL on read;
- rotation, retirement, destruction and a compromised flag every process sees;
- keyring stores on Firestore, PostgreSQL, Cloud Storage and S3, and in memory;
- `Encrypted<T>` fields with serde and sqlx support, and an AAD that binds a value to its row;
- deterministic fields for equality queries, across rotations;
- sweeps that re-seal stored values, and the migration from kms-aead's envelope values.

Documentation: the [keyring chapters](https://kms-aead-rust.abdolence.dev/keyring.html) of the
book, and the [API docs](https://docs.rs/kms-aead-keyring).

## Quick start

Cargo.toml:

```toml
[dependencies]
kms-aead = "0.30"
kms-aead-keyring = { version = "0.30", features = ["ring"] }
```

A keyring on the memory store with a local KEK, which needs no cloud credentials:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, Purpose,
};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = LocalKmsProvider::ephemeral(
        LocalKekId::try_from("tenant-kek".to_string())?,
        AeadBackend::Ring,
    )?;
    let keyring = Keyring::open_or_create(
        MemoryKeyringStore::new(),
        provider,
        AeadBackend::Ring,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new(),
    )
    .await?;

    // The AAD binds the value to user 42's email
    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let value = keyring.encrypt(&aad, &"alice@example.com".to_string()).await?;

    // The previous version keeps decrypting after a rotation
    keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, "alice@example.com");

    Ok(())
}
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring`.

## Licence

Apache Software License (ASL)
