[![Cargo](https://img.shields.io/crates/v/kms-aead-keyring.svg)](https://crates.io/crates/kms-aead-keyring)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)

# kms-aead-keyring

Field encryption with a keyring, over [kms-aead](https://crates.io/crates/kms-aead). A keyring is
the record of one scope's key versions, such as a tenant's, kept in a keyring store. Each version
is a data encryption key encrypted by a KEK in a KMS.

The library provides:

- values in Tink's wire format, with a 4-byte key id instead of an encrypted DEK, which Tink and
  BigQuery read too;
- no KMS encryption on write, and one KMS decryption per key version per DEK cache TTL, on
  write and read;
- staged rotation, retirement, destruction and a compromised flag every process sees;
- separate application and administration APIs, so applications run with KMS decrypt and store
  read only, and keyrings are created and rotated from infrastructure;
- keyring stores on Firestore, PostgreSQL, Cloud Storage and S3, and in memory for tests;
- `Encrypted<T, Randomized>` fields of application types, with serde, tokio-postgres and sqlx
  support, and an AAD that binds a value to its row;
- deterministic fields for equality queries, across rotations;
- beacons, blind indexes for lookups of randomised fields;
- sweeps that re-encrypt stored values, finding the records to visit, and the records under any one
  key version, such as a compromised one, with one range query on a 5-byte encryption marker, and
  the migration from kms-aead's envelope values.

Documentation: the [keyring chapters](https://kms-aead-rust.abdolence.dev/keyring.html) of the
book, and the [API docs](https://docs.rs/kms-aead-keyring).

## Quick start

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.31", features = ["ring"] }
kms-aead-keyring = { version = "0.31", features = ["ring", "admin"] }
secret-vault-value = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

A keyring on the memory store with a local KEK, which needs no cloud credentials. Creating and
rotating the keyring needs the `admin` feature; an application that only encrypts and decrypts
builds without it and opens the keyring with `KeyringRegistry::open`:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Purpose,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(provider, TENANT, KeyringAlgorithms::new())
        .await?;
    // The application's handle on the same keyring
    let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

    // The AAD binds the value to user 42's email
    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let alice = Email("alice@example.com".to_string());
    // One encryptor per write of a record, for every encrypted field it holds
    let value: Encrypted<Email, Randomized> =
        keyring.encryptor().await.encrypt(&aad, &alice).await?;

    // A rotation is staged, then promoted, here at once, since no other process has to see it
    // first; the previous version keeps decrypting
    let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
    admin.promote_now(staged).await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, alice);

    registry.shutdown(None).await;
    Ok(())
}
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring,admin`.

## Licence

Apache Software License (ASL)
