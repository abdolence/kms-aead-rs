Field encryption under a keyring is the `kms-aead-keyring` crate, see
[Keyring and field encryption](./keyring.md). Its features are in
[Cargo features](./features.md#kms-aead-keyring).

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.30", features = ["gcp-kms-encryption", "ring"] }
kms-aead-keyring = { version = "0.30", features = ["ring", "admin", "firestore"] }
secret-vault-value = "1"
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

A keyring on the memory store with a local KEK, for an application type `Email`. It needs no
cloud credentials, and needs the `admin` feature for `create`, `rotate` and `promote`:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldAad, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Purpose,
    Sealer,
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

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

// The AAD ties the value to user 42's email: `user/42/email`
let aad: FieldAad = EMAIL.aad(&EntityId::try_from("42")?);
let alice = Email("alice@example.com".to_string());
// One sealer per write of a record, for every encrypted field it holds
let sealer: Sealer<'_, MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = keyring.sealer().await;
let value: Encrypted<Email, Randomized> = sealer.encrypt(&aad, &alice).await?;
assert_eq!(value.key_id(), KeyId::new(1));

// A staged rotation keeps the previous version decrypting. One process has nothing to wait for,
// so it promotes at once
let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
admin.promote_now(staged).await?;
assert_eq!(keyring.decrypt(&aad, &value).await?, alice);
registry.shutdown(None).await;
# Ok(())
# }
```

The registry, its handles and the sealer are in
[The registry and its handles](./keyring.md#the-registry-and-its-handles).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring,admin`.
