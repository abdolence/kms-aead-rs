# Keyring and field encryption

The `kms-aead-keyring` crate encrypts fields of application records under a keyring: the record
of one scope's key versions, such as a tenant's, kept in a keyring store. Each key version is a
data encryption key (DEK) encrypted by a KEK in the KMS, with a lifecycle state.

Compared to an envelope, a keyring value carries a 4-byte key id instead of its encrypted DEK:

- no KMS encryption on write, and one KMS decryption per key version per DEK cache TTL, on write
  and read;
- 33 bytes of overhead per value, 21 for deterministic values, see
  [Formats of `Encrypted`](./formats.md#formats-of-encrypted);
- central staged rotation, retirement, destruction and a compromised flag, for every process
  that uses the keyring;
- deterministic fields that a data store finds by equality, across rotations;
- beacons, blind indexes that a data store matches by equality beside randomised fields;
- values in Tink's wire format, which Tink and BigQuery read too.

The price is one more piece of infrastructure, the keyring store, which holds one small JSON
document per keyring. See [Choosing a mode](./intro.md#choosing-a-mode) for the comparison with
the envelope modes of kms-aead.

## Applications and administration

See [Applications and administration](./keyring/deployment.md).

## Getting started

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.30", features = ["gcp-kms-encryption", "ring"] }
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore"] }
secret-vault-value = "1"
```

Every feature is in [Cargo features](./features.md#kms-aead-keyring).

## First example

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
registry.shutdown().await?;
# Ok(())
# }
```

`KeyringRegistry::create` creates the record, with one active version of each purpose its
`KeyringAlgorithms` name, and fails with `RecordExists` when there is one already.
`open_or_create` creates it on the first start and opens it on every later one, and `admin` only
opens it. The three return a `KeyringAdmin`. `KeyringRegistry::open` returns a `Keyring`, and
fails with `RecordMissing` when there is no record; it is the application's call:

```rust,no_run
use firestore::FirestoreDb;
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::{Keyring, KeyringId, KeyringRegistry, KeyringRegistryOptions};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
    FirestoreKeyringStore::new(FirestoreDb::new("my-project").await?),
    KeyringRegistryOptions::new(),
)?;
let keyring: Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring> = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;
registry.shutdown().await?;
# Ok(())
# }
```

The registry takes the store and the backend as the type parameters of `KeyringRegistry<S, B>`,
and each call takes the provider, so that the handles are `Keyring<S, P, B>` and
`KeyringAdmin<S, P, B>`.

A `Keyring` and a `KeyringAdmin` of one keyring in one registry share its cached record and its
watch, so a write through the `KeyringAdmin` is seen by every `Keyring` at once.
`KeyringAdmin::keyring()` returns the `Keyring` it holds, for `id`, `record`, `reload`, encryption
and sweeps inside an administrative job. The example takes its `Keyring` there too, since the
ephemeral local KEK has no second copy to `open` the keyring with: `LocalKmsProvider` is not
`Clone`.

`Keyring::sealer` takes the cached record, and the `Sealer` seals under that record's active
versions; `decrypt` opens under the version the value names. A write takes one sealer and seals
every encrypted field of the record through it, so that the seal marker it stores beside them
names the versions they are under, see [The seal marker](./operations/sweeps.md#the-seal-marker).
Neither calls the store while the cached record is fresh, nor the KMS while the version's DEK is
in the DEK cache, see [Record cache](./keyring/record-cache.md).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring,admin`.

## Chapters

- [Key versions and lifecycle](./keyring/lifecycle.md): the record, key ids, states and staged
  rotation;
- [Keyring stores](./keyring/stores.md): Firestore, PostgreSQL, Cloud Storage, S3 and memory;
- [Record cache](./keyring/record-cache.md): how fast a change reaches every process;
- [Encrypted fields and AAD](./keyring/fields.md): `Encrypted<T, Randomized>`, plaintext
  encodings, the default AAD and
  [why the keyring's AAD is structured](./keyring/fields.md#why-the-aad-is-structured), unlike
  the free bytes of kms-aead;
- [Deterministic fields](./keyring/deterministic.md): equality queries, and what they leak;
- [Beacons](./keyring/beacons.md): blind indexes of randomised fields, and what they leak;
- [BigQuery and Tink interop](./keyring/bigquery.md): the BigQuery and Tink checks and the keyset
  exports;
- [Operations](./operations.md): rotation, sweeps, migration and the emergency runbook.

The bytes of values, key ids and records are in [Formats](./formats.md).
