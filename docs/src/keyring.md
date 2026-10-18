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

## Getting started

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.30", features = ["gcp-kms-encryption", "ring"] }
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore"] }
secret-vault-value = "1"
```

The crate has no default features, and the backend features are those of kms-aead:

- `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto`: the crypto backends, see
  [Crypto backends](./crypto-backends.md). A keyring names its backend as a type parameter, such
  as `kms_aead::backends::Ring`;
- `deterministic`: deterministic key versions and every call on them, `encrypt_deterministic`,
  `decrypt_deterministic`, `decrypt_deterministic_with_trust` and `deterministic_probes`, see
  [Deterministic fields](./keyring/deterministic.md). The deterministic types exist in every
  build, so a process without the feature keeps a record's deterministic versions intact;
- `serde`: `Serialize` and `Deserialize` for `Encrypted`;
- `serde-json`: `serde`, and `Json<T>`, a plaintext stored as its JSON;
- `firestore`, `postgres`, `gcs`, `s3`: the keyring stores, see
  [Keyring stores](./keyring/stores.md). `gcs` has TLS variants listed there, and `postgres`
  also binds `Encrypted` in tokio-postgres;
- `bigquery-export`: `export_bigquery_keyset`, see
  [Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery).

Beacons and `export_tink_keyset` need no feature. The KMS providers come from kms-aead and its
provider features, and secret-vault-value's `SecretValue` is what an application type's `Plaintext`
encodes to.

## First example

A keyring on the memory store with a local KEK, for an application type `Email`. It needs no
cloud credentials:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldAad, FieldName, FieldSpec, KeyId, Keyring,
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

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let provider =
    LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let keyring: Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .open_or_create(provider, TENANT, KeyringAlgorithms::new())
    .await?;

// The AAD ties the value to user 42's email: `user/42/email`
let aad: FieldAad = EMAIL.aad(&EntityId::try_from("42")?);
let alice = Email("alice@example.com".to_string());
let value: Encrypted<Email, Randomized> = keyring.encrypt(&aad, &alice).await?;
assert_eq!(value.key_id(), KeyId::new(1));

// A staged rotation keeps the previous version decrypting
let staged: KeyId = keyring.rotate(Purpose::Randomized).await?;
keyring.promote(staged).await?;
assert_eq!(keyring.decrypt(&aad, &value).await?, alice);
registry.shutdown().await?;
# Ok(())
# }
```

`KeyringRegistry::open_or_create` creates the record on the first start, with one active version
of each purpose its `KeyringAlgorithms` name, and opens it on every later start.
`KeyringRegistry::open` only opens, and fails with `RecordMissing` when there is no record.
`KeyringRegistry::create` only creates, and is the call for the administrative job, see
[Principals](#principals). The registry takes the store and the backend as the type parameters of
`KeyringRegistry<S, B>`, and each call takes the provider, so that the handle it returns is a
`Keyring<S, P, B>`.

`encrypt` seals under the active version, and `decrypt` opens under the version the value names.
Neither calls the store while the cached record is fresh, nor the KMS while the version's DEK is
in the DEK cache, see [Record cache](./keyring/record-cache.md).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring`.

## Principals

The keyring calls split in two groups:

- serving calls: `encrypt`, `decrypt`, `beacon` and their variants, which read the record and
  decrypt DEKs. They need the KMS's decrypt right and read access to the store;
- administrative calls: `create`, `rotate`, `promote`, `change_algorithm`, `mark_compromised`,
  `retire`, `reinstate`, `destroy`, `dangerously_destroy_all_versions` and `reencrypt_deks`,
  which write the record, and the exports `export_bigquery_keyset` and `export_tink_keyset`.
  `create`, `rotate`, `change_algorithm`, `mark_compromised`, `reencrypt_deks` and the exports
  encrypt, so they need the KMS's encrypt right, and all but the exports need write access to the
  store.

Run the administrative calls in a job under its own principal, never in a request handler. The
deployment rule and the IAM roles per KMS are in
[Security considerations](./security.md#keyring-deployment).

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
