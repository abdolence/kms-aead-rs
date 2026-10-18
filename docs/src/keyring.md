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

A keyring has two sides, each with its own handle and its own rights:

- the application encrypts, decrypts, computes beacons and runs sweeps, on a `Keyring`, which
  `KeyringRegistry::open` returns in every build;
- the administration creates keyrings, rotates, promotes, retires and destroys versions, flags
  compromised ones, re-encrypts DEKs and exports keysets, on a `KeyringAdmin`, which
  `KeyringRegistry::create`, `open_or_create` and `admin` return with the `admin` feature.

The application builds without the `admin` feature and runs under a principal with the rights of
its row only:

| Side | Handle | KMS | Keyring store |
|---|---|---|---|
| Application | `Keyring` | decrypt: GCP `roles/cloudkms.cryptoKeyDecrypter`, AWS `kms:Decrypt`, Azure Key Vault unwrap key, Vault Transit decrypt | read, and listen or watch: Firestore read, PostgreSQL `SELECT` and `LISTEN`, Cloud Storage object read, S3 `GetObject` |
| Administration | `KeyringAdmin` | encrypt and decrypt | read and write: Firestore write, PostgreSQL `INSERT` and `UPDATE`, which also send the `NOTIFY`, Cloud Storage and S3 object write |

Sweeps run on the application's side: re-sealing a value encrypts it under a DEK the record
already holds, and never asks the KMS to encrypt a DEK. Every call that encrypts a DEK or writes
the record is a `KeyringAdmin` call. The exact roles per KMS are in
[Keyring deployment](./security.md#keyring-deployment), and the permissions per store in
[Keyring stores](./keyring/stores.md).

The `admin` feature keeps the administrative calls out of the application's build, and the rights
keep them out of its reach: without the KMS encrypt right and write access to the store, those
calls fail in any build.

An application opens only keyrings that exist: `open` on a keyring the store holds no record of
fails with `KeyringError::RecordMissing`. So the administration creates each keyring before an
application opens it:

- from infrastructure: a job, a CLI or a deployment step, built with the `admin` feature and run
  with the administrative rights, calls `create` or `open_or_create`;
- or from an application that provisions lazily, such as one keyring per tenant on the tenant's
  first request. Such an application enables `admin` and is given the administrative rights
  deliberately, and is then trusted as the administration is, see
  [Keyring limits](./security.md#keyring-limits).

An application's own tests that create keyrings in `MemoryKeyringStore` enable `admin` for the
tests only:

```toml
[dependencies]
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore"] }

[dev-dependencies]
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore", "admin"] }
```

Be aware Cargo unifies the features of the packages one command builds: a `cargo build` of a
workspace with both the application and an administrative job gives the application `admin`
too. Build and deploy the application with `cargo build -p <application>`.

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
- `admin`: `KeyringAdmin`, the registry's `create`, `open_or_create` and `admin`, and the types
  of the administrative calls, `Rotation`, `EncryptedKeyset`, `KeysetSelection` and the
  `encodings` module, see [Applications and administration](#applications-and-administration);
- `deterministic`: deterministic key versions and every call on them, `encrypt_deterministic`,
  `decrypt_deterministic`, `decrypt_deterministic_with_trust` and `deterministic_probes`, see
  [Deterministic fields](./keyring/deterministic.md). The deterministic types exist in every
  build, so a process without the feature keeps a record's deterministic versions intact;
- `serde`: `Serialize` and `Deserialize` for `Encrypted` and `SealMarker`, as bytes;
- `serde-json`: `serde`, and `Json<T>`, a plaintext stored as its JSON;
- `firestore`, `postgres`, `gcs`, `s3`: the keyring stores, see
  [Keyring stores](./keyring/stores.md). `gcs` has TLS variants listed there, and `postgres`
  also binds `Encrypted` and `SealMarker` in tokio-postgres, as `BYTEA`;
- `sqlx`: `Encrypted` and `SealMarker` in sqlx on PostgreSQL, as `BYTEA`;
- `bigquery-export`: `admin`, and `export_bigquery_keyset`, see
  [Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery).

Beacons need no feature, and `export_tink_keyset` needs `admin` only. The KMS providers come from
kms-aead and its provider features, and secret-vault-value's `SecretValue` is what an application
type's `Plaintext` encodes to.

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
let value: Encrypted<Email, Randomized> = keyring.encrypt(&aad, &alice).await?;
assert_eq!(value.key_id(), KeyId::new(1));

// A staged rotation keeps the previous version decrypting
let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
admin.promote(staged).await?;
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

`encrypt` seals under the active version, and `decrypt` opens under the version the value names.
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
