# Keyring and field encryption

The `kms-aead-keyring` crate encrypts fields of application records under a keyring: the record
of one scope's key versions, such as a tenant's, kept in a keyring store. Each key version is a
data encryption key (DEK) wrapped by a KEK in the KMS, with a lifecycle state.

Compared to an envelope, a keyring value carries a 4-byte key id instead of its wrapped DEK:

- no KMS call on write, and on read only one unwrap per key version per DEK cache TTL;
- 33 bytes of overhead per value, 21 for deterministic values;
- central rotation, retirement, destruction and a compromised flag, for every process that uses
  the keyring;
- deterministic fields that a data store finds by equality, across rotations;
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
```

The crate has no default features, and the backend features are those of kms-aead:

- `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto`: the crypto backends, see
  [Crypto backends](./crypto-backends.md);
- `deterministic`: creating deterministic key versions, see
  [Deterministic fields](./keyring/deterministic.md);
- `legacy-formats`: reading envelope values written by kms-aead 0.28.1 and earlier, for the
  [migration](./operations.md#migrating-from-envelope-values);
- `serde`: `Serialize` and `Deserialize` for `Encrypted`;
- `serde-json`: `serde`, and `Json<T>`, a plaintext stored as its JSON;
- `firestore`, `postgres`, `gcs`: the keyring stores, see [Keyring stores](./keyring/stores.md).
  `postgres` and `gcs` have TLS variants listed there;
- `bigquery-export`: `export_bigquery_keyset`, see
  [Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery).

The KMS providers come from kms-aead and its provider features.

## First example

A keyring on the memory store with a local KEK. It needs no cloud credentials:

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

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
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

// The AAD ties the value to user 42's email: `user/42/email`
let aad = EMAIL.aad(&EntityId::try_from("42")?);
let value = keyring.encrypt(&aad, &"alice@example.com".to_string()).await?;

// A rotation keeps the previous version decrypting
keyring.rotate(Purpose::Randomized).await?;
assert_eq!(keyring.decrypt(&aad, &value).await?, "alice@example.com");
# Ok(())
# }
```

`Keyring::open_or_create` creates the record on the first start, with one active version of each
purpose the `KeyringPolicy` names, and opens it on every later start. `Keyring::open` only
opens, and fails with `RecordMissing` when there is no record. `Keyring::create` only creates, and
is the call for the administrative job, see [Principals](#principals).

`encrypt` seals under the active version, and `decrypt` opens under the version the value names.
Neither calls the store while the cached record is fresh, nor the KMS while the version's DEK is
in the DEK cache, see [Record cache](./keyring/record-cache.md).

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs),
run it with `cargo run -p kms-aead-keyring --example local_kms --features ring`.

## Principals

The keyring calls split in two groups:

- serving calls: `encrypt`, `decrypt` and their variants, which read the record and unwrap DEKs.
  They need the KMS's decrypt right and read access to the store;
- administrative calls: `create`, `rotate`, `change_algorithm`, `mark_compromised`, `retire`,
  `reinstate`, `destroy` and `rewrap`, which write the record, and `export_bigquery_keyset`. All
  of them but `retire`, `reinstate` and `destroy` wrap, so they need the KMS's encrypt right, and
  all but the export need write access to the store.

Run the administrative calls in a job under its own principal, never in a request handler. The
deployment rule and the IAM roles per KMS are in
[Security considerations](./security.md#keyring-deployment).

## Chapters

- [Key versions and lifecycle](./keyring/lifecycle.md): the record, key ids and states;
- [Keyring stores](./keyring/stores.md): Firestore, PostgreSQL, Cloud Storage and memory;
- [Record cache](./keyring/record-cache.md): how fast a change reaches every process;
- [Encrypted fields and AAD](./keyring/fields.md): `Encrypted<T>`, plaintext encodings and the
  default AAD;
- [Deterministic fields](./keyring/deterministic.md): equality queries, and what they leak;
- [Wrap-time key binding](./keyring/key-binding.md): `bind_keys`, and Azure;
- [BigQuery and Tink interop](./keyring/bigquery.md): the wire format, the BigQuery checks and
  the keyset export;
- [Operations](./operations.md): rotation, sweeps, migration and the emergency runbook.
