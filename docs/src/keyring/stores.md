# Keyring stores

A keyring store keeps one record per keyring id, with a compare-and-swap on each, and optionally
signals changes to it. The library provides:

| Store | Type | Feature | Revision | Push |
|---|---|---|---|---|
| Memory | `MemoryKeyringStore` | none | a write counter | every write |
| Firestore | `FirestoreKeyringStore` | `firestore` | the document's update time | a listener on the document |
| PostgreSQL | `PostgresKeyringStore` | `postgres` | a `revision` column | `NOTIFY` |
| Cloud Storage | `GcsKeyringStore` | `gcs` | the object's generation | none |

Every store keeps the record as the same [JSON document](./lifecycle.md#the-record), and every
read checks it. A store with push makes a change reach the other processes within seconds; without
push, the record TTL bounds it, see [Record cache](./record-cache.md).

The store's access control is what the record's integrity rests on: only the administrative
principal writes the record, and the serving principals read it. Back the store up, or keep its
history, since values cannot be read without the wrapped DEKs in the record, see
[the runbook](../operations.md#the-keyring-record-was-deleted-or-corrupted).

## Memory

`MemoryKeyringStore` keeps records in the process's memory. It is for tests, examples and a single
process that creates its keyring at start. `Clone` shares the same records. A record in it is
gone when the process exits, and so are the values sealed under it.

## Firestore

The record of a keyring is the document `kms_keyrings/<keyring id>`, whose fields are those of the
record's JSON. `with_collection` names another collection. A create fails when the document
exists, and an update carries the update time it read as its precondition.

```rust,no_run
use firestore::FirestoreDb;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::{Keyring, KeyringId, KeyringOptions};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?, AeadBackend::Ring)?;
let db = FirestoreDb::new("my-project").await?;
let store = FirestoreKeyringStore::new(db);

let keyring = Keyring::open(
    store,
    provider,
    AeadBackend::Ring,
    KeyringId::try_from("tenant-42".to_string())?,
    KeyringOptions::new(),
)
.await?;
# let _ = keyring;
# Ok(())
# }
```

`FirestoreDb` is the `firestore` crate's own client: the application builds it with the
project, database and credentials it chooses. The version of the `firestore` crate is part of
this crate's API under the `firestore` feature.

Each keyring holds one listen stream, on its document. Firestore's point-in-time recovery
restores an earlier record. Be aware the `firestore` crate logs every listen event at `trace` level on its
`firestore` target, documents included, so that level writes wrapped DEKs to the log. Keep it off
where the log leaves the administrative principal's reach.

## PostgreSQL

One row per keyring, in a table the operator creates. The library runs no migrations. The table,
`kms_keyrings` unless `with_table` names another:

```sql
CREATE TABLE kms_keyrings (
    id         TEXT PRIMARY KEY,
    record     JSONB NOT NULL,
    revision   BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

- The serving principal needs `SELECT` on it, and the administrative one also `INSERT` and
  `UPDATE`;
- the table name is unqualified, so the connection's `search_path` selects the schema;
- every write sends `NOTIFY <table>, '<keyring id>'` when it commits. The keyrings of a store
  share one listener on that channel, which holds one connection of the pool while any of them
  watches;
- PostgreSQL lets any session notify any channel. A keyring revalidates at most once per
  `reload_min_interval` however many signals arrive, so a stray `NOTIFY` costs one read.

```rust,no_run
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::{PostgresKeyringStore, PostgresTable};
use kms_aead_keyring::{Keyring, KeyringId, KeyringOptions};
use sqlx::postgres::PgPool;

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?, AeadBackend::Ring)?;
let pool = PgPool::connect("postgres://app@db/app").await?;
let store = PostgresKeyringStore::new(pool)
    .with_table(PostgresTable::try_from("tenant_keyrings".to_string())?);

let keyring = Keyring::open(
    store,
    provider,
    AeadBackend::Ring,
    KeyringId::try_from("tenant-42".to_string())?,
    KeyringOptions::new(),
)
.await?;
# let _ = keyring;
# Ok(())
# }
```

The `PgPool` is sqlx's: the application owns the pool, its connection options and its TLS stack.
The TLS features, one of which a TLS connection needs:

- `postgres-tls-rustls`: rustls with aws-lc-rs;
- `postgres-tls-rustls-ring`: rustls with ring;
- `postgres-tls-native`: the platform TLS library.

The same feature gives `Encrypted` sqlx's `Type`, `Encode` and `Decode` as `BYTEA`, see
[Encrypted fields](./fields.md#postgresql).

## Cloud Storage

Each record is the object `kms-keyrings/<keyring id>.json` in a bucket, through the
`google.storage.v2` gRPC API. `with_prefix` sets another prefix; one that should read as a folder
ends with `/`. A write is conditional on the generation the writer read, and a revalidation reads
the object only when its generation changed.

- The serving principal needs `storage.objects.get` on the bucket, and the administrative one also
  `storage.objects.create` and `storage.objects.delete`, since a write replaces the object;
- Cloud Storage has no change notification the store listens to, so a process sees a change once
  its record is older than `record_ttl`, 5 minutes by default;
- turn on object versioning on the bucket: every record written is then kept as a noncurrent
  version, to restore from.

```rust,no_run
use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
use gcloud_sdk::GoogleApi;
use kms_aead_keyring::store::{GcsBucketName, GcsKeyringStore};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let client =
    GoogleApi::from_function(StorageClient::new, "https://storage.googleapis.com", None).await?;
let store = GcsKeyringStore::new(client, GcsBucketName::try_from("my-keyrings".to_string())?)?;
# let _ = store;
# Ok(())
# }
```

The client is gcloud-sdk's, built with the credentials, endpoint and TLS stack the application
chooses. The `gcs` feature has no TLS root store, so it needs one of gcloud-sdk's root store
features from the application, or one of:

- `gcs-tls-roots`: the system's native roots;
- `gcs-tls-webpki`: the bundled WebPKI roots.

## Your own store

`KeyringStore` is a trait with four methods, `load`, `revalidate`, `compare_and_swap` and `watch`,
which returns `None` for a store without push, a `Revision` type and a `KIND`, such as
`StoreKind::Other("spanner")`, for spans and errors. When implementing it:

- write each method as an `async fn` whose future is `Send`;
- read a stored document with `KeyringRecord::from_json` and write one with
  `KeyringRecord::to_json`, so the document is the one every store keeps and every read checks it;
- wrap the client's errors in `KeyringError::Store` with the client's error as the root cause.
  Never format the record or the request into an error and never log either, since both carry
  wrapped DEKs.

`MemoryKeyringStore` is the reference implementation, see
[its source](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/src/store/memory.rs).
