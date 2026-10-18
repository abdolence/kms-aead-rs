# Keyring stores

A keyring store keeps one record per keyring id, with a compare-and-swap on each, and optionally
signals changes to it. The library provides:

| Store | Type | Feature | Revision | Push |
|---|---|---|---|---|
| Memory | `MemoryKeyringStore` | none | a write counter | every write |
| Firestore | `FirestoreKeyringStore` | `firestore` | the document's update time | a listener on the document |
| PostgreSQL | `PostgresKeyringStore` | `postgres` | a `revision` column | `NOTIFY` |
| Cloud Storage | `GcsKeyringStore` | `gcs` | the object's generation | none |
| S3 | `S3KeyringStore` | `s3` | the object's ETag | none |

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
- every write sends `NOTIFY <table>, '<keyring id>'` when it commits;
- PostgreSQL lets any session notify any channel. A keyring revalidates at most once per
  `reload_min_interval` however many signals arrive, so a stray `NOTIFY` costs one read.

The store connects through tokio-postgres, with a `tokio_postgres::Config` and a TLS connector the
application chooses. `NoTls` for a local database:

```rust,no_run
use kms_aead_keyring::store::{PostgresKeyringStore, PostgresTable};
use tokio_postgres::{Config, NoTls};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let config: Config = "postgres://app@localhost/app".parse()?;
let store: PostgresKeyringStore<NoTls> = PostgresKeyringStore::new(config, NoTls)
    .with_table(PostgresTable::try_from("tenant_keyrings".to_string())?);
# let _ = store;
# Ok(())
# }
```

tokio-postgres-rustls's `MakeRustlsConnect` for production, here with the platform's root
certificates:

```rust,no_run
use kms_aead_keyring::store::PostgresKeyringStore;
use rustls::{ClientConfig, RootCertStore};
use tokio_postgres::Config;
use tokio_postgres_rustls::MakeRustlsConnect;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut roots = RootCertStore::empty();
roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
let tls = MakeRustlsConnect::new(
    ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth(),
);
let config: Config = "postgres://app@db.internal/app?sslmode=require".parse()?;
let store: PostgresKeyringStore<MakeRustlsConnect> = PostgresKeyringStore::new(config, tls);
# let _ = store;
# Ok(())
# }
```

`postgres-native-tls`'s `MakeTlsConnector` works the same way for the platform TLS library.

The store opens at most two connections, whatever the number of keyrings on it:

- the query connection, on the first read or write. When it is lost, the call that finds it lost
  fails, and the next call connects again. Concurrent calls wait for one attempt;
- the listener connection, on the first watch, shared by every keyring that watches. It closes when
  the last watch is dropped. When it is lost, every keyring hears of it, the store reconnects
  after a delay that doubles from 0.5 to 30 seconds, and the keyrings revalidate.

Clones of the store share both connections. Set `connect_timeout` on the `Config` to bound each
attempt: calls wait for the attempt in progress.

The `postgres` feature also enables kms-aead's `postgres` feature, which gives `Encrypted`
tokio-postgres's `ToSql` and `FromSql` as `BYTEA`, see
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

## S3

Each record is the object `kms-keyrings/<keyring id>.json` in a bucket of Amazon S3 or of an
S3-compatible server. `with_prefix` sets another prefix; one that should read as a folder ends
with `/`. A create is conditional on no object existing (`If-None-Match: *`), an update on the
ETag the writer read (`If-Match`), and a revalidation reads the object only when its ETag changed
(`If-None-Match` on the read).

- The serving principal needs `s3:GetObject` on the objects, and the administrative one also
  `s3:PutObject`;
- S3 has no change notification the store listens to, so a process sees a change once its record
  is older than `record_ttl`, 5 minutes by default;
- turn on versioning on the bucket: every record written is then kept as a noncurrent version, to
  restore from.

```rust,no_run
use aws_config::BehaviorVersion;
use kms_aead_keyring::store::{S3BucketName, S3KeyringStore};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
let store = S3KeyringStore::new(
    aws_sdk_s3::Client::new(&config),
    S3BucketName::try_from("my-keyrings".to_string())?,
);
# let _ = store;
# Ok(())
# }
```

The client is aws-sdk-s3's, built with the credentials, region, endpoint and HTTP client the
application chooses. The `s3` feature enables the SDK's default HTTPS client, rustls on
aws-lc-rs, as kms-aead's AWS KMS provider does.

An S3-compatible server works when it honours both preconditions on writes. Set its endpoint on
the client, and `force_path_style(true)` when it serves buckets by path, as MinIO does by default:

```rust,no_run
use aws_config::BehaviorVersion;
use kms_aead_keyring::store::{S3BucketName, S3KeyringStore};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let config = aws_config::defaults(BehaviorVersion::latest())
    .endpoint_url("http://minio:9000")
    .load()
    .await;
let client = aws_sdk_s3::Client::from_conf(
    aws_sdk_s3::config::Builder::from(&config)
        .force_path_style(true)
        .build(),
);
let store = S3KeyringStore::new(client, S3BucketName::try_from("my-keyrings".to_string())?);
# let _ = store;
# Ok(())
# }
```

Be aware that a server must refuse an update whose object does not exist. MinIO
`RELEASE.2025-07-23T15-54-02Z` writes the object instead, so an update recreates a deleted record
there. The library's tests run on the `pgsty/minio` build of MinIO
`RELEASE.2026-08-04T00-00-00Z`, which refuses it as S3 does.

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
