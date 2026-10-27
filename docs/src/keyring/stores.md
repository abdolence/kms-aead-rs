# Keyring stores

A keyring store keeps one record per keyring id, with a compare-and-swap and a delete on each, and
optionally signals changes to it. The library provides:

| Store | Type | Feature | Revision | Push |
|---|---|---|---|---|
| Memory | `testing::MemoryKeyringStore` | none | a write counter | every write |
| Firestore | `store::FirestoreKeyringStore` | `firestore` | the document's update time | a listener on the document |
| PostgreSQL | `store::PostgresKeyringStore` | `postgres` | a `revision` column | `NOTIFY` |
| Cloud Storage | `store::GcsKeyringStore` | `gcs` | the object's generation | none |
| S3 | `store::S3KeyringStore` | `s3` | the object's ETag | none |

Every store keeps the record as the same [JSON document](../formats.md#keyring-records), and every
read checks it. A store with push makes a change reach the other processes within seconds; without
push, the record TTL bounds it, see [Record cache](./record-cache.md).

The rights of the application and the administration on each store are in
[Store rights](./deployment.md#store-rights).

Back the store up, or keep its history, since values cannot be read without the encrypted DEKs
in the record, see [the runbook](../operations/runbook.md#the-keyring-record-was-deleted-or-corrupted).
A backup is also a copy of the record that `KeyringAdmin::dangerously_shred()` does not reach, see
[What a delete removes](#what-a-delete-removes).

## Memory

`MemoryKeyringStore` loses its records when the process exits, and with them the encrypted DEK of
every version: a value encrypted under a keyring in it, and kept anywhere that outlives the process,
never decrypts again. Use it for tests, or for values that never outlive the process.

It lives in `kms_aead_keyring::testing` for that reason, and is compiled in every build. `Clone`
shares the same records. It keeps each record as its JSON document, as the other stores do, and
signals a watch on every write. A delete removes the entry.

## Firestore

The record of a keyring is the document `kms_keyrings/<keyring id>`, whose fields are those of the
record's JSON. `with_collection` takes another collection than
`FirestoreKeyringStore::DEFAULT_COLLECTION`, as firestore-rs's `FirestoreCollectionId`. A create fails when the document exists, and an
update carries the update time it read as its precondition.

```rust,no_run
use firestore::FirestoreDb;
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::{Keyring, KeyringId, KeyringRegistry, KeyringRegistryOptions};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let db = FirestoreDb::new("my-project").await?;
let store = FirestoreKeyringStore::new(db);

let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
    store,
    KeyringRegistryOptions::new(),
)?;
let keyring: Keyring<FirestoreKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .open(provider, KeyringId::try_from("tenant-42".to_string())?)
    .await?;
# let _ = keyring;
registry.shutdown(None).await;
# Ok(())
# }
```

`FirestoreDb` is the `firestore` crate's own client: the application builds it with the
project, database and credentials it chooses. The version of the `firestore` crate is part of
this crate's API under the Firestore features.

The `firestore` feature is the store on firestore-rs without its default features, so it has no TLS
root store and no crypto provider, and needs a firestore-rs or gcloud-sdk root store feature from
the application, or one of:

- `firestore-tls-roots`: the system's native roots, firestore-rs's `tls-roots`, which brings
  native-tls and so OpenSSL on Linux;
- `firestore-tls-webpki`: rustls, with the bundled WebPKI roots for the gRPC connection to
  Firestore, and no native TLS;

each with firestore-rs's `auth-default-crypto`. A delete removes the document, with its update time
as the precondition.

Each store holds one listen stream, with a target on the document of each keyring it watches. Firestore's point-in-time recovery
restores an earlier record. Be aware the `firestore` crate logs every listen event at `trace` level on its
`firestore` target, documents included, so that level writes encrypted DEKs to the log. Keep it off
where the log leaves the administration's reach.

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

- the rights of the application and the administration on the table are in
  [Store rights](./deployment.md#store-rights);
- the table name is unqualified, so the connection's `search_path` selects the schema;
- the `revision` of a row is the server's clock in microseconds when the row is created, and the
  larger of that and the previous revision plus one at each write. A row deleted and created again
  therefore never repeats a revision of the id, which a running process that missed the deletion
  would take for an unchanged record;
- every write sends `NOTIFY <table>, '<keyring id>'` when it commits, through `pg_notify` in the
  same statement, and so does a delete, which removes the row at its revision;
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
`google.storage.v2` gRPC API. `with_prefix` sets another `ObjectPrefix` than
`GcsKeyringStore::DEFAULT_PREFIX`; one that should read as a folder ends with `/`. A write is
conditional on the generation the writer read, and a revalidation reads the object only when its
generation changed.

- the rights of the application and the administration on the bucket are in
  [Store rights](./deployment.md#store-rights);
- Cloud Storage has no change notification the store listens to, so a process sees a change once
  its record is older than `record_ttl`, 5 minutes by default;
- turn on object versioning on the bucket: every record written is then kept as a noncurrent
  version, to restore from;
- a delete removes every generation of the object, the noncurrent ones included, so versioning
  does not keep a shredded record. Soft delete keeps what a delete removes, see
  [What a delete removes](#what-a-delete-removes).

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
S3-compatible server. `with_prefix` sets another `ObjectPrefix` than
`S3KeyringStore::DEFAULT_PREFIX`; one that should read as a folder ends with `/`. A create is
conditional on no object existing (`If-None-Match: *`), an update on the ETag the writer read
(`If-Match`), and a revalidation reads the object only when its ETag changed (`If-None-Match` on
the read).

- the rights of the application and the administration on the objects are in
  [Store rights](./deployment.md#store-rights);
- S3 has no change notification the store listens to, so a process sees a change once its record
  is older than `record_ttl`, 5 minutes by default;
- turn on versioning on the bucket: every record written is then kept as a noncurrent version, to
  restore from;
- a delete removes every version and delete marker of the object, so versioning does not keep a
  shredded record, see [What a delete removes](#what-a-delete-removes).

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

### S3-compatible servers

A server is S3-compatible for this store when it passes the store conformance suite,
[`kms-aead-keyring/tests/store_conformance.rs`](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/tests/store_conformance.rs).
Its checks include the ones a compare-and-swap needs from the server: it refuses a create over an
existing object, an update at a stale ETag, and an update of an object that does not exist. A
server that writes the object in the last case, as some MinIO releases do, recreates a deleted
record on the next administrative write. To run the suite against a server, with the credentials
of the environment:

```sh
KEYRING_S3_ENDPOINT=http://minio:9000 KEYRING_S3_BUCKET=my-keyrings \
  cargo test -p kms-aead-keyring --features s3 --test store_conformance s3:: -- --ignored
```

Set the server's endpoint on the client, and `force_path_style(true)` when it serves buckets by
path, as MinIO does by default. aws-sdk-s3 adds a CRC checksum to every upload by default, which
some S3-compatible servers do not accept, and every write of the record then fails there.
`request_checksum_calculation(RequestChecksumCalculation::WhenRequired)` sends a checksum
only where the operation requires one, which the store's `PutObject` does not:

```rust,no_run
use aws_config::BehaviorVersion;
use aws_sdk_s3::config::RequestChecksumCalculation;
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
        .request_checksum_calculation(RequestChecksumCalculation::WhenRequired)
        .build(),
);
let store = S3KeyringStore::new(client, S3BucketName::try_from("my-keyrings".to_string())?);
# let _ = store;
# Ok(())
# }
```

## What a delete removes

`KeyringStore::delete` is the call `KeyringAdmin::dangerously_shred()` makes once every version of
the record is destroyed, see [Shredding a keyring](../operations/runbook.md#shredding-a-keyring). It
removes the record with the copies the store itself keeps. A copy the store keeps outside the reach
of its API is the operator's to delete:

| Store | A delete removes | The operator's |
|---|---|---|
| Memory | the entry | nothing |
| Firestore | the document, with its update time as the precondition | the document served to reads at an earlier time for one hour, and for seven days with point-in-time recovery on; backups and exports |
| PostgreSQL | the row at its revision, and sends the `NOTIFY` as a write does | the row's earlier versions until a vacuum reclaims them; backups, WAL archives and replicas |
| Cloud Storage | every generation of the object, noncurrent ones included: the noncurrent generations first, then the live object, conditional on the generation read, then that generation | the bucket's soft delete keeps every deleted generation restorable for its retention, 7 days by default |
| S3 | every version and delete marker of the object: the noncurrent ones first, then the live object with `If-Match` on its ETag, then the live version, then the delete marker that left | replication and backups |

Point-in-time recovery is Firestore's retention of every version of a document for up to seven days.
Soft delete is Cloud Storage's retention of a deleted object, which can be restored until the
retention ends. A bucket of keyring records turns soft delete off, or counts the retention into the
time a shred takes. The WAL is PostgreSQL's write-ahead log of committed changes.

A lifecycle rule of the bucket that deletes live objects, such as a Cloud Storage `Delete` rule on
age or an S3 expiration of current versions, shreds the keyrings it removes: every running process
that holds one takes the deletion at its next revalidation. A rule on noncurrent versions only
leaves the live records alone. The condition of the S3 delete holds only on a server that honours
`If-Match` on `DeleteObject`, as S3 does for general purpose buckets. Community MinIO releases
ignore it; PGSTY's Silo fork honours it from `RELEASE.2026-09-16`, within one server pool.

A delete needs rights a write does not: the administration's permissions per store are in
[Store rights](./deployment.md#store-rights).

## Your own store

`KeyringStore` is a trait with five methods, `load`, `revalidate`, `compare_and_swap`, `delete` and
`watch`, which returns `None` for a store without push, a `Revision` type and a `KIND`, such as
`StoreKind::Other("spanner")`, for spans and errors. When implementing it:

- write each method as an `async fn` whose future is `Send`;
- implement `delete(id, expected)`, which has no default:
  - it deletes the record when its stored revision is `expected`, with every earlier version of it
    the store keeps, and returns `Deletion::Deleted` once the store holds no record of the id, also
    when it held none, and `Deletion::Conflict` when the stored revision is another, leaving the
    record;
  - it returns errors as `load` does, as `KeyringError::Store` with `StoreOperation::Delete`. A
    delete that fails may have removed part of the earlier versions already, and the caller
    repeats it with the same `expected`; one that conflicts may have removed them too. The keyring
    deletes a record only in a shred, once every version of it is destroyed, so those versions hold
    only keys the shred destroys. A store that cannot delete them in one step with the live record
    removes them first, since a record gone from the store reads as shredded and no shred deletes
    it again;
  - it never gives an id the same revision twice, across a delete too: a revision that restarts at
    1 for a record created again lets a process that missed the deletion keep the deleted record;
  - a store with push signals the deletion as a change;
- read a stored document with `KeyringRecord::from_json` and write one with
  `KeyringRecord::to_json`, so the document is the one every store keeps and every read checks it;
- return the client's errors as `KeyringError::Store`, with the client's error as the root cause.
  Never format the record or the request into an error and never log either, since both carry
  encrypted DEKs.

`MemoryKeyringStore` is the reference implementation, see
[its source](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/src/testing.rs),
and the [conformance suite](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/tests/store_conformance.rs)
holds the checks every store passes.
