# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

A rotation is staged: `rotate(purpose)` adds a pending version, which every process decrypts under
once its record refreshes, and `promote(key_id)` makes it active once every process has had time
to see it, see [Staged rotation](./keyring/lifecycle.md#staged-rotation). The previous version keeps
decrypting. Nothing is lost while the change propagates: processes on the old record seal under
the previous version until their record refreshes, and those values decrypt.

The administrative job runs a rotation in steps:

1. `rotate(purpose)`;
2. export the `Readable` BigQuery keysets again, which then hold the pending version;
3. wait the longest time any process may run without a successful refresh of its record, counted
   from `staged_at()`, and check that no process logged "The keyring record could not be
   revalidated" meanwhile;
4. `promote(key_id)`.

How often:

- A randomised DEK with random 96-bit nonces is good for about 2^32 values, see
  [Nonces](./security.md#nonces). The library cannot count the values a fleet seals, so estimate
  them: at 550 values per second a version reaches 2^32 in 90 days. Rotate every 30 to 90 days,
  sooner at higher rates. AES-256-GCM, AES-256-GCM-SIV and ChaCha20-Poly1305 all take a 12-byte
  nonce, so the same cadence applies to each;
- AES-GCM also bounds the data sealed under one key: RFC 8446, section 5.5, allows 2^38.5 bytes
  for an AE advantage of about 2^-57. The keyring does not count bytes, since its DEKs are shared
  across processes, so schedule rotation to stay below 2^38 bytes per version under AES-GCM, the
  default [`max_bytes`](./dek-caching.md#volume-limit) of a store-less envelope. AES-256-GCM-SIV
  and ChaCha20-Poly1305 need no volume bound beyond the count of values;
- a deterministic version has no nonce, so it is rotated by policy and on compromise only. Every
  deterministic rotation adds a probe to each equality query until a full sweep re-seals every
  row, see [Queries across rotations](./keyring/deterministic.md#queries-across-rotations), so
  rotate deterministic versions rarely;
- a beacon version likewise, since every beacon rotation adds a probe to each lookup until a
  re-index, see [Rotating beacon versions](./keyring/beacons.md#rotating-beacon-versions).

After a promotion, export the `Single` BigQuery keysets of the new deterministic version, since
a pending version has none.

Rotation does not touch values already written. To stop reading them under the old version, run a
[sweep](#sweeps), then `retire` the version.

## Rotating the KEK

The KEK rotates in the KMS on its own schedule. After a rotation, `reencrypt_deks()` decrypts every
DEK in the record and encrypts it again under the KEK's current version. No value changes. A keyring
that is not re-encrypted keeps working as long as the old KEK versions stay enabled in the KMS.

`reencrypt_deks` runs in the administrative job, like every call that encrypts.

## Sweeps

A sweep re-seals stored values under the active versions: after a rotation, to retire the old
version, after a compromise, and to migrate envelope values. It is a job the application runs, a
CLI or a Kubernetes Job, never a task inside the library: only the application knows its tables,
its pages and its write rules.

### The seal marker

Each record of the application keeps a `SealMarker` beside its encrypted fields, as plain fields
an index covers:

```json
{"format": "keyring", "randomized": 3, "deterministic": null, "beacon": 1073741825}
```

- `format` is `keyring` or `envelope`, the layout of the record's encrypted fields;
- `randomized`, `deterministic` and `beacon` are the oldest key version of each purpose among its
  values and beacons.

A write that touches any encrypted field of a record re-seals all of them under the active
versions, computes its beacons again, and writes `SealMarker::keyring` of their key ids, which
`value.key_id()` reads. Then one query finds every record a sweep still has to
visit: after the promotion of randomised key id `n`, the records whose `seal.randomized < n`, and
likewise for deterministic and beacon versions. A key id goes up to 2^32 - 1, so a SQL column
holding one is a `BIGINT`.

### Finding records behind

`Keyring::seal_thresholds()` returns the active version of each purpose as a `SealThresholds`,
with `None` for a purpose the keyring has no active version of. Key ids compare by
`KeyId::as_u32()` within one purpose, the order in which the keyring numbers its versions, so the
query of a sweep is:

- `seal.randomized < thresholds.randomized`, and likewise for `deterministic` and `beacon`;
- `seal.format = 'envelope'`, for the records not yet migrated.

A store whose query cannot express the condition, or a candidate read back before its re-seal,
uses `SealMarker::is_behind(&thresholds)`, the same test in Rust: true for an envelope marker,
and for a marker that names a version below the threshold of its purpose. A purpose without a
threshold has nothing to re-seal under, so no marker is behind on it.

The thresholds come from the cached record, so a job that starts right after a promotion in
another process calls `reload()` first.

### Re-sealing a value

`Keyring::reseal(aad, value)` returns `None` for a value under the active randomised version, and
otherwise reads it with `decrypt_with_trust` and seals it again under the active version. The
`Resealed` it returns holds the new `value` and the `trust` of the version the old value was read
under, so the compromised-value decision stays with the caller, see
[The trust of re-sealed values](#the-trust-of-re-sealed-values). `reseal_deterministic` does the
same for deterministic values, under the `deterministic` feature.

A beacon cannot be re-sealed: it is a MAC of the plaintext. A field with a beacon is read with
`decrypt_with_trust` instead, and its plaintext gives both the value under the active version,
through `encrypt`, and the beacon under the active beacon version, through `beacon(field,
&plaintext)`. `Resealed` holds no plaintext, since a beacon rotation leaves the value itself
current, and `reseal` then opens nothing.

### Running a sweep

`sweep::run` drives the application's re-seal over a stream of candidates, with at most
`concurrency` in flight, and counts what happened. Here over an in-memory table:

```rust
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SealThresholds, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, Keyring,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, KeyringResult, Plaintext,
    Purpose, Resealed, Rotation,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[derive(Clone)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

#[derive(Clone)]
struct UserRow {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// The users table, by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

/// Re-seals the row of `user` under the active version.
async fn reseal(
    keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>,
    table: &Table,
    user: &str,
) -> KeyringResult<ResealOutcome> {
    let Some(row) = table.lock().unwrap().get(user).cloned() else {
        return Ok(ResealOutcome::Skipped);
    };
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let Some(resealed): Option<Resealed<Email, Randomized>> =
        keyring.reseal(&aad, &row.email).await?
    else {
        return Ok(ResealOutcome::Skipped);
    };
    let seal = SealMarker::keyring([resealed.value.key_id()])?;
    let email = resealed.value;
    table
        .lock()
        .unwrap()
        .insert(user.to_string(), UserRow { email, seal });
    Ok(ResealOutcome::Resealed {
        from_compromised: matches!(resealed.trust, KeyTrust::Compromised(_)),
    })
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let keyring: Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .open_or_create(provider, TENANT, KeyringAlgorithms::new())
#     .await?;
# let table = Table::default();
# for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
#     let email = keyring
#         .encrypt(&EMAIL.aad(&EntityId::try_from(user)?), &Email(email.to_string()))
#         .await?;
#     let seal = SealMarker::keyring([email.key_id()])?;
#     table.lock().unwrap().insert(user.to_string(), UserRow { email, seal });
# }
let staged: KeyId = keyring.rotate(Purpose::Randomized).await?;
// After the wait for every process to see the staged version
let rotation: Rotation = keyring.promote(staged).await?;

// The query: every row behind the active versions
let thresholds: SealThresholds = keyring.seal_thresholds();
let candidates = table
    .lock()
    .unwrap()
    .iter()
    .filter(|(_, row)| row.seal.is_behind(&thresholds))
    .map(|(user, _)| user.clone())
    .collect::<Vec<String>>();

let report: SweepReport = sweep::run(
    keyring.id(),
    stream::iter(candidates),
    NonZeroUsize::new(8).unwrap(),
    |candidate| {
        let (keyring, table) = (&keyring, &table);
        async move { reseal(keyring, table, &candidate).await }
    },
)
.await;

// Nothing left under the old version: retire it
let behind = table
    .lock()
    .unwrap()
    .values()
    .any(|row| row.seal.is_behind(&thresholds));
if report.failed == 0 && !behind {
    if let Some(previous) = rotation.previous {
        keyring.retire(previous).await?;
    }
}
# assert_eq!(report.resealed, 2);
# registry.shutdown().await?;
# Ok(())
# }
```

The `SweepReport` counts every candidate once in `scanned`, and once in `resealed`, `skipped` or
`failed`. A re-seal that fails does not stop the sweep: it is counted in `failed` and logged at
`WARN` with the candidate's `Display` and the error's `Display`. A candidate is the application's
own type, such as a record id, a struct of key columns or the record itself, and its `Display`
names the record and nothing else. A record id is often an entity id, so read the sweep's log as
an administrative log.

The re-seal returns `Result<ResealOutcome, E>` with the application's own error type, any type
that implements `Display`. The keyring's calls inside it return a `KeyringError`, and a `From`
impl on the application's error lets `?` convert it, as the examples below do with an error of
their data store; a re-seal with no errors of its own returns `KeyringResult<ResealOutcome>`, as
above. The error's `Display` is the application's text and goes to the log as it is, so it carries
no value, secret or personal data. The report counts failures and keeps no error: an application
that wants the errors themselves records them inside its re-seal.

Once a sweep reports `failed == 0` and the query returns nothing, `retire` the old version. Keep it
retired for a while before `destroy`: `reinstate` brings a retired version back for a value that
turned up after all, while a destroyed one is gone.

### Sweeps by store

At millions of records a sweep streams its candidates from the store and never holds the result
of its query in memory. Every example below has the same four properties:

- it resumes without a checkpoint: the query is the checkpoint, since a re-sealed record no longer
  matches it, so a cancelled or failed run is started again over the same query;
- a concurrent writer wins: the write is conditional on the record the sweep read, and a record
  that changed in between is `Skipped`. The application's own write re-seals every field under
  the active versions anyway;
- `concurrency` bounds the re-seals in flight, and with them the load on both the store and the
  KMS. The DEK cache keeps each version's key, so a sweep makes one KMS decrypt per key version
  and cache TTL, never one per record. The keys of a compromised version are the exception: they are decrypted
  for every value and never cached;
- it ends with `retire`, then later `destroy`, once a run reports `failed == 0` and the query
  returns nothing.

#### Firestore

The marker is a map field, `seal`, whose `seal.randomized` Firestore indexes by default. The query
streams with `stream_query_with_errors()`, so that a document that does not read is a failed
candidate, and the sweep never ends early on it. The write carries the document's update time as
its precondition, and Firestore refuses it once anything changed the document since the query
read it:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use firestore::errors::FirestoreError;
use firestore::{
    paths, FirestoreDb, FirestoreResult, FirestoreTimestamp, FirestoreWritePrecondition,
};
use futures_util::StreamExt;
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SealThresholds, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Resealed,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;

const USERS: &str = "users";
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();

# #[derive(Clone)]
# struct Email(String);
#
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }
#
#[derive(Serialize, Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id", skip_serializing)]
    id: String,
    #[serde(rename = "_firestore_updated", skip_serializing)]
    updated: FirestoreTimestamp,
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// A document the query returned, or the error of reading it, which the sweep counts as failed.
struct Candidate(FirestoreResult<UserDoc>);

/// The document id, and nothing of its fields.
impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(doc) => write!(f, "{USERS}/{}", doc.id),
            Err(_) => write!(f, "an unreadable document of {USERS}"),
        }
    }
}

/// Why the re-seal of a document failed: an error of the keyring or of the users collection.
enum SweepError {
    Keyring(KeyringError),
    Users(FirestoreError),
}

impl From<KeyringError> for SweepError {
    fn from(error: KeyringError) -> Self {
        SweepError::Keyring(error)
    }
}

impl From<FirestoreError> for SweepError {
    fn from(error: FirestoreError) -> Self {
        SweepError::Users(error)
    }
}

/// The text the sweep logs: codes, never Firestore's messages, since a deserialisation error can
/// quote the field it could not read.
impl Display for SweepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SweepError::Keyring(error) => write!(f, "the keyring failed with {}", error.code()),
            SweepError::Users(FirestoreError::DatabaseError(error)) => {
                write!(f, "the users collection failed with {}", error.public.code)
            }
            SweepError::Users(FirestoreError::DeserializeError(_)) => {
                f.write_str("a document of users did not deserialise")
            }
            SweepError::Users(_) => f.write_str("the users collection failed"),
        }
    }
}

async fn reseal(
    keyring: &UsersKeyring,
    db: &FirestoreDb,
    candidate: Candidate,
) -> Result<ResealOutcome, SweepError> {
    let doc = candidate.0?;
    let aad = EMAIL.aad(&EntityId::try_from(doc.id.as_str())?);
    let Some(resealed): Option<Resealed<Email, Randomized>> =
        keyring.reseal(&aad, &doc.email).await?
    else {
        return Ok(ResealOutcome::Skipped);
    };
    let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
    let update = UserDoc {
        seal: SealMarker::keyring([resealed.value.key_id()])?,
        email: resealed.value,
        ..doc
    };
    let written: FirestoreResult<UserDoc> = db
        .fluent()
        .update()
        .fields(paths!(UserDoc::{email, seal}))
        .in_col(USERS)
        .precondition(FirestoreWritePrecondition::UpdateTime(update.updated.into()))
        .document_id(&update.id)
        .object(&update)
        .execute()
        .await;
    match written {
        Ok(_) => Ok(ResealOutcome::Resealed { from_compromised }),
        // A write since the query: the writer re-sealed the document itself
        Err(FirestoreError::DatabaseError(error)) if error.public.code == "FailedPrecondition" => {
            Ok(ResealOutcome::Skipped)
        }
        Err(error) => Err(SweepError::Users(error)),
    }
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let db = FirestoreDb::new("my-project").await?;
let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
    FirestoreKeyringStore::new(db.clone()),
    KeyringRegistryOptions::new(),
)?;
let keyring: UsersKeyring = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;

let thresholds: SealThresholds = keyring.seal_thresholds();
if let Some(active) = thresholds.randomized {
    let candidates = db
        .fluent()
        .select()
        .from(USERS)
        .filter(|q| q.field("seal.randomized").less_than(active.as_u32()))
        .obj::<UserDoc>()
        .stream_query_with_errors()
        .await?
        .map(Candidate);
    let report: SweepReport = sweep::run(keyring.id(), candidates, CONCURRENCY, |candidate| {
        let (keyring, db) = (&keyring, &db);
        async move { reseal(keyring, db, candidate).await }
    })
    .await;
    println!("{report:?}");
}
registry.shutdown().await?;
# Ok(())
# }
```

A query of `seal.randomized` matches no document without that field: documents written before the
marker existed are found by `seal.format == "envelope"` only once a backfill wrote their marker,
or by a scan of the collection that tests `is_behind` on each, since the marker reads as
`SealMarker::ENVELOPE` through `#[serde(default)]`.

`partition_query()` splits a collection into cursors that separate workers run in parallel, for
a sweep faster than one stream reads. Firestore partitions only a query with no filter, so each
worker tests `is_behind(&thresholds)` on its documents and skips the current ones before the
re-seal.

#### PostgreSQL

The marker is four columns, `seal_format TEXT`, and `seal_randomized`, `seal_deterministic`,
`seal_beacon` as `BIGINT`, since a key id goes up to 2^32 - 1. The candidates stream in pages
by keyset pagination on the primary key, with `futures_util::stream::unfold`: each page is one
short query, so no transaction stays open across the sweep, and memory holds one page. The
`UPDATE` is conditional on the bytes it read, which a write of any other process changes, since
every randomised value has its own nonce. A process that has not seen the promotion yet still
seals under the old version and leaves `seal_randomized` as it was, so the marker alone does not
detect its write:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use futures_util::{stream, Stream, StreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SealThresholds, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, Keyring, KeyringError,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Resealed,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, Config, NoTls, Row};

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const PAGE_SIZE: u16 = 1000;
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();

# #[derive(Clone)]
# struct Email(String);
#
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }
#
/// A row the query returned, or the error of reading its page, which the sweep counts as failed.
enum Candidate {
    Row { id: i64, email: Encrypted<Email, Randomized> },
    Unread(tokio_postgres::Error),
}

/// The row id, and nothing of its columns.
impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Candidate::Row { id, .. } => write!(f, "users/{id}"),
            Candidate::Unread(_) => f.write_str("a row or page of users that did not read"),
        }
    }
}

impl TryFrom<Row> for Candidate {
    type Error = tokio_postgres::Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Ok(Candidate::Row {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
        })
    }
}

/// Why the re-seal of a row failed: an error of the keyring or of the users table.
enum SweepError {
    Keyring(KeyringError),
    Users(tokio_postgres::Error),
}

impl From<KeyringError> for SweepError {
    fn from(error: KeyringError) -> Self {
        SweepError::Keyring(error)
    }
}

impl From<tokio_postgres::Error> for SweepError {
    fn from(error: tokio_postgres::Error) -> Self {
        SweepError::Users(error)
    }
}

/// The text the sweep logs: codes, never the server's message, whose detail can quote a row's
/// values.
impl Display for SweepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SweepError::Keyring(error) => write!(f, "the keyring failed with {}", error.code()),
            SweepError::Users(error) => match error.code() {
                Some(state) => write!(f, "the users table failed with SQLSTATE {}", state.code()),
                None => f.write_str("the users table failed"),
            },
        }
    }
}

/// The rows whose `seal_randomized` is below `active`, a page at a time in the order of `id`.
fn candidates(client: &Client, active: KeyId) -> impl Stream<Item = Candidate> + '_ {
    let active = i64::from(active.as_u32());
    stream::unfold(Some(i64::MIN), move |after| async move {
        let rows = client
            .query(
                "SELECT id, email FROM users \
                 WHERE seal_randomized < $1 AND id > $2 ORDER BY id LIMIT $3",
                &[&active, &after?, &i64::from(PAGE_SIZE)],
            )
            .await;
        let page = match rows {
            Ok(rows) => rows
                .into_iter()
                .map(|row| Candidate::try_from(row).unwrap_or_else(Candidate::Unread))
                .collect::<Vec<Candidate>>(),
            Err(error) => return Some((vec![Candidate::Unread(error)], None)),
        };
        let last = page.iter().rev().find_map(|candidate| match candidate {
            Candidate::Row { id, .. } => Some(*id),
            Candidate::Unread(_) => None,
        });
        let next = match last {
            Some(last) if page.len() == usize::from(PAGE_SIZE) => Some(last),
            _ => None,
        };
        (!page.is_empty()).then_some((page, next))
    })
    .flat_map(stream::iter)
}

async fn reseal(
    keyring: &UsersKeyring,
    client: &Client,
    candidate: Candidate,
) -> Result<ResealOutcome, SweepError> {
    let (id, email) = match candidate {
        Candidate::Row { id, email } => (id, email),
        Candidate::Unread(error) => return Err(SweepError::Users(error)),
    };
    let aad = EMAIL.aad(&EntityId::try_from(id.to_string())?);
    let Some(resealed): Option<Resealed<Email, Randomized>> =
        keyring.reseal(&aad, &email).await?
    else {
        return Ok(ResealOutcome::Skipped);
    };
    let seal = SealMarker::keyring([resealed.value.key_id()])?;
    let seal_randomized: Option<i64> = seal.randomized.map(|key_id| i64::from(key_id.as_u32()));
    let updated: u64 = client
        .execute(
            "UPDATE users SET email = $2, seal_format = 'keyring', seal_randomized = $3 \
             WHERE id = $1 AND email = $4",
            &[&id, &resealed.value, &seal_randomized, &email],
        )
        .await?;
    Ok(match updated {
        // A write since the query: the writer re-sealed the row itself
        0 => ResealOutcome::Skipped,
        _ => ResealOutcome::Resealed {
            from_compromised: matches!(resealed.trust, KeyTrust::Compromised(_)),
        },
    })
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let config: Config = "postgres://app@localhost/app".parse()?;
let (client, connection) = config.connect(NoTls).await?;
tokio::spawn(connection);
let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
    PostgresKeyringStore::new(config, NoTls),
    KeyringRegistryOptions::new(),
)?;
let keyring: UsersKeyring = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;

let thresholds: SealThresholds = keyring.seal_thresholds();
if let Some(active) = thresholds.randomized {
    let report: SweepReport = sweep::run(
        keyring.id(),
        candidates(&client, active),
        CONCURRENCY,
        |candidate| {
            let (keyring, client) = (&keyring, &client);
            async move { reseal(keyring, client, candidate).await }
        },
    )
    .await;
    println!("{report:?}");
}
registry.shutdown().await?;
# Ok(())
# }
```

One tokio-postgres `Client` pipelines the page queries and the concurrent `UPDATE`s on one
connection. The primary key serves every page, and the filter on `seal_randomized` reads each row
once over the whole sweep; an index on `seal_randomized` serves a sweep that leaves most rows
current.

A single query read through a portal is the alternative to pages: `Transaction::bind` and
`query_portal_raw` fetch the rows of one `SELECT` in batches. A portal lives only inside its
transaction, so that transaction stays open for the whole sweep, hours at millions of rows. Its
snapshot keeps vacuum from removing the dead row versions the `UPDATE`s leave behind, and the
`UPDATE`s run on a second connection, since the first holds the portal.

#### BigQuery

A field BigQuery reads, declared with `Interop::BigQuery`, is re-sealed by one `UPDATE` in SQL,
with no Rust loop and no value leaving BigQuery. The marker is a `STRUCT<format STRING,
randomized INT64, deterministic INT64, beacon INT64>` column. With `keyset` standing for the
`KEYS.KEYSET_CHAIN(…)` expression of a `Readable(Purpose::Randomized)` export, see
[Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery), and
`@active` for the active version's key id:

```sql
UPDATE users
SET
  email = AEAD.ENCRYPT(
    keyset,
    AEAD.DECRYPT_BYTES(keyset, email, CAST(CONCAT('user/', id, '/email') AS BYTES)),
    CAST(CONCAT('user/', id, '/email') AS BYTES)),
  seal = STRUCT(
    'keyring' AS format,
    @active AS randomized,
    seal.deterministic AS deterministic,
    seal.beacon AS beacon)
WHERE seal.randomized < @active;
```

`AEAD.DECRYPT_BYTES`, and `AEAD.ENCRYPT` of bytes, take the AAD as `BYTES`, the UTF-8 of the
same text. `AEAD.ENCRYPT` seals under the keyset's primary, which a `Readable` export sets to the active
version. A keyset exported before the promotion has the previous version as its primary, so the
sweep exports its keyset after the promotion, and then takes `@active` from
`seal_thresholds().randomized`: the export reads the record from the store and takes it as the
cached record, so both come from the same record. The statement re-seals every randomised field
of the row, or `@active` is not the oldest version among them.

This sweep:

- resumes without a checkpoint: the statement is atomic, and a failed one changed nothing;
- loses no concurrent write: BigQuery runs DML under snapshot isolation, and of two conflicting
  statements on the same rows one fails and runs again, and its `WHERE` then sees the other's
  marker;
- makes no KMS call per record: BigQuery opens the keyset through Cloud KMS for the statement;
- ends with `retire`, then later `destroy`, once `SELECT COUNT(*) FROM users WHERE
  seal.randomized < @active` returns 0.

A `Readable` keyset leaves a compromised version out, so the values under it fail
`AEAD.DECRYPT_BYTES` and the whole statement with them. After a compromise those rows go through
the Rust path below, where `reseal` reports their trust.

Other fields, such as ChaCha20-Poly1305 values or values under a custom AAD, are re-sealed in
Rust. BigQuery runs only a few DML statements on one table at a time, so the write is one `MERGE`
per page of rows rather than one `UPDATE` per row, conditional on the bytes each row held:

```sql
MERGE users u
USING UNNEST(@pages) p
ON u.id = p.id AND u.phone = p.old_phone
WHEN MATCHED THEN UPDATE SET
  phone = p.phone,
  seal = STRUCT(
    'keyring' AS format,
    p.seal_randomized AS randomized,
    u.seal.deterministic AS deterministic,
    u.seal.beacon AS beacon);
```

The pages stream from the application's BigQuery client, a query of `SELECT id, phone FROM users
WHERE seal.randomized < @active` read a page at a time, and the client runs the `MERGE`. The
candidate is then a page, and the report counts pages:

```rust
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;

use futures_util::Stream;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, Keyring, KeyringError,
    Plaintext, Resealed,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;

const PHONE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("phone"),
);
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(2).unwrap();

# struct Phone(String);
#
# impl Plaintext for Phone {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Phone)
#     }
# }
#
/// A row of `SELECT id, phone FROM users WHERE seal.randomized < @active`.
struct UserRow {
    id: String,
    phone: Encrypted<Phone, Randomized>,
}

/// A page of rows, as the application's BigQuery client reads the query result.
struct UsersPage {
    /// The page token the client read the page with, which names the page and no row.
    token: String,
    rows: Vec<UserRow>,
}

impl Display for UsersPage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users page {}", self.token)
    }
}

/// One element of `@pages`: a row re-sealed, with the bytes it held.
struct PhoneUpdate {
    id: String,
    old_phone: Encrypted<Phone, Randomized>,
    phone: Encrypted<Phone, Randomized>,
    seal_randomized: Option<KeyId>,
}

/// Re-seals the `pages` of the query, and writes each through `merge`, which runs the `MERGE`
/// and returns its number of affected rows. `ClientError` is the error of the application's
/// BigQuery client, which a `KeyringError` converts into, and its `Display` is the text the
/// sweep logs for a failed page.
async fn sweep_phones<Pages, Merge, Merged, ClientError>(
    keyring: &UsersKeyring,
    pages: Pages,
    merge: Merge,
) -> SweepReport
where
    Pages: Stream<Item = UsersPage>,
    Merge: Fn(Vec<PhoneUpdate>) -> Merged,
    Merged: Future<Output = Result<u64, ClientError>>,
    ClientError: From<KeyringError> + Display,
{
    sweep::run(keyring.id(), pages, CONCURRENCY, |page| {
        let merge = &merge;
        async move {
            let mut updates = Vec::with_capacity(page.rows.len());
            let mut from_compromised = false;
            for row in page.rows {
                let aad = PHONE.aad(&EntityId::try_from(row.id.as_str())?);
                let Some(resealed): Option<Resealed<Phone, Randomized>> =
                    keyring.reseal(&aad, &row.phone).await?
                else {
                    continue;
                };
                from_compromised |= matches!(resealed.trust, KeyTrust::Compromised(_));
                updates.push(PhoneUpdate {
                    seal_randomized: SealMarker::keyring([resealed.value.key_id()])?.randomized,
                    id: row.id,
                    old_phone: row.phone,
                    phone: resealed.value,
                });
            }
            if updates.is_empty() {
                return Ok(ResealOutcome::Skipped);
            }
            Ok::<ResealOutcome, ClientError>(match merge(updates).await? {
                0 => ResealOutcome::Skipped,
                _ => ResealOutcome::Resealed { from_compromised },
            })
        }
    })
    .await
}
#
# fn main() {}
```

A page is re-sealed sequentially inside its re-seal, and `concurrency` bounds the pages in flight,
which BigQuery's limit on concurrent DML per table sets low. The four properties hold per page: a
row that a concurrent writer changed fails the `ON` condition and stays in the query for the next
run.

### The trust of re-sealed values

A sweep reads every field with `decrypt_with_trust`, and reports in `ResealOutcome::Resealed`
whether the `KeyTrust` of any of them is compromised. A value read under a compromised version is untrusted data: whoever holds the
leaked DEK can have forged it. Re-sealing it under a new version makes it read as trusted
everywhere afterwards.

So after a compromise the application decides per record before it re-seals:

- a quarantine field beside the marker, for a person to review;
- a comparison against a backup taken before the compromise;
- or acceptance, when forged values do no harm.

`SweepReport::resealed_from_compromised` counts the records that went through that decision.

## Migrating from envelope values

Values that kms-aead's `KmsAeadEnvelope` wrote, per call or store-less, move to keyring values in
five steps:

1. the model gains `seal: SealMarker` with `#[serde(default)]`, or a column default, so every
   record without one reads as `SealMarker::ENVELOPE`;
2. the field keeps its stored bytes, whose layout the marker names;
3. reads go through the marker: `Keyring::decrypt_envelope` opens an envelope value, with
   the AAD and the algorithm the application used for it, and `Keyring::decrypt` a keyring value;
4. a sweep over `seal.format = 'envelope'` re-seals each record as keyring values and writes its
   keyring marker;
5. once that query returns nothing, the read path drops its envelope branch.

The keyring's provider decrypts the envelope values, so they must have been encrypted by the
keyring's KEK. `decrypt_envelope` reads Tink's KMS envelope, the layout kms-aead 0.30 writes.
Values written by kms-aead 0.29 or earlier are upgraded in place first, with
`KmsAeadEnvelope::upgrade_legacy_value(aad, value)` under kms-aead's `legacy-formats` feature, see
[Upgrading stored values](./formats.md#upgrading-stored-values). The layout of a value is always
the marker's, never inferred from its bytes.

`decrypt_envelope` decrypts whatever encrypted DEK an envelope value carries, under the
keyring's KEK. It knows no key version, and so no compromised flag and no destroyed state: keep its
branch in the read path for the migration only.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/migrate.rs),
run it with `cargo run -p kms-aead-keyring --example migrate --features ring`.

## Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

### A plaintext DEK leaked

Or is suspected to have.

1. `mark_compromised(key_id, note)`: the version is flagged and, if active, replaced in one write
   by a version that is active at once. The replacement skips the staged wait on purpose: sealing
   under the leaked key stops at each process's next refresh, and a process that has not seen the
   replacement yet reloads its record once, rate-limited, when it meets a value under it. When the
   KMS cannot encrypt a new DEK, the flag lands alone and `encrypt` fails with `NoActiveVersion`;
   once the KMS answers, `rotate` and `promote` at once, since nothing seals under the purpose
   meanwhile, or `promote` the pending version if the purpose has one. A pending version itself
   is never compromised: `destroy` it instead;
2. every process stops using the key within the bound of the
   [record cache](./keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep with `decrypt_with_trust`, and decide per record on the values read through the
   compromised version, see [The trust of re-sealed values](#the-trust-of-re-sealed-values);
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. `retire` the version once the sweep is done.

Rotation protects nothing already copied: backups, point-in-time recovery and data exports still
hold values the leaked DEK opens. Treat them as exposed and revoke the secrets inside them.

### A KMS IAM over-grant

1. Fix the IAM binding, back to the split in
   [Keyring deployment](./security.md#keyring-deployment);
2. rotate the KEK in the KMS and `reencrypt_deks()`;
3. with KMS data-access logs enabled in advance, list the `Decrypt` calls the wrong principal
   made: every encrypted DEK they decrypted is a leaked DEK, see above. Without those logs, every
   version is a leaked DEK.

### An encrypted DEK or the keyring record leaked

Harmless by itself, since decrypting needs the KMS. If the attacker may also gain `Decrypt` on the
KEK, follow the IAM over-grant steps. If the attacker may also write the keyring store, see
[the next case](#a-version-the-administrative-job-did-not-create) and the store-writer threat in
[Keyring deployment](./security.md#keyring-deployment).

### A version the administrative job did not create

This case starts from the `ERROR` event of a refused record that moves backwards, whose `rule`
names the version, or from a version in the record that the administrative job's log does not
show. Either means that something other than the job wrote the record: a restore, which
[the next case](#the-keyring-record-was-deleted-or-corrupted) covers, or a writer of the
store.

1. If the version is active, `mark_compromised` it, so that nothing new is sealed under it from
   each process's next refresh. If it is pending, `destroy` it;
2. `retire` and then `destroy` the version, after a sweep if values were sealed under it;
3. check the KMS audit log for the `Encrypt` call that encrypted its DEK. None means its encrypted
   DEK was copied or relabelled from another version, of this keyring or of another under the
   same KEK, which the KMS decrypts as it would the original; one from a principal other than the
   administrative job is an IAM over-grant, see above;
4. audit who can write the keyring store: the serving principal has no write, and only the
   administrative job should.

### The keyring record was deleted or corrupted

Running processes keep their cached record and log a `WARN`; new processes fail at `open`.

1. Restore the record from the store's backup: Firestore point-in-time recovery, a PostgreSQL
   backup, or a noncurrent version of the Cloud Storage or S3 object. The encrypted DEKs inside are
   still valid under the KEK;
2. repeat on the restored record every administrative call made after the copy was taken, from
   the administrative job's log, before starting new processes.

A running process refuses a restored copy that is older than its cached record and logs an
`ERROR`, while new processes take it. Values are never lost with the record as long as a copy of
it exists. Without any copy they are gone, so keep versioning on the bucket and back up the
table.

### Crypto-shredding

To make a scope's values unrecoverable:

- with a KEK per scope: destroy the KEK's versions in the KMS. Every encrypted DEK of the scope is
  then unrecoverable, backups included;
- with a shared KEK: `dangerously_destroy_all_versions`, which destroys every version of the
  keyring in one write, so that it encrypts and decrypts nothing from then on. A backup of the
  record still holds the encrypted DEKs, which the KMS opens as long as the KEK version that
  encrypted them exists, so then either delete the record and every backup of it, or destroy that
  KEK version: on GCP, Vault Transit and the local KMS, rotate the KEK, `reencrypt_deks` every
  other keyring under it, then destroy the previous KEK version. On AWS rotated key material is
  never destroyed, so only the deletion of the KMS key itself shreds.

A deployment that needs shredding guarantees uses a KEK per scope.

### A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.
