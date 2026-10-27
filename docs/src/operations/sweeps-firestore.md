# Sweeps on Firestore

A sweep of a Firestore collection: the encryption marker as a field, the query for the documents
behind, and the conditional write back. The mechanism is in [Sweeps](./sweeps.md), and the example
has the five properties of [Sweeps by store](./sweeps.md#sweeps-by-store).

The marker is a `bytes` field, `encryption_marker`, and the query is one range filter on it.
Firestore indexes a field ascending and descending by default, and the query needs the ascending
index only, so a field override keeps just that one. firestore-rs declares it with its index
management, behind its `admin` feature:

```rust,ignore
use firestore::{FirestoreDb, FirestoreIndexSyncReport, FirestoreResult};

/// Keeps the ascending index of `encryption_marker` in the `users` collection group, and drops the descending
/// one.
async fn sync_users_indexes(db: &FirestoreDb) -> FirestoreResult<FirestoreIndexSyncReport> {
    db.fluent()
        .indexes()
        .collection_group("users")
        .field_overrides(|f| f.fields([f.field("encryption_marker").indexes([f.ascending()])]))
        .sync()
        .await
}
```

The declaration runs from an administrative job, such as a deploy step, since `.sync()` needs the
Firestore Admin API and `roles/datastore.indexAdmin`; the application that sweeps does not run it.
The [index management chapter](https://firestore-rust.abdolence.dev/index-management.html) of
firestore-rs covers `.plan()`, `.sync()` and running them from a deploy.

A project that manages its indexes outside Rust sets the same override with `gcloud`:

```sh
gcloud firestore indexes fields update encryption_marker --collection-group=users --index=order=ASCENDING
```

The query streams with `stream_query_with_errors()`, so that a document that does not read is a
failed candidate, and the sweep never ends early on it. `sweep::reencrypt_records_batched` cuts the documents into
batches of 500, each re-encrypted through one encryptor and written back in one `BatchWrite`. Each
write of the batch carries its document's update time as its precondition, and Firestore refuses it
once anything changed the document since the query read it:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::time::Duration;

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreBatchWriteResponse, FirestoreDb, FirestoreDbOptions,
    FirestoreSimpleBatchWriteOptions, FirestoreSimpleBatchWriter, FirestoreTimestamp,
    FirestoreWritePrecondition,
};
use futures_util::TryStreamExt;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ReencryptOutcome, EncryptionMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringError, Plaintext,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
# use kms_aead::providers::GcpKmsKeyRef;
# use kms_aead_keyring::{KeyringId, KeyringRegistry, KeyringRegistryOptions};

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;

const USERS: &str = "users";
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// Firestore's limit of writes in one `BatchWrite`.
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(500).unwrap();
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// How long the batch writer retries a failed `BatchWrite` before the batch fails with its error.
/// The writer retries with no limit of its own, so without this a sweep against a Firestore that
/// refuses or fails its requests never ends.
const BATCH_WRITE_RETRY_LIMIT: Duration = Duration::from_secs(5);
/// How long a request waits for an answer, so that one to a Firestore that stopped answering fails.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
#[derive(Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id")]
    id: String,
    #[serde(rename = "_firestore_updated")]
    updated: FirestoreTimestamp,
    email: Encrypted<Email, Randomized>,
}

/// The fields a re-encryption writes: the encrypted fields and the marker of the encryptor that encrypted
/// them.
#[derive(Serialize, Deserialize)]
struct UserFields {
    email: Encrypted<Email, Randomized>,
    encryption_marker: EncryptionMarker,
}

/// The document id, and nothing of its fields.
impl Display for UserDoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{USERS}/{}", self.id)
    }
}

/// Why the sweep failed on a document or a batch: an error of the keyring or of the users
/// collection, or the status of a document's write in a batch, `None` for a status the batch did
/// not return.
enum SweepError {
    Keyring(KeyringError),
    Users(FirestoreError),
    Write(Option<Code>),
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
            SweepError::Write(Some(code)) => write!(f, "its write failed with {code:?}"),
            SweepError::Write(None) => f.write_str("its write returned no status"),
        }
    }
}

/// Re-encrypts every user whose marker is below the current one, in batches of [`BATCH_SIZE`] with
/// [`CONCURRENCY`] in flight, and returns the sweep's report.
async fn sweep_users(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
) -> Result<SweepReport, FirestoreError> {
    let current: EncryptionMarker = keyring.record().encryption_marker();
    let candidates = writer
        .db
        .fluent()
        .select()
        .fields(paths!(UserFields::{email, encryption_marker}))
        .from(USERS)
        .filter(|q| q.field("encryption_marker").less_than(current))
        .obj::<UserDoc>()
        .stream_query_with_errors()
        .await?
        .err_into::<SweepError>();
    let report: SweepReport = sweep::reencrypt_records_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(BATCH_SIZE)
            .with_concurrency(CONCURRENCY),
        |docs: Vec<UserDoc>| reencrypt_batch(keyring, writer, docs),
    )
    .await;
    Ok(report)
}

/// Re-encrypts a batch of documents through one encryptor and writes them back in one `BatchWrite`,
/// each write stamped with the encryptor's marker and conditional on the update time the query read.
/// A batch is not atomic: a document changed since the query fails its own write only, and the
/// sweep counts it as skipped.
async fn reencrypt_batch(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    docs: Vec<UserDoc>,
) -> Result<Vec<(UserDoc, Result<ReencryptOutcome, SweepError>)>, SweepError> {
    let encryptor = keyring.encryptor().await;
    let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
    let mut batch = writer.new_batch();
    let mut done: Vec<(UserDoc, Result<ReencryptOutcome, SweepError>)> =
        Vec::with_capacity(docs.len());
    let mut queued: Vec<(UserDoc, ReencryptOutcome)> = Vec::with_capacity(docs.len());
    for doc in docs {
        let queue = async {
            let aad = EMAIL.aad(&EntityId::try_from(doc.id.as_str())?);
            let reencrypted = encryptor.reencrypt(&aad, &doc.email).await?;
            let outcome = ReencryptOutcome::from(&reencrypted);
            // A current value still gets the encryptor's marker, so that it leaves the query.
            let email = reencrypted.map_or_else(|| doc.email.clone(), |reencrypted| reencrypted.value);
            writer
                .db
                .fluent()
                .update()
                .fields(paths!(UserFields::{email, encryption_marker}))
                .in_col(USERS)
                .precondition(FirestoreWritePrecondition::UpdateTime(doc.updated.into()))
                .document_id(&doc.id)
                .object(&UserFields { email, encryption_marker })
                .add_to_batch(&mut batch)?;
            Ok::<ReencryptOutcome, SweepError>(outcome)
        };
        match queue.await {
            Ok(outcome) => queued.push((doc, outcome)),
            Err(error) => done.push((doc, Err(error))),
        }
    }
    if queued.is_empty() {
        return Ok(done);
    }
    let response: FirestoreBatchWriteResponse = batch.write().await?;
    done.extend(queued.into_iter().enumerate().map(|(index, (doc, outcome))| {
        let code: Option<Code> = response
            .statuses
            .get(index)
            .and_then(|status| Code::try_from(status.code).ok());
        let outcome = match code {
            Some(Code::Ok) => Ok(outcome),
            // Written since the query: the writer encrypted the document under its own record.
            Some(Code::FailedPrecondition) => Ok(ReencryptOutcome::Skipped),
            _ => Err(SweepError::Write(code)),
        };
        (doc, outcome)
    }));
    Ok(done)
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let db: FirestoreDb = FirestoreDb::with_options(
    FirestoreDbOptions::new("my-project".to_string()).with_request_timeout(REQUEST_TIMEOUT),
)
.await?;
let writer: FirestoreSimpleBatchWriter = db
    .create_simple_batch_writer_with_options(
        FirestoreSimpleBatchWriteOptions::new()
            .with_retry_max_elapsed_time(BATCH_WRITE_RETRY_LIMIT),
    )
    .await?;
# let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
#     FirestoreKeyringStore::new(db.clone()),
#     KeyringRegistryOptions::new(),
# )?;
# let keyring: UsersKeyring = registry
#     .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
#     .await?;
let report: SweepReport = sweep_users(&keyring, &writer).await?;
println!("{report:?}");
# registry.shutdown(None).await;
# Ok(())
# }
```

The retry limit ends retries, and the request timeout ends a request that never gets an answer, the
candidate query included.

`CONCURRENCY` batches of 500 writes in flight are a high write rate for a collection that has seen
little traffic. Firestore advises starting a new collection at 500 writes a second and raising the
rate by 50% every 5 minutes, its 500/50/5 rule, so raise `CONCURRENCY` step by step on one.

A range filter never matches a document without the field, so a document written before the marker
needs the marker written first, see [Move envelope values to a
keyring](../use-cases/envelope-to-keyring.md).

A partitioned query does not fit the sweep: `PartitionQuery` takes no filter, so its workers would
read every document, the current ones included.

The marker takes 10 bytes of a document: the field name as a 5-byte string and the 5 bytes of the
value. Its entry in the ascending index takes the size of the document's name, of its parent's
name, of the field name and of the value, plus 32 bytes, by Firestore's storage size rules: about
70 bytes for a short document id in a top-level collection. 10 million documents hold about 0.1 GB
of markers and 0.7 GB of index, about $0.13 a month at about $0.18 per GiB.

The [`sweep_firestore` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_firestore.rs)
runs this sweep end to end, from the writes to the report, on the Firestore emulator. Its memory
holds the batches in flight only, so it runs the same over millions of documents. A stream that
ends early, on a deadline or an error, leaves the documents it did not reach below the current
marker, and the next run of the sweep finds them.
