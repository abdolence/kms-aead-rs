# Sweeps on Firestore

A sweep of a Firestore collection: the seal marker as a field, the query for the documents behind,
and the conditional write back. The mechanism is in [Sweeps](./sweeps.md), and the example has the
five properties of [Sweeps by store](./sweeps.md#sweeps-by-store).

The marker is a `bytes` field, `seal`, and the query is one range filter on it. Firestore indexes a
field ascending and descending by default, and the query needs the ascending index only, so an
exemption keeps just that one:

```sh
gcloud firestore indexes fields update seal --collection-group=users --index=order=ASCENDING
```

The query streams with `stream_query_with_errors()`, so that a document that does not read is a
failed candidate, and the sweep never ends early on it. `sweep::run_batched` cuts the documents into
batches of 500, each re-sealed through one sealer and written back in one `BatchWrite`. Each write
of the batch carries its document's update time as its precondition, and Firestore refuses it once
anything changed the document since the query read it:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreBatchWriteResponse, FirestoreDuration, FirestoreSimpleBatchWriteOptions,
    FirestoreSimpleBatchWriter, FirestoreTimestamp, FirestoreWritePrecondition,
};
use futures_util::TryStreamExt;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringResult, Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
# use firestore::FirestoreDb;
# use kms_aead::providers::GcpKmsKeyRef;
# use kms_aead_keyring::{KeyringId, KeyringRegistry, KeyringRegistryOptions};

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, FirestoreKeyringStore, GcpKmsProvider, Ring>;

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
const BATCH_WRITE_RETRY_LIMIT: FirestoreDuration = FirestoreDuration::from_secs(5);
/// The algorithm of the store-less envelope that wrote the values before the migration.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

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
    /// An envelope value under `SealMarker::ENVELOPE`, a keyring value under any other marker.
    #[serde(with = "serde_bytes")]
    email: Vec<u8>,
    #[serde(default)]
    seal: SealMarker,
}

/// The fields a re-seal writes: the encrypted fields and the marker of the sealer that sealed
/// them.
#[derive(Serialize, Deserialize)]
struct UserFields {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
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

/// Re-seals every user whose marker is below the current one, in batches of [`BATCH_SIZE`] with
/// [`CONCURRENCY`] in flight, and returns the sweep's report.
async fn sweep_users(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
) -> Result<SweepReport, FirestoreError> {
    let current: SealMarker = keyring.record().seal_marker();
    let candidates = writer
        .db
        .fluent()
        .select()
        .fields(paths!(UserFields::{email, seal}))
        .from(USERS)
        .filter(|q| q.field("seal").less_than(current))
        .obj::<UserDoc>()
        .stream_query_with_errors()
        .await?
        .err_into::<SweepError>();
    let report: SweepReport = sweep::run_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(BATCH_SIZE)
            .with_concurrency(CONCURRENCY),
        |docs: Vec<UserDoc>| reseal_batch(keyring, writer, docs),
    )
    .await;
    Ok(report)
}

/// The AAD the application gave its envelope values.
fn envelope_aad(id: &str) -> Vec<u8> {
    format!("users:{id}:email").into_bytes()
}

/// `email`, the stored bytes of user `id` under the marker `seal`, under the active version of
/// `sealer`, and the outcome of its re-seal. A keyring value under that version comes back as it
/// is, with `ResealOutcome::Skipped`.
async fn reseal_email(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    id: &str,
    seal: SealMarker,
    email: &[u8],
) -> KeyringResult<(Encrypted<Email, Randomized>, ResealOutcome)> {
    let aad = EMAIL.aad(&EntityId::try_from(id)?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Email, Envelope>::try_from(email.to_vec())?;
        let opened: Email = keyring
            .decrypt_envelope_for_migration(&envelope_aad(id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let email = Encrypted::<Email, Randomized>::try_from(email.to_vec())?;
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &email).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the record gets the marker alone
        None => (email, ResealOutcome::Skipped),
    })
}

/// Re-seals a batch of documents through one sealer and writes them back in one `BatchWrite`,
/// each write stamped with the sealer's marker and conditional on the update time the query read.
/// A batch is not atomic: a conflict fails its own write only.
async fn reseal_batch(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    docs: Vec<UserDoc>,
) -> Result<Vec<(UserDoc, Result<ResealOutcome, SweepError>)>, SweepError> {
    let sealer: UsersSealer<'_> = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut batch = writer.new_batch();
    let mut done: Vec<(UserDoc, Result<ResealOutcome, SweepError>)> =
        Vec::with_capacity(docs.len());
    let mut queued: Vec<(UserDoc, ResealOutcome)> = Vec::with_capacity(docs.len());
    for doc in docs {
        let queue = async {
            let (email, outcome) =
                reseal_email(keyring, &sealer, &doc.id, doc.seal, &doc.email).await?;
            writer
                .db
                .fluent()
                .update()
                .fields(paths!(UserFields::{email, seal}))
                .in_col(USERS)
                .precondition(FirestoreWritePrecondition::UpdateTime(doc.updated.into()))
                .document_id(&doc.id)
                .object(&UserFields { email, seal })
                .add_to_batch(&mut batch)?;
            Ok::<ResealOutcome, SweepError>(outcome)
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
            // A write since the query: the writer re-sealed the document itself
            Some(Code::FailedPrecondition) => Ok(ResealOutcome::Skipped),
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
# let db = FirestoreDb::new("my-project").await?;
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
# registry.shutdown().await?;
# Ok(())
# }
```

The retry limit ends retries, not a request: a request on a connection that never answers, the
candidate query included, waits until HTTP/2 keep-alive drops the connection, so the job timeout of
the scheduler that runs the sweep is what bounds a run.

A range filter never matches a document without the field. `#[serde(default)]` reads a document
written before the marker as `SealMarker::ENVELOPE`, and the query finds it only once its `seal`
holds those bytes, see [Move envelope values to a keyring](../use-cases/envelope-to-keyring.md).

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
