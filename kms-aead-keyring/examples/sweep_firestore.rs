//! A sweep on Firestore: writes users a batch at a time, each batch through a `Sealer` and in one
//! `BatchWrite`, rotates and promotes the randomised version, re-seals every document whose marker
//! is below the current one with `sweep::run_batched`, each batch through one sealer and written
//! back in one `BatchWrite` conditional on the update time of each document, and prints the
//! sweep's report. The re-seal is the one of
//! [Sweeps on Firestore](https://kms-aead-rust.abdolence.dev/operations/sweeps-firestore.html) in the book.
//!
//! The sweep is `sweep_users` and `reseal_batch`. `seed_test_data` and `delete_test_data`, at the
//! end of the file, only write the example's users before it and delete them after.
//!
//! A sweep is a job that runs on a schedule, and again until its report shows nothing scanned.
//! Retiring the previous version is a separate administrative step, see
//! [Rotation cadence](https://kms-aead-rust.abdolence.dev/operations/rotation.html#rotation-cadence).
//!
//! Every read and write is sized for millions of documents, and memory holds the batches in flight
//! only. The sweep's candidates are one streamed query, which `sweep::run_batched` cuts into
//! batches as they arrive. A stream can end early, on a deadline or an error midway, and the sweep
//! then resumes when it runs again: every document it re-sealed has left `seal < current`, so the
//! query returns exactly the documents it did not write, and nothing else needs to record how far
//! it got. The same holds for a sweep stopped part-way or one that failed on some documents. A
//! partitioned query does not fit the sweep: `PartitionQuery` takes no filter, so its workers would
//! read every document, the current ones included. The cleanup streams the ids into batches of
//! deletes the same way.
//!
//! The example runs on the emulator that `FIRESTORE_EMULATOR_HOST` names, or on Firestore with
//! application default credentials when it is unset, in the project `PROJECT_ID`. It writes the
//! keyring record and the users to two collections of its own and deletes their documents at the
//! end. The keyring is under an ephemeral local KEK, so no cloud KMS is needed.
//!
//! ```sh
//! docker run --rm -d --name kms-aead-firestore -p 8687:8687 \
//!   gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
//!   gcloud emulators firestore start --host-port=0.0.0.0:8687
//! FIRESTORE_EMULATOR_HOST=127.0.0.1:8687 PROJECT_ID=kms-aead-emulator \
//!   cargo run -p kms-aead-keyring --example sweep_firestore --features ring,admin,serde,firestore -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreBatchWriteResponse, FirestoreCollectionId, FirestoreDb, FirestoreDuration,
    FirestoreSimpleBatchWriteOptions, FirestoreSimpleBatchWriter, FirestoreTimestamp,
    FirestoreWritePrecondition,
};
use futures_util::stream::TryChunksError;
use futures_util::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
    Purpose, Resealed,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

type UsersKeyring = Keyring<FirestoreKeyringStore, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// The documents of a batch, re-sealed through one sealer and written in one `BatchWrite`:
/// Firestore's limit of writes per request. The seeding and the cleanup write as many per batch.
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(500).unwrap();
/// The batches in flight at once. On a new collection of a real database, raise the write rate
/// step by step, as Firestore's 500/50/5 rule for ramping up traffic advises.
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// How long the batch writer retries a failed `BatchWrite` before the batch fails with its error.
/// The writer retries with no limit of its own, so without this a sweep against a Firestore that
/// refuses or fails its requests never ends. The limit ends retries, not a request: one on a
/// connection that never answers waits until HTTP/2 keep-alive drops the connection.
const BATCH_WRITE_RETRY_LIMIT: FirestoreDuration = FirestoreDuration::from_secs(5);
/// The users between two progress lines.
const PROGRESS_EVERY: usize = 100_000;
const DEFAULT_USERS: u32 = 100;

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

/// A user document as the sweep reads it.
#[derive(Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id")]
    id: String,
    #[serde(rename = "_firestore_updated")]
    updated: FirestoreTimestamp,
    email: Encrypted<Email, Randomized>,
}

/// The fields every write of a user stores: the encrypted fields and the marker of the sealer
/// that sealed them.
#[derive(Serialize, Deserialize)]
struct UserFields {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
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
            SweepError::Users(error) => match error {
                FirestoreError::DatabaseError(error) => {
                    write!(f, "the users collection failed with {}", error.public.code)
                }
                FirestoreError::DeserializeError(_) => {
                    f.write_str("a document of users did not deserialise")
                }
                _ => f.write_str("the users collection failed"),
            },
            SweepError::Write(Some(code)) => write!(f, "its write failed with {code:?}"),
            SweepError::Write(None) => f.write_str("its write returned no status"),
        }
    }
}

/// A document by its id, the candidate the sweep logs a failure with.
impl Display for UserDoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users/{}", self.id)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: u32 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USERS,
    };
    let suffix = uuid::Uuid::now_v7().simple();
    let keyrings = FirestoreCollectionId::new(format!("sweep_example_keyrings_{suffix}"))?;
    let users = FirestoreCollectionId::new(format!("sweep_example_users_{suffix}"))?;
    let db = FirestoreDb::new(std::env::var("PROJECT_ID")?).await?;
    let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
        FirestoreKeyringStore::new(db.clone()).with_collection(keyrings.clone()),
        KeyringRegistryOptions::new(),
    )?;
    let writer: FirestoreSimpleBatchWriter = db
        .create_simple_batch_writer_with_options(
            FirestoreSimpleBatchWriteOptions::new()
                .with_retry_max_elapsed_time(BATCH_WRITE_RETRY_LIMIT),
        )
        .await?;

    let outcome = run(&registry, &writer, &users, count).await;
    let shutdown = registry.shutdown().await;
    let cleanup = delete_test_data(&writer, &[&users, &keyrings]).await;
    outcome?;
    shutdown?;
    cleanup?;
    Ok(())
}

/// Seeds `count` users, rotates, sweeps and prints the sweep's report.
async fn run(
    registry: &KeyringRegistry<FirestoreKeyringStore, Ring>,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let admin: KeyringAdmin<FirestoreKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(
            LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring: &UsersKeyring = admin.keyring();
    seed_test_data(keyring, writer, users, count).await?;

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    let started = Instant::now();
    let report: SweepReport = sweep_users(keyring, writer, users).await?;
    println!(
        "swept to seal marker {} in {:.2?}: scanned {}, resealed {} ({} from a compromised \
         version), skipped {}, failed {}",
        keyring.record().seal_marker(),
        started.elapsed(),
        report.scanned,
        report.resealed,
        report.resealed_from_compromised,
        report.skipped,
        report.failed
    );
    if report.failed > 0 {
        return Err(format!("{} users failed; the next run retries them", report.failed).into());
    }
    Ok(())
}

/// Re-seals every user whose marker is below the current one, in batches of [`BATCH_SIZE`] with
/// [`CONCURRENCY`] in flight, and returns the sweep's report.
async fn sweep_users(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
) -> Result<SweepReport, FirestoreError> {
    let current: SealMarker = keyring.record().seal_marker();
    // One query, streamed in the order of the `seal` index with the fields the sweep reads. A
    // document that does not read is a failed candidate, and the sweep goes on.
    let candidates = writer
        .db
        .fluent()
        .select()
        .fields(paths!(UserFields::{email, seal}))
        .from(users.as_str())
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
        |docs: Vec<UserDoc>| reseal_batch(keyring, writer, users, docs),
    )
    .await;
    Ok(report)
}

/// Re-seals a batch of documents through one sealer and writes them back in one `BatchWrite`,
/// each write stamped with the sealer's marker and conditional on the update time the query read.
///
/// The batch is the sealer's one write: it is sent as soon as the documents are sealed, so the
/// sealer is not held across more than one request. A batch is not atomic: a conflict fails its
/// own write only.
async fn reseal_batch(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    docs: Vec<UserDoc>,
) -> Result<Vec<(UserDoc, Result<ResealOutcome, SweepError>)>, SweepError> {
    let sealer = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut batch = writer.new_batch();
    let mut done: Vec<(UserDoc, Result<ResealOutcome, SweepError>)> =
        Vec::with_capacity(docs.len());
    let mut queued: Vec<(UserDoc, ResealOutcome)> = Vec::with_capacity(docs.len());
    for doc in docs {
        let queue = async {
            let aad = EMAIL.aad(&EntityId::try_from(doc.id.as_str())?);
            let resealed: Option<Resealed<Email, Randomized>> =
                sealer.reseal(&aad, &doc.email).await?;
            let (email, outcome) = match resealed {
                Some(resealed) => {
                    let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
                    (resealed.value, ResealOutcome::Resealed { from_compromised })
                }
                None => (doc.email.clone(), ResealOutcome::Skipped),
            };
            writer
                .db
                .fluent()
                .update()
                .fields(paths!(UserFields::{email, seal}))
                .in_col(users.as_str())
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
    done.extend(
        queued
            .into_iter()
            .enumerate()
            .map(|(index, (doc, outcome))| {
                let code: Option<Code> = response
                    .statuses
                    .get(index)
                    .and_then(|status| Code::try_from(status.code).ok());
                let outcome = match code {
                    Some(Code::Ok) => Ok(outcome),
                    // A write since the query: the writer sealed the document under its own
                    // record.
                    Some(Code::FailedPrecondition) => Ok(ResealOutcome::Skipped),
                    _ => Err(SweepError::Write(code)),
                };
                (doc, outcome)
            }),
    );
    Ok(done)
}

/// Adds `count` users to `done`, and prints the total each time it passes a multiple of
/// [`PROGRESS_EVERY`].
fn count_progress(done: &AtomicUsize, count: usize, what: &str) {
    let before: usize = done.fetch_add(count, Ordering::Relaxed);
    let after: usize = before + count;
    if before / PROGRESS_EVERY != after / PROGRESS_EVERY {
        println!("{what} {after} users");
    }
}

// The example's own data, not part of a sweep: its users and keyring record, written before the
// sweep and deleted after it.

/// Writes users `1..=count`, a batch of [`BATCH_SIZE`] at a time through one sealer and in one
/// `BatchWrite`, with [`CONCURRENCY`] batches in flight.
async fn seed_test_data(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let written = AtomicUsize::new(0);
    stream::iter(1..=count)
        .chunks(BATCH_SIZE.get())
        .map(Ok)
        .try_for_each_concurrent(CONCURRENCY.get(), |batch_users: Vec<u32>| {
            let written = &written;
            async move {
                let batch_count = batch_users.len();
                let sealer = keyring.sealer().await;
                let seal: SealMarker = sealer.record().seal_marker();
                let mut batch = writer.new_batch();
                for user in batch_users {
                    let id = user.to_string();
                    let fields = UserFields {
                        email: sealer
                            .encrypt(
                                &EMAIL.aad(&EntityId::try_from(id.as_str())?),
                                &Email(format!("user-{id}@example.com")),
                            )
                            .await?,
                        seal,
                    };
                    writer
                        .db
                        .fluent()
                        .update()
                        .in_col(users.as_str())
                        .precondition(FirestoreWritePrecondition::Exists(false))
                        .document_id(&id)
                        .object(&fields)
                        .add_to_batch(&mut batch)?;
                }
                every_write_succeeded(&batch.write().await?)?;
                count_progress(written, batch_count, "wrote");
                Ok::<(), Box<dyn Error>>(())
            }
        })
        .await?;
    println!(
        "wrote {count} users at seal marker {} in {:.2?}",
        keyring.record().seal_marker(),
        started.elapsed()
    );
    Ok(())
}

/// The id of any document, for the cleanup.
#[derive(Deserialize)]
struct DocId {
    #[serde(rename = "_firestore_id")]
    id: String,
}

/// Deletes every document of `collections`, streaming the ids of each into batches of
/// [`BATCH_SIZE`] deletes with [`CONCURRENCY`] in flight.
async fn delete_test_data(
    writer: &FirestoreSimpleBatchWriter,
    collections: &[&FirestoreCollectionId],
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let mut deleted: usize = 0;
    for collection in collections {
        deleted += writer
            .db
            .fluent()
            .select()
            .from(collection.as_str())
            .obj::<DocId>()
            .stream_query_with_errors()
            .await?
            .try_chunks(BATCH_SIZE.get())
            .map_err(
                |error: TryChunksError<DocId, FirestoreError>| -> Box<dyn Error> { error.1.into() },
            )
            .map_ok(|docs: Vec<DocId>| async move {
                let mut batch = writer.new_batch();
                for doc in &docs {
                    writer
                        .db
                        .fluent()
                        .delete()
                        .from(collection.as_str())
                        .document_id(&doc.id)
                        .add_to_batch(&mut batch)?;
                }
                every_write_succeeded(&batch.write().await?)?;
                Ok::<usize, Box<dyn Error>>(docs.len())
            })
            .try_buffer_unordered(CONCURRENCY.get())
            .try_fold(0, |deleted: usize, count: usize| async move {
                Ok(deleted + count)
            })
            .await?;
    }
    println!(
        "deleted the example's {deleted} documents in {:.2?}",
        started.elapsed()
    );
    Ok(())
}

/// Fails unless every write of a seeding or cleanup batch succeeded, with the code of the first
/// that did not.
fn every_write_succeeded(response: &FirestoreBatchWriteResponse) -> Result<(), Box<dyn Error>> {
    match response
        .statuses
        .iter()
        .map(|status| Code::try_from(status.code))
        .find(|code| *code != Ok(Code::Ok))
    {
        Some(code) => Err(format!("a write of a batch failed with {code:?}").into()),
        None => Ok(()),
    }
}
