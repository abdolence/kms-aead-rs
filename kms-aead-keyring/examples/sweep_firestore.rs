//! A keyring sweep on Firestore: re-encrypts every document whose encryption marker is below the
//! current one, a batch at a time through one `Encryptor`, each batch in one `BatchWrite` that
//! writes a document only if it is unchanged since the query read it. The sweep is `sweep_users`
//! and `reencrypt_batch`, and
//! [Sweeps on Firestore](https://kms-aead-rust.abdolence.dev/operations/sweeps-firestore.html)
//! in the book explains it. The rest of the file runs it: it seeds users, rotates, sweeps, and
//! deletes the users.
//!
//! The example runs on the emulator that `FIRESTORE_EMULATOR_HOST` names, or on Firestore with
//! application default credentials when it is unset, in the project `PROJECT_ID`. Its keyring is
//! under an ephemeral local KEK, so no cloud KMS is needed.
//!
//! ```sh
//! docker run --rm -d --name kms-aead-firestore -p 8687:8687 \
//!   gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
//!   gcloud emulators firestore start --host-port=0.0.0.0:8687
//! FIRESTORE_EMULATOR_HOST=127.0.0.1:8687 PROJECT_ID=kms-aead-emulator \
//!   cargo run -p kms-aead-keyring --example sweep_firestore \
//!   --features ring,admin,firestore-tls-roots -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreBatchWriteResponse, FirestoreCollectionId, FirestoreDb, FirestoreDbOptions,
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
use kms_aead_keyring::sweep::{
    self, BatchedSweepOptions, EncryptionMarker, ReencryptOutcome, SweepReport,
};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
    Purpose,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

type UsersKeyring = Keyring<FirestoreKeyringStore, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// Firestore's limit of writes in one `BatchWrite`.
const DOCUMENTS_PER_BATCH: NonZeroUsize = NonZeroUsize::new(500).unwrap();
/// On a collection that has seen little traffic, raise this step by step: Firestore advises
/// ramping writes up by 50% every 5 minutes from 500 a second.
const BATCHES_IN_FLIGHT: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// The batch writer retries a failed `BatchWrite` without a limit of its own, so a Firestore that
/// refuses its requests would never end the sweep.
const BATCH_WRITE_RETRY_LIMIT: Duration = Duration::from_secs(5);
/// Fails a request to a Firestore that stopped answering.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_USER_COUNT: u32 = 100;

/// A user document as the sweep reads it.
#[derive(Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id")]
    id: String,
    #[serde(rename = "_firestore_updated")]
    updated: FirestoreTimestamp,
    email: Encrypted<Email, Randomized>,
}

/// The fields a write of a user stores: the encrypted fields, and the marker of the encryptor that
/// encrypted them, which the sweep's query ranges over.
#[derive(Serialize, Deserialize)]
struct UserFields {
    email: Encrypted<Email, Randomized>,
    encryption_marker: EncryptionMarker,
}

/// Re-encrypts every user whose marker is below the current one, in batches of
/// [`DOCUMENTS_PER_BATCH`] with [`BATCHES_IN_FLIGHT`] in flight. The query is the checkpoint: a
/// document the sweep wrote no longer matches it, so a sweep that stopped part-way resumes by
/// running again.
async fn sweep_users(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
) -> Result<SweepReport, FirestoreError> {
    let current: EncryptionMarker = keyring.record().encryption_marker();
    // A document that does not read is a failed candidate, and the sweep goes on.
    let candidates = writer
        .db
        .fluent()
        .select()
        .fields(paths!(UserFields::{email, encryption_marker}))
        .from(users.as_str())
        .filter(|q| q.field("encryption_marker").less_than(current))
        .obj::<UserDoc>()
        .stream_query_with_errors()
        .await?
        .err_into::<SweepError>();
    let report: SweepReport = sweep::reencrypt_records_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(DOCUMENTS_PER_BATCH)
            .with_concurrency(BATCHES_IN_FLIGHT),
        |docs: Vec<UserDoc>| reencrypt_batch(keyring, writer, users, docs),
    )
    .await;
    Ok(report)
}

/// Re-encrypts a batch of documents through one encryptor and writes them back in one
/// `BatchWrite`, each write stamped with the encryptor's marker and conditional on the update time
/// the query read. A batch is not atomic: a document changed since the query fails its own write
/// only, and the sweep counts it as skipped.
async fn reencrypt_batch(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
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
            let email =
                reencrypted.map_or_else(|| doc.email.clone(), |reencrypted| reencrypted.value);
            writer
                .db
                .fluent()
                .update()
                .fields(paths!(UserFields::{email, encryption_marker}))
                .in_col(users.as_str())
                .precondition(FirestoreWritePrecondition::UpdateTime(doc.updated.into()))
                .document_id(&doc.id)
                .object(&UserFields {
                    email,
                    encryption_marker,
                })
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
                    // Written since the query: the writer encrypted the document under its own
                    // record.
                    Some(Code::FailedPrecondition) => Ok(ReencryptOutcome::Skipped),
                    _ => Err(SweepError::Write(code)),
                };
                (doc, outcome)
            }),
    );
    Ok(done)
}

/// Why the sweep failed on a document or a batch: an error of the keyring or of the users
/// collection, or the status of a document's write, `None` for a status the batch did not return.
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

/// The document by its id: the candidate the sweep logs a failure with.
impl Display for UserDoc {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users/{}", self.id)
    }
}

/// The application's email type, encrypted as the UTF-8 of the address.
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

// Running the example: seeds the users, rotates, sweeps, and deletes the example's documents.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: u32 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USER_COUNT,
    };
    let suffix = uuid::Uuid::now_v7().simple();
    let keyrings = FirestoreCollectionId::new(format!("sweep_example_keyrings_{suffix}"))?;
    let users = FirestoreCollectionId::new(format!("sweep_example_users_{suffix}"))?;
    let db: FirestoreDb = FirestoreDb::with_options(
        FirestoreDbOptions::new(std::env::var("PROJECT_ID")?).with_request_timeout(REQUEST_TIMEOUT),
    )
    .await?;
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
    registry.shutdown(None).await;
    let cleanup = delete_test_data(&writer, &[&users, &keyrings]).await;
    outcome?;
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
        "swept to encryption marker {} in {:.2?}: {report:?}",
        keyring.record().encryption_marker(),
        started.elapsed(),
    );
    if report.failed > 0 {
        return Err(format!("{} users failed; the next run retries them", report.failed).into());
    }
    Ok(())
}

// The example's own data: users written before the sweep and deleted after it.

/// Writes users `1..=count`, [`DOCUMENTS_PER_BATCH`] at a time through one encryptor and in one
/// `BatchWrite`, with [`BATCHES_IN_FLIGHT`] batches in flight.
async fn seed_test_data(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    stream::iter(1..=count)
        .chunks(DOCUMENTS_PER_BATCH.get())
        .map(Ok)
        .try_for_each_concurrent(BATCHES_IN_FLIGHT.get(), |ids: Vec<u32>| async move {
            let encryptor = keyring.encryptor().await;
            let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
            let mut batch = writer.new_batch();
            for user in ids {
                let id = user.to_string();
                let fields = UserFields {
                    email: encryptor
                        .encrypt(
                            &EMAIL.aad(&EntityId::try_from(id.as_str())?),
                            &Email(format!("user-{id}@example.com")),
                        )
                        .await?,
                    encryption_marker,
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
            Ok::<(), Box<dyn Error>>(())
        })
        .await?;
    println!(
        "wrote {count} users at encryption marker {} in {:.2?}",
        keyring.record().encryption_marker(),
        started.elapsed()
    );
    Ok(())
}

/// The id of any document.
#[derive(Deserialize)]
struct DocId {
    #[serde(rename = "_firestore_id")]
    id: String,
}

/// Deletes every document of `collections`, streaming the ids of each into batches of
/// [`DOCUMENTS_PER_BATCH`] deletes with [`BATCHES_IN_FLIGHT`] in flight.
async fn delete_test_data(
    writer: &FirestoreSimpleBatchWriter,
    collections: &[&FirestoreCollectionId],
) -> Result<(), Box<dyn Error>> {
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
            .try_chunks(DOCUMENTS_PER_BATCH.get())
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
            .try_buffer_unordered(BATCHES_IN_FLIGHT.get())
            .try_fold(0, |deleted: usize, count: usize| async move {
                Ok(deleted + count)
            })
            .await?;
    }
    println!("deleted the example's {deleted} documents");
    Ok(())
}

/// Fails with the code of the first write of a seeding or cleanup batch that did not succeed.
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
