//! A sweep on Firestore: writes users a batch at a time, each batch through a `Sealer` and in one
//! `BatchWrite`, rotates and promotes the randomised version, re-seals every document whose marker
//! is below the current one with `sweep::run_batched`, each batch through one sealer and written
//! back in one `BatchWrite` conditional on the update time of each document, and retires the
//! previous version once the query of its seal range finds no document. The re-seal is the one of
//! [Sweeps by store](https://kms-aead-rust.abdolence.dev/operations.html#firestore) in the book.
//!
//! Every read and write is sized for millions of documents, and memory holds a few pages at most.
//! The sweep reads its candidates in pages, each one `RunQuery` of at most `PAGE_SIZE` documents
//! that starts after the marker and the name of the last document of the page before. One query
//! over the whole range would keep its stream open for as long as the sweep runs, while Google's
//! client libraries give a `RunQuery` call
//! [a deadline of 300 seconds](https://docs.cloud.google.com/dotnet/docs/reference/Google.Cloud.Firestore.V1/latest/Google.Cloud.Firestore.V1.FirestoreSettings),
//! and firestore-rs retries a query only until its stream opens, so an error midway ends it. A
//! partitioned query does not fit either: `PartitionQuery` takes no filter, so its workers would
//! read every document, the current ones included. The existence check before `retire` reads one
//! document, and the cleanup lists the documents a page at a time and deletes them in batches.
//!
//! A sweep stopped part-way, or one that failed on some documents, resumes when it runs again:
//! the query of the markers below the current one returns exactly the documents it did not write,
//! so nothing else needs to record how far it got.
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
//! The argument is the number of users, 100 by default. The emulator scans the whole collection
//! for every query, so there each page of the sweep and of the cleanup costs as much as the first
//! reading all of them; Firestore serves a page from the index.

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::firestore::v1::Document;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreBatchWriteResponse, FirestoreCollectionId, FirestoreDb, FirestoreQueryCursor,
    FirestoreReference, FirestoreResult, FirestoreSimpleBatchWriter, FirestoreTimestamp,
    FirestoreWritePrecondition,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{
    self, BatchedSweepOptions, ResealOutcome, SealMarker, SealRange, SweepReport,
};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, KeyVersion, Keyring,
    KeyringAdmin, KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, Plaintext, Purpose, Resealed, Rotation,
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
/// The documents of a page of the sweep's query, `BATCH_SIZE` times `CONCURRENCY`: one page fills
/// every batch in flight, and reads in well under a second.
const PAGE_SIZE: u16 = 8000;
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

/// The id and the full name of any document, for the cleanup and the check before `retire`.
#[derive(Deserialize)]
struct DocId {
    #[serde(rename = "_firestore_id")]
    id: String,
    #[serde(rename = "_firestore_full_id")]
    name: String,
}

/// The last document of a page of the sweep's query, which the next page starts after.
#[derive(Deserialize)]
struct PageEnd {
    #[serde(rename = "_firestore_full_id")]
    name: String,
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

/// The next page of the documents whose marker is below `current`, in the order of the `seal`
/// index: at most [`PAGE_SIZE`] of them from the cursor `from`, with the fields the sweep reads,
/// and the cursor after the last of them to read the next page from. `None` once a page came back
/// short.
///
/// Each page starts after the last document of the one before, whatever the sweep wrote
/// meanwhile: a re-sealed document moves to the current marker, out of the range the pages walk,
/// so a page read while earlier pages are still being written neither repeats nor skips one.
async fn next_page(
    db: &FirestoreDb,
    users: &FirestoreCollectionId,
    current: SealMarker,
    from: Option<FirestoreQueryCursor>,
) -> FirestoreResult<Option<(Vec<Document>, Option<FirestoreQueryCursor>)>> {
    let Some(from) = from else {
        return Ok(None);
    };
    let page: Vec<Document> = db
        .fluent()
        .select()
        .fields(paths!(UserFields::{email, seal}))
        .from(users.as_str())
        .filter(|q| q.field("seal").less_than(current))
        .order(|o| o.fields([o.field("seal").asc(), o.field("__name__").asc()]))
        .start_at(from)
        .limit(u32::from(PAGE_SIZE))
        .query()
        .await?;
    let next: Option<FirestoreQueryCursor> = match page.last() {
        Some(last) if page.len() == usize::from(PAGE_SIZE) => {
            let end: PageEnd = FirestoreDb::deserialize_doc_to(last)?;
            Some(FirestoreQueryCursor::AfterValue(vec![
                end.seal.into(),
                FirestoreReference(end.name).into(),
            ]))
        }
        _ => None,
    };
    Ok(Some((page, next)))
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

/// Deletes every document of `collection` a page at a time, each page in batches of
/// [`BATCH_SIZE`], and returns how many there were.
///
/// Each page starts after the name of the last document of the one before, so no query scans
/// past the documents the cleanup already deleted.
async fn delete_all(
    writer: &FirestoreSimpleBatchWriter,
    collection: &FirestoreCollectionId,
) -> Result<usize, Box<dyn Error>> {
    let mut deleted: usize = 0;
    let mut after: Option<FirestoreQueryCursor> = None;
    loop {
        let query = writer
            .db
            .fluent()
            .select()
            .from(collection.as_str())
            .order(|o| o.fields([o.field("__name__").asc()]))
            .limit(u32::from(PAGE_SIZE));
        let page: Vec<DocId> = match after {
            Some(after) => query.start_at(after),
            None => query,
        }
        .obj()
        .query()
        .await?;
        stream::iter(page.chunks(BATCH_SIZE.get()))
            .map(Ok)
            .try_for_each_concurrent(CONCURRENCY.get(), |docs: &[DocId]| async move {
                let mut batch = writer.new_batch();
                for doc in docs {
                    writer
                        .db
                        .fluent()
                        .delete()
                        .from(collection.as_str())
                        .document_id(&doc.id)
                        .add_to_batch(&mut batch)?;
                }
                every_write_succeeded(&batch.write().await?)
            })
            .await?;
        deleted += page.len();
        match page.last() {
            Some(last) if page.len() == usize::from(PAGE_SIZE) => {
                after = Some(FirestoreQueryCursor::AfterValue(vec![FirestoreReference(
                    last.name.clone(),
                )
                .into()]));
            }
            _ => return Ok(deleted),
        }
    }
}

/// Writes `count` users, rotates, sweeps, and retires the previous version.
async fn run(
    registry: &KeyringRegistry<FirestoreKeyringStore, Ring>,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let db: &FirestoreDb = &writer.db;
    let admin: KeyringAdmin<FirestoreKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(
            LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring: &UsersKeyring = admin.keyring();

    let started = Instant::now();
    let written = AtomicUsize::new(0);
    // Only the batches in flight are in memory: each is sealed through one sealer and
    // created in one `BatchWrite`.
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
                    db.fluent()
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

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    let rotation: Rotation = admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let previous: KeyId = rotation
        .previous
        .ok_or("the keyring had an active version")?;

    let started = Instant::now();
    let current: SealMarker = keyring.record().seal_marker();
    // The first page starts at the lowest marker. A page query that fails returns its error,
    // which the sweep counts as failed, and ends the stream; a document that does not read is a
    // failed candidate of its own.
    let first_page = FirestoreQueryCursor::BeforeValue(vec![SealMarker::ENVELOPE.into()]);
    let candidates = stream::try_unfold(Some(first_page), |from: Option<FirestoreQueryCursor>| {
        next_page(db, users, current, from)
    })
    .map_ok(|page: Vec<Document>| {
        stream::iter(page).map(|doc: Document| FirestoreDb::deserialize_doc_to::<UserDoc>(&doc))
    })
    .try_flatten()
    .err_into::<SweepError>();
    let swept = AtomicUsize::new(0);
    let report: SweepReport = sweep::run_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(BATCH_SIZE)
            .with_concurrency(CONCURRENCY),
        |docs: Vec<UserDoc>| {
            let swept = &swept;
            async move {
                let batch_count = docs.len();
                let outcomes = reseal_batch(keyring, writer, users, docs).await;
                count_progress(swept, batch_count, "swept");
                outcomes
            }
        },
    )
    .await;
    println!(
        "swept to seal marker {current} in {:.2?}: scanned {}, resealed {}, skipped {}, failed {}",
        started.elapsed(),
        report.scanned,
        report.resealed,
        report.skipped,
        report.failed
    );

    let started = Instant::now();
    let range: SealRange = keyring
        .record()
        .version(previous)
        .and_then(KeyVersion::seal_range)
        .ok_or("a replaced version has a seal range")?;
    // One document is enough to refuse the retire.
    let under_previous: Vec<DocId> = db
        .fluent()
        .select()
        .from(users.as_str())
        .filter(|q| {
            q.for_all([
                q.field("seal").greater_than_or_equal(range.start()),
                range.end().and_then(|end| q.field("seal").less_than(end)),
            ])
        })
        .limit(1)
        .obj()
        .query()
        .await?;
    if report.failed > 0 || !under_previous.is_empty() {
        return Err(format!("users are left under key version {}", previous.as_u32()).into());
    }
    admin.retire(previous).await?;
    println!(
        "no user under key version {}, retired it in {:.2?}",
        previous.as_u32(),
        started.elapsed()
    );
    Ok(())
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
    let writer: FirestoreSimpleBatchWriter = db.create_simple_batch_writer().await?;
    let outcome = run(&registry, &writer, &users, count).await;
    registry.shutdown().await?;
    let started = Instant::now();
    let deleted = delete_all(&writer, &users).await? + delete_all(&writer, &keyrings).await?;
    println!(
        "deleted the example's {deleted} documents in {:.2?}",
        started.elapsed()
    );
    outcome
}
