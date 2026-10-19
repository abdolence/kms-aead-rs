//! A sweep on Firestore: writes users through a `Sealer`, each with its seal marker, rotates and
//! promotes the randomised version, re-seals every document whose marker is below the current one
//! a page at a time, each page through one sealer and written back in one batch of writes
//! conditional on the update time of each document, and retires the previous version once the query of
//! its seal range finds no document. The re-seal is the one of
//! [Sweeps by store](https://kms-aead-rust.abdolence.dev/operations.html#firestore) in the book.
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
use std::time::Instant;

use firestore::errors::FirestoreError;
use firestore::gcloud_sdk::google::rpc::Code;
use firestore::{
    paths, FirestoreCollectionId, FirestoreDb, FirestoreResult, FirestoreSimpleBatchWriter,
    FirestoreTimestamp, FirestoreWritePrecondition,
};
use futures_util::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{ResealOutcome, SealMarker, SealRange, SweepReport};
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
/// The documents of a page, re-sealed through one sealer and written in one batch: Firestore's
/// limit of writes per `BatchWrite` request.
const PAGE_SIZE: usize = 500;
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
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

/// The id of any document, for the cleanup.
#[derive(Deserialize)]
struct DocId {
    #[serde(rename = "_firestore_id")]
    id: String,
}

/// Why the re-seal of a document failed: an error of the keyring, of the users collection, or
/// the status of its write in a batch, `None` for a status the batch did not return.
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

/// Counts one document's outcome in `report`, and prints a failure with the document and the
/// code of the error.
fn tally(report: &mut SweepReport, doc: &dyn Display, outcome: Result<ResealOutcome, &SweepError>) {
    report.scanned += 1;
    match outcome {
        Ok(ResealOutcome::Resealed { from_compromised }) => {
            report.resealed += 1;
            report.resealed_from_compromised += u64::from(from_compromised);
        }
        Ok(ResealOutcome::Skipped) => report.skipped += 1,
        Err(error) => {
            report.failed += 1;
            eprintln!("the re-seal of {doc} failed: {error}");
        }
    }
}

/// Re-seals a page of documents through one sealer and writes them back in one batch, each
/// write stamped with the sealer's marker and conditional on the update time the query read.
///
/// The batch is the sealer's one write: it is sent as soon as the page is sealed, so the sealer
/// is not held across more than one request. A batch is not atomic: a conflict fails its own
/// write only.
async fn reseal_page(
    keyring: &UsersKeyring,
    writer: &FirestoreSimpleBatchWriter,
    users: &FirestoreCollectionId,
    page: Vec<FirestoreResult<UserDoc>>,
    report: &mut SweepReport,
) {
    let sealer = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut batch = writer.new_batch();
    let mut queued: Vec<(String, ResealOutcome)> = Vec::with_capacity(page.len());
    for doc in page {
        let doc: UserDoc = match doc {
            Ok(doc) => doc,
            Err(error) => {
                let error = SweepError::Users(error);
                tally(report, &"an unreadable document of users", Err(&error));
                continue;
            }
        };
        let queue = async {
            let aad = EMAIL.aad(&EntityId::try_from(doc.id.as_str())?);
            // A value under a version newer than the sealer's record fails with
            // `SealerOutdated`: the sweep counts it as failed, and the next run, on the
            // reloaded record, re-seals it.
            let resealed: Option<Resealed<Email, Randomized>> =
                sealer.reseal(&aad, &doc.email).await?;
            let (email, outcome) = match resealed {
                Some(resealed) => {
                    let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
                    (resealed.value, ResealOutcome::Resealed { from_compromised })
                }
                None => (doc.email, ResealOutcome::Skipped),
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
            Ok(outcome) => queued.push((doc.id, outcome)),
            Err(error) => tally(report, &format_args!("users/{}", doc.id), Err(&error)),
        }
    }
    if queued.is_empty() {
        return;
    }
    match batch.write().await {
        Ok(response) => {
            for (index, (id, outcome)) in queued.into_iter().enumerate() {
                let code: Option<Code> = response
                    .statuses
                    .get(index)
                    .and_then(|status| Code::try_from(status.code).ok());
                let outcome = match code {
                    Some(Code::Ok) => Ok(outcome),
                    // A write since the query: the writer sealed the document under its own
                    // record
                    Some(Code::FailedPrecondition) => Ok(ResealOutcome::Skipped),
                    _ => Err(SweepError::Write(code)),
                };
                tally(
                    report,
                    &format_args!("users/{id}"),
                    outcome.as_ref().copied(),
                );
            }
        }
        Err(error) => {
            let error = SweepError::Users(error);
            for (id, _) in queued {
                tally(report, &format_args!("users/{id}"), Err(&error));
            }
        }
    }
}

/// Deletes every document of `collection`, and returns how many there were.
async fn delete_all(
    db: &FirestoreDb,
    collection: &FirestoreCollectionId,
) -> FirestoreResult<usize> {
    let docs: Vec<DocId> = db
        .fluent()
        .select()
        .from(collection.as_str())
        .obj()
        .query()
        .await?;
    stream::iter(&docs)
        .map(Ok)
        .try_for_each_concurrent(CONCURRENCY.get(), |doc: &DocId| {
            db.fluent()
                .delete()
                .from(collection.as_str())
                .document_id(&doc.id)
                .execute()
        })
        .await?;
    Ok(docs.len())
}

/// Writes `count` users, rotates, sweeps, and retires the previous version.
async fn run(
    registry: &KeyringRegistry<FirestoreKeyringStore, Ring>,
    db: &FirestoreDb,
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

    let started = Instant::now();
    stream::iter(1..=count)
        .map(Ok)
        .try_for_each_concurrent(CONCURRENCY.get(), |user: u32| async move {
            let id = user.to_string();
            let sealer = keyring.sealer().await;
            let fields = UserFields {
                email: sealer
                    .encrypt(
                        &EMAIL.aad(&EntityId::try_from(id.as_str())?),
                        &Email(format!("user-{id}@example.com")),
                    )
                    .await?,
                seal: sealer.record().seal_marker(),
            };
            let _: UserFields = db
                .fluent()
                .insert()
                .into(users.as_str())
                .document_id(&id)
                .object(&fields)
                .execute()
                .await?;
            Ok::<(), Box<dyn Error>>(())
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
    let writer: FirestoreSimpleBatchWriter = db.create_simple_batch_writer().await?;
    let mut report = SweepReport::default();
    // One query, streamed in the order of the `seal` index and cut into pages. A re-sealed
    // document moves to the current marker, out of the range the stream is still walking, so the
    // sweep's own writes never bring a document back, and no cursor between pages is needed.
    let mut pages = db
        .fluent()
        .select()
        .from(users.as_str())
        .filter(|q| q.field("seal").less_than(current))
        .obj::<UserDoc>()
        .stream_query_with_errors()
        .await?
        .chunks(PAGE_SIZE);
    while let Some(page) = pages.next().await {
        reseal_page(keyring, &writer, users, page, &mut report).await;
    }
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
        .obj()
        .query()
        .await?;
    if report.failed > 0 || !under_previous.is_empty() {
        return Err(format!(
            "{} users are left under key version {}",
            under_previous.len(),
            previous.as_u32()
        )
        .into());
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
    let outcome = run(&registry, &db, &users, count).await;
    registry.shutdown().await?;
    let deleted = delete_all(&db, &users).await? + delete_all(&db, &keyrings).await?;
    println!("deleted the example's {deleted} documents");
    outcome
}
