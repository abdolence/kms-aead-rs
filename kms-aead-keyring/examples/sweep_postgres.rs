//! A sweep on PostgreSQL: writes users a batch at a time, each batch through a `Sealer` and in one
//! `INSERT`, rotates and promotes the randomised version, re-seals every row whose marker is below
//! the current one with `sweep::run_batched`, read in one streamed query, each batch through one
//! sealer and written back in one `UPDATE` conditional on the bytes it read of each row, and
//! prints the sweep's report. The re-seal is the one of
//! [Sweeps on PostgreSQL](https://kms-aead-rust.abdolence.dev/operations/sweeps-postgres.html) in the book.
//!
//! The sweep is `sweep_users` and `reseal_batch`. `create_test_schema`, `seed_test_data` and
//! `delete_test_data`, at the end of the file, only create the example's tables and users before
//! it and drop them after.
//!
//! A sweep is a job that runs on a schedule, and again until its report shows nothing scanned.
//! Retiring the previous version is a separate administrative step, see
//! [Rotation cadence](https://kms-aead-rust.abdolence.dev/operations/rotation.html#rotation-cadence).
//!
//! Every read and write is sized for millions of rows, and memory holds the batches in flight
//! only. The candidates are one query, `seal < $1` with no `ORDER BY`, so the planner is free to
//! read them from the index on `seal`, and `query_raw` streams its rows: the connection reads the
//! next rows off the socket only once the sweep has taken the ones before, so the server waits
//! rather than the client buffering. The stream holds its connection for as long as it runs, so
//! the `UPDATE`s go through a second one.
//!
//! The query holds one snapshot for as long as it streams, and while it is open `VACUUM` cannot
//! reclaim the old versions of the rows the sweep updates. A sweep stopped part-way, or one that
//! failed on some rows, resumes when it runs again: the query of the markers below the current one
//! returns exactly the rows it did not write, so a scheduled job that ends and runs again keeps
//! each snapshot short, and nothing else needs to record how far it got.
//!
//! The example creates the schema `sweep_example`, with the keyring table and the users table in
//! it, and drops it at the end. The schema's name is fixed, so that every statement of the example
//! is a literal, and a run drops a schema of that name left over from a run that crashed before
//! it starts. The keyring is under an ephemeral local KEK, so no cloud KMS is needed.
//!
//! ```sh
//! docker run --rm -d --name kms-aead-postgres -e POSTGRES_PASSWORD=postgres -p 5432:5432 postgres:18
//! KMS_AEAD_KEYRING_POSTGRES_URL=postgres://postgres:postgres@127.0.0.1:5432/postgres \
//!   cargo run -p kms-aead-keyring --example sweep_postgres --features ring,admin,postgres -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::collections::HashSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use futures_util::{future, stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
    Purpose, Resealed,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, Config, NoTls, Row};

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// The rows of a batch of the sweep and of an `INSERT` of the seeding: one sealer seals them, and
/// one statement of arrays of this length, some 0.2 MB of parameters at the example's row size,
/// writes them.
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
/// The batches in flight at once. On the example's one writing connection they queue up behind
/// each other; a pool of connections runs them in parallel.
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// The users between two progress lines.
const PROGRESS_EVERY: usize = 100_000;
const DEFAULT_USERS: i64 = 100;

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

/// Why the sweep failed on a row, a page of its query or a batch: an error of the keyring or of
/// the users table.
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

/// A row the sweep's query returned, by its id.
struct UserRow {
    id: i64,
    row: Row,
}

impl Display for UserRow {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users/{}", self.id)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: i64 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USERS,
    };
    // Every session of the example, the keyring store's included, resolves `users` and
    // `kms_keyrings` in the example's own schema.
    let mut config: Config = std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?.parse()?;
    config.options("-c search_path=sweep_example");
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    let (reader, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    create_test_schema(&client).await?;
    let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
        PostgresKeyringStore::new(config, NoTls),
        KeyringRegistryOptions::new(),
    )?;

    let outcome = run(&registry, &reader, &client, count).await;
    registry.shutdown(None).await;
    let cleanup = delete_test_data(&client).await;
    outcome?;
    cleanup?;
    Ok(())
}

/// Seeds `count` users, rotates, sweeps and prints the sweep's report.
async fn run(
    registry: &KeyringRegistry<PostgresKeyringStore<NoTls>, Ring>,
    reader: &Client,
    writer: &Client,
    count: i64,
) -> Result<(), Box<dyn Error>> {
    let admin: KeyringAdmin<PostgresKeyringStore<NoTls>, LocalKmsProvider<Ring>, Ring> = registry
        .create(
            LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring: &UsersKeyring = admin.keyring();
    seed_test_data(keyring, writer, count).await?;

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    let started = Instant::now();
    let report: SweepReport = sweep_users(keyring, reader, writer).await?;
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

/// Re-seals every user whose marker is below the current one, read through `reader` and written
/// back through `writer` in batches of [`BATCH_SIZE`] with [`CONCURRENCY`] in flight, and returns
/// the sweep's report.
async fn sweep_users(
    keyring: &UsersKeyring,
    reader: &Client,
    writer: &Client,
) -> Result<SweepReport, tokio_postgres::Error> {
    let current: SealMarker = keyring.record().seal_marker();
    // A row whose id does not read is a failed candidate. An error of the stream itself is one
    // failed candidate and ends the stream: once its connection drops, the stream returns that
    // error on every poll and never its end.
    let candidates = reader
        .query_raw("SELECT id, email FROM users WHERE seal < $1", [current])
        .await?
        .scan(
            false,
            |ended: &mut bool, row: Result<Row, tokio_postgres::Error>| {
                if *ended {
                    return future::ready(None);
                }
                *ended = row.is_err();
                future::ready(Some(row))
            },
        )
        .map(|row: Result<Row, tokio_postgres::Error>| {
            let row: Row = row?;
            Ok::<UserRow, SweepError>(UserRow {
                id: row.try_get("id")?,
                row,
            })
        });
    let report: SweepReport = sweep::run_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(BATCH_SIZE)
            .with_concurrency(CONCURRENCY),
        |batch: Vec<UserRow>| reseal_batch(keyring, writer, batch),
    )
    .await;
    Ok(report)
}

/// Re-seals a batch of rows through one sealer, and writes it back in one `UPDATE` that stamps
/// the sealer's marker and is conditional, row by row, on the bytes the query read.
///
/// The `UPDATE` is the sealer's one write: it runs as soon as the batch is sealed, so the sealer
/// is not held across more than one statement.
async fn reseal_batch(
    keyring: &UsersKeyring,
    client: &Client,
    batch: Vec<UserRow>,
) -> Result<Vec<(UserRow, Result<ResealOutcome, SweepError>)>, SweepError> {
    let sealer = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut done: Vec<(UserRow, Result<ResealOutcome, SweepError>)> =
        Vec::with_capacity(batch.len());
    let mut queued: Vec<(UserRow, ResealOutcome)> = Vec::with_capacity(batch.len());
    let mut ids: Vec<i64> = Vec::with_capacity(batch.len());
    let mut read_emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(batch.len());
    let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(batch.len());
    for user in batch {
        let resealed = async {
            let read_email: Encrypted<Email, Randomized> = user.row.try_get("email")?;
            let aad = EMAIL.aad(&EntityId::try_from(user.id.to_string())?);
            let resealed: Option<Resealed<Email, Randomized>> =
                sealer.reseal(&aad, &read_email).await?;
            Ok::<
                (
                    Encrypted<Email, Randomized>,
                    Option<Resealed<Email, Randomized>>,
                ),
                SweepError,
            >((read_email, resealed))
        };
        match resealed.await {
            Ok((read_email, Some(resealed))) => {
                let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
                emails.push(resealed.value);
                read_emails.push(read_email);
                ids.push(user.id);
                queued.push((user, ResealOutcome::Resealed { from_compromised }));
            }
            Ok((read_email, None)) => {
                emails.push(read_email.clone());
                read_emails.push(read_email);
                ids.push(user.id);
                queued.push((user, ResealOutcome::Skipped));
            }
            Err(error) => done.push((user, Err(error))),
        }
    }
    let written: HashSet<i64> = client
        .query(
            "UPDATE users SET email = batch.email, seal = $4
             FROM unnest($1::BIGINT[], $2::BYTEA[], $3::BYTEA[]) AS batch(id, email, read_email)
             WHERE users.id = batch.id AND users.email = batch.read_email
             RETURNING users.id",
            &[&ids, &emails, &read_emails, &seal],
        )
        .await?
        .iter()
        .map(|row| row.try_get("id"))
        .collect::<Result<HashSet<i64>, tokio_postgres::Error>>()?;
    done.extend(queued.into_iter().map(|(user, outcome)| {
        // A row the `UPDATE` did not return changed since the query: its writer sealed it under
        // its own record.
        let outcome = if written.contains(&user.id) {
            outcome
        } else {
            ResealOutcome::Skipped
        };
        (user, Ok(outcome))
    }));
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

// The example's own data, not part of a sweep: its schema with the keyring table and the users
// in it, created before the sweep and dropped after it.

/// Creates the schema `sweep_example`, dropping one left over from an earlier run first, with the
/// keyring table and the users table, indexed on `seal`, in it.
async fn create_test_schema(client: &Client) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute(
            "DROP SCHEMA IF EXISTS sweep_example CASCADE;
            CREATE SCHEMA sweep_example;
            CREATE TABLE sweep_example.kms_keyrings (
                id         TEXT PRIMARY KEY,
                record     JSONB NOT NULL,
                revision   BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            CREATE TABLE sweep_example.users (
                id    BIGINT PRIMARY KEY,
                email BYTEA NOT NULL,
                seal  BYTEA NOT NULL DEFAULT '\\x0100000000'
            );
            CREATE INDEX users_seal ON sweep_example.users (seal);",
        )
        .await
}

/// Writes users `1..=count`, a batch of [`BATCH_SIZE`] at a time through one sealer and in one
/// `INSERT`, with [`CONCURRENCY`] batches in flight.
async fn seed_test_data(
    keyring: &UsersKeyring,
    writer: &Client,
    count: i64,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    let written = AtomicUsize::new(0);
    stream::iter(1..=count)
        .chunks(BATCH_SIZE.get())
        .map(Ok)
        .try_for_each_concurrent(CONCURRENCY.get(), |ids: Vec<i64>| {
            let written = &written;
            async move {
                let sealer = keyring.sealer().await;
                let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(ids.len());
                for id in &ids {
                    emails.push(
                        sealer
                            .encrypt(
                                &EMAIL.aad(&EntityId::try_from(id.to_string())?),
                                &Email(format!("user-{id}@example.com")),
                            )
                            .await?,
                    );
                }
                let seal: SealMarker = sealer.record().seal_marker();
                writer
                    .execute(
                        "INSERT INTO users (id, email, seal)
                         SELECT id, email, $3 FROM unnest($1::BIGINT[], $2::BYTEA[]) AS batch(id, email)",
                        &[&ids, &emails, &seal],
                    )
                    .await?;
                count_progress(written, ids.len(), "wrote");
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

/// Drops the schema `sweep_example` with the keyring record and the users in it.
async fn delete_test_data(client: &Client) -> Result<(), tokio_postgres::Error> {
    let started = Instant::now();
    client
        .batch_execute("DROP SCHEMA sweep_example CASCADE")
        .await?;
    println!(
        "dropped the example's schema sweep_example in {:.2?}",
        started.elapsed()
    );
    Ok(())
}
