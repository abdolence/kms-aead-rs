//! A keyring sweep on PostgreSQL: re-encrypts every row whose encryption marker is below the
//! current one, a batch at a time through one `Encryptor`, each batch in one `UPDATE` that writes a
//! row only if it still holds the bytes the query read. The sweep is `sweep_users` and
//! `reencrypt_batch`, and
//! [Sweeps on PostgreSQL](https://kms-aead-rust.abdolence.dev/operations/sweeps-postgres.html)
//! in the book explains it. The rest of the file runs it: it creates a schema, seeds users,
//! rotates, sweeps, and drops the schema.
//!
//! The keyring is under an ephemeral local KEK, so no cloud KMS is needed.
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
use std::time::Instant;

use futures_util::{future, stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{
    self, BatchedSweepOptions, EncryptionMarker, ReencryptOutcome, SweepReport,
};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
    Purpose,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, Config, NoTls, Row};

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// The rows of one encryptor and of one statement over arrays of this length, some 0.2 MB of
/// parameters at the example's row size.
const ROWS_PER_BATCH: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
/// On the example's one writing connection the batches queue up behind each other; a pool of
/// connections runs them in parallel.
const BATCHES_IN_FLIGHT: NonZeroUsize = NonZeroUsize::new(16).unwrap();
const DEFAULT_USER_COUNT: i64 = 100;

/// A row the sweep's query returned.
struct UserRow {
    id: i64,
    email: Encrypted<Email, Randomized>,
}

/// Re-encrypts every user whose marker is below the current one, read through `reader` and written
/// back through `writer` in batches of [`ROWS_PER_BATCH`] with [`BATCHES_IN_FLIGHT`] in flight.
/// The query is the checkpoint: a row the sweep wrote no longer matches it, so a sweep that stopped
/// part-way resumes by running again.
async fn sweep_users(
    keyring: &UsersKeyring,
    reader: &Client,
    writer: &Client,
) -> Result<SweepReport, tokio_postgres::Error> {
    let current: EncryptionMarker = keyring.record().encryption_marker();
    // A row that does not read is a failed candidate. An error of the stream itself is one too, and
    // ends it: once its connection drops, the stream returns that error on every poll and never
    // its end.
    let mut failed = false;
    let candidates = reader
        .query_raw(
            "SELECT id, email FROM users WHERE encryption_marker < $1",
            [current],
        )
        .await?
        .take_while(move |row: &Result<Row, tokio_postgres::Error>| {
            let more = !failed;
            failed = row.is_err();
            future::ready(more)
        })
        .map(|row: Result<Row, tokio_postgres::Error>| {
            let row: Row = row?;
            Ok::<UserRow, SweepError>(UserRow {
                id: row.try_get("id")?,
                email: row.try_get("email")?,
            })
        });
    let report: SweepReport = sweep::reencrypt_records_batched(
        keyring.id(),
        candidates,
        BatchedSweepOptions::new()
            .with_batch_size(ROWS_PER_BATCH)
            .with_concurrency(BATCHES_IN_FLIGHT),
        |batch: Vec<UserRow>| reencrypt_batch(keyring, writer, batch),
    )
    .await;
    Ok(report)
}

/// Re-encrypts a batch of rows through one encryptor and writes it back in one `UPDATE` that
/// stamps the encryptor's marker, row by row only where the row still holds the bytes the query
/// read. A row changed since the query is not returned by the `UPDATE`, and the sweep counts it as
/// skipped.
async fn reencrypt_batch(
    keyring: &UsersKeyring,
    client: &Client,
    batch: Vec<UserRow>,
) -> Result<Vec<(UserRow, Result<ReencryptOutcome, SweepError>)>, SweepError> {
    let encryptor = keyring.encryptor().await;
    let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
    let mut done: Vec<(UserRow, Result<ReencryptOutcome, SweepError>)> =
        Vec::with_capacity(batch.len());
    let mut queued: Vec<(UserRow, ReencryptOutcome)> = Vec::with_capacity(batch.len());
    let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(batch.len());
    for user in batch {
        let reencrypt = async {
            let aad = EMAIL.aad(&EntityId::try_from(user.id.to_string())?);
            let reencrypted = encryptor.reencrypt(&aad, &user.email).await?;
            let outcome = ReencryptOutcome::from(&reencrypted);
            // A current value still gets the encryptor's marker, so that it leaves the query.
            let email =
                reencrypted.map_or_else(|| user.email.clone(), |reencrypted| reencrypted.value);
            Ok::<_, SweepError>((email, outcome))
        };
        match reencrypt.await {
            Ok((email, outcome)) => {
                emails.push(email);
                queued.push((user, outcome));
            }
            Err(error) => done.push((user, Err(error))),
        }
    }
    let ids: Vec<i64> = queued.iter().map(|(user, _)| user.id).collect();
    let read_emails: Vec<&Encrypted<Email, Randomized>> =
        queued.iter().map(|(user, _)| &user.email).collect();
    let written: HashSet<i64> = client
        .query(
            "UPDATE users SET email = batch.email, encryption_marker = $4
             FROM unnest($1::BIGINT[], $2::BYTEA[], $3::BYTEA[]) AS batch(id, email, read_email)
             WHERE users.id = batch.id AND users.email = batch.read_email
             RETURNING users.id",
            &[&ids, &emails, &read_emails, &encryption_marker],
        )
        .await?
        .iter()
        .map(|row| row.try_get("id"))
        .collect::<Result<HashSet<i64>, tokio_postgres::Error>>()?;
    done.extend(queued.into_iter().map(|(user, outcome)| {
        // Written since the query: the writer encrypted the row under its own record.
        let outcome = if written.contains(&user.id) {
            outcome
        } else {
            ReencryptOutcome::Skipped
        };
        (user, Ok(outcome))
    }));
    Ok(done)
}

/// Why the sweep failed on a row or a batch: an error of the keyring or of the users table.
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

/// The row by its id: the candidate the sweep logs a failure with.
impl Display for UserRow {
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

// Running the example: creates the schema, seeds the users, rotates, sweeps, and drops the schema.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: i64 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USER_COUNT,
    };
    // Every session of the example, the keyring store's included, resolves `users` and
    // `kms_keyrings` in the example's own schema.
    let mut config: Config = std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?.parse()?;
    config.options("-c search_path=sweep_example");
    // The query streams on its connection for as long as it runs, so the writes use another.
    let (writer, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    let (reader, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    create_test_schema(&writer).await?;
    let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
        PostgresKeyringStore::new(config, NoTls),
        KeyringRegistryOptions::new(),
    )?;

    let outcome = run(&registry, &reader, &writer, count).await;
    registry.shutdown(None).await;
    let cleanup = delete_test_data(&writer).await;
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
        "swept to encryption marker {} in {:.2?}: {report:?}",
        keyring.record().encryption_marker(),
        started.elapsed(),
    );
    if report.failed > 0 {
        return Err(format!("{} users failed; the next run retries them", report.failed).into());
    }
    Ok(())
}

// The example's own data: a schema with the users, created before the sweep and dropped after it.

/// Creates the schema `sweep_example` with the keyring table and the users table, indexed on
/// `encryption_marker`. The name is fixed so that every statement is a literal, and a schema of
/// that name left by a run that crashed is dropped first.
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
                encryption_marker  BYTEA NOT NULL
            );
            CREATE INDEX users_encryption_marker ON sweep_example.users (encryption_marker);",
        )
        .await
}

/// Writes users `1..=count`, [`ROWS_PER_BATCH`] at a time through one encryptor and in one
/// `INSERT`, with [`BATCHES_IN_FLIGHT`] batches in flight.
async fn seed_test_data(
    keyring: &UsersKeyring,
    writer: &Client,
    count: i64,
) -> Result<(), Box<dyn Error>> {
    let started = Instant::now();
    stream::iter(1..=count)
        .chunks(ROWS_PER_BATCH.get())
        .map(Ok)
        .try_for_each_concurrent(BATCHES_IN_FLIGHT.get(), |ids: Vec<i64>| async move {
            let encryptor = keyring.encryptor().await;
            let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(ids.len());
            for id in &ids {
                emails.push(
                    encryptor
                        .encrypt(
                            &EMAIL.aad(&EntityId::try_from(id.to_string())?),
                            &Email(format!("user-{id}@example.com")),
                        )
                        .await?,
                );
            }
            let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
            writer
                .execute(
                    "INSERT INTO users (id, email, encryption_marker)
                     SELECT id, email, $3 FROM unnest($1::BIGINT[], $2::BYTEA[]) AS batch(id, email)",
                    &[&ids, &emails, &encryption_marker],
                )
                .await?;
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

/// Drops the schema `sweep_example` with the keyring record and the users in it.
async fn delete_test_data(client: &Client) -> Result<(), tokio_postgres::Error> {
    client
        .batch_execute("DROP SCHEMA sweep_example CASCADE")
        .await
}
