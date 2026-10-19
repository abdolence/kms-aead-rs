//! A sweep on PostgreSQL: writes users through a `Sealer`, each with its seal marker, rotates and
//! promotes the randomised version, re-seals every row whose marker is below the current one in
//! pages ordered by `id`, each page through one sealer and written back in one `UPDATE`
//! conditional on the bytes it read of each row, and retires the
//! previous version once the query of its seal range finds no row. The re-seal is the one of
//! [Sweeps by store](https://kms-aead-rust.abdolence.dev/operations.html#postgresql) in the book.
//!
//! The example creates a schema of its own, with the keyring table and the users table in it, and
//! drops it at the end. The keyring is under an ephemeral local KEK, so no cloud KMS is needed.
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

use futures_util::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{ResealOutcome, SealMarker, SealRange, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, KeyVersion, Keyring,
    KeyringAdmin, KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, Plaintext, Purpose, Resealed, Rotation,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, Config, NoTls, Row};

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// The rows of a page, re-sealed through one sealer and written back in one `UPDATE` of three
/// arrays of this length, some 0.2 MB of parameters at the example's row size.
const PAGE_SIZE: u16 = 1000;
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
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

/// Counts one row's outcome in `report`, and prints a failure with the row and the code of the
/// error.
fn tally(report: &mut SweepReport, id: i64, outcome: Result<ResealOutcome, &SweepError>) {
    report.scanned += 1;
    match outcome {
        Ok(ResealOutcome::Resealed { from_compromised }) => {
            report.resealed += 1;
            report.resealed_from_compromised += u64::from(from_compromised);
        }
        Ok(ResealOutcome::Skipped) => report.skipped += 1,
        Err(error) => {
            report.failed += 1;
            eprintln!("the re-seal of users/{id} failed: {error}");
        }
    }
}

/// Re-seals the page of rows after `after`, in the order of `id`, whose marker is below `current`
/// through one sealer, and writes it back in one `UPDATE` that stamps the sealer's marker and is
/// conditional, row by row, on the bytes the query read. Returns the last id of the page, or
/// `None` after the last page.
///
/// The `UPDATE` is the sealer's one write: it runs as soon as the page is sealed, so the sealer
/// is not held across more than one statement.
async fn reseal_page(
    keyring: &UsersKeyring,
    client: &Client,
    current: SealMarker,
    after: i64,
    report: &mut SweepReport,
) -> Result<Option<i64>, tokio_postgres::Error> {
    let rows: Vec<Row> = client
        .query(
            "SELECT id, email FROM users WHERE seal < $1 AND id > $2 ORDER BY id LIMIT $3",
            &[&current, &after, &i64::from(PAGE_SIZE)],
        )
        .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let sealer = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut ids: Vec<i64> = Vec::with_capacity(rows.len());
    let mut read_emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(rows.len());
    let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(rows.len());
    let mut outcomes: Vec<ResealOutcome> = Vec::with_capacity(rows.len());
    for row in &rows {
        let id: i64 = row.try_get("id")?;
        let queue = async {
            let read_email: Encrypted<Email, Randomized> = row.try_get("email")?;
            let aad = EMAIL.aad(&EntityId::try_from(id.to_string())?);
            // A value under a version newer than the sealer's record fails with
            // `SealerOutdated`: the sweep counts it as failed, and the next run, on the reloaded
            // record, re-seals it.
            let resealed: Option<Resealed<Email, Randomized>> =
                sealer.reseal(&aad, &read_email).await?;
            match resealed {
                Some(resealed) => {
                    let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
                    emails.push(resealed.value);
                    outcomes.push(ResealOutcome::Resealed { from_compromised });
                }
                None => {
                    emails.push(read_email.clone());
                    outcomes.push(ResealOutcome::Skipped);
                }
            }
            ids.push(id);
            read_emails.push(read_email);
            Ok::<(), SweepError>(())
        };
        if let Err(error) = queue.await {
            tally(report, id, Err(&error));
        }
    }
    let written: Result<Vec<Row>, tokio_postgres::Error> = client
        .query(
            "UPDATE users SET email = page.email, seal = $4
             FROM unnest($1::BIGINT[], $2::BYTEA[], $3::BYTEA[]) AS page(id, email, read_email)
             WHERE users.id = page.id AND users.email = page.read_email
             RETURNING users.id",
            &[&ids, &emails, &read_emails, &seal],
        )
        .await;
    match written {
        Ok(written) => {
            let written: HashSet<i64> = written
                .iter()
                .map(|row| row.try_get("id"))
                .collect::<Result<HashSet<i64>, tokio_postgres::Error>>()?;
            for (id, outcome) in ids.into_iter().zip(outcomes) {
                // A row the `UPDATE` did not return changed since the query: its writer sealed it
                // under its own record
                let outcome = if written.contains(&id) {
                    outcome
                } else {
                    ResealOutcome::Skipped
                };
                tally(report, id, Ok(outcome));
            }
        }
        Err(error) => {
            let error = SweepError::Users(error);
            for id in ids {
                tally(report, id, Err(&error));
            }
        }
    }
    let last: Option<i64> = match rows.last() {
        Some(row) if rows.len() == usize::from(PAGE_SIZE) => Some(row.try_get("id")?),
        _ => None,
    };
    Ok(last)
}

/// Writes `count` users, rotates, sweeps, and retires the previous version.
async fn run(
    registry: &KeyringRegistry<PostgresKeyringStore<NoTls>, Ring>,
    client: &Client,
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

    let started = Instant::now();
    stream::iter(1..=count)
        .map(Ok)
        .try_for_each_concurrent(CONCURRENCY.get(), |id: i64| async move {
            let sealer = keyring.sealer().await;
            let email: Encrypted<Email, Randomized> = sealer
                .encrypt(
                    &EMAIL.aad(&EntityId::try_from(id.to_string())?),
                    &Email(format!("user-{id}@example.com")),
                )
                .await?;
            let seal: SealMarker = sealer.record().seal_marker();
            client
                .execute(
                    "INSERT INTO users (id, email, seal) VALUES ($1, $2, $3)",
                    &[&id, &email, &seal],
                )
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
    let mut report = SweepReport::default();
    // Pages by `id`, not by marker: a re-sealed row leaves the query but not the order, so the
    // next page starts after it whatever marker any write gave the rows of earlier pages.
    let mut after: Option<i64> = Some(i64::MIN);
    while let Some(last) = after {
        after = reseal_page(keyring, client, current, last, &mut report).await?;
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
    let under_previous: i64 = client
        .query_one(
            "SELECT count(*) FROM users WHERE seal >= $1 AND ($2::BYTEA IS NULL OR seal < $2)",
            &[&range.start(), &range.end()],
        )
        .await?
        .try_get(0)?;
    if report.failed > 0 || under_previous > 0 {
        return Err(format!(
            "{under_previous} users are left under key version {}",
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
    let count: i64 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USERS,
    };
    let schema = format!("sweep_example_{}", uuid::Uuid::now_v7().simple());
    // Every session of the example, the keyring store's included, resolves `users` and
    // `kms_keyrings` in the example's own schema.
    let mut config: Config = std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?.parse()?;
    config.options(format!("-c search_path={schema}"));
    let (client, connection) = config.connect(NoTls).await?;
    tokio::spawn(connection);
    client
        .batch_execute(&format!(
            "CREATE SCHEMA {schema};
            CREATE TABLE {schema}.kms_keyrings (
                id         TEXT PRIMARY KEY,
                record     JSONB NOT NULL,
                revision   BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            );
            CREATE TABLE {schema}.users (
                id    BIGINT PRIMARY KEY,
                email BYTEA NOT NULL,
                seal  BYTEA NOT NULL DEFAULT '\\x0100000000'
            );
            CREATE INDEX users_seal ON {schema}.users (seal);"
        ))
        .await?;

    let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
        PostgresKeyringStore::new(config, NoTls),
        KeyringRegistryOptions::new(),
    )?;
    let outcome = run(&registry, &client, count).await;
    registry.shutdown().await?;
    client
        .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
        .await?;
    println!("dropped the example's schema {schema}");
    outcome
}
