//! A sweep on PostgreSQL: writes users through a `Sealer`, each with its seal marker, rotates and
//! promotes the randomised version, re-seals every row whose marker is below the current one in
//! pages ordered by `id`, with an `UPDATE` conditional on the bytes it read, and retires the
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

use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;
use std::time::Instant;

use futures_util::{stream, Stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SealRange, SweepReport};
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

/// A row the query returned, or the error of reading its page, which the sweep counts as failed.
enum Candidate {
    Row {
        id: i64,
        email: Encrypted<Email, Randomized>,
    },
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

/// The rows whose marker is below `current`, a page at a time in the order of `id`.
fn candidates(client: &Client, current: SealMarker) -> impl Stream<Item = Candidate> + '_ {
    stream::unfold(Some(i64::MIN), move |after| async move {
        let rows = client
            .query(
                "SELECT id, email FROM users WHERE seal < $1 AND id > $2 ORDER BY id LIMIT $3",
                &[&current, &after?, &i64::from(PAGE_SIZE)],
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

/// Re-seals a row under the active version and writes the marker of the sealer's record, unless
/// the row changed since the query read it.
async fn reseal(
    keyring: &UsersKeyring,
    client: &Client,
    candidate: Candidate,
) -> Result<ResealOutcome, SweepError> {
    let (id, read_email) = match candidate {
        Candidate::Row { id, email } => (id, email),
        Candidate::Unread(error) => return Err(SweepError::Users(error)),
    };
    let sealer = keyring.sealer().await;
    let aad = EMAIL.aad(&EntityId::try_from(id.to_string())?);
    // A value under a version newer than the sealer's record fails with `SealerOutdated`: the sweep
    // counts it as failed, and the next run, on the reloaded record, re-seals it.
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &read_email).await?;
    let (email, outcome) = match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        None => (read_email.clone(), ResealOutcome::Skipped),
    };
    let seal: SealMarker = sealer.record().seal_marker();
    let updated: u64 = client
        .execute(
            "UPDATE users SET email = $2, seal = $3 WHERE id = $1 AND email = $4",
            &[&id, &email, &seal, &read_email],
        )
        .await?;
    Ok(match updated {
        // A write since the query: the writer sealed the row under its own record
        0 => ResealOutcome::Skipped,
        _ => outcome,
    })
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
    let report: SweepReport = sweep::run(
        keyring.id(),
        candidates(client, current),
        CONCURRENCY,
        |candidate| reseal(keyring, client, candidate),
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
