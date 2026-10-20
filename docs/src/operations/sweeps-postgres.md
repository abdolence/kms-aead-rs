# Sweeps on PostgreSQL

A sweep of a PostgreSQL table: the seal marker as a column, the query for the rows behind, and the
conditional write back. The mechanism is in [Sweeps](./sweeps.md), and the example has the five
properties of [Sweeps by store](./sweeps.md#sweeps-by-store).

The marker is a `BYTEA` column with a btree index. Its default, the bytes of
`SealMarker::ENVELOPE`, gives the rows written before the column a marker too:

```sql
ALTER TABLE users ADD COLUMN seal BYTEA NOT NULL DEFAULT '\x0100000000';
CREATE INDEX users_seal ON users (seal);
```

The candidates are one query, `seal < $1` with no `ORDER BY`, so the planner is free to read them
from the index on `seal`, and `query_raw` streams its rows: memory holds the batches in flight only.
The query holds its connection for as long as it streams, so the `UPDATE`s go through a second one.
`sweep::run_batched` cuts the candidates into batches of 1000 rows, each re-sealed through one sealer
and written back in one `UPDATE` over arrays of the ids, the new values and the values it read. The
`UPDATE` is conditional on the bytes it read, which a write of any other process changes, since
every randomised value has its own nonce. A process that has not seen the promotion yet still seals
under the old version and stamps the old epoch, which the row holds already, so the marker alone
does not detect its write:

```rust,no_run
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use futures_util::{future, StreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, NoTls, Row};
# use kms_aead::providers::GcpKmsKeyRef;
# use kms_aead_keyring::{KeyringId, KeyringRegistry, KeyringRegistryOptions};
# use tokio_postgres::Config;

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
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
/// A row the query returned, by its id. Its other columns are decoded in its batch, so a row that
/// does not decode is one failed candidate.
struct UserRow {
    id: i64,
    row: Row,
}

/// The row id, and nothing of its columns.
impl Display for UserRow {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users/{}", self.id)
    }
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
        .query_raw("SELECT id, email, seal FROM users WHERE seal < $1", [current])
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

/// The AAD the application gave its envelope values.
fn envelope_aad(id: i64) -> Vec<u8> {
    format!("users:{id}:email").into_bytes()
}

/// The stored `email` of `user`, that value under the active version of `sealer`, and the outcome
/// of its re-seal. A keyring value under that version comes back as it is, with
/// `ResealOutcome::Skipped`.
async fn reseal_row(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    user: &UserRow,
) -> Result<(Vec<u8>, Encrypted<Email, Randomized>, ResealOutcome), SweepError> {
    let read_email: Vec<u8> = user.row.try_get("email")?;
    let seal: SealMarker = user.row.try_get("seal")?;
    let aad = EMAIL.aad(&EntityId::try_from(user.id.to_string())?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Email, Envelope>::try_from(read_email.clone()).map_err(KeyringError::from)?;
        let opened: Email = keyring
            .decrypt_envelope_for_migration(&envelope_aad(user.id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((read_email, sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let email = Encrypted::<Email, Randomized>::try_from(read_email.clone()).map_err(KeyringError::from)?;
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &email).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (read_email, resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the row gets the marker alone
        None => (read_email, email, ResealOutcome::Skipped),
    })
}

/// Re-seals a batch of rows through one sealer, and writes it back in one `UPDATE` that stamps
/// the sealer's marker and is conditional, row by row, on the bytes the query read.
async fn reseal_batch(
    keyring: &UsersKeyring,
    client: &Client,
    batch: Vec<UserRow>,
) -> Result<Vec<(UserRow, Result<ResealOutcome, SweepError>)>, SweepError> {
    let sealer: UsersSealer<'_> = keyring.sealer().await;
    let seal: SealMarker = sealer.record().seal_marker();
    let mut done: Vec<(UserRow, Result<ResealOutcome, SweepError>)> =
        Vec::with_capacity(batch.len());
    let mut queued: Vec<(UserRow, ResealOutcome)> = Vec::with_capacity(batch.len());
    let mut ids: Vec<i64> = Vec::with_capacity(batch.len());
    let mut read_emails: Vec<Vec<u8>> = Vec::with_capacity(batch.len());
    let mut emails: Vec<Encrypted<Email, Randomized>> = Vec::with_capacity(batch.len());
    for user in batch {
        match reseal_row(keyring, &sealer, &user).await {
            Ok((read_email, email, outcome)) => {
                ids.push(user.id);
                read_emails.push(read_email);
                emails.push(email);
                queued.push((user, outcome));
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
        // A row the `UPDATE` did not return changed since the query: its writer re-sealed it
        let outcome = if written.contains(&user.id) {
            outcome
        } else {
            ResealOutcome::Skipped
        };
        (user, Ok(outcome))
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
# let config: Config = "postgres://app@localhost/app".parse()?;
# let (client, connection) = config.connect(NoTls).await?;
# tokio::spawn(connection);
# let (reader, connection) = config.connect(NoTls).await?;
# tokio::spawn(connection);
# let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
#     PostgresKeyringStore::new(config, NoTls),
#     KeyringRegistryOptions::new(),
# )?;
# let keyring: UsersKeyring = registry
#     .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
#     .await?;
let report: SweepReport = sweep_users(&keyring, &reader, &client).await?;
println!("{report:?}");
# registry.shutdown(None).await;
# Ok(())
# }
```

`SealMarker` is a `BYTEA` parameter and column through tokio-postgres with the `postgres` feature,
and through sqlx with the `sqlx` feature. The query holds one snapshot for as long as it streams,
and while it is open `VACUUM` cannot reclaim the old versions of the rows the sweep updates; a
scheduled job that ends and runs again keeps each snapshot short, since the query of the markers
below the current one returns exactly the rows the last run did not write.

The marker takes 6 bytes of a row: its 5 bytes and a 1-byte length header. A btree on a column of a
few distinct epochs stores each one once per page with the list of its rows: measured on
PostgreSQL 18 over 1 million rows of 7 epochs, the column took 6 bytes per row and its index about 7.
10 million rows hold about 130 MB of markers and index.

The [`sweep_postgres` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_postgres.rs)
runs this sweep end to end, from the writes to the report, on a local PostgreSQL.
