# Sweeps on PostgreSQL

A sweep of a PostgreSQL table: the encryption marker as a column, the query for the rows behind,
and the conditional write back. The mechanism is in [Sweeps](./sweeps.md), and the example has the
five properties of [Sweeps by store](./sweeps.md#sweeps-by-store).

The marker is a `BYTEA` column with a btree index:

```sql
CREATE TABLE users (
    id BIGINT PRIMARY KEY,
    email BYTEA NOT NULL,
    encryption_marker BYTEA NOT NULL
);
CREATE INDEX users_encryption_marker ON users (encryption_marker);
```

The candidates are one query, `encryption_marker < $1` with no `ORDER BY`, so the planner is free to
read them from the index on `encryption_marker`, and `query_raw` streams its rows: memory holds the
batches in flight only. The query holds its connection for as long as it streams, so the `UPDATE`s
go through a second one. `sweep::reencrypt_records_batched` cuts the candidates into batches of 1000 rows, each
re-encrypted through one encryptor and written back in one `UPDATE` over arrays of the ids, the new
values and the values it read. The `UPDATE` is conditional on the bytes it read, which a write of
any other process changes, since every randomised value has its own nonce. A process that has not
seen the promotion yet still encrypts under the old version and stamps the old epoch, which the row
holds already, so the marker alone does not detect its write:

```rust,no_run
use std::collections::HashSet;
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use futures_util::{future, StreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ReencryptOutcome, EncryptionMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringError, Plaintext,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, NoTls, Row};
# use kms_aead::providers::GcpKmsKeyRef;
# use kms_aead_keyring::{KeyringId, KeyringRegistry, KeyringRegistryOptions};
# use tokio_postgres::Config;

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();

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
/// A row the query returned.
struct UserRow {
    id: i64,
    email: Encrypted<Email, Randomized>,
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

/// Re-encrypts every user whose marker is below the current one, read through `reader` and written
/// back through `writer` in batches of [`BATCH_SIZE`] with [`CONCURRENCY`] in flight, and returns
/// the sweep's report.
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
        .query_raw("SELECT id, email FROM users WHERE encryption_marker < $1", [current])
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
            .with_batch_size(BATCH_SIZE)
            .with_concurrency(CONCURRENCY),
        |batch: Vec<UserRow>| reencrypt_batch(keyring, writer, batch),
    )
    .await;
    Ok(report)
}

/// Re-encrypts a batch of rows through one encryptor and writes it back in one `UPDATE` that stamps
/// the encryptor's marker, row by row only where the row still holds the bytes the query read. A
/// row changed since the query is not returned by the `UPDATE`, and the sweep counts it as skipped.
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
            let email = reencrypted.map_or_else(|| user.email.clone(), |reencrypted| reencrypted.value);
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

`CONCURRENCY` bounds the batches in flight, but one writing connection runs their `UPDATE`s one
after another; a pool of connections runs them in parallel.

`EncryptionMarker` is a `BYTEA` parameter and column through tokio-postgres with the `postgres`
feature, and through sqlx with the `sqlx` feature. The query holds one snapshot for as long as it
streams, and while it is open `VACUUM` cannot reclaim the old versions of the rows the sweep
updates; a scheduled job that ends and runs again keeps each snapshot short, since the query of the
markers below the current one returns exactly the rows the last run did not write.

The marker takes 6 bytes of a row: its 5 bytes and a 1-byte length header. A btree on a column of a
few distinct epochs stores each one once per page with the list of its rows: measured on
PostgreSQL 18 over 1 million rows of 7 epochs, the column took 6 bytes per row and its index about 7.
10 million rows hold about 130 MB of markers and index.

The [`sweep_postgres` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_postgres.rs)
runs this sweep end to end, from the writes to the report, on a local PostgreSQL.
