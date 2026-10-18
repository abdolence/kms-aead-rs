//! `Encrypted` values stored as `BYTEA` through tokio-postgres and sqlx. They are ignored by
//! default; to run them:
//!
//! ```sh
//! docker run --rm -d --name kms-aead-pg-fields -e POSTGRES_PASSWORD=postgres -p 55432:5432 postgres:16
//! DATABASE_URL=postgres://postgres:postgres@127.0.0.1:55432/postgres \
//!   cargo test --features ring,postgres,sqlx --test postgres_fields -- --ignored
//! ```

use std::collections::BTreeSet;
use std::error::Error;

use kms_aead::errors::KmsAeadError;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope, Ring, ValueStruct};
use sqlx::{Connection, PgConnection, Row};

type TestResult<T> = Result<T, Box<dyn Error>>;

type LocalEnvelope = KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>;

const EMAILS: [&str; 3] = ["ada@example.com", "grace@example.com", "edsger@example.com"];
const AAD: &[u8] = b"users/email";
const CREATE_TABLE: &str = "CREATE TEMP TABLE users (email BYTEA NOT NULL)";
const INSERT: &str = "INSERT INTO users (email) VALUES ($1)";
const SELECT_ANY: &str = "SELECT email FROM users WHERE email = ANY($1)";
/// A first byte that starts no envelope layout.
const SELECT_MALFORMED: &str = "SELECT '\\x02'::bytea";

/// An envelope on a fresh local key, and `EMAILS` sealed under it.
async fn sealed_emails() -> TestResult<(LocalEnvelope, Vec<Encrypted<String, Envelope>>)> {
    let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("users".to_string())?)?;
    let envelope = LocalEnvelope::new(provider)?;
    let mut sealed = Vec::new();
    for email in EMAILS {
        sealed.push(envelope.encrypt_field(AAD, &email.to_string()).await?);
    }
    Ok((envelope, sealed))
}

fn stored_bytes(values: &[Encrypted<String, Envelope>]) -> BTreeSet<Vec<u8>> {
    values.iter().map(|value| value.value().clone()).collect()
}

/// The first two of `EMAILS`, the ones the probes select by `= ANY($1)`.
fn selected_emails() -> BTreeSet<String> {
    BTreeSet::from([EMAILS[0].to_string(), EMAILS[1].to_string()])
}

#[tokio::test]
#[ignore = "needs a PostgreSQL server at DATABASE_URL"]
async fn tokio_postgres_stores_values_and_checks_them_at_decode() -> TestResult<()> {
    let (envelope, sealed) = sealed_emails().await?;
    let (client, connection) =
        tokio_postgres::connect(&std::env::var("DATABASE_URL")?, tokio_postgres::NoTls).await?;
    tokio::spawn(connection);
    client.execute(CREATE_TABLE, &[]).await?;
    for value in &sealed {
        client.execute(INSERT, &[value]).await?;
    }

    let rows = client.query(SELECT_ANY, &[&&sealed[..2]]).await?;
    let selected = rows
        .iter()
        .map(|row| row.try_get(0))
        .collect::<Result<Vec<Encrypted<String, Envelope>>, _>>()?;
    let malformed = client
        .query_one(SELECT_MALFORMED, &[])
        .await?
        .try_get::<_, Encrypted<String, Envelope>>(0)
        .err();

    assert_eq!(stored_bytes(&selected), stored_bytes(&sealed[..2]));
    let mut emails = BTreeSet::new();
    for value in &selected {
        emails.insert(envelope.decrypt_field(AAD, value).await?);
    }
    assert_eq!(emails, selected_emails());
    assert!(
        matches!(&malformed, Some(error)
            if error.source().is_some_and(|source| source.is::<KmsAeadError>())),
        "{malformed:?}"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "needs a PostgreSQL server at DATABASE_URL"]
async fn sqlx_stores_values_and_checks_them_at_decode() -> TestResult<()> {
    let (envelope, sealed) = sealed_emails().await?;
    let mut connection = PgConnection::connect(&std::env::var("DATABASE_URL")?).await?;
    sqlx::query(CREATE_TABLE).execute(&mut connection).await?;
    for value in &sealed {
        sqlx::query(INSERT)
            .bind(value)
            .execute(&mut connection)
            .await?;
    }

    let rows = sqlx::query(SELECT_ANY)
        .bind(&sealed[..2])
        .fetch_all(&mut connection)
        .await?;
    let selected = rows
        .iter()
        .map(|row| row.try_get(0))
        .collect::<Result<Vec<Encrypted<String, Envelope>>, _>>()?;
    let malformed = sqlx::query(SELECT_MALFORMED)
        .fetch_one(&mut connection)
        .await?
        .try_get::<Encrypted<String, Envelope>, _>(0);

    assert_eq!(stored_bytes(&selected), stored_bytes(&sealed[..2]));
    let mut emails = BTreeSet::new();
    for value in &selected {
        emails.insert(envelope.decrypt_field(AAD, value).await?);
    }
    assert_eq!(emails, selected_emails());
    assert!(
        matches!(&malformed, Err(sqlx::Error::ColumnDecode { source, .. })
            if source.is::<KmsAeadError>()),
        "{malformed:?}"
    );
    Ok(())
}
