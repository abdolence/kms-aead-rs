use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::future::poll_fn;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::join_all;
use tokio::sync::mpsc;
use tokio_postgres::tls::{MakeTlsConnect, TlsConnect};
use tokio_postgres::types::ToSql;
use tokio_postgres::{AsyncMessage, Client, Config, Connection, Socket};

use super::{
    KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap, WatchEvent,
};
use crate::errors::{Identifier, IdentifierRule, KeyringResult};
use crate::{KeyringError, KeyringId, KeyringRecord};

/// The delay before the second attempt to replace a lost listener connection. The first attempt
/// is immediate, and the delay doubles up to [`LISTENER_MAX_RETRY_DELAY`].
const LISTENER_FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
const LISTENER_MAX_RETRY_DELAY: Duration = Duration::from_secs(30);

/// A keyring store on PostgreSQL: one row per keyring in a table the operator creates, with a
/// `revision` counter for the compare-and-swap and `NOTIFY` for push.
///
/// The library runs no migrations. The table, [`PostgresTable::DEFAULT_NAME`] unless
/// [`with_table`](Self::with_table) names another, is:
///
/// ```sql
/// CREATE TABLE kms_keyrings (
///     id         TEXT PRIMARY KEY,
///     record     JSONB NOT NULL,
///     revision   BIGINT NOT NULL,
///     updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
/// );
/// ```
///
/// The serving principal needs `SELECT` on it, and the administrative one also `INSERT` and
/// `UPDATE`. Every write sends `NOTIFY <table>, '<keyring id>'` when it commits, and a
/// [`watch`](KeyringStore::watch) listens on that channel. PostgreSQL lets any session notify
/// any channel; a keyring revalidates at most once per
/// [`reload_min_interval`](crate::KeyringOptions::reload_min_interval) however many signals
/// arrive. PostgreSQL keeps no notification for a lost session, so a watch reports a lost
/// listener connection as [`WatchEvent::Disconnected`], replaces it, and reports
/// [`WatchEvent::Reconnected`], on which the keyring revalidates.
///
/// The store opens at most two connections with `config` and `tls`, both tokio-postgres's:
///
/// - the query connection, opened by the first call that reads or writes, and opened again by
///   the first call after it closes. Concurrent callers wait for one attempt and share its
///   outcome. The call that finds the connection lost fails; the next one reconnects;
/// - the listener connection, opened by the first watch and closed once the last watch is
///   dropped, however many keyrings watch.
///
/// `Clone` shares both connections, and [`with_table`](Self::with_table) shares the query
/// connection.
#[derive(Clone)]
pub struct PostgresKeyringStore<T> {
    connections: Arc<Connections<T>>,
    table: PostgresTable,
    statements: Arc<Statements>,
    watches: Arc<Watches>,
}

/// The name of the table of a [`PostgresKeyringStore`], which is also its `NOTIFY` channel:
/// 1 to 63 characters of `a`-`z`, `0`-`9` and `_`, not starting with a digit. The name is
/// unqualified, so the connection's `search_path` selects the schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PostgresTable(String);

/// The revision of a record in a [`PostgresKeyringStore`]: the row's `revision` column, 1 when
/// the record is created and incremented by every write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PostgresRevision(i64);

/// How a store connects, and its query connection, which the clones of a store share.
struct Connections<T> {
    config: Config,
    tls: T,
    /// The attempts to open the query connection so far. A caller reads it before it waits for
    /// `query`, so that it takes the outcome of an attempt made meanwhile rather than repeating
    /// a failed one.
    attempts: AtomicU64,
    query: tokio::sync::Mutex<QueryConnection>,
}

enum QueryConnection {
    Unopened,
    Open(Arc<Client>),
    Failed(Arc<tokio_postgres::Error>),
}

/// A connection listening on a store's channel.
struct Listener<S> {
    /// Held so that the session stays open: dropping the last client ends it.
    _client: Client,
    connection: Connection<Socket, S>,
}

/// The SQL of each operation, built once, since the table name is part of it.
struct Statements {
    load: String,
    revalidate: String,
    create: String,
    update: String,
}

/// The senders of the live watches of a store, by keyring id, which its listener task signals.
///
/// The map is not empty exactly while the task runs: a watch that finds it empty starts the
/// task, and the task ends when it finds every watch dropped. Only the task removes senders, so
/// that both decisions are taken under the one lock.
#[derive(Default)]
struct Watches(Mutex<HashMap<KeyringId, Vec<mpsc::Sender<WatchEvent>>>>);

impl<T> PostgresKeyringStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    /// The store on the table [`PostgresTable::DEFAULT_NAME`] of the database `config` names,
    /// over `tls`: `tokio_postgres::NoTls`, or a TLS connector such as tokio-postgres-rustls's
    /// `MakeRustlsConnect`. It connects on first use, not here.
    ///
    /// `config` bounds each attempt to connect only with its `connect_timeout`, and callers
    /// wait for the attempt in progress.
    pub fn new(config: Config, tls: T) -> Self {
        let table = PostgresTable(PostgresTable::DEFAULT_NAME.to_string());
        Self {
            connections: Arc::new(Connections {
                config,
                tls,
                attempts: AtomicU64::new(0),
                query: tokio::sync::Mutex::new(QueryConnection::Unopened),
            }),
            statements: Arc::new(Statements::new(&table)),
            table,
            watches: Arc::default(),
        }
    }

    /// The store on `table` instead.
    pub fn with_table(self, table: PostgresTable) -> Self {
        Self {
            statements: Arc::new(Statements::new(&table)),
            table,
            watches: Arc::default(),
            ..self
        }
    }
}

impl<T> Connections<T>
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    /// The query connection's client, opening the connection when it is not open.
    async fn client(&self) -> Result<Arc<Client>, Arc<tokio_postgres::Error>> {
        let seen = self.attempts.load(Ordering::Acquire);
        let mut query = self.query.lock().await;
        match &*query {
            QueryConnection::Open(client) if !client.is_closed() => return Ok(client.clone()),
            QueryConnection::Failed(error) if self.attempts.load(Ordering::Acquire) != seen => {
                return Err(error.clone());
            }
            QueryConnection::Unopened | QueryConnection::Open(_) | QueryConnection::Failed(_) => {}
        }
        let opened = self.config.connect(self.tls.clone()).await;
        self.attempts.fetch_add(1, Ordering::Release);
        match opened {
            Ok((client, connection)) => {
                let client = Arc::new(client);
                // The task ends with the session; the client then reports itself closed.
                tokio::spawn(connection);
                *query = QueryConnection::Open(client.clone());
                Ok(client)
            }
            Err(error) => {
                let error = Arc::new(error);
                *query = QueryConnection::Failed(error.clone());
                Err(error)
            }
        }
    }

    /// A new connection listening on `table`'s channel. A notification that arrives before the
    /// `LISTEN` completes goes to `watches`.
    async fn listen(
        &self,
        table: &PostgresTable,
        watches: &Watches,
    ) -> Result<Listener<T::Stream>, tokio_postgres::Error> {
        let (client, mut connection) = self.config.connect(self.tls.clone()).await?;
        let statement = format!(r#"LISTEN "{table}""#);
        {
            let listening = client.batch_execute(&statement);
            tokio::pin!(listening);
            // The connection makes progress only while its messages are polled.
            loop {
                tokio::select! {
                    listened = &mut listening => {
                        listened?;
                        break;
                    }
                    message = poll_fn(|cx| connection.poll_message(cx)) => match message {
                        Some(Ok(AsyncMessage::Notification(notification))) => {
                            watches.signal(Some(notification.payload()), WatchEvent::Changed);
                        }
                        Some(Ok(_)) => {}
                        Some(Err(error)) => return Err(error),
                        // The session ended, and the `LISTEN` will never complete. The listener
                        // reports the end to its watches when it is first polled.
                        None => break,
                    },
                }
            }
        }
        Ok(Listener {
            _client: client,
            connection,
        })
    }

    /// Forwards the notifications on `table`'s channel to the watches of the keyring each one
    /// names, until every watch is dropped. A lost connection is reported to every watch and
    /// replaced at once, then after a delay that doubles from [`LISTENER_FIRST_RETRY_DELAY`] up to
    /// [`LISTENER_MAX_RETRY_DELAY`] while PostgreSQL stays unreachable.
    async fn forward(
        self: Arc<Self>,
        mut listener: Listener<T::Stream>,
        table: PostgresTable,
        watches: Arc<Watches>,
    ) {
        loop {
            loop {
                let Some(senders) = watches.live() else {
                    return;
                };
                let received = tokio::select! {
                    _ = join_all(senders.iter().map(mpsc::Sender::closed)) => continue,
                    received = poll_fn(|cx| listener.connection.poll_message(cx)) => received,
                };
                match received {
                    Some(Ok(AsyncMessage::Notification(notification))) => {
                        watches.signal(Some(notification.payload()), WatchEvent::Changed);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
            watches.signal(None, WatchEvent::Disconnected);
            let mut delay = LISTENER_FIRST_RETRY_DELAY;
            listener = loop {
                let Some(senders) = watches.live() else {
                    return;
                };
                if let Ok(listener) = self.listen(&table, &watches).await {
                    break listener;
                }
                tokio::select! {
                    _ = join_all(senders.iter().map(mpsc::Sender::closed)) => {}
                    () = tokio::time::sleep(delay) => {}
                }
                delay = (delay * 2).min(LISTENER_MAX_RETRY_DELAY);
            };
            watches.signal(None, WatchEvent::Reconnected);
        }
    }
}

impl Watches {
    /// The map stays consistent through a panic elsewhere: no code under the lock panics
    /// between two changes of it.
    fn lock(&self) -> MutexGuard<'_, HashMap<KeyringId, Vec<mpsc::Sender<WatchEvent>>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `events` to the watches of `id` when the listener task runs, and gives it back when
    /// none does.
    fn join(
        &self,
        id: &KeyringId,
        events: mpsc::Sender<WatchEvent>,
    ) -> Result<(), mpsc::Sender<WatchEvent>> {
        let mut watches = self.lock();
        if watches.is_empty() {
            return Err(events);
        }
        watches.entry(id.clone()).or_default().push(events);
        Ok(())
    }

    /// Adds `events` to the watches of `id`, and returns `true` when no listener task runs, so
    /// that the caller starts one.
    fn insert(&self, id: &KeyringId, events: mpsc::Sender<WatchEvent>) -> bool {
        let mut watches = self.lock();
        let start = watches.is_empty();
        watches.entry(id.clone()).or_default().push(events);
        start
    }

    /// Forgets the dropped watches, and returns a sender of each live one, or `None` when every
    /// watch is dropped, after which the listener task ends.
    fn live(&self) -> Option<Vec<mpsc::Sender<WatchEvent>>> {
        let mut watches = self.lock();
        watches.retain(|_, senders| {
            senders.retain(|events| !events.is_closed());
            !senders.is_empty()
        });
        (!watches.is_empty()).then(|| watches.values().flatten().cloned().collect())
    }

    /// Sends `event` to the watches of the keyring `payload` names, or to every watch when it is
    /// `None`. A full channel already holds a signal, and the revalidation it causes covers this
    /// one too.
    fn signal(&self, payload: Option<&str>, event: WatchEvent) {
        let watches = self.lock();
        let senders: Vec<_> = match payload {
            None => watches.values().flatten().collect(),
            Some(payload) => KeyringId::try_from(payload.to_string())
                .ok()
                .and_then(|id| watches.get(&id))
                .into_iter()
                .flatten()
                .collect(),
        };
        for events in senders {
            // A dropped watch is forgotten by `live`.
            let _ = events.try_send(event);
        }
    }
}

impl Statements {
    fn new(table: &PostgresTable) -> Self {
        let table = &table.0;
        // The record crosses as its JSON text both ways, so that `from_json` checks the document
        // PostgreSQL holds, byte caps included.
        Self {
            load: format!(r#"SELECT record::text, revision FROM "{table}" WHERE id = $1"#),
            revalidate: format!(
                r#"SELECT CASE WHEN revision <> $2 THEN record::text END, revision
                FROM "{table}" WHERE id = $1"#
            ),
            // `pg_notify` runs once per written row, inside the statement's own transaction: a
            // conflict signals nothing, and the signal is delivered when the write commits.
            create: format!(
                r#"WITH written AS (
                    INSERT INTO "{table}" (id, record, revision)
                    VALUES ($1, convert_from($2, 'UTF8')::jsonb, 1)
                    ON CONFLICT (id) DO NOTHING
                    RETURNING id, revision
                )
                SELECT revision, pg_notify($3, id)::text FROM written"#
            ),
            update: format!(
                r#"WITH written AS (
                    UPDATE "{table}"
                    SET record = convert_from($2, 'UTF8')::jsonb, revision = revision + 1,
                        updated_at = now()
                    WHERE id = $1 AND revision = $4
                    RETURNING id, revision
                )
                SELECT revision, pg_notify($3, id)::text FROM written"#
            ),
        }
    }
}

impl PostgresTable {
    /// The table of a store that [`with_table`](PostgresKeyringStore::with_table) names no
    /// other for.
    pub const DEFAULT_NAME: &'static str = "kms_keyrings";
}

impl TryFrom<String> for PostgresTable {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] when `name` breaks the rule of the type.
    fn try_from(name: String) -> KeyringResult<Self> {
        let invalid = |rule| KeyringError::invalid_identifier(Identifier::PostgresTable, rule);
        if name.is_empty() || name.len() > 63 {
            return Err(invalid(IdentifierRule::Length));
        }
        let allowed = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_';
        if !name.chars().all(allowed) || name.starts_with(|c: char| c.is_ascii_digit()) {
            return Err(invalid(IdentifierRule::Character));
        }
        Ok(Self(name))
    }
}

impl Display for PostgresTable {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Display for PostgresRevision {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// The store error of `operation` for `error`. A server error keeps its primary message and
/// SQLSTATE only: its detail, hint and context may quote the row, and with it the record's
/// encrypted DEKs. Its `Display` and `Debug` carry all three, so it is not kept as the root cause.
fn store_error(
    operation: StoreOperation,
    error: impl Into<Arc<tokio_postgres::Error>>,
) -> KeyringError {
    let error = error.into();
    if let Some(database) = error.as_db_error() {
        let message = format!(
            "{} (SQLSTATE {})",
            database.message(),
            database.code().code()
        );
        return KeyringError::store(StoreKind::Postgres, operation, &message);
    }
    KeyringError::store_caused_by(StoreKind::Postgres, operation, error)
}

fn stored(
    id: &KeyringId,
    document: &str,
    revision: i64,
) -> KeyringResult<Stored<PostgresRevision>> {
    Ok(Stored {
        record: KeyringRecord::from_json(id, document.as_bytes())?,
        revision: PostgresRevision(revision),
    })
}

impl<T> KeyringStore for PostgresKeyringStore<T>
where
    T: MakeTlsConnect<Socket> + Clone + Send + Sync + 'static,
    T::Stream: Send + 'static,
    T::TlsConnect: Send,
    <T::TlsConnect as TlsConnect<Socket>>::Future: Send,
{
    type Revision = PostgresRevision;

    const KIND: StoreKind = StoreKind::Postgres;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<PostgresRevision>>> {
        let row: Option<(String, i64)> = async {
            let client = self.connections.client().await?;
            let row = client
                .query_opt(&self.statements.load, &[&id.as_str()])
                .await?;
            row.map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
                .transpose()
        }
        .await
        .map_err(|error: Arc<tokio_postgres::Error>| store_error(StoreOperation::Load, error))?;
        row.map(|(document, revision)| stored(id, &document, revision))
            .transpose()
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &PostgresRevision,
    ) -> KeyringResult<Revalidation<PostgresRevision>> {
        let row: Option<(Option<String>, i64)> = async {
            let client = self.connections.client().await?;
            let row = client
                .query_opt(&self.statements.revalidate, &[&id.as_str(), &known.0])
                .await?;
            row.map(|row| Ok((row.try_get(0)?, row.try_get(1)?)))
                .transpose()
        }
        .await
        .map_err(|error: Arc<tokio_postgres::Error>| {
            store_error(StoreOperation::Revalidate, error)
        })?;
        match row {
            None => Ok(Revalidation::Missing),
            Some((None, _)) => Ok(Revalidation::Unchanged),
            Some((Some(document), revision)) => {
                stored(id, &document, revision).map(Revalidation::Changed)
            }
        }
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&PostgresRevision>,
    ) -> KeyringResult<Swap<PostgresRevision>> {
        let document = record.to_json()?;
        let id = record.id().as_str();
        let channel = self.table.0.as_str();
        let (statement, parameters): (_, Vec<&(dyn ToSql + Sync)>) = match expected {
            None => (&self.statements.create, vec![&id, &document, &channel]),
            Some(expected) => (
                &self.statements.update,
                vec![&id, &document, &channel, &expected.0],
            ),
        };
        let written: Option<i64> = async {
            let client = self.connections.client().await?;
            let row = client.query_opt(statement, &parameters).await?;
            row.map(|row| row.try_get(0)).transpose().map_err(Arc::new)
        }
        .await
        .map_err(|error: Arc<tokio_postgres::Error>| {
            store_error(StoreOperation::CompareAndSwap, error)
        })?;
        Ok(written.map_or(Swap::Conflict, |revision| {
            Swap::Written(PostgresRevision(revision))
        }))
    }

    /// A watch on the store's shared listener. The first watch opens the listener connection,
    /// which closes once the last watch is dropped.
    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        let (events, receiver) = mpsc::channel(16);
        if let Err(events) = self.watches.join(id, events) {
            let listener = self
                .connections
                .listen(&self.table, &self.watches)
                .await
                .map_err(|error| store_error(StoreOperation::Watch, error))?;
            // Another watch may have started the listener meanwhile; this one is then dropped,
            // and its connection closed.
            if self.watches.insert(id, events) {
                tokio::spawn(self.connections.clone().forward(
                    listener,
                    self.table.clone(),
                    self.watches.clone(),
                ));
            }
        }
        Ok(Some(KeyringWatch::new(receiver)))
    }
}

#[cfg(test)]
mod tests {
    use tokio_postgres::NoTls;

    use super::*;
    use crate::test_support::TestResult;

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn revalidate_returns_no_payload_when_unchanged() -> TestResult {
        let (client, connection) =
            tokio_postgres::connect(&std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?, NoTls)
                .await?;
        tokio::spawn(connection);
        let table =
            PostgresTable::try_from(format!("kms_keyrings_{}", uuid::Uuid::now_v7().simple()))?;
        client
            .batch_execute(&format!(
                r#"CREATE TABLE "{table}" (id TEXT PRIMARY KEY, record JSONB NOT NULL,
                    revision BIGINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
                INSERT INTO "{table}" (id, record, revision) VALUES ('tenant-42', '{{}}', 7)"#
            ))
            .await?;
        let revalidate = Statements::new(&table).revalidate;
        for (known, payload) in [(7_i64, false), (6, true)] {
            let row = client
                .query_one(&revalidate, &[&"tenant-42", &known])
                .await?;
            let (record, revision): (Option<String>, i64) = (row.try_get(0)?, row.try_get(1)?);
            assert_eq!((record.is_some(), revision), (payload, 7));
        }
        client
            .batch_execute(&format!(r#"DROP TABLE "{table}""#))
            .await?;
        Ok(())
    }
}
