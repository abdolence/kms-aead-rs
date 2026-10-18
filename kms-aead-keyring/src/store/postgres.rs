use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use futures_util::future::join_all;
use sqlx::postgres::{PgListener, PgPool};
use sqlx::AssertSqlSafe;
use tokio::sync::mpsc;

use super::{
    KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap, WatchEvent,
};
use crate::errors::{Identifier, IdentifierRule, KeyringResult, KeyringStoreError};
use crate::{KeyringError, KeyringId, KeyringRecord};

/// A keyring store on PostgreSQL: one row per keyring in a table the operator creates, with a
/// `revision` counter for the compare-and-swap and `NOTIFY` for push.
///
/// The library runs no migrations. The table, `kms_keyrings` unless
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
/// The [`PgPool`] is sqlx's, a deliberate integration point: the application owns the pool, its
/// connection options and its TLS stack, which the `postgres-tls-*` features select. The watches
/// of a store share one listener, which holds one connection of the pool from the first watch
/// until the last one is dropped, however many keyrings watch. `Clone` shares the pool and the
/// listener.
#[derive(Clone)]
pub struct PostgresKeyringStore {
    pool: PgPool,
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

impl PostgresKeyringStore {
    /// The store on the table `kms_keyrings` of `pool`'s database.
    pub fn new(pool: PgPool) -> Self {
        let table = PostgresTable(String::from("kms_keyrings"));
        Self {
            pool,
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
/// wrapped keys.
fn store_error(operation: StoreOperation, error: sqlx::Error) -> KeyringError {
    let error = match error {
        sqlx::Error::Database(database) => {
            let message = format!(
                "{} (SQLSTATE {})",
                database.message(),
                database.code().unwrap_or_default()
            );
            return KeyringError::Store(KeyringStoreError::new(
                StoreKind::Postgres,
                operation,
                message,
            ));
        }
        error => error,
    };
    KeyringError::Store(
        KeyringStoreError::new(StoreKind::Postgres, operation, error.to_string())
            .with_root_cause(Arc::new(error)),
    )
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

/// A listener on `table`'s channel, on a connection of its own from `pool`.
async fn listen(pool: &PgPool, table: &PostgresTable) -> Result<PgListener, sqlx::Error> {
    let mut listener = PgListener::connect_with(pool).await?;
    // `forward` replaces a lost connection itself, so that every watch hears of both ends of
    // the gap.
    listener.eager_reconnect(false);
    listener.listen(&table.0).await?;
    Ok(listener)
}

/// Forwards the notifications on `table`'s channel to the watches of the keyring each one names,
/// until every watch is dropped or the pool is closed. A lost connection is reported to every
/// watch and replaced at once, then after a delay that doubles up to 30 seconds while
/// PostgreSQL stays unreachable.
async fn forward(
    mut listener: PgListener,
    pool: PgPool,
    table: PostgresTable,
    watches: Arc<Watches>,
) {
    const FIRST_RETRY_DELAY: Duration = Duration::from_millis(500);
    const MAX_RETRY_DELAY: Duration = Duration::from_secs(30);
    loop {
        loop {
            let Some(senders) = watches.live() else {
                return;
            };
            let received = tokio::select! {
                _ = join_all(senders.iter().map(mpsc::Sender::closed)) => continue,
                received = listener.try_recv() => received,
            };
            match received {
                Ok(Some(notification)) => {
                    watches.signal(Some(notification.payload()), WatchEvent::Changed);
                }
                Ok(None) | Err(_) => break,
            }
        }
        watches.signal(None, WatchEvent::Disconnected);
        let mut delay = FIRST_RETRY_DELAY;
        listener = loop {
            let Some(senders) = watches.live() else {
                return;
            };
            if pool.is_closed() {
                watches.lock().clear();
                return;
            }
            if let Ok(listener) = listen(&pool, &table).await {
                break listener;
            }
            tokio::select! {
                _ = join_all(senders.iter().map(mpsc::Sender::closed)) => {}
                () = tokio::time::sleep(delay) => {}
            }
            delay = (delay * 2).min(MAX_RETRY_DELAY);
        };
        watches.signal(None, WatchEvent::Reconnected);
    }
}

impl KeyringStore for PostgresKeyringStore {
    type Revision = PostgresRevision;

    const KIND: StoreKind = StoreKind::Postgres;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<PostgresRevision>>> {
        let row: Option<(String, i64)> =
            sqlx::query_as(AssertSqlSafe(self.statements.load.as_str()))
                .bind(id.as_str())
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| store_error(StoreOperation::Load, error))?;
        row.map(|(document, revision)| stored(id, &document, revision))
            .transpose()
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &PostgresRevision,
    ) -> KeyringResult<Revalidation<PostgresRevision>> {
        let row: Option<(Option<String>, i64)> =
            sqlx::query_as(AssertSqlSafe(self.statements.revalidate.as_str()))
                .bind(id.as_str())
                .bind(known.0)
                .fetch_optional(&self.pool)
                .await
                .map_err(|error| store_error(StoreOperation::Revalidate, error))?;
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
        let statement = match expected {
            None => self.statements.create.as_str(),
            Some(_) => self.statements.update.as_str(),
        };
        let mut query = sqlx::query_scalar(AssertSqlSafe(statement))
            .bind(record.id().as_str())
            .bind(document)
            .bind(self.table.0.as_str());
        if let Some(expected) = expected {
            query = query.bind(expected.0);
        }
        let written: Option<i64> = query
            .fetch_optional(&self.pool)
            .await
            .map_err(|error| store_error(StoreOperation::CompareAndSwap, error))?;
        Ok(written.map_or(Swap::Conflict, |revision| {
            Swap::Written(PostgresRevision(revision))
        }))
    }

    /// A watch on the store's shared listener. The first watch starts the listener on a
    /// connection of the pool, which it returns once the last watch is dropped.
    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        let (events, receiver) = mpsc::channel(16);
        if let Err(events) = self.watches.join(id, events) {
            let listener = listen(&self.pool, &self.table)
                .await
                .map_err(|error| store_error(StoreOperation::Watch, error))?;
            // Another watch may have started the listener meanwhile; this one is then dropped,
            // and its connection goes back to the pool.
            if self.watches.insert(id, events) {
                tokio::spawn(forward(
                    listener,
                    self.pool.clone(),
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
    use super::*;
    use crate::testing::TestResult;

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn revalidate_returns_no_payload_when_unchanged() -> TestResult {
        let pool = PgPool::connect(&std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?).await?;
        let table =
            PostgresTable::try_from(format!("kms_keyrings_{}", uuid::Uuid::now_v7().simple()))?;
        sqlx::raw_sql(AssertSqlSafe(format!(
            r#"CREATE TABLE "{table}" (id TEXT PRIMARY KEY, record JSONB NOT NULL,
                revision BIGINT NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
            INSERT INTO "{table}" (id, record, revision) VALUES ('tenant-42', '{{}}', 7)"#
        )))
        .execute(&pool)
        .await?;
        let revalidate = Statements::new(&table).revalidate;
        for (known, payload) in [(7_i64, false), (6, true)] {
            let (record, revision): (Option<String>, i64) =
                sqlx::query_as(AssertSqlSafe(revalidate.as_str()))
                    .bind("tenant-42")
                    .bind(known)
                    .fetch_one(&pool)
                    .await?;
            assert_eq!((record.is_some(), revision), (payload, 7));
        }
        sqlx::query(AssertSqlSafe(format!(r#"DROP TABLE "{table}""#)))
            .execute(&pool)
            .await?;
        Ok(())
    }
}
