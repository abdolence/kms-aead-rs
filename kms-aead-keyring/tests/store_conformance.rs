//! The behaviour every keyring store keeps. `conformance` runs each check against one store; a
//! store feature adds its own test at the end of the file.

use std::time::Duration;

use kms_aead_keyring::store::{
    KeyringStore, MemoryKeyringStore, Revalidation, Stored, Swap, WatchEvent,
};
use kms_aead_keyring::{KeyringId, KeyringRecord, KeyringResult};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A keyring id no other test uses, so that the checks can share a database.
fn unique_keyring_id() -> KeyringResult<KeyringId> {
    KeyringId::try_from(format!("conformance-{}", uuid::Uuid::now_v7()))
}

/// The wrapped key of every version of [`record`]: `[0xFF][0x01][0x00]` starts encrypted key
/// layout v1 with no key version, and `wrapped` follows.
const WRAPPED_DEK: &str = "/wEAd3JhcHBlZA==";

/// As [`WRAPPED_DEK`], with `record-bytes-marker` after the layout bytes: a wrapped key whose
/// bytes a test looks for in the store's errors.
#[cfg(any(feature = "firestore", feature = "postgres", feature = "gcs"))]
const MARKED_WRAPPED_DEK: &str = "/wEAcmVjb3JkLWJ5dGVzLW1hcmtlcg==";

/// The record of `id` after `rotations` rotations: randomized versions 1 to `rotations`
/// decrypt only, and the next one is active.
fn record(id: &KeyringId, rotations: u32) -> KeyringResult<KeyringRecord> {
    record_wrapping(id, rotations, WRAPPED_DEK)
}

/// As [`record`], with every version's wrapped key `wrapped_dek`, in standard base64.
fn record_wrapping(
    id: &KeyringId,
    rotations: u32,
    wrapped_dek: &str,
) -> KeyringResult<KeyringRecord> {
    let versions: Vec<_> = (1..=rotations + 1)
        .map(|key_id| {
            json!({
                "key_id": key_id,
                "algorithm": "aes-256-gcm",
                "state": if key_id > rotations { "active" } else { "decrypt_only" },
                "compromised": null,
                "created_at": "2026-01-10T09:00:00Z",
                "state_changed_at": "2026-01-10T09:00:00Z",
                "wrapped_dek": wrapped_dek,
            })
        })
        .collect();
    let document = json!({
        "schema": 1,
        "id": id.as_str(),
        "kek": { "provider": "local", "key": "conformance" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": null },
        "versions": versions,
        "created_at": "2026-01-10T09:00:00Z",
        "updated_at": "2026-01-10T09:00:00Z",
    });
    KeyringRecord::from_json(id, document.to_string().as_bytes())
}

/// The revision a write landed at.
fn written<R>(swap: Swap<R>) -> Result<R, &'static str> {
    match swap {
        Swap::Written(revision) => Ok(revision),
        Swap::Conflict => Err("the write conflicted"),
    }
}

/// The record a load or revalidation returned.
fn same_record<R>(stored: &Stored<R>, expected: &KeyringRecord) -> KeyringResult<bool> {
    Ok(stored.record.to_json()? == expected.to_json()?)
}

async fn an_absent_record_loads_as_none(store: impl KeyringStore) -> TestResult {
    assert!(store.load(&unique_keyring_id()?).await?.is_none());
    Ok(())
}

async fn a_created_record_loads_at_its_revision(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let created = record(&id, 0)?;
    let revision = written(store.compare_and_swap(&created, None).await?)?;
    let loaded = store.load(&id).await?.ok_or("the record is gone")?;
    assert!(same_record(&loaded, &created)?);
    assert_eq!(loaded.revision, revision);
    Ok(())
}

async fn creating_an_existing_record_conflicts(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    assert_eq!(
        store.compare_and_swap(&record(&id, 1)?, None).await?,
        Swap::Conflict
    );
    let loaded = store.load(&id).await?.ok_or("the record is gone")?;
    assert!(same_record(&loaded, &record(&id, 0)?)?);
    Ok(())
}

async fn an_update_at_the_current_revision_writes_a_new_one(
    store: impl KeyringStore,
) -> TestResult {
    let id = unique_keyring_id()?;
    let created = written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    let rotated = record(&id, 1)?;
    let updated = written(store.compare_and_swap(&rotated, Some(&created)).await?)?;
    assert_ne!(updated, created);
    let loaded = store.load(&id).await?.ok_or("the record is gone")?;
    assert!(same_record(&loaded, &rotated)?);
    assert_eq!(loaded.revision, updated);
    Ok(())
}

async fn an_update_at_a_stale_revision_conflicts(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let created = written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    let updated = written(
        store
            .compare_and_swap(&record(&id, 1)?, Some(&created))
            .await?,
    )?;
    assert_eq!(
        store
            .compare_and_swap(&record(&id, 2)?, Some(&created))
            .await?,
        Swap::Conflict
    );
    let loaded = store.load(&id).await?.ok_or("the record is gone")?;
    assert!(same_record(&loaded, &record(&id, 1)?)?);
    assert_eq!(loaded.revision, updated);
    Ok(())
}

async fn an_update_of_an_absent_record_conflicts(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let elsewhere = unique_keyring_id()?;
    let revision = written(
        store
            .compare_and_swap(&record(&elsewhere, 0)?, None)
            .await?,
    )?;
    assert_eq!(
        store
            .compare_and_swap(&record(&id, 0)?, Some(&revision))
            .await?,
        Swap::Conflict
    );
    assert!(store.load(&id).await?.is_none());
    Ok(())
}

async fn revalidating_the_current_revision_is_unchanged(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let revision = written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    assert!(matches!(
        store.revalidate(&id, &revision).await?,
        Revalidation::Unchanged
    ));
    Ok(())
}

async fn revalidating_a_stale_revision_returns_the_record(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let created = written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    let updated = written(
        store
            .compare_and_swap(&record(&id, 1)?, Some(&created))
            .await?,
    )?;
    match store.revalidate(&id, &created).await? {
        Revalidation::Changed(stored) => {
            assert!(same_record(&stored, &record(&id, 1)?)?);
            assert_eq!(stored.revision, updated);
        }
        other => return Err(format!("expected the changed record, got {other:?}").into()),
    }
    Ok(())
}

async fn revalidating_an_absent_record_is_missing(store: impl KeyringStore) -> TestResult {
    let elsewhere = unique_keyring_id()?;
    let revision = written(
        store
            .compare_and_swap(&record(&elsewhere, 0)?, None)
            .await?,
    )?;
    assert!(matches!(
        store.revalidate(&unique_keyring_id()?, &revision).await?,
        Revalidation::Missing
    ));
    Ok(())
}

async fn records_are_kept_apart_by_id(store: impl KeyringStore) -> TestResult {
    let first = unique_keyring_id()?;
    let second = unique_keyring_id()?;
    let first_revision = written(store.compare_and_swap(&record(&first, 0)?, None).await?)?;
    written(store.compare_and_swap(&record(&second, 3)?, None).await?)?;
    let loaded = store.load(&first).await?.ok_or("the record is gone")?;
    assert!(same_record(&loaded, &record(&first, 0)?)?);
    assert!(matches!(
        store.revalidate(&first, &first_revision).await?,
        Revalidation::Unchanged
    ));
    Ok(())
}

/// A store without push returns no watch; one with push signals a write of the record it
/// watches, and only of that record.
async fn a_write_signals_the_watch_of_its_record(store: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let Some(mut watch) = store.watch(&id).await? else {
        return Ok(());
    };
    written(
        store
            .compare_and_swap(&record(&unique_keyring_id()?, 0)?, None)
            .await?,
    )?;
    written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
    let event = tokio::time::timeout(Duration::from_secs(10), watch.next()).await?;
    assert_eq!(event, Some(WatchEvent::Changed));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), watch.next())
            .await
            .is_err(),
        "a write of another record signalled the watch"
    );
    Ok(())
}

/// A store error carries none of the record it failed to write: the wrapped key appears neither
/// as text nor as bytes in the error's `Display`, its `Debug`, or those of its causes.
/// `failing` is a store whose write at `expected` fails.
#[cfg(any(feature = "firestore", feature = "postgres", feature = "gcs"))]
async fn a_store_error_carries_no_record_bytes<S: KeyringStore>(
    failing: S,
    expected: Option<&S::Revision>,
) -> TestResult {
    let marked = record_wrapping(&unique_keyring_id()?, 0, MARKED_WRAPPED_DEK)?;
    let error = match failing.compare_and_swap(&marked, expected).await {
        Err(error) => error,
        Ok(swap) => return Err(format!("the write did not fail: {swap:?}").into()),
    };
    assert!(matches!(error, kms_aead_keyring::KeyringError::Store(_)));
    let mut rendered = format!("{error}\n{error:?}");
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        rendered.push_str(&format!("\n{cause}\n{cause:?}"));
        source = cause.source();
    }
    let marker = b"record-bytes-marker";
    let as_bytes = |bytes: &[u8]| {
        let listed = format!("{bytes:?}");
        listed[1..listed.len() - 1].to_string()
    };
    for leaked in [
        "record-bytes-marker".to_string(),
        MARKED_WRAPPED_DEK.to_string(),
        as_bytes(marker),
        as_bytes(MARKED_WRAPPED_DEK.as_bytes()),
        marker.iter().map(|byte| format!("{byte:02x}")).collect(),
    ] {
        assert!(!rendered.contains(&leaked), "the error carries {leaked}");
    }
    Ok(())
}

/// Runs every check, each against a store `new_store` returns.
async fn conformance<S: KeyringStore>(new_store: impl Fn() -> S) -> TestResult {
    an_absent_record_loads_as_none(new_store()).await?;
    a_created_record_loads_at_its_revision(new_store()).await?;
    creating_an_existing_record_conflicts(new_store()).await?;
    an_update_at_the_current_revision_writes_a_new_one(new_store()).await?;
    an_update_at_a_stale_revision_conflicts(new_store()).await?;
    an_update_of_an_absent_record_conflicts(new_store()).await?;
    revalidating_the_current_revision_is_unchanged(new_store()).await?;
    revalidating_a_stale_revision_returns_the_record(new_store()).await?;
    revalidating_an_absent_record_is_missing(new_store()).await?;
    records_are_kept_apart_by_id(new_store()).await?;
    a_write_signals_the_watch_of_its_record(new_store()).await
}

#[tokio::test]
async fn the_memory_store_conforms() -> TestResult {
    conformance(MemoryKeyringStore::new).await
}

/// The Firestore store, on the emulator `FIRESTORE_EMULATOR_HOST` names, or on Firestore with
/// application default credentials when it is unset, in the project `PROJECT_ID`. The records
/// go to the collection `kms_aead_rs_ci_keyrings`.
#[cfg(feature = "firestore")]
mod firestore_store {
    use std::error::Error;

    use firestore::{FirestoreDb, FirestoreTimestamp};
    use kms_aead_keyring::store::FirestoreKeyringStore;

    use super::*;

    async fn store() -> Result<FirestoreKeyringStore, Box<dyn Error>> {
        let db = FirestoreDb::new(std::env::var("PROJECT_ID")?).await?;
        Ok(FirestoreKeyringStore::new(db).with_collection("kms_aead_rs_ci_keyrings"))
    }

    #[tokio::test]
    #[ignore = "needs a Firestore emulator or project, see the module docs"]
    async fn the_firestore_store_conforms() -> TestResult {
        let store = store().await?;
        conformance(|| store.clone()).await
    }

    /// Firestore refuses an update time that is not a whole microsecond.
    #[tokio::test]
    #[ignore = "needs a Firestore emulator or project, see the module docs"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let misaligned = FirestoreTimestamp(
            jiff::Timestamp::now().checked_add(jiff::SignedDuration::from_nanos(1))?,
        );
        super::a_store_error_carries_no_record_bytes(store().await?, Some(&misaligned)).await
    }
}

/// The PostgreSQL store, against the database at `KMS_AEAD_KEYRING_POSTGRES_URL`. Each test
/// creates tables of its own, so that tests share neither rows nor `NOTIFY` channels.
#[cfg(feature = "postgres")]
mod postgres {
    use std::time::{Duration, Instant};

    use kms_aead_keyring::store::{
        KeyringStore, KeyringWatch, PostgresKeyringStore, PostgresTable, WatchEvent,
    };
    use kms_aead_keyring::{Encrypted, KeyringError, KeyringResult};
    use sqlx::postgres::{PgConnectOptions, PgPool, PgPoolOptions};
    use sqlx::AssertSqlSafe;

    use super::{conformance, record, unique_keyring_id, written, TestResult};

    fn connect_options() -> Result<PgConnectOptions, Box<dyn std::error::Error>> {
        Ok(std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?.parse()?)
    }

    async fn connect() -> Result<PgPool, Box<dyn std::error::Error>> {
        Ok(PgPool::connect_with(connect_options()?).await?)
    }

    /// A new table with the documented DDL.
    async fn create_table(pool: &PgPool) -> Result<PostgresTable, Box<dyn std::error::Error>> {
        let table =
            PostgresTable::try_from(format!("kms_keyrings_{}", uuid::Uuid::now_v7().simple()))?;
        sqlx::query(AssertSqlSafe(format!(
            "CREATE TABLE {table} (
                id         TEXT PRIMARY KEY,
                record     JSONB NOT NULL,
                revision   BIGINT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )"
        )))
        .execute(pool)
        .await?;
        Ok(table)
    }

    async fn drop_table(pool: &PgPool, table: &PostgresTable) -> TestResult {
        sqlx::query(AssertSqlSafe(format!("DROP TABLE {table}")))
            .execute(pool)
            .await?;
        Ok(())
    }

    async fn next_event(
        watch: &mut KeyringWatch,
    ) -> Result<Option<WatchEvent>, tokio::time::error::Elapsed> {
        tokio::time::timeout(Duration::from_secs(10), watch.next()).await
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn the_postgres_store_conforms() -> TestResult {
        let pool = connect().await?;
        let table = create_table(&pool).await?;
        conformance(|| PostgresKeyringStore::with_table(pool.clone(), table.clone())).await?;
        drop_table(&pool, &table).await
    }

    /// A server error may quote the row: a check violation's detail quotes its first bytes, and a
    /// trigger whatever it chooses. This one quotes the whole record.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let pool = connect().await?;
        let table = create_table(&pool).await?;
        sqlx::raw_sql(AssertSqlSafe(format!(
            "CREATE FUNCTION {table}_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
            BEGIN
                RAISE EXCEPTION 'refused' USING DETAIL = NEW.record::text, HINT = NEW.record::text;
            END $$;
            CREATE TRIGGER refuse BEFORE INSERT ON {table}
                FOR EACH ROW EXECUTE FUNCTION {table}_refuse();"
        )))
        .execute(&pool)
        .await?;
        let failing = PostgresKeyringStore::with_table(pool.clone(), table.clone());
        super::a_store_error_carries_no_record_bytes(failing, None).await?;
        drop_table(&pool, &table).await?;
        sqlx::query(AssertSqlSafe(format!("DROP FUNCTION {table}_refuse")))
            .execute(&pool)
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn equality_probes_match_with_any() -> TestResult {
        let pool = connect().await?;
        let table = format!("encrypted_{}", uuid::Uuid::now_v7().simple());
        sqlx::query(AssertSqlSafe(format!(
            "CREATE TABLE {table} (id INT PRIMARY KEY, email BYTEA NOT NULL)"
        )))
        .execute(&pool)
        .await?;
        let values = (1..=4u8)
            .map(|row| {
                let mut bytes = vec![0x01, 0, 0, 0, 1];
                bytes.extend_from_slice(&[row; 12 + 16]);
                Encrypted::<String>::try_from(bytes)
            })
            .collect::<KeyringResult<Vec<_>>>()?;
        for (id, value) in (1..).zip(&values) {
            sqlx::query(AssertSqlSafe(format!(
                "INSERT INTO {table} VALUES ($1, $2)"
            )))
            .bind(id)
            .bind(value)
            .execute(&pool)
            .await?;
        }
        let probes = [values[3].clone(), values[1].clone()];
        let matched: Vec<(i32, Encrypted<String>)> = sqlx::query_as(AssertSqlSafe(format!(
            "SELECT id, email FROM {table} WHERE email = ANY($1) ORDER BY id"
        )))
        .bind(&probes[..])
        .fetch_all(&pool)
        .await?;
        assert_eq!(matched, [(2, values[1].clone()), (4, values[3].clone())]);
        sqlx::query(AssertSqlSafe(format!("DROP TABLE {table}")))
            .execute(&pool)
            .await?;
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_stored_value_that_is_no_keyring_value_fails_to_decode() -> TestResult {
        let pool = connect().await?;
        let decoded = sqlx::query_scalar::<_, Encrypted<String>>("SELECT '\\x00'::bytea")
            .fetch_one(&pool)
            .await;
        assert!(matches!(decoded, Err(sqlx::Error::ColumnDecode { .. })));
        Ok(())
    }

    /// A lost listener connection is reported, and the listener comes back on its own and
    /// listens again: the keyring revalidates on `Reconnected`, since PostgreSQL drops the
    /// notifications of a closed session.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_lost_listener_connection_signals_disconnected_then_reconnected() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = format!("listener-{}", uuid::Uuid::now_v7().simple());
        let pool = PgPool::connect_with(connect_options()?.application_name(&application)).await?;
        let store = PostgresKeyringStore::with_table(pool, table.clone());
        let id = unique_keyring_id()?;
        let mut watch = store.watch(&id).await?.ok_or("the store has no push")?;
        sqlx::query(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE application_name = $1",
        )
        .bind(&application)
        .execute(&admin)
        .await?;
        assert_eq!(
            next_event(&mut watch).await?,
            Some(WatchEvent::Disconnected)
        );
        assert_eq!(next_event(&mut watch).await?, Some(WatchEvent::Reconnected));
        written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
        assert_eq!(next_event(&mut watch).await?, Some(WatchEvent::Changed));
        drop_table(&admin, &table).await
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn dropping_the_watch_returns_its_connection() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let pool = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_millis(500))
            .connect_with(connect_options()?)
            .await?;
        let store = PostgresKeyringStore::with_table(pool, table.clone());
        let id = unique_keyring_id()?;
        let watch = store.watch(&id).await?.ok_or("the store has no push")?;
        assert!(matches!(store.load(&id).await, Err(KeyringError::Store(_))));
        drop(watch);
        let deadline = Instant::now() + Duration::from_secs(10);
        while store.load(&id).await.is_err() {
            assert!(Instant::now() < deadline, "the watch kept its connection");
        }
        drop_table(&admin, &table).await
    }

    /// The keyring over the PostgreSQL store.
    #[cfg(feature = "ring")]
    mod keyring {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use kms_aead::providers::{LocalKekId, LocalKmsProvider};
        use kms_aead::AeadBackend;
        use kms_aead_keyring::store::{
            KeyringStore, KeyringWatch, PostgresKeyringStore, PostgresRevision, Revalidation,
            StoreKind, Stored, Swap,
        };
        use kms_aead_keyring::{
            Keyring, KeyringId, KeyringOptions, KeyringPolicy, KeyringRecord, KeyringResult,
        };

        use super::{connect, create_table, drop_table};
        use crate::{unique_keyring_id, TestResult};

        /// A store that counts the revalidations a keyring asks of it.
        struct CountingStore {
            inner: PostgresKeyringStore,
            revalidations: Arc<AtomicUsize>,
        }

        impl KeyringStore for CountingStore {
            type Revision = PostgresRevision;

            const KIND: StoreKind = PostgresKeyringStore::KIND;

            async fn load(
                &self,
                id: &KeyringId,
            ) -> KeyringResult<Option<Stored<PostgresRevision>>> {
                self.inner.load(id).await
            }

            async fn revalidate(
                &self,
                id: &KeyringId,
                known: &PostgresRevision,
            ) -> KeyringResult<Revalidation<PostgresRevision>> {
                self.revalidations.fetch_add(1, Ordering::SeqCst);
                self.inner.revalidate(id, known).await
            }

            async fn compare_and_swap(
                &self,
                record: &KeyringRecord,
                expected: Option<&PostgresRevision>,
            ) -> KeyringResult<Swap<PostgresRevision>> {
                self.inner.compare_and_swap(record, expected).await
            }

            async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
                self.inner.watch(id).await
            }
        }

        /// Any session may `NOTIFY` the channel. A flood of signals costs a keyring one
        /// revalidation per `reload_min_interval`, and at least one.
        #[tokio::test]
        #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
        async fn notify_from_another_session_is_rate_limited() -> TestResult {
            let pool = connect().await?;
            let table = create_table(&pool).await?;
            let revalidations = Arc::new(AtomicUsize::new(0));
            let store = CountingStore {
                inner: PostgresKeyringStore::with_table(pool.clone(), table.clone()),
                revalidations: revalidations.clone(),
            };
            let interval = Duration::from_millis(500);
            let id = unique_keyring_id()?;
            let keyring = Keyring::open_or_create(
                store,
                LocalKmsProvider::ephemeral(
                    LocalKekId::try_from("postgres-kek".to_string())?,
                    AeadBackend::Ring,
                )?,
                AeadBackend::Ring,
                id.clone(),
                KeyringPolicy::new(),
                KeyringOptions::new().with_reload_min_interval(interval),
            )
            .await?;
            // The watch task's first revalidation, which no signal causes.
            let deadline = Instant::now() + Duration::from_secs(10);
            while revalidations.load(Ordering::SeqCst) == 0 {
                assert!(
                    Instant::now() < deadline,
                    "the watch task never revalidated"
                );
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let before = revalidations.load(Ordering::SeqCst);
            let started = Instant::now();
            // One transaction each: PostgreSQL folds equal notifications of one transaction.
            for _ in 0..100 {
                sqlx::query("SELECT pg_notify($1, $2)")
                    .bind(table.to_string())
                    .bind(id.as_str())
                    .execute(&pool)
                    .await?;
            }
            tokio::time::sleep(3 * interval).await;
            let caused = revalidations.load(Ordering::SeqCst) - before;
            let intervals = started.elapsed().as_millis() / interval.as_millis();
            assert!(caused >= 1, "no signal reached the keyring");
            assert!(
                caused as u128 <= intervals + 1,
                "{caused} revalidations in {intervals} intervals"
            );
            drop(keyring);
            drop_table(&pool, &table).await
        }
    }
}

/// The GCS store against the bucket `KEYRING_GCS_BUCKET` names, with the application default
/// credentials. Each run writes under a prefix of its own, `kms-keyrings-conformance/<uuid>/`,
/// and leaves its objects for the bucket's lifecycle rule.
#[cfg(feature = "gcs")]
mod gcs {
    use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
    use gcloud_sdk::GoogleApi;
    use kms_aead_keyring::store::{GcsBucketName, GcsKeyringStore};

    use super::{conformance, TestResult};

    async fn store() -> Result<GcsKeyringStore, Box<dyn std::error::Error>> {
        let bucket = GcsBucketName::try_from(std::env::var("KEYRING_GCS_BUCKET")?)?;
        let client =
            GoogleApi::from_function(StorageClient::new, "https://storage.googleapis.com", None)
                .await?;
        Ok(GcsKeyringStore::new(client, bucket)?.with_prefix(format!(
            "kms-keyrings-conformance/{}/",
            uuid::Uuid::now_v7()
        )))
    }

    #[tokio::test]
    #[ignore = "needs the GCS bucket KEYRING_GCS_BUCKET names, and credentials for it"]
    async fn the_gcs_store_conforms() -> TestResult {
        let store = store().await?;
        conformance(|| store.clone()).await
    }

    /// An object name past the service's 1,024-byte limit makes every write fail.
    #[tokio::test]
    #[ignore = "needs the GCS bucket KEYRING_GCS_BUCKET names, and credentials for it"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let failing = store().await?.with_prefix("x".repeat(1100));
        super::a_store_error_carries_no_record_bytes(failing, None).await
    }
}
