//! The behaviour every keyring store keeps. `conformance` runs each check against one store; a
//! store feature adds its own test at the end of the file.

use std::time::Duration;

use kms_aead_keyring::store::{KeyringStore, Revalidation, Stored, Swap, WatchEvent};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{KeyringId, KeyringRecord, KeyringResult};
use serde_json::json;

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A keyring id no other test uses, so that the checks can share a database.
fn unique_keyring_id() -> KeyringResult<KeyringId> {
    KeyringId::try_from(format!("conformance-{}", uuid::Uuid::now_v7()))
}

/// The encrypted DEK of every version of [`record`]: `[0xFF][0x01][0x00]` starts encrypted key
/// layout v1 with no key version, and `wrapped` follows.
const ENCRYPTED_DEK: &str = "/wEAd3JhcHBlZA==";

/// As [`ENCRYPTED_DEK`], with `record-bytes-marker` after the layout bytes: an encrypted DEK whose
/// bytes a test looks for in the store's errors.
#[cfg(any(
    feature = "firestore",
    feature = "postgres",
    feature = "gcs",
    feature = "s3"
))]
const MARKED_ENCRYPTED_DEK: &str = "/wEAcmVjb3JkLWJ5dGVzLW1hcmtlcg==";

/// The record of `id` after `rotations` rotations: randomised versions 1 to `rotations`
/// decrypt only, and the next one is active, each version from the epoch of its own key id.
fn record(id: &KeyringId, rotations: u32) -> KeyringResult<KeyringRecord> {
    record_holding(id, rotations, ENCRYPTED_DEK)
}

/// As [`record`], with every version's encrypted DEK in `encrypted_dek`, in standard base64.
fn record_holding(
    id: &KeyringId,
    rotations: u32,
    encrypted_dek: &str,
) -> KeyringResult<KeyringRecord> {
    let versions: Vec<_> = (1..=rotations + 1)
        .map(|key_id| {
            json!({
                "key_id": key_id,
                "algorithm": "aes-256-gcm",
                "state": if key_id > rotations { "active" } else { "decrypt_only" },
                "compromised": null,
                "seal_epochs": {
                    "start": key_id,
                    "end": if key_id > rotations { None } else { Some(key_id + 1) },
                },
                "created_at": "2026-01-10T09:00:00Z",
                "state_changed_at": "2026-01-10T09:00:00Z",
                "encrypted_dek": encrypted_dek,
            })
        })
        .collect();
    let document = json!({
        "schema": 1,
        "id": id.as_str(),
        "kek": { "provider": "local", "key": "conformance" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": null },
        "seal_epoch": rotations + 1,
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

/// A store error carries none of the record it failed to write: the encrypted DEK appears neither
/// as text nor as bytes in the error's `Display`, its `Debug`, or those of its causes.
/// `failing` is a store whose write at `expected` fails.
#[cfg(any(
    feature = "firestore",
    feature = "postgres",
    feature = "gcs",
    feature = "s3"
))]
async fn a_store_error_carries_no_record_bytes<S: KeyringStore>(
    failing: S,
    expected: Option<&S::Revision>,
) -> TestResult {
    let marked = record_holding(&unique_keyring_id()?, 0, MARKED_ENCRYPTED_DEK)?;
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
        MARKED_ENCRYPTED_DEK.to_string(),
        as_bytes(marker),
        as_bytes(MARKED_ENCRYPTED_DEK.as_bytes()),
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
        Ok(FirestoreKeyringStore::new(db).with_collection("kms_aead_rs_ci_keyrings".to_string()))
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
        let misaligned =
            FirestoreTimestamp(jiff::Timestamp::new(jiff::Timestamp::now().as_second(), 1)?);
        super::a_store_error_carries_no_record_bytes(store().await?, Some(&misaligned)).await
    }
}

/// The PostgreSQL store, against the database at `KMS_AEAD_KEYRING_POSTGRES_URL`. Each test
/// creates tables of its own, so that tests share neither rows nor `NOTIFY` channels, and names
/// its store's sessions, so that it finds them in `pg_stat_activity`.
#[cfg(feature = "postgres")]
mod postgres {
    use std::error::Error;
    use std::time::{Duration, Instant};

    use kms_aead_keyring::store::{
        KeyringStore, KeyringWatch, PostgresKeyringStore, PostgresTable, WatchEvent,
    };
    use kms_aead_keyring::KeyringError;
    use tokio_postgres::{Client, Config, NoTls};

    use super::{conformance, record, unique_keyring_id, written, TestResult};

    fn config() -> Result<Config, Box<dyn Error>> {
        Ok(std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?.parse()?)
    }

    /// A session of the test's own, outside every store.
    async fn connect() -> Result<Client, Box<dyn Error>> {
        let (client, connection) = config()?.connect(NoTls).await?;
        tokio::spawn(connection);
        Ok(client)
    }

    /// A store on `table` whose sessions carry the application name `application`.
    fn named_store(
        application: &str,
        table: &PostgresTable,
    ) -> Result<PostgresKeyringStore<NoTls>, Box<dyn Error>> {
        let mut config = config()?;
        config.application_name(application);
        Ok(PostgresKeyringStore::new(config, NoTls).with_table(table.clone()))
    }

    fn unique_application() -> String {
        format!("keyring-{}", uuid::Uuid::now_v7().simple())
    }

    /// The open sessions named `application`.
    async fn sessions(admin: &Client, application: &str) -> Result<i64, Box<dyn Error>> {
        let row = admin
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE application_name = $1",
                &[&application],
            )
            .await?;
        Ok(row.try_get(0)?)
    }

    async fn terminate_sessions(admin: &Client, application: &str) -> TestResult {
        admin
            .execute(
                "SELECT pg_terminate_backend(pid) FROM pg_stat_activity
                WHERE application_name = $1",
                &[&application],
            )
            .await?;
        Ok(())
    }

    /// A new table with the documented DDL.
    async fn create_table(admin: &Client) -> Result<PostgresTable, Box<dyn Error>> {
        let table =
            PostgresTable::try_from(format!("kms_keyrings_{}", uuid::Uuid::now_v7().simple()))?;
        admin
            .batch_execute(&format!(
                "CREATE TABLE {table} (
                    id         TEXT PRIMARY KEY,
                    record     JSONB NOT NULL,
                    revision   BIGINT NOT NULL,
                    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
                )"
            ))
            .await?;
        Ok(table)
    }

    async fn drop_table(admin: &Client, table: &PostgresTable) -> TestResult {
        admin.batch_execute(&format!("DROP TABLE {table}")).await?;
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
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let store = PostgresKeyringStore::new(config()?, NoTls).with_table(table.clone());
        conformance(|| store.clone()).await?;
        drop_table(&admin, &table).await
    }

    /// A server error may quote the row: a check violation's detail quotes its first bytes, and a
    /// trigger whatever it chooses. This one quotes the whole record.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        admin
            .batch_execute(&format!(
                "CREATE FUNCTION {table}_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN
                    RAISE EXCEPTION 'refused' USING DETAIL = NEW.record::text, HINT = NEW.record::text;
                END $$;
                CREATE TRIGGER refuse BEFORE INSERT ON {table}
                    FOR EACH ROW EXECUTE FUNCTION {table}_refuse();"
            ))
            .await?;
        let failing = PostgresKeyringStore::new(config()?, NoTls).with_table(table.clone());
        super::a_store_error_carries_no_record_bytes(failing, None).await?;
        drop_table(&admin, &table).await?;
        admin
            .batch_execute(&format!("DROP FUNCTION {table}_refuse"))
            .await?;
        Ok(())
    }

    /// The watches of a store and its clones share one listener connection, so a watch per
    /// keyring costs no connection beyond the store's two.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn many_watches_share_one_connection() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let store = named_store(&application, &table)?;
        let mut watches = Vec::new();
        for _ in 0..5 {
            let tenant = store.clone();
            watches.push(
                tenant
                    .watch(&unique_keyring_id()?)
                    .await?
                    .ok_or("the store has no push")?,
            );
        }
        assert!(store.load(&unique_keyring_id()?).await?.is_none());
        assert_eq!(sessions(&admin, &application).await?, 2);
        drop(watches);
        drop_table(&admin, &table).await
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_change_signals_only_its_keyrings_watches() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let store = PostgresKeyringStore::new(config()?, NoTls).with_table(table.clone());
        let changed = unique_keyring_id()?;
        let mut changed_watches = [
            store
                .watch(&changed)
                .await?
                .ok_or("the store has no push")?,
            store
                .watch(&changed)
                .await?
                .ok_or("the store has no push")?,
        ];
        let mut unchanged_watch = store
            .watch(&unique_keyring_id()?)
            .await?
            .ok_or("the store has no push")?;
        written(store.compare_and_swap(&record(&changed, 0)?, None).await?)?;
        for watch in &mut changed_watches {
            assert_eq!(next_event(watch).await?, Some(WatchEvent::Changed));
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(200), unchanged_watch.next())
                .await
                .is_err(),
            "a write of another keyring signalled the watch"
        );
        drop_table(&admin, &table).await
    }

    /// A lost listener connection is reported to every watch, and the listener comes back on
    /// its own and listens again: the keyring revalidates on `Reconnected`, since PostgreSQL
    /// drops the notifications of a closed session.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_lost_connection_reaches_every_watch() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let store = named_store(&application, &table)?;
        let id = unique_keyring_id()?;
        let mut watches = [
            store.watch(&id).await?.ok_or("the store has no push")?,
            store
                .watch(&unique_keyring_id()?)
                .await?
                .ok_or("the store has no push")?,
        ];
        terminate_sessions(&admin, &application).await?;
        for watch in &mut watches {
            assert_eq!(next_event(watch).await?, Some(WatchEvent::Disconnected));
            assert_eq!(next_event(watch).await?, Some(WatchEvent::Reconnected));
        }
        written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
        assert_eq!(
            next_event(&mut watches[0]).await?,
            Some(WatchEvent::Changed)
        );
        drop_table(&admin, &table).await
    }

    /// The call that finds the query connection lost may fail with it; the next one opens a new
    /// connection.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_lost_query_connection_reconnects_on_the_next_call() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let store = named_store(&application, &table)?;
        let id = unique_keyring_id()?;
        written(store.compare_and_swap(&record(&id, 0)?, None).await?)?;
        terminate_sessions(&admin, &application).await?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while sessions(&admin, &application).await? > 0 {
            assert!(
                Instant::now() < deadline,
                "the session outlived its termination"
            );
        }
        let first = store.load(&id).await;
        assert!(matches!(first, Ok(Some(_)) | Err(KeyringError::Store(_))));
        assert!(store.load(&id).await?.is_some());
        drop_table(&admin, &table).await
    }

    /// The listener connection stays open while any watch runs, and closes once the last one
    /// is dropped.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn dropping_the_watch_returns_its_connection() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let store = named_store(&application, &table)?;
        let first = store
            .watch(&unique_keyring_id()?)
            .await?
            .ok_or("the store has no push")?;
        let last = store
            .watch(&unique_keyring_id()?)
            .await?
            .ok_or("the store has no push")?;
        drop(first);
        assert_eq!(sessions(&admin, &application).await?, 1);
        drop(last);
        let deadline = Instant::now() + Duration::from_secs(10);
        while sessions(&admin, &application).await? > 0 {
            assert!(Instant::now() < deadline, "the watch kept its connection");
        }
        drop_table(&admin, &table).await
    }

    /// Shutdown closes the listener connection and ends every watch, and keeps the query
    /// connection, which the keyrings' handles still use.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn shutdown_closes_the_listener_connection() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let store = named_store(&application, &table)?;
        let mut watches = [
            store
                .watch(&unique_keyring_id()?)
                .await?
                .ok_or("the store has no push")?,
            store
                .watch(&unique_keyring_id()?)
                .await?
                .ok_or("the store has no push")?,
        ];
        assert!(store.load(&unique_keyring_id()?).await?.is_none());
        assert_eq!(sessions(&admin, &application).await?, 2);

        store.shutdown(None).await;
        for watch in &mut watches {
            assert_eq!(next_event(watch).await?, None);
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while sessions(&admin, &application).await? > 1 {
            assert!(
                Instant::now() < deadline,
                "the listener connection stayed open"
            );
        }
        assert!(store.watch(&unique_keyring_id()?).await?.is_none());
        assert!(store.load(&unique_keyring_id()?).await?.is_none());
        drop_table(&admin, &table).await
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn shutdown_twice_is_a_no_op() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let store = PostgresKeyringStore::new(config()?, NoTls).with_table(table.clone());
        let _watch = store.watch(&unique_keyring_id()?).await?;
        store.shutdown(None).await;
        tokio::time::timeout(Duration::from_secs(1), store.shutdown(None)).await?;
        assert!(store.watch(&unique_keyring_id()?).await?.is_none());
        drop_table(&admin, &table).await
    }

    /// Shutdown interrupts the delay between two attempts to replace a lost listener
    /// connection, here while a role that may no longer log in keeps every attempt failing.
    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn shutdown_during_a_reconnect_delay_returns_at_once() -> TestResult {
        let admin = connect().await?;
        let table = create_table(&admin).await?;
        let application = unique_application();
        let role = format!("keyring_{}", uuid::Uuid::now_v7().simple());
        admin
            .batch_execute(&format!("CREATE ROLE {role} LOGIN PASSWORD '{role}'"))
            .await?;
        let mut config = config()?;
        config
            .user(&role)
            .password(&role)
            .application_name(&application);
        let store = PostgresKeyringStore::new(config, NoTls).with_table(table.clone());
        let mut watch = store
            .watch(&unique_keyring_id()?)
            .await?
            .ok_or("the store has no push")?;

        admin
            .batch_execute(&format!("ALTER ROLE {role} NOLOGIN"))
            .await?;
        terminate_sessions(&admin, &application).await?;
        assert_eq!(
            next_event(&mut watch).await?,
            Some(WatchEvent::Disconnected)
        );
        // Four failed attempts in, the delay before the next one is 4 seconds.
        tokio::time::sleep(Duration::from_secs(4)).await;
        let started = Instant::now();
        store.shutdown(None).await;
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "shutdown took {:?}",
            started.elapsed()
        );
        assert_eq!(next_event(&mut watch).await?, None);

        admin.batch_execute(&format!("DROP ROLE {role}")).await?;
        drop_table(&admin, &table).await
    }

    /// The keyring over the PostgreSQL store, which the administrative API creates.
    #[cfg(all(feature = "ring", feature = "admin"))]
    mod keyring {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        use kms_aead::backends::Ring;
        use kms_aead::providers::{LocalKekId, LocalKmsProvider};
        use kms_aead_keyring::store::{
            KeyringStore, KeyringWatch, PostgresKeyringStore, PostgresRevision, Revalidation,
            StoreKind, Stored, Swap,
        };
        use kms_aead_keyring::{
            KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRecord, KeyringRegistry,
            KeyringRegistryOptions, KeyringResult,
        };

        use tokio_postgres::NoTls;

        use super::{config, connect, create_table, drop_table};
        use crate::{unique_keyring_id, TestResult};

        /// A store that counts the revalidations a keyring asks of it.
        struct CountingStore {
            inner: PostgresKeyringStore<NoTls>,
            revalidations: Arc<AtomicUsize>,
        }

        impl KeyringStore for CountingStore {
            type Revision = PostgresRevision;

            const KIND: StoreKind = PostgresKeyringStore::<NoTls>::KIND;

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

            async fn shutdown(&self, timeout: Option<Duration>) {
                self.inner.shutdown(timeout).await;
            }
        }

        /// Any session may `NOTIFY` the channel. A flood of signals costs a keyring one
        /// revalidation per `reload_min_interval`, and at least one.
        #[tokio::test]
        #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
        async fn notify_from_another_session_is_rate_limited() -> TestResult {
            let admin = connect().await?;
            let table = create_table(&admin).await?;
            let revalidations = Arc::new(AtomicUsize::new(0));
            let store = CountingStore {
                inner: PostgresKeyringStore::new(config()?, NoTls).with_table(table.clone()),
                revalidations: revalidations.clone(),
            };
            let interval = Duration::from_millis(500);
            let id = unique_keyring_id()?;
            let registry = KeyringRegistry::<CountingStore, Ring>::new(
                store,
                KeyringRegistryOptions::new().with_reload_min_interval(interval),
            )?;
            let keyring: KeyringAdmin<CountingStore, LocalKmsProvider<Ring>, Ring> = registry
                .open_or_create(
                    LocalKmsProvider::ephemeral(LocalKekId::try_from("postgres-kek".to_string())?)?,
                    id.clone(),
                    KeyringAlgorithms::new(),
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
                admin
                    .execute(
                        "SELECT pg_notify($1, $2)",
                        &[&table.to_string(), &id.as_str()],
                    )
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
            registry.shutdown().await?;
            drop_table(&admin, &table).await
        }
    }
}

/// The GCS store against the bucket `KEYRING_GCS_BUCKET` names, with the application default
/// credentials. Each run writes under a prefix of its own, `kms-keyrings-conformance/<uuid>/`,
/// and leaves its objects for the bucket's lifecycle rule.
#[cfg(feature = "gcs")]
mod gcs {
    use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
    use gcloud_sdk::google::storage::v2::{
        write_object_request, ChecksummedData, Object, WriteObjectRequest, WriteObjectSpec,
    };
    use gcloud_sdk::{tonic, GoogleApi};
    use kms_aead_keyring::errors::{RecordInvalidError, RecordInvalidReason};
    use kms_aead_keyring::store::{GcsBucketName, GcsKeyringStore, KeyringStore};
    use kms_aead_keyring::KeyringError;

    use super::{conformance, unique_keyring_id, TestResult};

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

    /// An object past the 1 MiB record cap loads as too large, whatever it holds.
    #[tokio::test]
    #[ignore = "needs the GCS bucket KEYRING_GCS_BUCKET names, and credentials for it"]
    async fn an_object_over_the_record_cap_is_too_large() -> TestResult {
        let bucket = std::env::var("KEYRING_GCS_BUCKET")?;
        let resource = format!("projects/_/buckets/{bucket}");
        let prefix = format!("kms-keyrings-conformance/{}/", uuid::Uuid::now_v7());
        let id = unique_keyring_id()?;
        let client =
            GoogleApi::from_function(StorageClient::new, "https://storage.googleapis.com", None)
                .await?;
        let mut request = tonic::Request::new(tokio_stream::once(WriteObjectRequest {
            finish_write: true,
            first_message: Some(write_object_request::FirstMessage::WriteObjectSpec(
                WriteObjectSpec {
                    resource: Some(Object {
                        bucket: resource.clone(),
                        name: format!("{prefix}{id}.json"),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            )),
            data: Some(write_object_request::Data::ChecksummedData(
                ChecksummedData {
                    content: vec![b' '; (1 << 20) + 1],
                    crc32c: None,
                },
            )),
            ..Default::default()
        }));
        request.metadata_mut().insert(
            "x-goog-request-params",
            format!("bucket={resource}").parse()?,
        );
        client.get().write_object(request).await?;
        let store =
            GcsKeyringStore::new(client, GcsBucketName::try_from(bucket)?)?.with_prefix(prefix);
        assert!(matches!(
            store.load(&id).await,
            Err(KeyringError::RecordInvalid(RecordInvalidError {
                reason: RecordInvalidReason::TooLarge,
                ..
            }))
        ));
        Ok(())
    }
}

/// The S3 store against the S3-compatible server at `KEYRING_S3_ENDPOINT`, such as MinIO, in the
/// bucket `KEYRING_S3_BUCKET`, with path-style requests and the credentials of the environment.
/// Each run writes under a prefix of its own, `kms-keyrings-conformance/<uuid>/`.
#[cfg(feature = "s3")]
mod s3 {
    use aws_config::{BehaviorVersion, Region};
    use aws_sdk_s3::primitives::ByteStream;
    use kms_aead_keyring::errors::{RecordInvalidError, RecordInvalidReason};
    use kms_aead_keyring::store::{KeyringStore, S3BucketName, S3KeyringStore};
    use kms_aead_keyring::KeyringError;

    use super::{conformance, unique_keyring_id, TestResult};

    /// The client of the server `KEYRING_S3_ENDPOINT` names. Without the variable it fails,
    /// rather than sending the tests to AWS.
    async fn client() -> Result<aws_sdk_s3::Client, Box<dyn std::error::Error>> {
        let config = aws_config::defaults(BehaviorVersion::latest())
            .endpoint_url(std::env::var("KEYRING_S3_ENDPOINT")?)
            .region(Region::new("us-east-1"))
            .load()
            .await;
        Ok(aws_sdk_s3::Client::from_conf(
            aws_sdk_s3::config::Builder::from(&config)
                .force_path_style(true)
                .build(),
        ))
    }

    fn bucket() -> Result<S3BucketName, Box<dyn std::error::Error>> {
        Ok(S3BucketName::try_from(std::env::var("KEYRING_S3_BUCKET")?)?)
    }

    fn run_prefix() -> String {
        format!("kms-keyrings-conformance/{}/", uuid::Uuid::now_v7())
    }

    async fn store() -> Result<S3KeyringStore, Box<dyn std::error::Error>> {
        Ok(S3KeyringStore::new(client().await?, bucket()?).with_prefix(run_prefix()))
    }

    #[tokio::test]
    #[ignore = "needs the S3 server KEYRING_S3_ENDPOINT names, see the module docs"]
    async fn the_s3_store_conforms() -> TestResult {
        let store = store().await?;
        conformance(|| store.clone()).await
    }

    /// An object key past the 1,024-byte limit makes every write fail.
    #[tokio::test]
    #[ignore = "needs the S3 server KEYRING_S3_ENDPOINT names, see the module docs"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let failing = store().await?.with_prefix("x".repeat(1100));
        super::a_store_error_carries_no_record_bytes(failing, None).await
    }

    /// An object past the 1 MiB record cap loads as too large, whatever it holds.
    #[tokio::test]
    #[ignore = "needs the S3 server KEYRING_S3_ENDPOINT names, see the module docs"]
    async fn an_object_over_the_record_cap_is_too_large() -> TestResult {
        let client = client().await?;
        let bucket = bucket()?;
        let prefix = run_prefix();
        let id = unique_keyring_id()?;
        client
            .put_object()
            .bucket(bucket.to_string())
            .key(format!("{prefix}{id}.json"))
            .body(ByteStream::from(vec![b' '; (1 << 20) + 1]))
            .send()
            .await?;
        let store = S3KeyringStore::new(client, bucket).with_prefix(prefix);
        assert!(matches!(
            store.load(&id).await,
            Err(KeyringError::RecordInvalid(RecordInvalidError {
                reason: RecordInvalidReason::TooLarge,
                ..
            }))
        ));
        Ok(())
    }
}
