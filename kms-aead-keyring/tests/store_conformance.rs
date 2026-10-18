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
/// layout v1 with no key version, and `wrapped` follows. A store error never contains it.
const WRAPPED_DEK: &str = "/wEAd3JhcHBlZA==";

/// The record of `id` after `rotations` rotations: randomized versions 1 to `rotations`
/// decrypt only, and the next one is active.
fn record(id: &KeyringId, rotations: u32) -> KeyringResult<KeyringRecord> {
    let versions: Vec<_> = (1..=rotations + 1)
        .map(|key_id| {
            json!({
                "key_id": key_id,
                "algorithm": "aes-256-gcm",
                "state": if key_id > rotations { "active" } else { "decrypt_only" },
                "compromised": null,
                "created_at": "2026-01-10T09:00:00Z",
                "state_changed_at": "2026-01-10T09:00:00Z",
                "wrapped_dek": WRAPPED_DEK,
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
    use kms_aead_keyring::KeyringError;

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

    #[tokio::test]
    #[ignore = "needs a Firestore emulator or project, see the module docs"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let store = store().await?;
        let record = record(&unique_keyring_id()?, 2)?;
        let created = written(store.compare_and_swap(&record, None).await?)?;
        // Firestore refuses an update time that is not a whole microsecond.
        let misaligned =
            FirestoreTimestamp(created.0.checked_add(jiff::SignedDuration::from_nanos(1))?);
        let error = store
            .compare_and_swap(&record, Some(&misaligned))
            .await
            .err()
            .ok_or("Firestore took a misaligned update time")?;
        assert!(matches!(error, KeyringError::Store(_)));
        let mut texts = vec![error.to_string(), format!("{error:?}")];
        let mut source = error.source();
        while let Some(cause) = source {
            texts.push(cause.to_string());
            texts.push(format!("{cause:?}"));
            source = cause.source();
        }
        assert!(texts.iter().all(|text| !text.contains(WRAPPED_DEK)));
        Ok(())
    }
}
