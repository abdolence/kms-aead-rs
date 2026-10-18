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

/// `[0xFF][0x01][0x00]` starts encrypted key layout v1 with no key version; `wrapped` follows.
const WRAPPED_DEK: &str = "/wEAd3JhcHBlZA==";

/// As [`WRAPPED_DEK`], with `record-bytes-marker` after the layout bytes: a wrapped key whose
/// bytes a test looks for in the store's errors.
#[cfg(feature = "gcs")]
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
/// as text nor as bytes in the error's `Display`, its `Debug`, or its root cause's. `failing` is
/// a store whose writes fail.
#[cfg(feature = "gcs")]
async fn a_store_error_carries_no_record_bytes(failing: impl KeyringStore) -> TestResult {
    let id = unique_keyring_id()?;
    let marked = record_wrapping(&id, 0, MARKED_WRAPPED_DEK)?;
    let error = match failing.compare_and_swap(&marked, None).await {
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

/// The GCS store against the bucket `KEYRING_GCS_BUCKET` names, with the application default
/// credentials. Each run writes under a prefix of its own, `kms-keyrings-conformance/<uuid>/`,
/// and leaves its objects for the bucket's lifecycle rule.
#[cfg(feature = "gcs")]
mod gcs {
    use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
    use gcloud_sdk::GoogleApi;
    use kms_aead_keyring::store::{GcsBucketName, GcsKeyringStore, KeyringStore};

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

    #[tokio::test]
    #[ignore = "needs the GCS bucket KEYRING_GCS_BUCKET names, and credentials for it"]
    async fn watch_returns_none() -> TestResult {
        assert!(store().await?.watch(&unique_keyring_id()?).await?.is_none());
        Ok(())
    }

    /// An object name past the service's 1,024-byte limit makes every write fail.
    #[tokio::test]
    #[ignore = "needs the GCS bucket KEYRING_GCS_BUCKET names, and credentials for it"]
    async fn a_store_error_carries_no_record_bytes() -> TestResult {
        let failing = store().await?.with_prefix("x".repeat(1100));
        super::a_store_error_carries_no_record_bytes(failing).await
    }
}
