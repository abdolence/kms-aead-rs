//! The Firestore store's listen stream on Firestore itself, with hundreds of targets on it: the
//! emulator does not enforce Firestore's limits. The test runs in the project `PROJECT_ID` with
//! the application default credentials, writes documents to the collection
//! `kms_aead_rs_ci_keyrings`, and deletes them at the end.

use std::time::Duration;

use firestore::{FirestoreCollectionId, FirestoreDb};
use futures_util::future::try_join_all;
use kms_aead_keyring::store::{FirestoreKeyringStore, KeyringStore, WatchEvent};
use kms_aead_keyring::{KeyringId, KeyringResult};
use serde_json::{json, Value};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const COLLECTION: FirestoreCollectionId =
    FirestoreCollectionId::from_static("kms_aead_rs_ci_keyrings");

const WATCHED_KEYRINGS: usize = 500;

#[tokio::test]
#[ignore = "needs Firestore in PROJECT_ID with application default credentials"]
async fn hundreds_of_keyrings_share_one_stream() -> TestResult {
    let db = FirestoreDb::new(std::env::var("PROJECT_ID")?).await?;
    let store = FirestoreKeyringStore::new(db.clone()).with_collection(COLLECTION);
    let run = uuid::Uuid::now_v7().simple();
    let ids = (0..WATCHED_KEYRINGS)
        .map(|keyring| KeyringId::try_from(format!("live-{run}-{keyring}")))
        .collect::<KeyringResult<Vec<_>>>()?;

    let signalled = async {
        let mut watches = try_join_all(ids.iter().map(|id| store.watch(id)))
            .await?
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or("the store has no push")?;
        let first_states = try_join_all(
            watches
                .iter_mut()
                .map(|watch| tokio::time::timeout(Duration::from_secs(60), watch.next())),
        )
        .await?;
        assert!(first_states
            .iter()
            .all(|event| *event == Some(WatchEvent::Changed)));

        let document = json!({ "written": true });
        try_join_all(ids.iter().map(|id| {
            db.fluent()
                .insert()
                .into(COLLECTION.as_str())
                .document_id(id.as_str())
                .object(&document)
                .execute::<Value>()
        }))
        .await?;
        let events = try_join_all(
            watches
                .iter_mut()
                .map(|watch| tokio::time::timeout(Duration::from_secs(60), watch.next())),
        )
        .await?;
        let changed = events
            .iter()
            .filter(|event| **event == Some(WatchEvent::Changed))
            .count();
        assert_eq!(changed, WATCHED_KEYRINGS);
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;

    try_join_all(ids.iter().map(|id| {
        db.fluent()
            .delete()
            .from(COLLECTION.as_str())
            .document_id(id.as_str())
            .execute()
    }))
    .await?;
    store.shutdown(None).await;
    signalled
}
