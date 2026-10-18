use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ::firestore::errors::FirestoreError;
use ::firestore::gcloud_sdk::google::firestore::v1::Document;
use ::firestore::gcloud_sdk::prost_types::Timestamp;
use ::firestore::{
    FirestoreDb, FirestoreListenEvent, FirestoreListenerTarget, FirestoreListenerTargetChangeType,
    FirestoreMemListenStateStorage, FirestoreTimestamp, FirestoreWritePrecondition,
};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{mpsc, watch};

use super::{
    KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap, WatchEvent,
};
use crate::errors::{KeyringError, KeyringResult, KeyringStoreError};
use crate::{KeyringId, KeyringRecord};

/// The one target of a watch's listener, which listens to nothing else.
const WATCH_TARGET: FirestoreListenerTarget = FirestoreListenerTarget::new(1);
/// How long a watch waits for Firestore's first state of the document. The keyring awaits the
/// watch when it opens, and the load just before it reached Firestore.
const WATCH_START: Duration = Duration::from_secs(10);

/// A keyring store on Firestore. The record of a keyring is the document `<collection>/<id>`,
/// whose fields are those of the record's JSON document, and its revision is the document's
/// update time. `Clone` shares the client.
///
/// A create fails when the document exists, and an update carries the expected update time as
/// its precondition, so that Firestore refuses a write over a record that changed since it was
/// read. [`watch`](KeyringStore::watch) opens a listener on the document: each keyring holds one
/// listen stream.
///
/// [`FirestoreDb`] and [`FirestoreTimestamp`] are firestore-rs's own types, a deliberate
/// integration point: the application builds the client, with the project, the database and the
/// credentials it chooses, and the store's revision is Firestore's timestamp. firestore-rs's
/// version is part of this crate's API under the `firestore` feature.
///
/// firestore-rs logs every listen event at `trace` level on its `firestore` target, documents
/// included, so that level writes encrypted DEKs to the log. Keep it off where the log leaves the
/// administrative principal's reach.
#[derive(Clone)]
pub struct FirestoreKeyringStore {
    db: FirestoreDb,
    collection: String,
}

/// The update time of a document Firestore returns from a write.
#[derive(Deserialize)]
struct WrittenDocument {
    #[serde(rename = "_firestore_updated")]
    update_time: FirestoreTimestamp,
}

impl FirestoreKeyringStore {
    /// The collection of [`new`](Self::new).
    pub const DEFAULT_COLLECTION: &'static str = "kms_keyrings";

    /// The store in the collection [`DEFAULT_COLLECTION`](Self::DEFAULT_COLLECTION) of `db`'s
    /// database.
    pub fn new(db: FirestoreDb) -> Self {
        Self {
            db,
            collection: Self::DEFAULT_COLLECTION.to_string(),
        }
    }

    /// The store in `collection` instead. Firestore's rules for a collection id apply, and
    /// Firestore checks them on the first call.
    pub fn with_collection(self, collection: String) -> Self {
        Self { collection, ..self }
    }

    async fn document(
        &self,
        id: &KeyringId,
        operation: StoreOperation,
    ) -> KeyringResult<Option<Document>> {
        self.db
            .fluent()
            .select()
            .by_id_in(&self.collection)
            .one(id.as_str())
            .await
            .map_err(|error| store_error(operation, error))
    }
}

impl KeyringStore for FirestoreKeyringStore {
    type Revision = FirestoreTimestamp;

    const KIND: StoreKind = StoreKind::Firestore;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<FirestoreTimestamp>>> {
        self.document(id, StoreOperation::Load)
            .await?
            .map(|document| stored(id, &document, StoreOperation::Load))
            .transpose()
    }

    /// One document read: Firestore has no conditional read, so the update time is compared
    /// here.
    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &FirestoreTimestamp,
    ) -> KeyringResult<Revalidation<FirestoreTimestamp>> {
        let operation = StoreOperation::Revalidate;
        match self.document(id, operation).await? {
            None => Ok(Revalidation::Missing),
            Some(document) if update_time(&document, operation)? == *known => {
                Ok(Revalidation::Unchanged)
            }
            Some(document) => stored(id, &document, operation).map(Revalidation::Changed),
        }
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&FirestoreTimestamp>,
    ) -> KeyringResult<Swap<FirestoreTimestamp>> {
        let id = record.id();
        let fields: Value = serde_json::from_slice(&record.to_json()?)
            .map_err(|_| KeyringError::malformed(id, None))?;
        let written = match expected {
            None => {
                self.db
                    .fluent()
                    .insert()
                    .into(&self.collection)
                    .document_id(id.as_str())
                    .object(&fields)
                    .execute::<WrittenDocument>()
                    .await
            }
            Some(revision) => {
                self.db
                    .fluent()
                    .update()
                    .in_col(&self.collection)
                    .precondition(FirestoreWritePrecondition::UpdateTime((*revision).into()))
                    .document_id(id.as_str())
                    .object(&fields)
                    .execute::<WrittenDocument>()
                    .await
            }
        };
        match written {
            Ok(document) => Ok(Swap::Written(document.update_time)),
            Err(error) => refused(error),
        }
    }

    /// A listener on the document, with one stream to Firestore per watch. It returns once
    /// Firestore has sent the document's current state, so that every write after it signals,
    /// and that state itself signals nothing. A signal is a change of the document's update
    /// time, or its creation or deletion.
    ///
    /// firestore-rs reconnects on its own and tells the store nothing of a lost stream, so the
    /// watch sends [`Disconnected`](WatchEvent::Disconnected) only when Firestore removes the
    /// target, and [`Reconnected`](WatchEvent::Reconnected) whenever a later stream opens.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Store`] also when Firestore sends no state of the document within 10
    /// seconds.
    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        let failed = |error| store_error(StoreOperation::Watch, error);
        let mut listener = self
            .db
            .create_listener(FirestoreMemListenStateStorage::new())
            .await
            .map_err(failed)?;
        self.db
            .fluent()
            .select()
            .by_id_in(&self.collection)
            .batch_listen([id.as_str()])
            .add_target(WATCH_TARGET, &mut listener)
            .map_err(failed)?;
        let (sender, receiver) = mpsc::channel(16);
        let signals = sender.clone();
        // Set by the first `Current`: Firestore sends the document's state at the start of every
        // stream, and only the first one is the state the watch starts from.
        let (current, mut first_current) = watch::channel(false);
        // The update time of the document as the listener last saw it, `None` while it is
        // absent. Firestore repeats a document's state, a deletion of an absent one included,
        // so a signal is sent only when this changes.
        let seen = Mutex::new(None::<Timestamp>);
        listener
            .start(move |event| {
                let live = *current.borrow();
                let changed = |update_time: Option<Timestamp>| {
                    let mut seen = seen.lock().unwrap_or_else(PoisonError::into_inner);
                    let changed = *seen != update_time;
                    *seen = update_time;
                    (live && changed).then_some(WatchEvent::Changed)
                };
                let signal = match event {
                    FirestoreListenEvent::DocumentChange(change) => {
                        changed(change.document.and_then(|document| document.update_time))
                    }
                    FirestoreListenEvent::DocumentDelete(_)
                    | FirestoreListenEvent::DocumentRemove(_) => changed(None),
                    FirestoreListenEvent::TargetChange(change) => {
                        match FirestoreListenerTargetChangeType::try_from(change.target_change_type)
                        {
                            Ok(FirestoreListenerTargetChangeType::Current) => {
                                current.send_replace(true);
                                None
                            }
                            Ok(FirestoreListenerTargetChangeType::Add) => {
                                live.then_some(WatchEvent::Reconnected)
                            }
                            Ok(FirestoreListenerTargetChangeType::Remove) => {
                                Some(WatchEvent::Disconnected)
                            }
                            _ => None,
                        }
                    }
                    _ => None,
                };
                // A full channel already holds a signal, which covers this one; a closed one
                // stops the listener below.
                if let Some(signal) = signal {
                    let _ = signals.try_send(signal);
                }
                std::future::ready(Ok(()))
            })
            .await
            .map_err(failed)?;
        let started = tokio::time::timeout(WATCH_START, first_current.wait_for(|live| *live))
            .await
            .is_ok_and(|current| current.is_ok());
        if !started {
            let _ = listener.shutdown().await;
            return Err(KeyringError::Store(KeyringStoreError::new(
                Self::KIND,
                StoreOperation::Watch,
                "Firestore sent no state of the document".to_string(),
            )));
        }
        tokio::spawn(async move {
            sender.closed().await;
            let _ = listener.shutdown().await;
        });
        Ok(Some(KeyringWatch::new(receiver)))
    }
}

fn stored(
    id: &KeyringId,
    document: &Document,
    operation: StoreOperation,
) -> KeyringResult<Stored<FirestoreTimestamp>> {
    let fields: Value =
        FirestoreDb::deserialize_doc_to(document).map_err(|_| KeyringError::malformed(id, None))?;
    let json = serde_json::to_vec(&fields).map_err(|_| KeyringError::malformed(id, None))?;
    Ok(Stored {
        record: KeyringRecord::from_json(id, &json)?,
        revision: update_time(document, operation)?,
    })
}

fn update_time(
    document: &Document,
    operation: StoreOperation,
) -> KeyringResult<FirestoreTimestamp> {
    let update_time = document.update_time.ok_or_else(|| {
        KeyringError::Store(KeyringStoreError::new(
            FirestoreKeyringStore::KIND,
            operation,
            "Firestore returned a document without an update time".to_string(),
        ))
    })?;
    FirestoreTimestamp::try_from(update_time).map_err(|error| store_error(operation, error))
}

/// The outcome of a write Firestore refused: [`Swap::Conflict`] when the document exists on a
/// create, or its update time is another or it is gone on an update.
fn refused(error: FirestoreError) -> KeyringResult<Swap<FirestoreTimestamp>> {
    match &error {
        FirestoreError::DataConflictError(_) | FirestoreError::DataNotFoundError(_) => {
            Ok(Swap::Conflict)
        }
        FirestoreError::DatabaseError(failed) if failed.public.code == "FailedPrecondition" => {
            Ok(Swap::Conflict)
        }
        _ => Err(store_error(StoreOperation::CompareAndSwap, error)),
    }
}

fn store_error(operation: StoreOperation, error: FirestoreError) -> KeyringError {
    KeyringError::Store(
        KeyringStoreError::new(FirestoreKeyringStore::KIND, operation, error.to_string())
            .with_root_cause(Arc::new(error)),
    )
}

#[cfg(test)]
mod tests {
    use ::firestore::gcloud_sdk::tonic::Status;

    use super::*;

    #[test]
    fn a_failed_precondition_is_conflict() {
        let error = FirestoreError::from(Status::failed_precondition("the update time differs"));
        assert!(matches!(refused(error), Ok(Swap::Conflict)));
    }
}
