use std::sync::Arc;
use std::time::Duration;

use ::firestore::errors::FirestoreError;
use ::firestore::gcloud_sdk::google::firestore::v1::Document;
use ::firestore::{
    FirestoreCollectionId, FirestoreDb, FirestoreTimestamp, FirestoreWritePrecondition,
};
use serde::Deserialize;
use serde_json::Value;

use self::listener::Watches;
use super::{KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap};
use crate::errors::{KeyringError, KeyringResult};
use crate::{KeyringId, KeyringRecord};

mod listener;

/// A keyring store on Firestore. The record of a keyring is the document `<collection>/<id>`,
/// whose fields are those of the record's JSON document, and its revision is the document's
/// update time. `Clone` shares the client and the listener.
///
/// A create fails when the document exists, and an update carries the expected update time as
/// its precondition, so that Firestore refuses a write over a record that changed since it was
/// read. [`watch`](KeyringStore::watch) listens to the document through the store's listener,
/// whose single listen stream to Firestore carries every keyring that the store and its clones
/// watch. [`shutdown`](KeyringStore::shutdown) closes it, and so does dropping the store's last
/// clone, which ends every watch. [`with_collection`](Self::with_collection) starts a listener of
/// its own.
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
    collection: FirestoreCollectionId,
    watches: Arc<Watches>,
}

/// The update time of a document Firestore returns from a write.
#[derive(Deserialize)]
struct WrittenDocument {
    #[serde(rename = "_firestore_updated")]
    update_time: FirestoreTimestamp,
}

impl FirestoreKeyringStore {
    /// The collection of [`new`](Self::new).
    pub const DEFAULT_COLLECTION: FirestoreCollectionId =
        FirestoreCollectionId::from_static("kms_keyrings");

    /// The store in the collection [`DEFAULT_COLLECTION`](Self::DEFAULT_COLLECTION) of `db`'s
    /// database.
    pub fn new(db: FirestoreDb) -> Self {
        Self {
            db,
            collection: Self::DEFAULT_COLLECTION,
            watches: Arc::default(),
        }
    }

    /// The store in `collection` instead, validated by [`FirestoreCollectionId::new`] or
    /// [`FirestoreCollectionId::from_static`].
    pub fn with_collection(self, collection: FirestoreCollectionId) -> Self {
        Self {
            collection,
            watches: Arc::default(),
            ..self
        }
    }

    async fn document(
        &self,
        id: &KeyringId,
        operation: StoreOperation,
    ) -> KeyringResult<Option<Document>> {
        self.db
            .fluent()
            .select()
            .by_id_in(self.collection.as_str())
            .one(id.as_str())
            .await
            .map_err(|error| {
                KeyringError::store_caused_by(
                    FirestoreKeyringStore::KIND,
                    operation,
                    Arc::new(error),
                )
            })
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
                    .into(self.collection.as_str())
                    .document_id(id.as_str())
                    .object(&fields)
                    .execute::<WrittenDocument>()
                    .await
            }
            Some(revision) => {
                self.db
                    .fluent()
                    .update()
                    .in_col(self.collection.as_str())
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

    /// A watch on the document through the store's listener. It returns without waiting for
    /// Firestore's first state of the document, which signals once it arrives, whether the
    /// document exists or not: a write before it shows only in that state. After it, a signal is
    /// a change of the document's update time, or its creation or deletion. The watches of a
    /// keyring share its target, which leaves the stream at the first listen event after the
    /// last of them is dropped, and a watch that joins a keyring's target gets no signal of the
    /// state Firestore has already sent.
    ///
    /// firestore-rs reconnects a lost stream on its own and resumes every target, and the update
    /// time covers what Firestore sends again, so a reconnect signals nothing. When Firestore
    /// removes the keyring's target, the watch sends [`Disconnected`](super::WatchEvent::Disconnected),
    /// then [`Reconnected`](super::WatchEvent::Reconnected) once firestore-rs adds the target back.
    /// The watch ends instead when firestore-rs gives up on the target, as its
    /// [`has_target`](firestore::FirestoreListenerControlHandle::has_target) reports.
    ///
    /// firestore-rs reports a listener that stopped on its own only when a target is added. The
    /// first watch of a keyring the store does not watch yet then fails, every watch ends, and
    /// every later watch fails too. firestore-rs logs the error the listener stopped with.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Store`] when firestore-rs refuses the target, as it refuses every one once
    /// the listener has stopped on its own.
    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        self.watches.watch(&self.db, &self.collection, id).await
    }

    /// Stops the listener, which closes its stream, and joins it: every watch ends, and a later
    /// watch is `None`. Loads and writes keep working.
    async fn shutdown(&self, timeout: Option<Duration>) {
        self.watches.shutdown(timeout).await;
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
        KeyringError::store(
            FirestoreKeyringStore::KIND,
            operation,
            "Firestore returned a document without an update time",
        )
    })?;
    FirestoreTimestamp::try_from(update_time).map_err(|error| {
        KeyringError::store_caused_by(FirestoreKeyringStore::KIND, operation, Arc::new(error))
    })
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
        _ => Err(KeyringError::store_caused_by(
            FirestoreKeyringStore::KIND,
            StoreOperation::CompareAndSwap,
            Arc::new(error),
        )),
    }
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
