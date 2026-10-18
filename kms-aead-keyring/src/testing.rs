//! What tests of an application's keyring code use: [`MemoryKeyringStore`], a store that keeps
//! its records in the process.

use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use tokio::sync::mpsc;

use crate::errors::KeyringResult;
use crate::store::{KeyringStore, KeyringWatch, Revalidation, StoreKind, Stored, Swap, WatchEvent};
use crate::{KeyringId, KeyringRecord};

/// A keyring store in the process's memory, for tests and for values that never outlive the
/// process. `Clone` shares the same records.
///
/// Its records are lost when the process exits, and with them the wrapped keys of every version:
/// a value encrypted under a keyring in this store, and kept anywhere that outlives the process,
/// never decrypts again.
///
/// It keeps each record as its JSON document, as the other stores do, so every read checks the
/// document, and it signals a watch on every write.
#[derive(Clone, Default)]
pub struct MemoryKeyringStore {
    state: Arc<Mutex<MemoryState>>,
}

#[derive(Default)]
struct MemoryState {
    documents: HashMap<KeyringId, MemoryDocument>,
    watchers: HashMap<KeyringId, Vec<mpsc::Sender<WatchEvent>>>,
    writes: u64,
}

struct MemoryDocument {
    json: Vec<u8>,
    revision: MemoryRevision,
}

/// The revision of a record in a [`MemoryKeyringStore`]: the store's count of writes when the
/// record was written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemoryRevision(u64);

impl Display for MemoryRevision {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl MemoryKeyringStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The state, also from a poisoned lock: nothing that runs under the lock panics.
    fn lock(&self) -> MutexGuard<'_, MemoryState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl MemoryDocument {
    fn stored(&self, id: &KeyringId) -> KeyringResult<Stored<MemoryRevision>> {
        Ok(Stored {
            record: KeyringRecord::from_json(id, &self.json)?,
            revision: self.revision,
        })
    }
}

impl KeyringStore for MemoryKeyringStore {
    type Revision = MemoryRevision;

    const KIND: StoreKind = StoreKind::Memory;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<MemoryRevision>>> {
        self.lock()
            .documents
            .get(id)
            .map(|document| document.stored(id))
            .transpose()
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &MemoryRevision,
    ) -> KeyringResult<Revalidation<MemoryRevision>> {
        match self.lock().documents.get(id) {
            None => Ok(Revalidation::Missing),
            Some(document) if document.revision == *known => Ok(Revalidation::Unchanged),
            Some(document) => document.stored(id).map(Revalidation::Changed),
        }
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&MemoryRevision>,
    ) -> KeyringResult<Swap<MemoryRevision>> {
        let json = record.to_json()?;
        let id = record.id();
        let mut state = self.lock();
        let stored = state.documents.get(id).map(|document| document.revision);
        if stored.as_ref() != expected {
            return Ok(Swap::Conflict);
        }
        state.writes += 1;
        let revision = MemoryRevision(state.writes);
        state
            .documents
            .insert(id.clone(), MemoryDocument { json, revision });
        if let Some(watchers) = state.watchers.get_mut(id) {
            // A full channel already holds a signal, which covers this write too.
            watchers.retain(|watcher| {
                !matches!(
                    watcher.try_send(WatchEvent::Changed),
                    Err(mpsc::error::TrySendError::Closed(_))
                )
            });
        }
        Ok(Swap::Written(revision))
    }

    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        let (sender, receiver) = mpsc::channel(16);
        self.lock()
            .watchers
            .entry(id.clone())
            .or_default()
            .push(sender);
        Ok(Some(KeyringWatch::new(receiver)))
    }
}
