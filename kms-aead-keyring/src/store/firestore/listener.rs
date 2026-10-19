//! The watches of a [`FirestoreKeyringStore`](super::FirestoreKeyringStore) and its clones: one
//! firestore-rs listener, whose one listen stream holds a documents target for each watched
//! keyring.
//!
//! The listener's callback does the routing on firestore-rs's own loop: it signals each event to
//! the watches of its target's keyring, ends the keyrings whose target firestore-rs gave up on,
//! and takes the target of a keyring whose watches were all dropped off the stream.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use ::firestore::errors::FirestoreError;
use ::firestore::gcloud_sdk::google::firestore::v1::TargetChange;
use ::firestore::gcloud_sdk::prost_types::Timestamp;
use ::firestore::{
    FirestoreCollectionId, FirestoreDb, FirestoreListenEvent, FirestoreListener,
    FirestoreListenerTarget, FirestoreListenerTargetChangeType, FirestoreMemListenStateStorage,
    FirestoreResult,
};
use tokio::sync::mpsc;

use super::FirestoreKeyringStore;
use crate::errors::{KeyringError, KeyringResult};
use crate::store::{KeyringStore, KeyringWatch, StoreOperation, WatchEvent};
use crate::KeyringId;

/// The watches of a store and its clones, and the firestore-rs listener that signals them.
#[derive(Default)]
pub(super) struct Watches {
    /// Held across the first watch's start, around each watch's route, and across a shutdown, so
    /// that a watch either adds its target to the running listener or finds the store stopped.
    listener: tokio::sync::Mutex<ListenerState>,
    /// Shared with the listener's callback. Taken after `listener`, and never across an await.
    routes: Arc<Mutex<Routes>>,
}

#[derive(Default)]
enum ListenerState {
    #[default]
    Unstarted,
    Running(FirestoreListener<FirestoreDb, FirestoreMemListenStateStorage>),
    /// Shut down: a later watch is `None`.
    Stopped,
}

/// The watched keyrings by target. A target is never reused, so that an event Firestore still
/// sends for a removed target reaches no later keyring.
///
/// No code under the lock panics between two changes of the map, so a poisoned lock is taken as
/// it is.
#[derive(Default)]
struct Routes {
    by_target: HashMap<FirestoreListenerTarget, Route>,
    /// How many targets were allocated so far; the next one is one more.
    allocated: u32,
}

/// One keyring's target on the stream, and the watches it signals.
struct Route {
    id: KeyringId,
    watches: Vec<mpsc::Sender<WatchEvent>>,
    /// Firestore sends a document's state again when it adds a target from scratch or resumes
    /// one, so a change is signalled only when this changes.
    document: DocumentState,
    /// Firestore removed the target on its own, and firestore-rs has not added it back yet.
    removed: bool,
}

/// A document as a route last saw it.
#[derive(Clone, PartialEq)]
enum DocumentState {
    /// Firestore has sent no state on the target yet. A write between the keyring's load and the
    /// target's first state shows only in that state, never as a change of it, so the first state
    /// always signals, and the keyring revalidates on it.
    Unseen,
    Absent,
    UpdatedAt(Timestamp),
}

impl Watches {
    /// A watch of `id`'s document in `collection` of `db`, or `None` once the store is shut down.
    /// The first watch starts the listener.
    pub(super) async fn watch(
        &self,
        db: &FirestoreDb,
        collection: &FirestoreCollectionId,
        id: &KeyringId,
    ) -> KeyringResult<Option<KeyringWatch>> {
        let failed = |error: FirestoreError| {
            KeyringError::store_caused_by(
                FirestoreKeyringStore::KIND,
                StoreOperation::Watch,
                Arc::new(error),
            )
        };
        let (events, receiver) = mpsc::channel(16);
        let mut state = self.listener.lock().await;
        if let ListenerState::Unstarted = *state {
            let listener = Self::start(db, Arc::clone(&self.routes))
                .await
                .map_err(failed)?;
            *state = ListenerState::Running(listener);
        }
        let ListenerState::Running(listener) = &mut *state else {
            return Ok(None);
        };
        let mut routes = Routes::lock(&self.routes);
        if !routes.join(id, &events) {
            let target = routes.insert(id.clone(), events);
            let added = db
                .fluent()
                .select()
                .by_id_in(collection.as_str())
                .batch_listen([id.as_str()])
                .add_target(target.clone(), listener);
            if let Err(error) = added {
                // firestore-rs refuses every target once its loop has stopped on its own, so
                // every watch ends with it.
                if matches!(error, FirestoreError::SystemError(_)) {
                    routes.by_target.clear();
                } else {
                    routes.by_target.remove(&target);
                }
                return Err(failed(error));
            }
        }
        Ok(Some(KeyringWatch::new(receiver)))
    }

    /// Ends every watch and stops the listener, aborting it at `timeout`.
    pub(super) async fn shutdown(&self, timeout: Option<Duration>) {
        let mut state = self.listener.lock().await;
        Routes::lock(&self.routes).by_target.clear();
        if let ListenerState::Running(listener) = &mut *state {
            // firestore-rs logs the error its loop stopped with, which is all this returns.
            let _ = match timeout {
                None => listener.shutdown().await,
                Some(timeout) => listener.shutdown_with_timeout(timeout).await,
            };
        }
        *state = ListenerState::Stopped;
    }

    /// A started listener without targets, whose callback routes every event through `routes`.
    async fn start(
        db: &FirestoreDb,
        routes: Arc<Mutex<Routes>>,
    ) -> FirestoreResult<FirestoreListener<FirestoreDb, FirestoreMemListenStateStorage>> {
        let mut listener = db
            .create_listener(FirestoreMemListenStateStorage::new())
            .await?;
        let handle = listener.control_handle();
        listener
            .start(move |event| {
                let released = {
                    let mut routes = Routes::lock(&routes);
                    routes.apply(event, |target| handle.has_target(target));
                    routes.release_dropped()
                };
                let handle = handle.clone();
                // The released targets' routes are gone, so each one left on the stream after an
                // error would stay there: every target is tried, and the first error returned.
                async move {
                    let mut removed: FirestoreResult<()> = Ok(());
                    for target in released {
                        removed = removed.and(handle.remove_target(&target).await.map(drop));
                    }
                    Ok(removed?)
                }
            })
            .await?;
        Ok(listener)
    }
}

impl Routes {
    fn lock(routes: &Mutex<Self>) -> MutexGuard<'_, Self> {
        routes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `events` to the route of `id`, and returns whether there was one. The joining watch
    /// gets no signal of the document's state, which its keyring's first revalidation covers.
    fn join(&mut self, id: &KeyringId, events: &mpsc::Sender<WatchEvent>) -> bool {
        let Some(route) = self.by_target.values_mut().find(|route| route.id == *id) else {
            return false;
        };
        route.watches.push(events.clone());
        true
    }

    fn insert(
        &mut self,
        id: KeyringId,
        events: mpsc::Sender<WatchEvent>,
    ) -> FirestoreListenerTarget {
        // firestore-rs refuses every target past `i32::MAX`, so a saturated count fails each later
        // watch rather than reusing a target.
        self.allocated = self.allocated.saturating_add(1);
        let target = FirestoreListenerTarget::new(self.allocated);
        self.by_target.insert(
            target.clone(),
            Route {
                id,
                watches: vec![events],
                document: DocumentState::Unseen,
                removed: false,
            },
        );
        target
    }

    /// Applies one event of the listen stream. An event for a target without a route, such as
    /// one removed since, is dropped. `has_target` is firestore-rs's answer to whether it still
    /// listens to a target.
    fn apply(
        &mut self,
        event: FirestoreListenEvent,
        has_target: impl Fn(&FirestoreListenerTarget) -> bool,
    ) {
        let (targets, document) = match event {
            FirestoreListenEvent::DocumentChange(change) => (
                change.target_ids,
                change
                    .document
                    .and_then(|document| document.update_time)
                    .map_or(DocumentState::Absent, DocumentState::UpdatedAt),
            ),
            FirestoreListenEvent::DocumentDelete(delete) => {
                (delete.removed_target_ids, DocumentState::Absent)
            }
            FirestoreListenEvent::DocumentRemove(remove) => {
                (remove.removed_target_ids, DocumentState::Absent)
            }
            FirestoreListenEvent::TargetChange(change) => {
                self.target_change(change, has_target);
                return;
            }
            // An existence filter checks a query's count, which a single document needs no
            // check of.
            FirestoreListenEvent::Filter(_) => return,
        };
        for target in targets {
            let route = FirestoreListenerTarget::try_from(target)
                .ok()
                .and_then(|target| self.by_target.get_mut(&target));
            if let Some(route) = route {
                route.document(document.clone());
            }
        }
    }

    /// Applies a target change to the routes of the targets it names, or to every route when it
    /// names none, and ends the route of each target Firestore removed that firestore-rs no
    /// longer listens to.
    fn target_change(
        &mut self,
        change: TargetChange,
        has_target: impl Fn(&FirestoreListenerTarget) -> bool,
    ) {
        let Ok(change_type) =
            FirestoreListenerTargetChangeType::try_from(change.target_change_type)
        else {
            return;
        };
        // A removal without a cause acknowledges that of a released target, whose route is gone.
        if change_type == FirestoreListenerTargetChangeType::Remove && change.cause.is_none() {
            return;
        }
        let named: Vec<FirestoreListenerTarget> = change
            .target_ids
            .into_iter()
            .filter_map(|target| FirestoreListenerTarget::try_from(target).ok())
            .collect();
        // firestore-rs unregisters a target it gives up on before its callback sees the removal,
        // so `has_target` is final here; a target it keeps is added back after the retry delay.
        self.by_target.retain(|target, route| {
            if !named.is_empty() && !named.contains(target) {
                return true;
            }
            !route.target_change(change_type) || has_target(target)
        });
    }

    /// Forgets the dropped watches, and removes the routes left with none. Their targets are
    /// returned, for the caller to take off the stream.
    fn release_dropped(&mut self) -> Vec<FirestoreListenerTarget> {
        self.by_target
            .extract_if(|_, route| {
                route.watches.retain(|events| !events.is_closed());
                route.watches.is_empty()
            })
            .map(|(target, _)| target)
            .collect()
    }
}

impl Route {
    /// Applies a target change of `change_type`, a removal being one Firestore made on its own,
    /// and returns whether Firestore removed the target.
    fn target_change(&mut self, change_type: FirestoreListenerTargetChangeType) -> bool {
        match change_type {
            // Firestore sends no document for a target whose document is absent: the target
            // becoming current without one is that state.
            FirestoreListenerTargetChangeType::Current => {
                if self.document == DocumentState::Unseen {
                    self.document(DocumentState::Absent);
                }
            }
            // A reconnected stream adds every target back with its resume state, and the update
            // time covers what Firestore sends again, so only a target Firestore removed is
            // reconnected.
            FirestoreListenerTargetChangeType::Add => {
                if std::mem::take(&mut self.removed) {
                    self.signal(WatchEvent::Reconnected);
                }
            }
            FirestoreListenerTargetChangeType::Remove => {
                self.removed = true;
                self.signal(WatchEvent::Disconnected);
                return true;
            }
            // A reset resends the document's state, which the update time compares.
            FirestoreListenerTargetChangeType::NoChange
            | FirestoreListenerTargetChangeType::Reset => {}
        }
        false
    }

    fn document(&mut self, document: DocumentState) {
        if self.document != document {
            self.document = document;
            self.signal(WatchEvent::Changed);
        }
    }

    /// Sends `event` to every watch of the route. A full channel already holds a signal that
    /// covers this one, and a closed one is released at the next event.
    fn signal(&self, event: WatchEvent) {
        for events in &self.watches {
            let _ = events.try_send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use ::firestore::gcloud_sdk::google::firestore::v1::{
        Document, DocumentChange, DocumentDelete,
    };
    use ::firestore::gcloud_sdk::google::rpc::Status;
    use ::firestore::gcloud_sdk::tonic::Code;
    use tokio::sync::mpsc::error::TryRecvError;

    use super::*;
    use crate::test_support::TestResult;

    /// A target change of `change_type` for `targets`, caused by `cause` when it is one.
    fn target_change(
        change_type: FirestoreListenerTargetChangeType,
        targets: &[i32],
        cause: Option<Code>,
    ) -> FirestoreListenEvent {
        FirestoreListenEvent::TargetChange(TargetChange {
            target_change_type: change_type.into(),
            target_ids: targets.to_vec(),
            cause: cause.map(|code| Status {
                code: code.into(),
                ..Status::default()
            }),
            ..TargetChange::default()
        })
    }

    /// A write of the document on `target` that left it at `update_time`.
    fn document_change(target: i32, update_time: Timestamp) -> FirestoreListenEvent {
        FirestoreListenEvent::DocumentChange(DocumentChange {
            document: Some(Document {
                update_time: Some(update_time),
                ..Document::default()
            }),
            target_ids: vec![target],
            ..DocumentChange::default()
        })
    }

    /// The wire id of the target of a route of the keyring `name`, added to `routes`, and the
    /// route's watch.
    fn watched(
        routes: &mut Routes,
        name: &str,
    ) -> Result<(i32, mpsc::Receiver<WatchEvent>), Box<dyn Error>> {
        let (events, watch) = mpsc::channel(16);
        let target = routes.insert(KeyringId::try_from(name.to_string())?, events);
        Ok((target.try_into()?, watch))
    }

    #[test]
    fn a_target_removed_for_a_transient_cause_disconnects_and_reconnects_only_its_keyring(
    ) -> TestResult {
        let mut routes = Routes::default();
        let (removed, mut tenant_a) = watched(&mut routes, "tenant-a")?;
        let (kept, mut tenant_b) = watched(&mut routes, "tenant-b")?;
        routes.apply(
            target_change(
                FirestoreListenerTargetChangeType::Remove,
                &[removed],
                Some(Code::Unavailable),
            ),
            |_| true,
        );
        routes.apply(
            target_change(FirestoreListenerTargetChangeType::Add, &[removed], None),
            |_| true,
        );
        // A reconnected stream adds every target back.
        routes.apply(
            target_change(FirestoreListenerTargetChangeType::Add, &[kept], None),
            |_| true,
        );
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Disconnected));
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Reconnected));
        assert_eq!(tenant_a.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(tenant_b.try_recv(), Err(TryRecvError::Empty));
        Ok(())
    }

    #[test]
    fn a_removed_target_ends_its_watch_only_once_firestore_rs_has_dropped_it() -> TestResult {
        let mut routes = Routes::default();
        let (retried, mut tenant_a) = watched(&mut routes, "tenant-a")?;
        let (ended, mut tenant_b) = watched(&mut routes, "tenant-b")?;
        let still_listened = FirestoreListenerTarget::try_from(retried)?;
        routes.apply(
            target_change(
                FirestoreListenerTargetChangeType::Remove,
                &[retried, ended],
                Some(Code::Unavailable),
            ),
            |target| *target == still_listened,
        );
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Disconnected));
        assert_eq!(tenant_a.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(tenant_b.try_recv(), Ok(WatchEvent::Disconnected));
        assert_eq!(tenant_b.try_recv(), Err(TryRecvError::Disconnected));
        Ok(())
    }

    #[test]
    fn the_last_dropped_watch_releases_its_keyrings_target() -> TestResult {
        let mut routes = Routes::default();
        let tenant_a = KeyringId::try_from("tenant-a".to_string())?;
        let (events, first) = mpsc::channel(16);
        let target = routes.insert(tenant_a.clone(), events);
        let (events, second) = mpsc::channel(16);
        assert!(routes.join(&tenant_a, &events));
        let _tenant_b = watched(&mut routes, "tenant-b")?;
        drop(first);
        assert!(routes.release_dropped().is_empty());
        drop(second);
        assert_eq!(routes.release_dropped(), vec![target]);
        Ok(())
    }

    #[test]
    fn the_first_document_state_signals_and_a_resent_one_does_not() -> TestResult {
        let mut routes = Routes::default();
        let (written, mut tenant_a) = watched(&mut routes, "tenant-a")?;
        let (absent, mut tenant_b) = watched(&mut routes, "tenant-b")?;
        let created = Timestamp {
            seconds: 1,
            nanos: 0,
        };
        let updated = Timestamp {
            seconds: 2,
            nanos: 0,
        };
        let current =
            |target| target_change(FirestoreListenerTargetChangeType::Current, &[target], None);
        let deleted = FirestoreListenEvent::DocumentDelete(DocumentDelete {
            removed_target_ids: vec![written],
            ..DocumentDelete::default()
        });
        for (event, signal) in [
            (document_change(written, created), Some(WatchEvent::Changed)),
            (document_change(written, created), None),
            (current(written), None),
            (document_change(written, updated), Some(WatchEvent::Changed)),
            (deleted.clone(), Some(WatchEvent::Changed)),
            (deleted, None),
        ] {
            routes.apply(event, |_| true);
            assert_eq!(tenant_a.try_recv().ok(), signal);
        }
        // Firestore sends no document for a target whose document is absent, only its CURRENT.
        for signal in [Some(WatchEvent::Changed), None] {
            routes.apply(current(absent), |_| true);
            assert_eq!(tenant_b.try_recv().ok(), signal);
        }
        Ok(())
    }
}
