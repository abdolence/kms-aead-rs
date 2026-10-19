//! The listener behind the watches of a [`FirestoreKeyringStore`](super::FirestoreKeyringStore)
//! and its clones: one firestore-rs listener, whose one listen stream holds a documents target
//! for each watched keyring.
//!
//! A task owns the listener. It adds a keyring's target with the keyring's first watch, on the
//! open stream, and removes it once the last watch is dropped. The listener's callback routes
//! each event by its target id to the watches of that target's keyring.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use ::firestore::errors::FirestoreError;
use ::firestore::gcloud_sdk::google::firestore::v1::{
    DocumentDelete, DocumentRemove, TargetChange,
};
use ::firestore::gcloud_sdk::prost_types::Timestamp;
use ::firestore::{
    FirestoreCollectionDocuments, FirestoreDb, FirestoreListenEvent, FirestoreListener,
    FirestoreListenerTarget, FirestoreListenerTargetChangeType, FirestoreListenerTargetParams,
    FirestoreMemListenStateStorage, FirestoreResult, FirestoreTargetType,
};
use futures_util::future::BoxFuture;
use futures_util::stream::{FuturesUnordered, StreamExt};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinSet;
use tokio::time::{Instant, MissedTickBehavior};

use super::FirestoreKeyringStore;
use crate::errors::{KeyringError, KeyringResult};
use crate::store::{join_until, KeyringStore, KeyringWatch, StoreOperation, WatchEvent};
use crate::KeyringId;

/// How long a watch waits for Firestore's first state of the document. The keyring awaits the
/// watch when it opens, and the load just before it reached Firestore.
const WATCH_START_TIMEOUT: Duration = Duration::from_secs(10);

/// How often the task asks firestore-rs whether it still listens to a target Firestore removed.
/// firestore-rs decides only after the callback has returned, and adds a target it keeps back only
/// after its retry delay, so the task asks until the target is back or gone.
const REMOVAL_CHECK_INTERVAL: Duration = Duration::from_millis(50);

/// The listener of a store and its clones. The first watch starts its task, and the store's
/// shutdown stops it.
#[derive(Default)]
pub(super) struct SharedListener {
    /// Held by a watch while it reaches the task, and by a shutdown until the task is joined, so
    /// that a watch either reaches the task before the shutdown's stop or finds the store stopped.
    state: tokio::sync::Mutex<ListenerState>,
}

#[derive(Default)]
struct ListenerState {
    commands: Commands,
    /// The listener task, kept until a shutdown has joined it, a cancelled one included. Dropping
    /// it with the last store clone aborts the task, which ends every watch.
    task: JoinSet<()>,
}

/// How watches reach the listener task.
#[derive(Default)]
enum Commands {
    /// No watch has started the task.
    #[default]
    Unstarted,
    /// The task stops once this sender is dropped and it has served the requests sent before.
    Running(mpsc::UnboundedSender<WatchRequest>),
    /// The store was shut down: no watch starts the task again.
    Stopped,
}

/// A watch of `id` signalled through `events`. The task answers on `registered` with the
/// `current` flag of the keyring's route, or with the error that kept its target off the stream.
struct WatchRequest {
    id: KeyringId,
    events: mpsc::Sender<WatchEvent>,
    registered: oneshot::Sender<KeyringResult<watch::Receiver<bool>>>,
}

/// The task that owns a store's firestore-rs listener.
struct ListenerTask {
    /// The listener while it runs, or the error it did not start or stopped with. A stopped
    /// listener is not replaced, and every later watch fails with that error.
    listener:
        Result<FirestoreListener<FirestoreDb, FirestoreMemListenStateStorage>, Arc<FirestoreError>>,
    /// The callback holds only a weak reference, so that the routes, and with them every
    /// watch's senders, go when the task ends, an abort included.
    routes: Arc<Mutex<Routes>>,
    collection: String,
    /// The target of the next keyring watched. Targets are never reused, so that an event
    /// Firestore still sends for a removed target reaches no later keyring.
    next_target: u32,
    /// One future per watch, which resolves with the watch's target once the watch is dropped or
    /// its route ends.
    releases: FuturesUnordered<BoxFuture<'static, FirestoreListenerTarget>>,
    /// The targets Firestore removed whose routes wait for firestore-rs to add them back or to
    /// stop listening to them.
    unsettled: HashSet<FirestoreListenerTarget>,
}

/// The watched keyrings, by keyring and by target. The task adds routes, and removes released
/// ones and those of targets firestore-rs stopped listening to; the callback routes events.
///
/// No code under the lock panics between two changes of the maps, so a poisoned lock is taken as
/// it is.
#[derive(Default)]
struct Routes {
    keyrings: HashMap<KeyringId, Route>,
    targets: HashMap<FirestoreListenerTarget, KeyringId>,
}

/// One keyring's target on the stream, and the watches it signals.
struct Route {
    target: FirestoreListenerTarget,
    events: Vec<mpsc::Sender<WatchEvent>>,
    /// The document's update time as the listener last saw it, `None` while it is absent.
    /// Firestore sends a document's state again when it adds a target from scratch or resumes
    /// one, so a change is signalled only when this changes.
    update_time: Option<Timestamp>,
    /// `true` once Firestore has sent the document's state on this target. A watch waits for it,
    /// and the route signals nothing before it. Dropped when the route ends.
    current: watch::Sender<bool>,
    state: TargetState,
}

/// Where a route's target stands, going by Firestore's target changes.
#[derive(Clone, Copy, PartialEq, Eq)]
enum TargetState {
    /// Firestore has not acknowledged the target yet. A change for every target leaves it out,
    /// as firestore-rs does.
    Adding,
    Listening,
    /// Firestore removed the target, and firestore-rs has not added it back yet.
    Removed,
}

impl SharedListener {
    /// A watch of `id`'s document in `collection` of `db`, or `None` once the store is shut down.
    /// The first watch starts the listener task.
    pub(super) async fn watch(
        &self,
        db: &FirestoreDb,
        collection: &str,
        id: &KeyringId,
    ) -> KeyringResult<Option<KeyringWatch>> {
        let (events, receiver) = mpsc::channel(16);
        let (registered, registration) = oneshot::channel();
        {
            let mut state = self.state.lock().await;
            let state = &mut *state;
            if let Commands::Unstarted = state.commands {
                let (sender, requests) = mpsc::unbounded_channel();
                state.task.spawn(ListenerTask::run(
                    db.clone(),
                    collection.to_string(),
                    requests,
                ));
                state.commands = Commands::Running(sender);
            }
            let Commands::Running(commands) = &state.commands else {
                return Ok(None);
            };
            // A closed channel means that the task has ended, and `registration` fails below.
            let _ = commands.send(WatchRequest {
                id: id.clone(),
                events,
                registered,
            });
        }
        let started = match registration.await {
            Ok(registered) => {
                let mut current = registered?;
                tokio::time::timeout(WATCH_START_TIMEOUT, current.wait_for(|current| *current))
                    .await
                    .map(|current| current.is_ok())
            }
            Err(_) => Ok(false),
        };
        match started {
            Ok(true) => Ok(Some(KeyringWatch::new(receiver))),
            // The task ended without answering, or the route ended before its target was current.
            Ok(false) => {
                if let Commands::Stopped = self.state.lock().await.commands {
                    return Ok(None);
                }
                Err(KeyringError::store(
                    FirestoreKeyringStore::KIND,
                    StoreOperation::Watch,
                    "Firestore stopped listening to the document",
                ))
            }
            Err(_) => Err(KeyringError::store(
                FirestoreKeyringStore::KIND,
                StoreOperation::Watch,
                "Firestore sent no state of the document",
            )),
        }
    }

    /// Stops the listener task and joins it, aborting it at `timeout`.
    pub(super) async fn shutdown(&self, timeout: Option<Duration>) {
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        let mut state = self.state.lock().await;
        state.commands = Commands::Stopped;
        join_until(&mut state.task, deadline).await;
    }
}

impl ListenerTask {
    /// Serves the watches that `requests` brings until the store shuts down, and shuts the
    /// listener down.
    async fn run(
        db: FirestoreDb,
        collection: String,
        mut requests: mpsc::UnboundedReceiver<WatchRequest>,
    ) {
        let routes = Arc::new(Mutex::new(Routes::default()));
        let (report_removal, mut removals) = mpsc::unbounded_channel();
        let mut task = ListenerTask {
            listener: Self::start(&db, Arc::downgrade(&routes), report_removal)
                .await
                .map_err(Arc::new),
            routes,
            collection,
            next_target: 1,
            releases: FuturesUnordered::new(),
            unsettled: HashSet::new(),
        };
        let mut removal_checks = tokio::time::interval(REMOVAL_CHECK_INTERVAL);
        removal_checks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                request = requests.recv() => match request {
                    Some(request) => task.register(request).await,
                    None => break,
                },
                Some(target) = task.releases.next() => task.release(target).await,
                Some(target) = removals.recv() => {
                    task.unsettled.insert(target);
                }
                _ = removal_checks.tick(), if !task.unsettled.is_empty() => task.settle_removals(),
            }
        }
        if let Ok(listener) = &mut task.listener {
            // firestore-rs logs the error its loop stopped with, which is all this returns.
            let _ = listener.shutdown().await;
        }
    }

    /// A started listener without targets, whose callback routes every event through `routes`
    /// and sends each target Firestore removed to `report_removal`.
    async fn start(
        db: &FirestoreDb,
        routes: Weak<Mutex<Routes>>,
        report_removal: mpsc::UnboundedSender<FirestoreListenerTarget>,
    ) -> FirestoreResult<FirestoreListener<FirestoreDb, FirestoreMemListenStateStorage>> {
        let mut listener = db
            .create_listener(FirestoreMemListenStateStorage::new())
            .await?;
        listener
            .start(move |event| {
                if let Some(routes) = routes.upgrade() {
                    let removed = Routes::lock(&routes).route(event);
                    for target in removed {
                        // A closed channel means that the task has ended.
                        let _ = report_removal.send(target);
                    }
                }
                std::future::ready(Ok(()))
            })
            .await?;
        Ok(listener)
    }

    /// Adds the request's watch to the watches of its keyring, with a new target for a keyring not
    /// watched yet, and answers it.
    async fn register(&mut self, request: WatchRequest) {
        let WatchRequest {
            id,
            events,
            registered,
        } = request;
        // A route firestore-rs stopped listening to is ended first, so that the watch does not
        // join it.
        self.settle_removals();
        let joined = Routes::lock(&self.routes).join(&id, &events);
        let route = match joined {
            Some(route) => Ok(route),
            None => {
                let target = FirestoreListenerTarget::new(self.next_target);
                // firestore-rs refuses every target past `i32::MAX`, so a saturated counter fails
                // each later watch rather than reusing a target.
                self.next_target = self.next_target.saturating_add(1);
                let current =
                    Routes::lock(&self.routes).insert(id.clone(), target.clone(), events.clone());
                self.add_target(&id, &target)
                    .await
                    .map(|()| (target, current))
            }
        };
        let answer = match route {
            Ok((target, current)) => {
                let mut ended = current.clone();
                self.releases.push(Box::pin(async move {
                    tokio::select! {
                        () = events.closed() => {}
                        // The route ended, which drops its `current` sender.
                        () = async { while ended.changed().await.is_ok() {} } => {}
                    }
                    target
                }));
                Ok(current)
            }
            Err(error) => Err(KeyringError::store_caused_by(
                FirestoreKeyringStore::KIND,
                StoreOperation::Watch,
                error,
            )),
        };
        // A closed answer means that the watch was cancelled, and its release follows.
        let _ = registered.send(answer);
    }

    /// Adds the target of `id`'s new route to the stream, or ends the route. A listener whose
    /// loop has stopped on its own refuses the target; its shutdown then returns why, every
    /// watch ends, and the task keeps that error for every later watch.
    async fn add_target(
        &mut self,
        id: &KeyringId,
        target: &FirestoreListenerTarget,
    ) -> Result<(), Arc<FirestoreError>> {
        let refused = match &mut self.listener {
            Err(stopped_with) => Arc::clone(stopped_with),
            Ok(listener) => {
                let documents = FirestoreCollectionDocuments::new(
                    self.collection.clone(),
                    vec![id.as_str().to_string()],
                );
                let error = match listener.add_target(FirestoreListenerTargetParams::new(
                    target.clone(),
                    FirestoreTargetType::Documents(documents),
                    HashMap::new(),
                )) {
                    Ok(()) => return Ok(()),
                    Err(error) => error,
                };
                if let FirestoreError::SystemError(_) = error {
                    let stopped_with = Arc::new(listener.shutdown().await.err().unwrap_or(error));
                    *Routes::lock(&self.routes) = Routes::default();
                    self.listener = Err(Arc::clone(&stopped_with));
                    stopped_with
                } else {
                    Arc::new(error)
                }
            }
        };
        Routes::lock(&self.routes).end(target);
        Err(refused)
    }

    /// Forgets the dropped watches of `target`'s route, and takes the target off the stream once
    /// the route has none left or has ended.
    async fn release(&mut self, target: FirestoreListenerTarget) {
        if Routes::lock(&self.routes).release(&target) {
            return;
        }
        if let Ok(listener) = &self.listener {
            // firestore-rs fails nothing here: it logs a resume state it could not forget. A
            // target it no longer has, such as one Firestore ended, is `Ok(false)`.
            let _ = listener.remove_target(&target).await;
        }
    }

    /// Ends the routes of the removed targets that firestore-rs no longer listens to, and forgets
    /// those it has added back.
    fn settle_removals(&mut self) {
        let listener = self.listener.as_ref().ok();
        let mut routes = Routes::lock(&self.routes);
        self.unsettled.retain(|target| {
            routes.settle(
                target,
                listener.is_some_and(|listener| listener.has_target(target)),
            )
        });
    }
}

impl Routes {
    fn lock(routes: &Mutex<Self>) -> MutexGuard<'_, Self> {
        routes.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Adds `events` to the route of `id`, and returns the route's target and `current` flag, or
    /// `None` when `id` has no route.
    fn join(
        &mut self,
        id: &KeyringId,
        events: &mpsc::Sender<WatchEvent>,
    ) -> Option<(FirestoreListenerTarget, watch::Receiver<bool>)> {
        let route = self.keyrings.get_mut(id)?;
        route.events.push(events.clone());
        Some((route.target.clone(), route.current.subscribe()))
    }

    /// Adds the route of `id` on `target`, signalling `events`, and returns its `current` flag.
    fn insert(
        &mut self,
        id: KeyringId,
        target: FirestoreListenerTarget,
        events: mpsc::Sender<WatchEvent>,
    ) -> watch::Receiver<bool> {
        let (current, receiver) = watch::channel(false);
        self.targets.insert(target.clone(), id.clone());
        self.keyrings.insert(
            id,
            Route {
                target,
                events: vec![events],
                update_time: None,
                current,
                state: TargetState::Adding,
            },
        );
        receiver
    }

    /// Removes the route of `target`. Its watches end once their releases drop the senders
    /// those hold.
    fn end(&mut self, target: &FirestoreListenerTarget) {
        if let Some(id) = self.targets.remove(target) {
            self.keyrings.remove(&id);
        }
    }

    /// Forgets the dropped watches of `target`'s route, removes the route when none is left, and
    /// returns whether the route is still there.
    fn release(&mut self, target: &FirestoreListenerTarget) -> bool {
        let Some(route) = self
            .targets
            .get(target)
            .and_then(|id| self.keyrings.get_mut(id))
        else {
            return false;
        };
        route.events.retain(|events| !events.is_closed());
        if !route.events.is_empty() {
            return true;
        }
        self.end(target);
        false
    }

    /// Ends the route of the removed `target` unless firestore-rs still `listened` to it, and
    /// returns whether the route still waits for firestore-rs to add the target back.
    fn settle(&mut self, target: &FirestoreListenerTarget, listened: bool) -> bool {
        let removed = self
            .targets
            .get(target)
            .and_then(|id| self.keyrings.get(id))
            .is_some_and(|route| route.state == TargetState::Removed);
        if removed && !listened {
            self.end(target);
        }
        removed && listened
    }

    /// The route of the target with the wire id `target`, if it has one.
    fn route_mut(&mut self, target: i32) -> Option<&mut Route> {
        let target = FirestoreListenerTarget::try_from(target).ok()?;
        self.keyrings.get_mut(self.targets.get(&target)?)
    }

    /// Applies one event of the listen stream, and returns the targets Firestore removed. An
    /// event for a target without a route, such as one removed since, is dropped.
    fn route(&mut self, event: FirestoreListenEvent) -> Vec<FirestoreListenerTarget> {
        match event {
            FirestoreListenEvent::DocumentChange(change) => {
                let update_time = change.document.and_then(|document| document.update_time);
                for target in change.target_ids {
                    if let Some(route) = self.route_mut(target) {
                        route.document(update_time);
                    }
                }
            }
            FirestoreListenEvent::DocumentDelete(DocumentDelete {
                removed_target_ids, ..
            })
            | FirestoreListenEvent::DocumentRemove(DocumentRemove {
                removed_target_ids, ..
            }) => {
                for target in removed_target_ids {
                    if let Some(route) = self.route_mut(target) {
                        route.document(None);
                    }
                }
            }
            FirestoreListenEvent::TargetChange(change) => return self.target_change(change),
            // An existence filter checks a query's count, which a single document needs no
            // check of.
            FirestoreListenEvent::Filter(_) => {}
        }
        Vec::new()
    }

    /// Applies a target change to the routes of the targets it names, or, when it names none, to
    /// those of the targets Firestore has acknowledged, and returns the targets Firestore removed.
    fn target_change(&mut self, change: TargetChange) -> Vec<FirestoreListenerTarget> {
        let change_type =
            match FirestoreListenerTargetChangeType::try_from(change.target_change_type) {
                Ok(
                    change_type @ (FirestoreListenerTargetChangeType::Add
                    | FirestoreListenerTargetChangeType::Current),
                ) => change_type,
                Ok(FirestoreListenerTargetChangeType::Remove) if change.cause.is_some() => {
                    FirestoreListenerTargetChangeType::Remove
                }
                // A removal without a cause acknowledges that of a released target, whose route is
                // gone. A reset resends the document's state, which the update time compares.
                _ => return Vec::new(),
            };
        let mut removed = Vec::new();
        let mut apply = |route: &mut Route| {
            if route.target_change(change_type) {
                removed.push(route.target.clone());
            }
        };
        if change.target_ids.is_empty() {
            self.keyrings
                .values_mut()
                .filter(|route| route.state == TargetState::Listening)
                .for_each(apply);
        } else {
            for target in change.target_ids {
                if let Some(route) = self.route_mut(target) {
                    apply(route);
                }
            }
        }
        removed
    }
}

impl Route {
    /// Applies a target change of `change_type`, a removal being one Firestore made on its own,
    /// and returns whether Firestore removed the target.
    fn target_change(&mut self, change_type: FirestoreListenerTargetChangeType) -> bool {
        match change_type {
            FirestoreListenerTargetChangeType::Current => {
                self.current.send_replace(true);
            }
            // A reconnected stream adds every target back with its resume state, and the update
            // time covers what Firestore sends again, so only a target Firestore removed is
            // reconnected.
            FirestoreListenerTargetChangeType::Add => {
                if std::mem::replace(&mut self.state, TargetState::Listening)
                    == TargetState::Removed
                {
                    self.signal(WatchEvent::Reconnected);
                }
            }
            FirestoreListenerTargetChangeType::Remove => {
                self.state = TargetState::Removed;
                self.signal(WatchEvent::Disconnected);
                return true;
            }
            FirestoreListenerTargetChangeType::NoChange
            | FirestoreListenerTargetChangeType::Reset => {}
        }
        false
    }

    /// Takes the document's update time from a change or deletion, and signals a change of it.
    fn document(&mut self, update_time: Option<Timestamp>) {
        if self.update_time != update_time {
            self.update_time = update_time;
            self.signal(WatchEvent::Changed);
        }
    }

    /// Sends `event` to every watch of the route once its target is current. Before that the
    /// keyring has not started following its watch, and its first revalidation covers what came
    /// earlier. A full channel already holds a signal that covers this one, and a closed one is
    /// released by the task.
    fn signal(&self, event: WatchEvent) {
        if !*self.current.borrow() {
            return;
        }
        for events in &self.events {
            let _ = events.try_send(event);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

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

    /// The watch of a current route of the keyring `name` on `target`, added to `routes`.
    fn watched(
        routes: &mut Routes,
        name: &str,
        target: i32,
    ) -> Result<mpsc::Receiver<WatchEvent>, Box<dyn Error>> {
        let (events, watch) = mpsc::channel(16);
        routes.insert(
            KeyringId::try_from(name.to_string())?,
            FirestoreListenerTarget::try_from(target)?,
            events,
        );
        for change_type in [
            FirestoreListenerTargetChangeType::Add,
            FirestoreListenerTargetChangeType::Current,
        ] {
            routes.route(target_change(change_type, &[target], None));
        }
        Ok(watch)
    }

    #[test]
    fn a_target_removed_for_a_transient_cause_disconnects_and_reconnects_only_its_keyring(
    ) -> TestResult {
        let mut routes = Routes::default();
        let mut tenant_a = watched(&mut routes, "tenant-a", 1)?;
        let mut tenant_b = watched(&mut routes, "tenant-b", 2)?;
        for target in routes.route(target_change(
            FirestoreListenerTargetChangeType::Remove,
            &[1],
            Some(Code::Unavailable),
        )) {
            routes.settle(&target, true);
        }
        routes.route(target_change(
            FirestoreListenerTargetChangeType::Add,
            &[1],
            None,
        ));
        // A reconnected stream adds every target back.
        routes.route(target_change(
            FirestoreListenerTargetChangeType::Add,
            &[2],
            None,
        ));
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Disconnected));
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Reconnected));
        assert_eq!(tenant_a.try_recv(), Err(TryRecvError::Empty));
        assert_eq!(tenant_b.try_recv(), Err(TryRecvError::Empty));
        Ok(())
    }

    #[test]
    fn a_target_firestore_rs_ended_ends_only_its_keyrings_watch() -> TestResult {
        let mut routes = Routes::default();
        let mut tenant_a = watched(&mut routes, "tenant-a", 1)?;
        let mut tenant_b = watched(&mut routes, "tenant-b", 2)?;
        for target in routes.route(target_change(
            FirestoreListenerTargetChangeType::Remove,
            &[1],
            Some(Code::InvalidArgument),
        )) {
            routes.settle(&target, false);
        }
        assert_eq!(tenant_a.try_recv(), Ok(WatchEvent::Disconnected));
        assert_eq!(tenant_a.try_recv(), Err(TryRecvError::Disconnected));
        assert_eq!(tenant_b.try_recv(), Err(TryRecvError::Empty));
        let (events, _watch) = mpsc::channel(16);
        assert!(routes
            .join(&KeyringId::try_from("tenant-a".to_string())?, &events)
            .is_none());
        Ok(())
    }

    #[test]
    fn a_change_for_every_target_skips_the_targets_firestore_has_not_added() -> TestResult {
        let mut routes = Routes::default();
        let _tenant_a = watched(&mut routes, "tenant-a", 1)?;
        let (events, _tenant_b) = mpsc::channel(16);
        let tenant_b = routes.insert(
            KeyringId::try_from("tenant-b".to_string())?,
            FirestoreListenerTarget::try_from(2)?,
            events,
        );
        routes.route(target_change(
            FirestoreListenerTargetChangeType::Current,
            &[],
            None,
        ));
        assert!(!*tenant_b.borrow());
        Ok(())
    }
}
