//! The in-process copy of one keyring record, [`RecordCache`]: what sealers and `decrypt` read
//! instead of the store, and the rules by which it is refreshed.
//!
//! - A record older than the TTL is revalidated with a conditional read by the first call that
//!   finds it so, while the other calls keep using it. A failed revalidation keeps it, and is
//!   retried after the reload interval.
//! - An unknown key id causes one reload, which concurrent misses share, at most once per reload
//!   interval. So does a key id that a sealer looks up and the record holds as pending, since a
//!   value under it shows that another process saw the version active.
//! - A store's change signal causes a revalidation, at most once per reload interval; signals
//!   inside the interval collapse into the next one.
//! - A refreshed record is taken only if it moves forward from the cached one, and a record that
//!   went missing from the store stays in use.
//! - Taking a record evicts from the DEK cache every key it takes out of use.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use kms_aead::cache::DekCache;
use kms_aead::KekRef;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::errors::{KeyringResult, RecordRegressedError, RegressionRule};
use crate::record::{check_successor, withdrawn_deks};
use crate::spans::{self, LoadChanged, LoadReason, Reload};
use crate::store::{KeyringStore, KeyringWatch, Revalidation, Stored, WatchEvent};
#[cfg(feature = "admin")]
use crate::{errors::RecordConflictError, record::RecordEdit, store::Swap};
use crate::{KeyId, KeyVersion, KeyVersionState, KeyringError, KeyringId, KeyringRecord, Purpose};

/// The cached record of one keyring, and the store it came from.
pub(crate) struct RecordCache<S: KeyringStore> {
    store: Arc<S>,
    id: KeyringId,
    kek: KekRef,
    dek_cache: DekCache,
    record_ttl: Duration,
    reload_min_interval: Duration,
    cached: Mutex<Cached<S::Revision>>,
    /// Held by every store read that may change the cached record, and by every write, so that
    /// one runs at a time and none takes a record older than the one another just took. It
    /// holds when the last reload for a key id that [`find`](Self::find) missed ran.
    refresh: tokio::sync::Mutex<Option<Instant>>,
    /// The reloads for key ids that `find` missed so far, read before waiting for `refresh`, so
    /// that a caller can tell that a reload ran while it waited.
    lookup_reloads: AtomicU64,
}

struct Cached<R> {
    record: Arc<KeyringRecord>,
    revision: R,
    revalidate_at: Instant,
}

impl<S: KeyringStore> RecordCache<S> {
    /// The cache of `stored`, the record of its keyring as just read or written. `kek` is the
    /// provider's, under which `dek_cache` holds the decrypted keys of the record's versions.
    pub(crate) fn new(
        store: Arc<S>,
        kek: KekRef,
        dek_cache: DekCache,
        record_ttl: Duration,
        reload_min_interval: Duration,
        stored: Stored<S::Revision>,
    ) -> Self {
        Self {
            store,
            id: stored.record.id().clone(),
            kek,
            dek_cache,
            record_ttl,
            reload_min_interval,
            cached: Mutex::new(Cached {
                record: Arc::new(stored.record),
                revision: stored.revision,
                revalidate_at: after(Instant::now(), record_ttl),
            }),
            refresh: tokio::sync::Mutex::default(),
            lookup_reloads: AtomicU64::new(0),
        }
    }

    pub(crate) fn id(&self) -> &KeyringId {
        &self.id
    }

    pub(crate) fn dek_cache(&self) -> &DekCache {
        &self.dek_cache
    }

    pub(crate) fn record(&self) -> Arc<KeyringRecord> {
        Arc::clone(&self.lock().record)
    }

    /// The cached record, revalidated first when it is older than the TTL and no other call is
    /// refreshing it.
    pub(crate) async fn current(&self) -> Arc<KeyringRecord> {
        if self.revalidation_due() {
            if let Ok(refresh) = self.refresh.try_lock() {
                // Another call may have revalidated between the check and the lock.
                if self.revalidation_due() {
                    self.revalidate(&refresh, LoadReason::Ttl).await;
                }
            }
        }
        self.record()
    }

    /// The cached record, reloaded first when `lookup` finds version `key_id` missing from it,
    /// or not yet usable: once for all the calls that miss it together, and at most once per
    /// reload interval. Returns the record, which may still miss the version, and what the miss
    /// caused, the `reload` span value.
    pub(crate) async fn find(
        &self,
        key_id: KeyId,
        lookup: VersionLookup,
    ) -> (Arc<KeyringRecord>, Reload) {
        let record = self.current().await;
        if lookup.miss(&record, key_id).is_none() {
            return (record, Reload::NotNeeded);
        }
        let reloads = self.lookup_reloads.load(Ordering::SeqCst);
        let mut last_reload = self.refresh.lock().await;
        let record = self.record();
        let Some(reason) = lookup.miss(&record, key_id) else {
            return (record, Reload::NotNeeded);
        };
        if self.lookup_reloads.load(Ordering::SeqCst) != reloads {
            return (record, Reload::Reloaded);
        }
        let now = Instant::now();
        if last_reload.is_some_and(|last| now < after(last, self.reload_min_interval)) {
            spans::reload_rate_limited(&self.id, key_id, reason);
            return (record, Reload::RateLimited);
        }
        *last_reload = Some(now);
        self.revalidate(&last_reload, reason).await;
        self.lookup_reloads.fetch_add(1, Ordering::SeqCst);
        (self.record(), Reload::Reloaded)
    }

    /// Reads the record from the store, past the TTL and the rate limit, and takes it unless it
    /// moves backwards. The cached record stays when the read fails. `reason` is the `reason`
    /// span value.
    pub(crate) async fn reload(&self, reason: LoadReason) -> KeyringResult<Arc<KeyringRecord>> {
        let refresh = self.refresh.lock().await;
        let span = spans::load(&self.id, S::KIND, reason);
        spans::in_span(span, async {
            let stored = spans::timed(self.store.load(&self.id))
                .await?
                .ok_or_else(|| KeyringError::RecordMissing(self.id.clone()))?;
            let revision = stored.revision.clone();
            match self.accept(&refresh, stored) {
                Ok(()) => {
                    spans::record_load(LoadChanged::Taken, Some(&revision));
                    Ok(self.record())
                }
                Err(rule) => {
                    spans::record_load(LoadChanged::Regressed, Some(&revision));
                    Err(self.regressed(rule))
                }
            }
        })
        .await
    }

    pub(crate) async fn read(
        store: &S,
        id: &KeyringId,
    ) -> KeyringResult<Option<Stored<S::Revision>>> {
        let span = spans::load(id, S::KIND, LoadReason::Open);
        spans::in_span(span, async {
            let stored = spans::timed(store.load(id)).await?;
            if let Some(stored) = &stored {
                spans::record_load(LoadChanged::Taken, Some(&stored.revision));
            }
            Ok(stored)
        })
        .await
    }

    /// Revalidates the cached record now, whatever its age, and takes what the store returns
    /// when it moves forward. A failure keeps the cached record, and the next TTL revalidation
    /// comes after the reload interval.
    async fn revalidate(&self, refresh: &RefreshGuard<'_>, reason: LoadReason) {
        let revision = self.lock().revision.clone();
        let span = spans::load(&self.id, S::KIND, reason);
        let result = spans::in_span(span, async {
            match spans::timed(self.store.revalidate(&self.id, &revision)).await? {
                Revalidation::Unchanged => {
                    spans::record_load(LoadChanged::Unchanged, None::<&S::Revision>)
                }
                Revalidation::Changed(stored) => {
                    let revision = stored.revision.clone();
                    match self.accept(refresh, stored) {
                        Ok(()) => spans::record_load(LoadChanged::Taken, Some(&revision)),
                        Err(rule) => {
                            spans::record_regressed(&self.id, rule);
                            spans::record_load(LoadChanged::Regressed, Some(&revision));
                        }
                    }
                }
                Revalidation::Missing => {
                    spans::record_missing_kept(&self.id);
                    spans::record_load(LoadChanged::Unchanged, None::<&S::Revision>);
                }
            }
            Ok(())
        })
        .await;
        let next = match result {
            Ok(()) => self.record_ttl,
            Err(error) => {
                spans::revalidation_failed(&self.id, &error);
                self.reload_min_interval
            }
        };
        self.lock().revalidate_at = after(Instant::now(), next);
    }

    fn accept(
        &self,
        refresh: &RefreshGuard<'_>,
        stored: Stored<S::Revision>,
    ) -> Result<(), RegressionRule> {
        check_successor(&self.record(), &stored.record)?;
        self.install(refresh, stored);
        Ok(())
    }

    /// Takes `stored` as the cached record, then evicts from the DEK cache the keys it takes out
    /// of use. A read that took the previous record just before can still cache such a key
    /// again after this eviction; the keyring evicts it once more after that read's miss.
    fn install(&self, _refresh: &RefreshGuard<'_>, stored: Stored<S::Revision>) {
        let next = Arc::new(stored.record);
        let held = std::mem::replace(
            &mut *self.lock(),
            Cached {
                record: Arc::clone(&next),
                revision: stored.revision,
                revalidate_at: after(Instant::now(), self.record_ttl),
            },
        )
        .record;
        for (_, encrypted_dek) in withdrawn_deks(&held, &next) {
            self.dek_cache.invalidate(&self.kek, encrypted_dek);
        }
        for purpose in Purpose::ALL {
            let before = held.active(purpose).map(KeyVersion::id);
            let after = next.active(purpose).map(KeyVersion::id);
            if before != after {
                spans::active_version_changed(&self.id, purpose, before, after);
            }
        }
    }

    /// Evicts from the DEK cache the keys of the cached record's versions, and no other key: the
    /// DEK cache may be shared with other keyrings and envelopes.
    pub(crate) fn evict_deks(&self) {
        for (_, dek_encryption) in self.record().dek_encryptions() {
            self.dek_cache
                .invalidate(&self.kek, &dek_encryption.encrypted_dek);
        }
    }

    fn regressed(&self, rule: RegressionRule) -> KeyringError {
        spans::record_regressed(&self.id, rule);
        KeyringError::RecordRegressed(RecordRegressedError {
            keyring: self.id.clone(),
            rule,
        })
    }

    fn revalidation_due(&self) -> bool {
        Instant::now() >= self.lock().revalidate_at
    }

    /// The cached state, also from a poisoned lock: nothing that runs under the lock panics.
    fn lock(&self) -> MutexGuard<'_, Cached<S::Revision>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The writes of a `KeyringAdmin`.
#[cfg(feature = "admin")]
impl<S: KeyringStore> RecordCache<S> {
    /// Applies `change` to the record as the store holds it and writes the result with a
    /// compare-and-swap, reading again after each conflict, up to `cas_retries` times. Takes the
    /// written record, records the conflicts retried on the current span, and returns what
    /// `change` returned. A stored record that moves backwards from the cached one is refused
    /// before `change` runs.
    pub(crate) async fn write<T>(
        &self,
        cas_retries: u32,
        mut change: impl AsyncFnMut(&mut RecordEdit) -> KeyringResult<T>,
    ) -> KeyringResult<T> {
        let refresh = self.refresh.lock().await;
        for conflicts in 0..=cas_retries {
            let stored = self.read_for_write().await?;
            let mut edit = RecordEdit::from(stored.record);
            let outcome = change(&mut edit).await?;
            let record = edit.finish()?;
            match self
                .store
                .compare_and_swap(&record, Some(&stored.revision))
                .await?
            {
                Swap::Written(revision) => {
                    self.install(&refresh, Stored { record, revision });
                    spans::record_cas_retries(conflicts);
                    return Ok(outcome);
                }
                Swap::Conflict => spans::write_conflict(&self.id, conflicts.saturating_add(1)),
            }
        }
        Err(KeyringError::RecordConflict(RecordConflictError {
            keyring: self.id.clone(),
            attempts: cas_retries.saturating_add(1),
        }))
    }

    /// The store's record, refused when it moves backwards from the cached one, for a write to
    /// build on.
    async fn read_for_write(&self) -> KeyringResult<Stored<S::Revision>> {
        let span = spans::load(&self.id, S::KIND, LoadReason::Admin);
        spans::in_span(span, async {
            let stored = spans::timed(self.store.load(&self.id))
                .await?
                .ok_or_else(|| KeyringError::RecordMissing(self.id.clone()))?;
            match check_successor(&self.record(), &stored.record) {
                Ok(()) => {
                    spans::record_load(LoadChanged::Unchanged, Some(&stored.revision));
                    Ok(stored)
                }
                Err(rule) => {
                    spans::record_load(LoadChanged::Regressed, Some(&stored.revision));
                    Err(self.regressed(rule))
                }
            }
        })
        .await
    }
}

impl<S: KeyringStore> RecordCache<S> {
    /// Revalidates `cache` once at the start, then on the change signals of `watch`, at most
    /// once per reload interval, until `stop` is set or its sender dropped, the watch ends, or
    /// the cache is dropped. A signal inside the interval waits for its end, and every signal
    /// that arrived meanwhile is covered by that one revalidation. The first revalidation covers
    /// a write between the record's load and the subscription, which no signal reports.
    ///
    /// `stop` ends every wait at once, while a revalidation in flight finishes and is taken. A
    /// watch that ends before `stop` is set means that the store stopped its listener under the
    /// keyring, which then runs on its record TTL.
    pub(crate) async fn follow(
        cache: Weak<Self>,
        id: KeyringId,
        interval: Duration,
        mut watch: KeyringWatch,
        mut stop: watch::Receiver<bool>,
    ) {
        let mut last: Option<Instant> = None;
        loop {
            if let Some(last) = last {
                loop {
                    tokio::select! {
                        biased;
                        _ = stop.wait_for(|stop| *stop) => return,
                        event = watch.next() => match event {
                            None => {
                                spans::watch_ended(&id);
                                return;
                            }
                            Some(event) if log_watch_event(&id, event) => break,
                            Some(_) => {}
                        },
                    }
                }
                tokio::select! {
                    biased;
                    _ = stop.wait_for(|stop| *stop) => return,
                    () = tokio::time::sleep_until(after(last, interval)) => {}
                }
            }
            // No more than were queued here, so that a listener that keeps sending cannot hold
            // the task in this loop.
            for _ in 0..watch.events.len() {
                let Ok(event) = watch.events.try_recv() else {
                    break;
                };
                log_watch_event(&id, event);
            }
            let Some(cache) = cache.upgrade() else {
                return;
            };
            last = Some(Instant::now());
            let refresh = tokio::select! {
                biased;
                _ = stop.wait_for(|stop| *stop) => return,
                refresh = cache.refresh.lock() => refresh,
            };
            cache.revalidate(&refresh, LoadReason::Watch).await;
        }
    }
}

/// A held lock of `RecordCache::refresh`: the witness that the caller runs alone among the
/// reads and writes that change the cached record.
type RefreshGuard<'a> = tokio::sync::MutexGuard<'a, Option<Instant>>;

/// The versions that [`RecordCache::find`] takes from the cached record without a reload.
#[derive(Debug, Clone, Copy)]
pub(crate) enum VersionLookup {
    /// Any version the record holds: what `decrypt` opens a value with.
    Any,
    /// A version past pending. A value or beacon under a version the record holds as pending
    /// was sealed by a process that saw it active, so the record is behind the store.
    PastPending,
}

impl VersionLookup {
    /// Why `record` misses version `key_id` for this lookup, the reason of the reload, or `None`
    /// when it has the version.
    fn miss(self, record: &KeyringRecord, key_id: KeyId) -> Option<LoadReason> {
        match (self, record.version(key_id).map(KeyVersion::state)) {
            (_, None) => Some(LoadReason::UnknownKeyId),
            (VersionLookup::PastPending, Some(KeyVersionState::Pending)) => {
                Some(LoadReason::PendingKeyId)
            }
            (_, Some(_)) => None,
        }
    }
}

/// `wait` after `start`, or an instant beyond any process's lifetime when that overflows, so
/// that a `Duration::MAX` option means never rather than a panic.
fn after(start: Instant, wait: Duration) -> Instant {
    const FAR_FUTURE: Duration = Duration::from_secs(100 * 365 * 24 * 60 * 60);
    start
        .checked_add(wait)
        .or_else(|| start.checked_add(FAR_FUTURE))
        .unwrap_or(start)
}

/// Logs a lost or regained connection, and returns whether `event` calls for a revalidation.
fn log_watch_event(keyring: &KeyringId, event: WatchEvent) -> bool {
    match event {
        WatchEvent::Changed => true,
        WatchEvent::Disconnected => {
            spans::watch_disconnected(keyring);
            false
        }
        WatchEvent::Reconnected => {
            spans::watch_reconnected(keyring);
            true
        }
    }
}
