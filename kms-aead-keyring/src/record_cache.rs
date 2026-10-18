//! The in-process copy of one keyring record, [`RecordCache`]: what `encrypt` and `decrypt`
//! read instead of the store, and the rules by which it is refreshed.
//!
//! - A record older than the TTL is revalidated with a conditional read by the first call that
//!   finds it so, while the other calls keep using it. A failed revalidation keeps it, and is
//!   retried after the reload interval.
//! - An unknown key id causes one reload, which concurrent misses share, at most once per reload
//!   interval.
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
use tokio::time::Instant;

use crate::errors::{KeyringResult, RecordConflictError, RecordRegressedError, RegressionRule};
use crate::record::{check_successor, withdrawn_deks, RecordEdit};
use crate::spans;
use crate::store::{KeyringStore, KeyringWatch, Revalidation, Stored, Swap, WatchEvent};
use crate::{KeyId, KeyVersion, KeyringError, KeyringId, KeyringRecord, Purpose};

/// The cached record of one keyring, and the store it came from.
pub(crate) struct RecordCache<S: KeyringStore> {
    store: S,
    id: KeyringId,
    kek: KekRef,
    dek_cache: DekCache,
    record_ttl: Duration,
    reload_min_interval: Duration,
    cached: Mutex<Cached<S::Revision>>,
    /// Held by every store read that may change the cached record, and by every write, so that
    /// one runs at a time and none takes a record older than the one another just took. It
    /// holds when the last reload for an unknown key id ran.
    refresh: tokio::sync::Mutex<Option<Instant>>,
    /// The reloads for unknown key ids so far, read before waiting for `refresh`, so that a
    /// caller can tell that a reload ran while it waited.
    unknown_id_reloads: AtomicU64,
}

struct Cached<R> {
    record: Arc<KeyringRecord>,
    revision: R,
    revalidate_at: Instant,
}

impl<S: KeyringStore> RecordCache<S> {
    /// The cache of `stored`, the record of its keyring as just read or written. `kek` is the
    /// provider's, under which `dek_cache` holds the unwrapped keys of the record's versions.
    pub(crate) fn new(
        store: S,
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
            unknown_id_reloads: AtomicU64::new(0),
        }
    }

    pub(crate) fn id(&self) -> &KeyringId {
        &self.id
    }

    pub(crate) fn store(&self) -> &S {
        &self.store
    }

    pub(crate) fn dek_cache(&self) -> &DekCache {
        &self.dek_cache
    }

    pub(crate) fn reload_min_interval(&self) -> Duration {
        self.reload_min_interval
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
                    self.revalidate(&refresh, "ttl").await;
                }
            }
        }
        self.record()
    }

    /// The cached record, reloaded first when it has no version `key_id`: once for all the
    /// calls that miss it together, and at most once per reload interval. Returns the record,
    /// which may still lack the version, and what the miss caused, the `reload` span value.
    pub(crate) async fn find(&self, key_id: KeyId) -> (Arc<KeyringRecord>, &'static str) {
        let record = self.current().await;
        if record.version(key_id).is_some() {
            return (record, "none");
        }
        let reloads = self.unknown_id_reloads.load(Ordering::SeqCst);
        let mut last_reload = self.refresh.lock().await;
        let record = self.record();
        if record.version(key_id).is_some() {
            return (record, "none");
        }
        if self.unknown_id_reloads.load(Ordering::SeqCst) != reloads {
            return (record, "reloaded");
        }
        let now = Instant::now();
        if last_reload.is_some_and(|last| now < after(last, self.reload_min_interval)) {
            spans::reload_rate_limited(&self.id, key_id);
            return (record, "rate_limited");
        }
        *last_reload = Some(now);
        self.revalidate(&last_reload, "unknown_key_id").await;
        self.unknown_id_reloads.fetch_add(1, Ordering::SeqCst);
        (self.record(), "reloaded")
    }

    /// Reads the record from the store, past the TTL and the rate limit, and takes it unless it
    /// moves backwards. The cached record stays when the read fails. `reason` is the `reason`
    /// span value.
    pub(crate) async fn reload(&self, reason: &'static str) -> KeyringResult<Arc<KeyringRecord>> {
        let refresh = self.refresh.lock().await;
        let span = spans::load(&self.id, S::KIND, reason);
        spans::in_span(span, async {
            let stored = spans::timed(self.store.load(&self.id))
                .await?
                .ok_or_else(|| KeyringError::RecordMissing(self.id.clone()))?;
            let revision = stored.revision.clone();
            match self.accept(&refresh, stored) {
                Ok(()) => {
                    spans::record_load("true", Some(&revision));
                    Ok(self.record())
                }
                Err(rule) => {
                    spans::record_load("regressed", Some(&revision));
                    Err(self.regressed(rule))
                }
            }
        })
        .await
    }

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

    pub(crate) async fn read(
        store: &S,
        id: &KeyringId,
    ) -> KeyringResult<Option<Stored<S::Revision>>> {
        let span = spans::load(id, S::KIND, "open");
        spans::in_span(span, async {
            let stored = spans::timed(store.load(id)).await?;
            if let Some(stored) = &stored {
                spans::record_load("true", Some(&stored.revision));
            }
            Ok(stored)
        })
        .await
    }

    /// The store's record, refused when it moves backwards from the cached one, for a write to
    /// build on.
    async fn read_for_write(&self) -> KeyringResult<Stored<S::Revision>> {
        let span = spans::load(&self.id, S::KIND, "admin");
        spans::in_span(span, async {
            let stored = spans::timed(self.store.load(&self.id))
                .await?
                .ok_or_else(|| KeyringError::RecordMissing(self.id.clone()))?;
            match check_successor(&self.record(), &stored.record) {
                Ok(()) => {
                    spans::record_load("false", Some(&stored.revision));
                    Ok(stored)
                }
                Err(rule) => {
                    spans::record_load("regressed", Some(&stored.revision));
                    Err(self.regressed(rule))
                }
            }
        })
        .await
    }

    /// Revalidates the cached record now, whatever its age, and takes what the store returns
    /// when it moves forward. A failure keeps the cached record, and the next TTL revalidation
    /// comes after the reload interval.
    async fn revalidate(&self, refresh: &RefreshGuard<'_>, reason: &'static str) {
        let revision = self.lock().revision.clone();
        let span = spans::load(&self.id, S::KIND, reason);
        let result = spans::in_span(span, async {
            match spans::timed(self.store.revalidate(&self.id, &revision)).await? {
                Revalidation::Unchanged => spans::record_load("false", None::<&S::Revision>),
                Revalidation::Changed(stored) => {
                    let revision = stored.revision.clone();
                    match self.accept(refresh, stored) {
                        Ok(()) => spans::record_load("true", Some(&revision)),
                        Err(rule) => {
                            spans::record_regressed(&self.id, rule);
                            spans::record_load("regressed", Some(&revision));
                        }
                    }
                }
                Revalidation::Missing => {
                    spans::record_missing_kept(&self.id);
                    spans::record_load("false", None::<&S::Revision>);
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
        for (_, dek) in withdrawn_deks(&held, &next) {
            self.dek_cache.invalidate(&self.kek, dek);
        }
        for purpose in [Purpose::Randomized, Purpose::Deterministic] {
            let before = held.active(purpose).map(KeyVersion::key_id);
            let after = next.active(purpose).map(KeyVersion::key_id);
            if before != after {
                spans::active_version_changed(&self.id, purpose, before, after);
            }
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

impl<S: KeyringStore> RecordCache<S> {
    /// Revalidates `cache` once at the start, then on the change signals of `watch`, at most
    /// once per reload interval, until the watch ends or the cache is dropped. A signal inside
    /// the interval waits for its end, and every signal that arrived meanwhile is covered by that
    /// one revalidation. The first revalidation covers a write between the record's load and the
    /// subscription, which no signal reports.
    pub(crate) async fn follow(
        cache: Weak<Self>,
        id: KeyringId,
        interval: Duration,
        mut watch: KeyringWatch,
    ) {
        let mut last: Option<Instant> = None;
        loop {
            if let Some(last) = last {
                loop {
                    match watch.next().await {
                        None => return,
                        Some(event) if log_watch_event(&id, event) => break,
                        Some(_) => {}
                    }
                }
                tokio::time::sleep_until(after(last, interval)).await;
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
            let refresh = cache.refresh.lock().await;
            cache.revalidate(&refresh, "watch").await;
        }
    }
}

/// A held lock of `RecordCache::refresh`: the witness that the caller runs alone among the
/// reads and writes that change the cached record.
type RefreshGuard<'a> = tokio::sync::MutexGuard<'a, Option<Instant>>;

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
