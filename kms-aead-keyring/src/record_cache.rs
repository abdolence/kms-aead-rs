//! The in-process copy of one keyring record, [`RecordCache`]: what encryptors and `decrypt` read
//! instead of the store, and the rules by which it is refreshed.
//!
//! - A record older than the TTL is revalidated with a conditional read by the first call that
//!   finds it so, while the other calls keep using it. A failed revalidation keeps it, and is
//!   retried after the reload interval.
//! - An unknown key id causes one reload, which concurrent misses share, at most once per reload
//!   interval. So does a key id that an encryptor looks up and the record holds as pending, since a
//!   value under it shows that another process saw the version active.
//! - A store's change signal causes a revalidation, at most once per reload interval; signals
//!   inside the interval collapse into the next one.
//! - A record read from the store has its signature checked under the registry's
//!   [`RecordSignaturePolicy`](crate::RecordSignaturePolicy) before any field of it is used.
//! - A refreshed record is taken only if it passes that check and moves forward from the cached
//!   one.
//! - A record that went missing from the store is a shredded keyring: the cache destroys every
//!   version of its record in the process, reads the store no more, and the registry opens the
//!   keyring anew. The deleted record stays the baseline of the id: the next record must be signed
//!   if it was, and must not revive a version it holds destroyed, so a copy of the record from
//!   before the deletion is refused, while a keyring created again has other versions and opens.
//! - Taking a record evicts from the DEK cache every key it takes out of use.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::time::Duration;

use jiff::Timestamp;
use kms_aead::backends::AeadBackend;
use kms_aead::cache::DekCache;
use kms_aead::KekRef;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::errors::{KeyringResult, RecordRegressedError, RegressionRule};
use crate::metrics::KeyringAttribute;
#[cfg(feature = "admin")]
use crate::record_signing::MaybeRecordSigner;
use crate::record_signing::RecordVerifier;
use crate::spans::{self, LoadChanged, LoadReason, Reload};
use crate::store::{KeyringStore, KeyringWatch, Revalidation, Stored, WatchEvent};
#[cfg(feature = "admin")]
use crate::{
    errors::RecordConflictError,
    record::RecordEdit,
    store::{Deletion, Swap},
};
use crate::{KeyId, KeyVersion, KeyVersionState, KeyringError, KeyringId, KeyringRecord, Purpose};

/// The cached record of one keyring, and the store it came from.
pub(crate) struct RecordCache<S: KeyringStore, B> {
    store: Arc<S>,
    /// The registry's record verification, on the keyrings' backend.
    verifier: Arc<RecordVerifier<B>>,
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
    keyring_attribute: KeyringAttribute,
}

struct Cached<R> {
    record: Arc<KeyringRecord>,
    revision: R,
    revalidate_at: Instant,
    /// Whether a read found the record gone from the store: `record` then has every version
    /// destroyed, and the cache reads the store no more.
    deleted: bool,
}

impl<S: KeyringStore, B: AeadBackend> RecordCache<S, B> {
    /// The cache of `stored`, the record of its keyring as just read and verified, or written.
    /// `kek` is the provider's, under which `dek_cache` holds the decrypted keys of the record's
    /// versions.
    pub(crate) fn new(
        store: Arc<S>,
        verifier: Arc<RecordVerifier<B>>,
        kek: KekRef,
        dek_cache: DekCache,
        record_ttl: Duration,
        reload_min_interval: Duration,
        stored: Stored<S::Revision>,
    ) -> Self {
        Self {
            store,
            verifier,
            id: stored.record.id().clone(),
            keyring_attribute: KeyringAttribute::new(stored.record.id()),
            kek,
            dek_cache,
            record_ttl,
            reload_min_interval,
            cached: Mutex::new(Cached {
                record: Arc::new(stored.record),
                revision: stored.revision,
                revalidate_at: deadline_after(Instant::now(), record_ttl),
                deleted: false,
            }),
            refresh: tokio::sync::Mutex::default(),
            lookup_reloads: AtomicU64::new(0),
        }
    }

    /// The registry's record verification, for the admin to check a signer against.
    #[cfg(feature = "admin")]
    pub(crate) fn verifier(&self) -> &RecordVerifier<B> {
        &self.verifier
    }

    pub(crate) fn id(&self) -> &KeyringId {
        &self.id
    }

    /// The `kms_aead.keyring` attribute of this keyring's metrics.
    pub(crate) fn keyring_attribute(&self) -> &KeyringAttribute {
        &self.keyring_attribute
    }

    pub(crate) fn dek_cache(&self) -> &DekCache {
        &self.dek_cache
    }

    #[cfg(feature = "admin")]
    pub(crate) fn record_ttl(&self) -> Duration {
        self.record_ttl
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
        if lookup.miss(&record, key_id).is_none() || self.is_deleted() {
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
        if last_reload.is_some_and(|last| now < deadline_after(last, self.reload_min_interval)) {
            spans::reload_rate_limited(&self.id, key_id, reason);
            return (record, Reload::RateLimited);
        }
        *last_reload = Some(now);
        self.revalidate(&last_reload, reason).await;
        self.lookup_reloads.fetch_add(1, Ordering::SeqCst);
        (self.record(), Reload::Reloaded)
    }

    /// Reads the record from the store, past the TTL and the rate limit, and takes it unless it
    /// moves backwards. The cached record stays when the read fails. A record gone from the
    /// store is taken as deleted, and a deleted record is not read again: both are
    /// `RecordMissing`. `reason` is the `reason` span value.
    pub(crate) async fn reload(&self, reason: LoadReason) -> KeyringResult<Arc<KeyringRecord>> {
        let refresh = self.refresh.lock().await;
        if self.is_deleted() {
            return Err(KeyringError::RecordMissing(self.id.clone()));
        }
        let span = spans::load(&self.id, S::KIND, reason);
        spans::in_span(span, async {
            let Some(stored) = spans::timed(
                &self.keyring_attribute,
                S::KIND,
                reason,
                self.store.load(&self.id),
            )
            .await?
            else {
                self.take_deletion(&refresh, Found::InStore)?;
                return Err(KeyringError::RecordMissing(self.id.clone()));
            };
            let revision = stored.revision.clone();
            match self.accept(&refresh, stored) {
                Ok(()) => {
                    spans::record_load(LoadChanged::Taken, Some(&revision));
                    Ok(self.record())
                }
                Err(Refusal::Regressed(rule)) => {
                    spans::record_load(LoadChanged::Regressed, Some(&revision));
                    Err(self.regressed(rule))
                }
                Err(Refusal::Signature(error)) => {
                    spans::record_load(LoadChanged::Refused, Some(&revision));
                    spans::record_refused(&self.keyring_attribute, &self.id, &error);
                    Err(error)
                }
            }
        })
        .await
    }

    /// The record of `id` as a keyring opens it, refused when its signature fails `verifier`.
    pub(crate) async fn read(
        store: &S,
        verifier: &RecordVerifier<B>,
        id: &KeyringId,
    ) -> KeyringResult<Option<Stored<S::Revision>>> {
        let span = spans::load(id, S::KIND, LoadReason::Open);
        spans::in_span(span, async {
            let stored = spans::timed(
                &KeyringAttribute::new(id),
                S::KIND,
                LoadReason::Open,
                store.load(id),
            )
            .await?;
            if let Some(stored) = &stored {
                verifier.check(&stored.record, None)?;
                verifier.warn_if_public_key_encrypted(&stored.record);
                spans::record_load(LoadChanged::Taken, Some(&stored.revision));
            }
            Ok(stored)
        })
        .await
    }

    /// Refuses `incoming`, the record of its keyring just read or created, when a process that
    /// took the deletion of the record `deleted` would not take it: an unsigned record where
    /// `deleted` was signed under `VerifyIfSigned`, or one that revives a version `deleted` holds
    /// destroyed, as a copy of the record from before the deletion does. A keyring created again
    /// under the id has other versions and passes. The checks of a deleted record outlive it,
    /// as those of a held one, until the process restarts.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordSignatureRemoved`] and [`KeyringError::RecordRegressed`].
    pub(crate) fn check_recreated(
        verifier: &RecordVerifier<B>,
        deleted: &KeyringRecord,
        incoming: &KeyringRecord,
    ) -> KeyringResult<()> {
        verifier.check(incoming, Some(deleted))?;
        deleted
            .check_recreated(incoming)
            .map_err(|rule| regression_error(incoming.id(), rule))
    }

    /// Revalidates the cached record now, whatever its age, and takes what the store returns
    /// when it moves forward, or its deletion. A failure keeps the cached record, and the next
    /// TTL revalidation comes after the reload interval. A deleted record is not revalidated.
    async fn revalidate(&self, refresh: &RefreshGuard<'_>, reason: LoadReason) {
        let revision = {
            let cached = self.lock();
            if cached.deleted {
                return;
            }
            cached.revision.clone()
        };
        let span = spans::load(&self.id, S::KIND, reason);
        let result = spans::in_span(span, async {
            match spans::timed(
                &self.keyring_attribute,
                S::KIND,
                reason,
                self.store.revalidate(&self.id, &revision),
            )
            .await?
            {
                Revalidation::Unchanged => {
                    spans::record_load(LoadChanged::Unchanged, None::<&S::Revision>)
                }
                Revalidation::Changed(stored) => {
                    let revision = stored.revision.clone();
                    match self.accept(refresh, stored) {
                        Ok(()) => spans::record_load(LoadChanged::Taken, Some(&revision)),
                        Err(Refusal::Regressed(rule)) => {
                            spans::record_regressed(&self.id, rule);
                            spans::record_load(LoadChanged::Regressed, Some(&revision));
                        }
                        Err(Refusal::Signature(error)) => {
                            spans::record_load(LoadChanged::Refused, Some(&revision));
                            spans::record_refused(&self.keyring_attribute, &self.id, &error);
                        }
                    }
                }
                Revalidation::Missing => self.take_deletion(refresh, Found::InStore)?,
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
        self.lock().revalidate_at = deadline_after(Instant::now(), next);
    }

    /// Takes `stored` when its signature passes the registry's verification, against the held
    /// record, and it moves forward from the held record.
    fn accept(
        &self,
        refresh: &RefreshGuard<'_>,
        stored: Stored<S::Revision>,
    ) -> Result<(), Refusal> {
        let held = self.record();
        self.verifier
            .check(&stored.record, Some(&held))
            .map_err(Refusal::Signature)?;
        held.check_successor(&stored.record)
            .map_err(Refusal::Regressed)?;
        self.verifier.warn_if_public_key_encrypted(&stored.record);
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
                revalidate_at: deadline_after(Instant::now(), self.record_ttl),
                deleted: false,
            },
        )
        .record;
        self.withdraw(&held, &next);
    }

    /// Takes the deletion of the record from the store as the shredding of the keyring: the
    /// cached record has every version destroyed from now on, which evicts every key of the
    /// keyring from the DEK cache, the cache reads the store no more, and the registry opens the
    /// keyring anew. A read that took the record before still finds its key withdrawn, see
    /// `Keyring::with_cached_dek`.
    ///
    /// A deletion found in the store is logged: a `WARN` as a possible accidental deletion, or an
    /// `INFO` when the held record had every version destroyed already, which only a shred
    /// leaves. A deletion by [`shred`](Self::shred) is not logged; its span records it.
    ///
    /// # Errors
    ///
    /// The errors of [`KeyringRecord::deleted`], which a record that holds its invariants never
    /// meets; the cached record then stays.
    fn take_deletion(&self, _refresh: &RefreshGuard<'_>, found: Found) -> KeyringResult<()> {
        let held = self.record();
        let next = Arc::new(held.deleted(Timestamp::now())?);
        {
            let mut cached = self.lock();
            cached.record = Arc::clone(&next);
            cached.deleted = true;
        }
        self.withdraw(&held, &next);
        if matches!(found, Found::InStore) {
            spans::record_load(LoadChanged::Deleted, None::<&S::Revision>);
            spans::record_deleted(&self.id, held.all_destroyed());
        }
        Ok(())
    }

    /// Evicts from the DEK cache the keys of `held` that `next`, the record taken in its place,
    /// takes out of use, and logs every change of an active version.
    fn withdraw(&self, held: &KeyringRecord, next: &KeyringRecord) {
        for (_, encrypted_dek) in held.withdrawn_deks(next) {
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
        for (_, encrypted_dek) in self.record().encrypted_deks() {
            self.dek_cache.invalidate(&self.kek, &encrypted_dek);
        }
    }

    fn regressed(&self, rule: RegressionRule) -> KeyringError {
        regression_error(&self.id, rule)
    }

    fn revalidation_due(&self) -> bool {
        let cached = self.lock();
        !cached.deleted && Instant::now() >= cached.revalidate_at
    }
}

impl<S: KeyringStore, B> RecordCache<S, B> {
    pub(crate) fn record(&self) -> Arc<KeyringRecord> {
        Arc::clone(&self.lock().record)
    }

    /// Whether a read found the record gone from the store, so that the registry opens the
    /// keyring anew.
    pub(crate) fn is_deleted(&self) -> bool {
        self.lock().deleted
    }

    /// The cached state, also from a poisoned lock: nothing that runs under the lock panics.
    fn lock(&self) -> MutexGuard<'_, Cached<S::Revision>> {
        self.cached.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// The writes of a `KeyringAdmin`.
#[cfg(feature = "admin")]
impl<S: KeyringStore, B: AeadBackend> RecordCache<S, B> {
    /// Applies `change` to the record as the store holds it and writes the result with a
    /// compare-and-swap, reading again after each conflict, up to `cas_retries` times. Takes the
    /// written record, records the conflicts retried on the current span, and returns what
    /// `change` returned. A stored record that moves backwards from the cached one is refused
    /// before `change` runs.
    ///
    /// `signer` signs the result, and `write` says what the write may do with the stored
    /// record's signature: a signing admin's write re-signs a signed record and refuses an
    /// unsigned one, except `sign_record`, and an unsigned admin's write refuses a signed record,
    /// except `dangerously_unsign_record`. Each refusal comes before any store write, and a new
    /// signature is verified under the signer's own key before the compare-and-swap.
    pub(crate) async fn write<T, R: MaybeRecordSigner>(
        &self,
        cas_retries: u32,
        signer: &R,
        write: SignedWrite,
        mut change: impl AsyncFnMut(&mut RecordEdit) -> KeyringResult<T>,
    ) -> KeyringResult<T> {
        let refresh = self.refresh.lock().await;
        for conflicts in 0..=cas_retries {
            let stored = self.read_for_write(&refresh).await?;
            self.check_signed_write(signer, &stored.record, write)?;
            let mut edit = RecordEdit::from(stored.record);
            let outcome = change(&mut edit).await?;
            if self
                .swap(&refresh, signer, edit, &stored.revision)
                .await?
                .is_some()
            {
                spans::record_cas_retries(conflicts);
                return Ok(outcome);
            }
            spans::write_conflict(&self.id, conflicts.saturating_add(1));
        }
        Err(self.conflict(cas_retries))
    }

    /// Destroys every version of the record as the store holds it, in one write signed as a
    /// lifecycle change, then deletes the record at the revision written, and takes the
    /// deletion. A record whose every version is destroyed already is deleted without a write,
    /// and a record already gone is taken as deleted. A conflict of the write or of the delete
    /// starts again from a new read, up to `cas_retries` times.
    pub(crate) async fn shred<R: MaybeRecordSigner>(
        &self,
        cas_retries: u32,
        signer: &R,
    ) -> KeyringResult<()> {
        let refresh = self.refresh.lock().await;
        for conflicts in 0..=cas_retries {
            let stored = match self.read_for_write(&refresh).await {
                Err(KeyringError::RecordMissing(_)) => return Ok(()),
                read => read?,
            };
            self.check_signed_write(signer, &stored.record, SignedWrite::Change)?;
            let revision = if stored.record.all_destroyed() {
                Some(stored.revision)
            } else {
                let mut edit = RecordEdit::from(stored.record);
                edit.destroy_all(Timestamp::now());
                self.swap(&refresh, signer, edit, &stored.revision).await?
            };
            if let Some(revision) = revision {
                if self.store.delete(&self.id, &revision).await? == Deletion::Deleted {
                    self.take_deletion(&refresh, Found::Shredded)?;
                    spans::record_cas_retries(conflicts);
                    return Ok(());
                }
            }
            spans::write_conflict(&self.id, conflicts.saturating_add(1));
        }
        Err(self.conflict(cas_retries))
    }

    /// Refuses a write over `stored` that `write` does not allow the admin's `signer`, before any
    /// store write.
    fn check_signed_write<R: MaybeRecordSigner>(
        &self,
        signer: &R,
        stored: &KeyringRecord,
        write: SignedWrite,
    ) -> KeyringResult<()> {
        match (signer.signer_key(), stored.signature(), write) {
            (None, Some(_), SignedWrite::Change | SignedWrite::Sign)
            | (None, None, SignedWrite::Sign) => {
                Err(KeyringError::RecordSignerMissing(self.id.clone()))
            }
            (Some(_), None, SignedWrite::Change) => {
                Err(KeyringError::RecordUnsigned(self.id.clone()))
            }
            _ => Ok(()),
        }
    }

    /// Writes `edit`, signed by `signer`, over the stored revision `expected`, and takes it:
    /// the revision written, or `None` on a conflict.
    async fn swap<R: MaybeRecordSigner>(
        &self,
        refresh: &RefreshGuard<'_>,
        signer: &R,
        edit: RecordEdit,
        expected: &S::Revision,
    ) -> KeyringResult<Option<S::Revision>> {
        let record = edit.finish()?.signed_by::<B, R>(signer).await?;
        match self.store.compare_and_swap(&record, Some(expected)).await? {
            Swap::Written(revision) => {
                self.install(
                    refresh,
                    Stored {
                        record,
                        revision: revision.clone(),
                    },
                );
                Ok(Some(revision))
            }
            Swap::Conflict => Ok(None),
        }
    }

    fn conflict(&self, cas_retries: u32) -> KeyringError {
        KeyringError::RecordConflict(RecordConflictError {
            keyring: self.id.clone(),
            attempts: cas_retries.saturating_add(1),
        })
    }

    /// The store's record, refused when it moves backwards from the cached one, for a write to
    /// build on. A record gone from the store is taken as deleted, and is `RecordMissing`, also
    /// when the cache took the deletion before: the store is then not read, as another record
    /// may hold the id.
    async fn read_for_write(
        &self,
        refresh: &RefreshGuard<'_>,
    ) -> KeyringResult<Stored<S::Revision>> {
        if self.is_deleted() {
            return Err(KeyringError::RecordMissing(self.id.clone()));
        }
        let span = spans::load(&self.id, S::KIND, LoadReason::Admin);
        spans::in_span(span, async {
            let Some(stored) = spans::timed(
                &self.keyring_attribute,
                S::KIND,
                LoadReason::Admin,
                self.store.load(&self.id),
            )
            .await?
            else {
                self.take_deletion(refresh, Found::InStore)?;
                return Err(KeyringError::RecordMissing(self.id.clone()));
            };
            let held = self.record();
            if let Err(error) = self.verifier.check(&stored.record, Some(&held)) {
                spans::record_load(LoadChanged::Refused, Some(&stored.revision));
                spans::record_refused(&self.keyring_attribute, &self.id, &error);
                return Err(error);
            }
            match held.check_successor(&stored.record) {
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

impl<S: KeyringStore, B: AeadBackend> RecordCache<S, B> {
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
                    () = tokio::time::sleep_until(deadline_after(last, interval)) => {}
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
            if cache.is_deleted() {
                return;
            }
        }
    }
}

/// A held lock of `RecordCache::refresh`: the witness that the caller runs alone among the
/// reads and writes that change the cached record.
type RefreshGuard<'a> = tokio::sync::MutexGuard<'a, Option<Instant>>;

/// How a process came to take the deletion of its record.
enum Found {
    /// A read found the record gone.
    InStore,
    /// This process deleted it, in `RecordCache::shred`.
    #[cfg(feature = "admin")]
    Shredded,
}

/// Why a record read from the store was not taken.
enum Refusal {
    /// It moves a version backwards from the held record.
    Regressed(RegressionRule),
    /// Its signature failed the registry's record verification.
    Signature(KeyringError),
}

/// What an administrative write may do with the signature of the record it reads.
#[cfg(feature = "admin")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignedWrite {
    /// A lifecycle change: re-signs a signed record under a signer, and leaves an unsigned record
    /// unsigned without one; neither admin writes over a record of the other kind.
    Change,
    /// `sign_record`: a signer signs the record as it is, signed or not.
    Sign,
    /// `dangerously_unsign_record`: an unsigned admin writes the record without its signature.
    Unsign,
}

/// The versions that [`RecordCache::find`] takes from the cached record without a reload.
#[derive(Debug, Clone, Copy)]
pub(crate) enum VersionLookup {
    /// Any version the record holds: what `decrypt` decrypts a value with.
    Any,
    /// A version past pending. A value or beacon under a version the record holds as pending
    /// was encrypted by a process that saw it active, so the record is behind the store.
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

/// The error for a record that moves backwards, logged as the alert on a regression.
fn regression_error(keyring: &KeyringId, rule: RegressionRule) -> KeyringError {
    spans::record_regressed(keyring, rule);
    KeyringError::RecordRegressed(RecordRegressedError {
        keyring: keyring.clone(),
        rule,
    })
}

/// `wait` after `start`, or an instant beyond any process's lifetime when that overflows, so
/// that a `Duration::MAX` option means never rather than a panic.
fn deadline_after(start: Instant, wait: Duration) -> Instant {
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
