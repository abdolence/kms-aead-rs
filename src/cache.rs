//! The cache of plaintext data encryption keys, [`DekCache`], which the store-less envelope and
//! the keyring share.

use std::collections::{HashMap, VecDeque};
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use rsb_derive::Builder;
use tokio::sync::OnceCell;

use crate::errors::KmsAeadSystemError;
#[cfg(feature = "deterministic")]
use crate::{checked_deterministic_key, DeterministicAlgorithm, DeterministicDataEncryptionKey};
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekRef, KmsAeadEncryptionProvider, KmsAeadResult,
};

const DEFAULT_MAX_ENTRIES: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is not zero");

/// The shortest period of the reaper, for TTLs under 4 ms.
const MIN_REAPER_PERIOD: Duration = Duration::from_millis(1);

const REAPER_THREAD_NAME: &str = "kms-aead-dek-reaper";

/// The settings of an enabled [`DekCache`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct DekCacheOptions {
    /// How long an entry serves lookups after it was inserted, however often it is used: 15
    /// minutes by default. Longer than zero.
    #[default = "Duration::from_secs(15 * 60)"]
    pub ttl: Duration,
    /// The entries of each purpose, randomized and deterministic, the cache holds at most: 1024
    /// by default. Past it, the oldest entry of that purpose is evicted.
    #[default = "DEFAULT_MAX_ENTRIES"]
    pub max_entries: NonZeroUsize,
}

/// Where the key of a [`DekCache::with_key`] call came from. Its `Display` is the value of the
/// `dek_cache` span field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DekCacheOutcome {
    /// From the cache, or from a concurrent call that unwrapped the same key.
    Hit,
    /// Unwrapped by the provider for this call, and cached.
    Miss,
    /// Unwrapped by the provider for this call: the cache is disabled.
    Disabled,
}

/// `hit`, `miss`, `disabled`.
impl Display for DekCacheOutcome {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DekCacheOutcome::Hit => "hit",
            DekCacheOutcome::Miss => "miss",
            DekCacheOutcome::Disabled => "disabled",
        })
    }
}

/// The one cache of plaintext data encryption keys (DEKs) unwrapped by a KMS, shared by the
/// store-less envelope and the keyring. `Clone` shares the same cache.
///
/// An entry is keyed by the provider's [`KekRef`] and the wrapped key's bytes, so a cache shared
/// by the providers of several KEKs never returns a key unwrapped under one KEK to a caller that
/// passed the provider of another: that provider's KMS is asked, and refuses a key wrapped under
/// a foreign KEK. The key version a wrapped key records is not part of the entry's key.
/// Randomized and deterministic keys are cached apart, up to
/// [`max_entries`](DekCacheOptions::max_entries) of each.
///
/// - A key reaches a caller only inside the closure of [`with_key`](Self::with_key), and stays
///   intact until the closure returns, whatever leaves the cache meanwhile.
/// - Concurrent misses for one key make one provider call, and every caller receives its result:
///   the key, or the error. When the caller making the call is cancelled, one of the callers
///   waiting on it makes the call instead.
/// - A failed unwrap leaves no entry, so that under a KMS outage every call fails as fast as the
///   KMS does.
/// - An entry serves lookups for [`ttl`](DekCacheOptions::ttl) after it was inserted, however
///   often it is used.
///
/// # Key lifetime
///
/// A key is dropped, which zeroizes its bytes, when its entry leaves the cache: once the entry
/// expires, is evicted for capacity, invalidated or cleared. A `with_key` call that already holds
/// the key keeps it until its closure returns, and a call waiting on an unwrap that started
/// before an [`invalidate`](Self::invalidate) or a [`clear`](Self::clear) receives that unwrap's
/// key, which is not cached.
///
/// Each enabled cache runs a reaper thread, `kms-aead-dek-reaper`, which drops the expired
/// entries every quarter of the TTL, and at least every millisecond, and exits once the cache is
/// dropped. It needs no traffic and no async runtime: the bytes of a key are gone `ttl` plus the
/// reaper period after it was inserted at most, or when the last `with_key` call holding it
/// returns, if that is later, as fast as the operating system schedules the thread.
///
/// A KMS key that is disabled, or an IAM grant that is revoked, reaches the keys this cache
/// holds only when their entries expire, or at [`invalidate`](Self::invalidate) or
/// [`clear`](Self::clear): until then those keys keep serving lookups without a KMS call.
///
/// # Defaults
///
/// [`DekCacheOptions::new`] gives a TTL of 15 minutes and 1024 entries per purpose. The per-call
/// envelope has no cache unless it is given one; the store-less envelope and the keyring use
/// `DekCache::new(DekCacheOptions::new())` unless they are given another.
#[derive(Clone)]
pub struct DekCache(Option<Arc<EnabledCache>>);

/// The maps of an enabled cache.
struct EnabledCache {
    options: DekCacheOptions,
    randomized: KeyMap<DataEncryptionKey>,
    #[cfg(feature = "deterministic")]
    deterministic: KeyMap<DeterministicDataEncryptionKey>,
    /// Never sends. Dropping it with the cache disconnects the reaper's receiver, which stops
    /// the reaper at once rather than at its next period.
    _reaper_stop: Sender<()>,
}

impl EnabledCache {
    /// A cache with `options`, and its reaper thread, which exits once the cache is dropped.
    fn start(options: DekCacheOptions) -> KmsAeadResult<(Arc<Self>, JoinHandle<()>)> {
        let (reaper_stop, reaper_stopped) = mpsc::channel();
        let period = (options.ttl / 4).max(MIN_REAPER_PERIOD);
        let cache = Arc::new(Self {
            options,
            randomized: KeyMap::new(),
            #[cfg(feature = "deterministic")]
            deterministic: KeyMap::new(),
            _reaper_stop: reaper_stop,
        });
        let reaped = Arc::downgrade(&cache);
        let reaper = thread::Builder::new()
            .name(REAPER_THREAD_NAME.to_string())
            .spawn(move || Self::reap(&reaped, &reaper_stopped, period))
            .map_err(|error| {
                KmsAeadSystemError::create(
                    "DEK_CACHE_REAPER",
                    &format!("Unable to start the DEK cache reaper thread: {error}"),
                )
            })?;
        Ok((cache, reaper))
    }

    /// Drops the expired entries of `cache` every `period`, until the cache is dropped and
    /// `stopped` disconnects with it.
    fn reap(cache: &Weak<Self>, stopped: &Receiver<()>, period: Duration) {
        while let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(period) {
            let Some(cache) = cache.upgrade() else {
                return;
            };
            cache.randomized.purge(cache.options.ttl);
            #[cfg(feature = "deterministic")]
            cache.deterministic.purge(cache.options.ttl);
        }
    }
}

/// The key of an entry. Wrapped keys are not secret, so they hash and compare in variable time.
#[derive(Clone, PartialEq, Eq, Hash)]
struct CacheKey {
    kek: KekRef,
    wrapped: Vec<u8>,
}

impl CacheKey {
    fn new(kek: KekRef, encrypted: &EncryptedDataEncryptionKey) -> Self {
        Self {
            kek,
            wrapped: encrypted.wrapped().to_vec(),
        }
    }
}

/// The entries of one purpose. The lock is held for map operations only, never across an
/// `.await`, a provider call or a caller's closure.
struct KeyMap<K>(Mutex<MapState<K>>);

struct MapState<K> {
    entries: HashMap<CacheKey, CachedDek<K>>,
    /// The keys of `entries` in insertion order. Every entry lives for the same TTL, so the
    /// front one is always the next to expire.
    insertion_order: VecDeque<CacheKey>,
    /// The unwraps under way, which concurrent misses for the same key wait on. An unwrap
    /// whose callers were all cancelled leaves a dangling entry, which the next miss of its key
    /// replaces and the reaper removes.
    unwraps: HashMap<CacheKey, Weak<SharedUnwrap<K>>>,
}

struct CachedDek<K> {
    dek: Arc<K>,
    inserted_at: Instant,
}

/// The result of one provider call, shared by every caller that missed the same key while it
/// ran.
type SharedUnwrap<K> = OnceCell<KmsAeadResult<Arc<K>>>;

impl<K> KeyMap<K> {
    fn new() -> Self {
        Self(Mutex::new(MapState {
            entries: HashMap::new(),
            insertion_order: VecDeque::new(),
            unwraps: HashMap::new(),
        }))
    }

    /// The map state, also from a poisoned lock: no caller code runs under it, and the map
    /// operations tolerate `entries` and `insertion_order` disagreeing.
    fn lock(&self) -> MutexGuard<'_, MapState<K>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The key cached under `cache_key`, or the key `unwrap_key` returns on a miss, which is
    /// cached unless an invalidation or a clear of the key came while it was unwrapped.
    async fn get_or_unwrap<F, Fut>(
        &self,
        cache_key: CacheKey,
        options: &DekCacheOptions,
        unwrap_key: F,
    ) -> KmsAeadResult<(Arc<K>, DekCacheOutcome)>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = KmsAeadResult<K>>,
    {
        let shared = {
            let mut state = self.lock();
            state.drop_expired(options.ttl, Instant::now());
            if let Some(cached) = state.entries.get(&cache_key) {
                return Ok((Arc::clone(&cached.dek), DekCacheOutcome::Hit));
            }
            state.shared_unwrap(&cache_key)
        };
        let mut unwrapped_here = false;
        let result = shared
            .get_or_init(|| {
                unwrapped_here = true;
                let unwrapping = unwrap_key();
                async move { unwrapping.await.map(Arc::new) }
            })
            .await
            .clone();
        if !unwrapped_here {
            return result.map(|dek| (dek, DekCacheOutcome::Hit));
        }
        let mut state = self.lock();
        if state.finish_unwrap(&cache_key, &shared) {
            if let Ok(dek) = &result {
                state.insert(cache_key, Arc::clone(dek), options.max_entries);
            }
        }
        result.map(|dek| (dek, DekCacheOutcome::Miss))
    }

    /// Drops the expired entries, and forgets the unwraps whose callers were all cancelled.
    fn purge(&self, ttl: Duration) {
        let mut state = self.lock();
        state.drop_expired(ttl, Instant::now());
        state.unwraps.retain(|_, shared| shared.strong_count() > 0);
    }
}

impl<K> MapState<K> {
    fn drop_expired(&mut self, ttl: Duration, now: Instant) {
        while let Some(oldest) = self.insertion_order.front() {
            let expired = self
                .entries
                .get(oldest)
                .is_none_or(|cached| now.saturating_duration_since(cached.inserted_at) >= ttl);
            if !expired {
                return;
            }
            if let Some(oldest) = self.insertion_order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }

    /// The unwrap under way for `cache_key`, or a new one registered for it.
    fn shared_unwrap(&mut self, cache_key: &CacheKey) -> Arc<SharedUnwrap<K>> {
        if let Some(shared) = self.unwraps.get(cache_key).and_then(Weak::upgrade) {
            return shared;
        }
        let shared = Arc::new(OnceCell::new());
        self.unwraps
            .insert(cache_key.clone(), Arc::downgrade(&shared));
        shared
    }

    /// Unregisters `shared`, and returns whether it was still registered for `cache_key`: an
    /// invalidation or a clear unregisters the unwraps under way, so that their keys are not
    /// cached.
    fn finish_unwrap(&mut self, cache_key: &CacheKey, shared: &Arc<SharedUnwrap<K>>) -> bool {
        let registered = self
            .unwraps
            .get(cache_key)
            .is_some_and(|registered| Weak::ptr_eq(registered, &Arc::downgrade(shared)));
        if registered {
            self.unwraps.remove(cache_key);
        }
        registered
    }

    /// Inserts `dek` as the newest entry, then evicts the oldest past `max_entries`.
    fn insert(&mut self, cache_key: CacheKey, dek: Arc<K>, max_entries: NonZeroUsize) {
        let cached = CachedDek {
            dek,
            inserted_at: Instant::now(),
        };
        if self.entries.insert(cache_key.clone(), cached).is_some() {
            self.insertion_order.retain(|listed| *listed != cache_key);
        }
        self.insertion_order.push_back(cache_key);
        while self.entries.len() > max_entries.get() {
            let Some(oldest) = self.insertion_order.pop_front() else {
                return;
            };
            self.entries.remove(&oldest);
        }
    }

    fn remove(&mut self, cache_key: &CacheKey) {
        if self.entries.remove(cache_key).is_some() {
            self.insertion_order.retain(|listed| listed != cache_key);
        }
        self.unwraps.remove(cache_key);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
        self.unwraps.clear();
    }
}

impl DekCache {
    /// A cache with `options`, and its reaper thread, which exits once the last clone of the
    /// cache is dropped.
    ///
    /// # Errors
    ///
    /// `INVALID_DEK_CACHE_TTL` when the TTL is zero, and `DEK_CACHE_REAPER` when the operating
    /// system refuses to start the reaper thread.
    pub fn new(options: DekCacheOptions) -> KmsAeadResult<Self> {
        if options.ttl.is_zero() {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_CACHE_TTL",
                "A DEK cache TTL of zero caches nothing: use DekCache::disabled",
            ));
        }
        let (cache, _detached_reaper) = EnabledCache::start(options)?;
        Ok(Self(Some(cache)))
    }

    /// A cache that holds nothing and runs no thread: every [`with_key`](Self::with_key) calls
    /// the provider, and [`invalidate`](Self::invalidate) and [`clear`](Self::clear) do nothing.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Whether the cache holds keys: `false` only for [`disabled`](Self::disabled).
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Runs `use_key` with the key `encrypted` wraps under `provider.kek()`, unwrapped by
    /// `provider` on a miss, and returns its result with where the key came from.
    ///
    /// `use_key` runs once, synchronously, after the lookup, and the key stays intact while it
    /// runs. It must not keep the key: a copy taken out of the closure outlives the cache's
    /// control of its lifetime.
    ///
    /// # Errors
    ///
    /// The provider's error, which every caller waiting on the same unwrap receives. The errors
    /// of `use_key` come back in its own return value.
    pub async fn with_key<P, T>(
        &self,
        provider: &P,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let unwrap_key = || provider.decrypt_data_encryption_key(encrypted);
        match &self.0 {
            Some(cache) => {
                let cache_key = CacheKey::new(provider.kek(), encrypted);
                let (dek, outcome) = cache
                    .randomized
                    .get_or_unwrap(cache_key, &cache.options, unwrap_key)
                    .await?;
                Ok((use_key(&dek), outcome))
            }
            None => {
                let dek = unwrap_key().await?;
                Ok((use_key(&dek), DekCacheOutcome::Disabled))
            }
        }
    }

    /// Runs `use_key` with the deterministic key `encrypted` wraps under `provider.kek()`, as
    /// [`with_key`](Self::with_key) does with randomized keys. The two purposes are cached apart,
    /// so the same wrapped key unwrapped for both is two entries.
    ///
    /// # Errors
    ///
    /// The provider's error, and `INVALID_KEY_LENGTH` when the unwrapped key does not fit
    /// `algorithm`, which every caller waiting on the same unwrap receives. The errors of
    /// `use_key` come back in its own return value.
    #[cfg(feature = "deterministic")]
    pub async fn with_deterministic_key<P, T>(
        &self,
        provider: &P,
        algorithm: DeterministicAlgorithm,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DeterministicDataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let unwrap_key = || async {
            let key = provider.decrypt_data_encryption_key(encrypted).await?;
            checked_deterministic_key(key, algorithm)
        };
        match &self.0 {
            Some(cache) => {
                let cache_key = CacheKey::new(provider.kek(), encrypted);
                let (dek, outcome) = cache
                    .deterministic
                    .get_or_unwrap(cache_key, &cache.options, unwrap_key)
                    .await?;
                Ok((use_key(&dek), outcome))
            }
            None => {
                let dek = unwrap_key().await?;
                Ok((use_key(&dek), DekCacheOutcome::Disabled))
            }
        }
    }

    /// Drops the entries of both purposes for `encrypted` under `kek`. The next
    /// [`with_key`](Self::with_key) of the key calls the provider, and an unwrap of it under way
    /// returns its key to its callers without caching it.
    pub fn invalidate(&self, kek: &KekRef, encrypted: &EncryptedDataEncryptionKey) {
        if let Some(cache) = &self.0 {
            let cache_key = CacheKey::new(kek.clone(), encrypted);
            cache.randomized.lock().remove(&cache_key);
            #[cfg(feature = "deterministic")]
            cache.deterministic.lock().remove(&cache_key);
        }
    }

    /// Drops every entry. The unwraps under way return their keys to their callers without
    /// caching them.
    pub fn clear(&self) {
        if let Some(cache) = &self.0 {
            cache.randomized.lock().clear();
            #[cfg(feature = "deterministic")]
            cache.deterministic.lock().clear();
        }
    }
}

/// Filling the cache for the crate's own callers, kept off the public API of [`DekCache`]: a
/// key inserted under the wrong wrapped bytes would seal values that no unwrap opens.
pub(crate) trait InsertDek {
    /// Caches `key`, which `kek` has just wrapped into `encrypted`, as an unwrap of `encrypted`
    /// would have. A disabled cache drops it.
    fn insert_dek(
        &self,
        kek: KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        key: DataEncryptionKey,
    );
}

impl InsertDek for DekCache {
    fn insert_dek(
        &self,
        kek: KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        key: DataEncryptionKey,
    ) {
        if let Some(cache) = &self.0 {
            cache.randomized.lock().insert(
                CacheKey::new(kek, encrypted),
                Arc::new(key),
                cache.options.max_entries,
            );
        }
    }
}

/// The options of an enabled cache, never its entries.
impl Debug for DekCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DekCache")
            .field(&self.0.as_ref().map(|cache| &cache.options))
            .finish()
    }
}

#[cfg(test)]
impl<K> KeyMap<K> {
    /// The key cached under `cache_key`, as a `Weak` that stops upgrading once the key is
    /// dropped, and its bytes with it zeroized.
    fn cached(&self, cache_key: &CacheKey) -> Option<Weak<K>> {
        let state = self.lock();
        state
            .entries
            .get(cache_key)
            .map(|cached| Arc::downgrade(&cached.dek))
    }
}

#[cfg(test)]
impl DekCache {
    /// The randomized key cached for `encrypted` under `kek`, as [`KeyMap::cached`] gives it.
    pub(crate) fn cached_dek(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DataEncryptionKey>> {
        let cache = self.0.as_ref()?;
        cache
            .randomized
            .cached(&CacheKey::new(kek.clone(), encrypted))
    }

    /// The deterministic key cached for `encrypted` under `kek`, as [`KeyMap::cached`] gives it.
    #[cfg(feature = "deterministic")]
    fn cached_deterministic_dek(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DeterministicDataEncryptionKey>> {
        let cache = self.0.as_ref()?;
        cache
            .deterministic
            .cached(&CacheKey::new(kek.clone(), encrypted))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};

    use futures::executor::block_on;

    use super::*;
    use crate::errors::KmsAeadError;
    use crate::test_provider::{
        let_spawned_tasks_wait, wait_until, CountingKmsProvider, TestKmsProvider, CONCURRENT_CALLS,
    };

    const ORDERS_KEK: &str = "orders";
    const BILLING_KEK: &str = "billing";
    /// The test provider's wrapped key is the key itself, and 64 bytes fit both purposes.
    const ORDERS_DEK: [u8; 64] = [0x42; 64];
    const BILLING_DEK: [u8; 64] = [0x24; 64];
    const SHORT_TTL: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn n_concurrent_misses_make_one_unwrap() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::Working,
            ORDERS_KEK,
        ));

        let lookups: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let (cache, provider, encrypted) =
                    (cache.clone(), Arc::clone(&provider), encrypted.clone());
                tokio::spawn(async move { cache.with_key(&*provider, &encrypted, |_| ()).await })
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(provider.unwraps(), 1);
        provider.open_gate();

        let mut misses = 0;
        for lookup in lookups {
            let ((), outcome) = lookup.await.unwrap()?;
            misses += usize::from(outcome == DekCacheOutcome::Miss);
        }
        assert_eq!(misses, 1);
        assert_eq!(provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn waiters_share_the_leaders_error() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::FailingToUnwrap,
            ORDERS_KEK,
        ));

        let lookups: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let (cache, provider, encrypted) =
                    (cache.clone(), Arc::clone(&provider), encrypted.clone());
                tokio::spawn(async move { cache.with_key(&*provider, &encrypted, |_| ()).await })
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(provider.unwraps(), 1);
        provider.open_gate();

        for lookup in lookups {
            let result = lookup.await.unwrap();
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "TEST_UNWRAP"),
                "{:?}",
                result.as_ref().err()
            );
        }
        assert_eq!(provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_unwrap_is_not_cached() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let failing = CountingKmsProvider::new(TestKmsProvider::FailingToUnwrap, ORDERS_KEK);
        let working = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let failed = cache.with_key(&failing, &encrypted, |_| ()).await;
        let ((), first) = cache.with_key(&working, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&working, &encrypted, |_| ()).await?;

        assert!(
            matches!(&failed, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "TEST_UNWRAP"),
            "{:?}",
            failed.as_ref().err()
        );
        assert_eq!(
            [first, second],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(working.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn an_entry_expires_after_ttl() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        tokio::time::sleep(SHORT_TTL * 2).await;
        let ((), third) = cache.with_key(&provider, &encrypted, |_| ()).await?;

        assert_eq!(
            [first, second, third],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn capacity_bounds_each_map() -> KmsAeadResult<()> {
        let max_entries = NonZeroUsize::new(2).unwrap();
        let cache = DekCache::new(DekCacheOptions::new().with_max_entries(max_entries))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let mut randomized = Vec::new();
        for byte in 1..=3 {
            let encrypted = EncryptedDataEncryptionKey::new(vec![byte; 32], None);
            cache.with_key(&provider, &encrypted, |_| ()).await?;
            randomized.push(cache.cached_dek(&provider.kek(), &encrypted).unwrap());
        }

        let live: Vec<_> = randomized
            .iter()
            .map(|dek| dek.strong_count() > 0)
            .collect();
        assert_eq!(live, [false, true, true]);

        #[cfg(feature = "deterministic")]
        {
            let mut deterministic = Vec::new();
            for byte in 4..=5 {
                let encrypted = EncryptedDataEncryptionKey::new(vec![byte; 64], None);
                let algorithm = DeterministicAlgorithm::Aes256Siv;
                cache
                    .with_deterministic_key(&provider, algorithm, &encrypted, |_| ())
                    .await?;
                deterministic.push(
                    cache
                        .cached_deterministic_dek(&provider.kek(), &encrypted)
                        .unwrap(),
                );
            }

            assert!(randomized[1].strong_count() > 0 && randomized[2].strong_count() > 0);
            assert!(deterministic.iter().all(|dek| dek.strong_count() > 0));
        }
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_forces_the_next_unwrap() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        cache.invalidate(&provider.kek(), &encrypted);
        let ((), third) = cache.with_key(&provider, &encrypted, |_| ()).await?;

        assert_eq!(
            [first, second, third],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[cfg(feature = "deterministic")]
    #[tokio::test]
    async fn invalidate_removes_both_purposes() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let algorithm = DeterministicAlgorithm::Aes256Siv;

        cache.with_key(&provider, &encrypted, |_| ()).await?;
        cache
            .with_deterministic_key(&provider, algorithm, &encrypted, |_| ())
            .await?;
        let randomized = cache.cached_dek(&provider.kek(), &encrypted).unwrap();
        let deterministic = cache
            .cached_deterministic_dek(&provider.kek(), &encrypted)
            .unwrap();
        cache.invalidate(&provider.kek(), &encrypted);
        let ((), outcome) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, |_| ())
            .await?;

        assert_eq!(randomized.strong_count() + deterministic.strong_count(), 0);
        assert_eq!(outcome, DekCacheOutcome::Miss);
        assert_eq!(provider.unwraps(), 3);
        Ok(())
    }

    #[cfg(feature = "deterministic")]
    #[tokio::test]
    async fn purposes_are_cached_apart() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let algorithm = DeterministicAlgorithm::Aes256Siv;

        let ((), randomized) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), deterministic) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, |_| ())
            .await?;
        let ((), again) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, |_| ())
            .await?;

        assert_eq!(
            [randomized, deterministic, again],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit
            ]
        );
        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn cache_is_namespaced_by_kek() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let orders = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let billing = CountingKmsProvider::new(TestKmsProvider::Working, BILLING_KEK);

        let ((), first) = cache.with_key(&orders, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&orders, &encrypted, |_| ()).await?;
        let ((), other_kek) = cache.with_key(&billing, &encrypted, |_| ()).await?;

        assert_eq!(
            [first, second, other_kek],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(billing.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_zeroizes_the_dek_bytes() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        cache.with_key(&provider, &encrypted, |_| ()).await?;
        let cached = cache.cached_dek(&provider.kek(), &encrypted).unwrap();
        assert_eq!(cached.strong_count(), 1);
        cache.invalidate(&provider.kek(), &encrypted);

        assert_eq!(cached.strong_count(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn clear_zeroizes_every_key() -> KmsAeadResult<()> {
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let encrypted: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new(vec![byte; 64], None))
            .collect();

        let mut cached = Vec::new();
        for encrypted in &encrypted {
            cache.with_key(&provider, encrypted, |_| ()).await?;
            cached.push(cache.cached_dek(&provider.kek(), encrypted).unwrap());
        }
        #[cfg(feature = "deterministic")]
        let deterministic = {
            let algorithm = DeterministicAlgorithm::Aes256Siv;
            cache
                .with_deterministic_key(&provider, algorithm, &encrypted[0], |_| ())
                .await?;
            cache
                .cached_deterministic_dek(&provider.kek(), &encrypted[0])
                .unwrap()
        };
        cache.clear();

        assert!(cached.iter().all(|dek| dek.strong_count() == 0));
        #[cfg(feature = "deterministic")]
        assert_eq!(deterministic.strong_count(), 0);
        Ok(())
    }

    #[test]
    fn an_expired_key_is_zeroized_without_traffic_or_runtime() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        assert!(tokio::runtime::Handle::try_current().is_err());
        block_on(cache.with_key(&provider, &encrypted, |_| ()))?;
        let cached = cache.cached_dek(&provider.kek(), &encrypted).unwrap();
        wait_until(|| cached.strong_count() == 0);

        assert_eq!(cached.strong_count(), 0);
        Ok(())
    }

    #[test]
    fn a_dropped_cache_stops_its_reaper() -> KmsAeadResult<()> {
        let (cache, reaper) = EnabledCache::start(DekCacheOptions::new())?;

        drop(cache);
        wait_until(|| reaper.is_finished());

        assert!(reaper.is_finished());
        Ok(())
    }

    #[tokio::test]
    async fn an_unwrap_in_flight_does_not_reinsert_after_invalidate() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;

        let mut outcomes = Vec::new();
        for clear in [false, true] {
            let provider = Arc::new(CountingKmsProvider::gated(
                TestKmsProvider::Working,
                ORDERS_KEK,
            ));
            let in_flight = tokio::spawn({
                let (cache, provider, encrypted) =
                    (cache.clone(), Arc::clone(&provider), encrypted.clone());
                async move { cache.with_key(&*provider, &encrypted, |_| ()).await }
            });
            let_spawned_tasks_wait().await;
            if clear {
                cache.clear();
            } else {
                cache.invalidate(&provider.kek(), &encrypted);
            }
            provider.open_gate();
            let ((), leader) = in_flight.await.unwrap()?;
            let ((), after) = cache.with_key(&*provider, &encrypted, |_| ()).await?;
            outcomes.push(([leader, after], provider.unwraps()));
            cache.clear();
        }

        let expected = ([DekCacheOutcome::Miss, DekCacheOutcome::Miss], 2);
        assert_eq!(outcomes, [expected; 2]);
        Ok(())
    }

    #[test]
    fn a_key_in_use_is_never_zeroized_mid_use() -> KmsAeadResult<()> {
        const USING_THREADS: usize = 4;
        const USES_PER_THREAD: usize = 5_000;
        let cache = DekCache::new(
            DekCacheOptions::new()
                .with_ttl(Duration::from_millis(2))
                .with_max_entries(NonZeroUsize::new(1).unwrap()),
        )?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let keys = [ORDERS_DEK, BILLING_DEK]
            .map(|dek| (EncryptedDataEncryptionKey::new(dek.to_vec(), None), dek));
        let using = AtomicBool::new(true);

        let failures = thread::scope(|scope| {
            let churn = scope.spawn(|| {
                while using.load(Ordering::Relaxed) {
                    cache.invalidate(&provider.kek(), &keys[0].0);
                    cache.clear();
                }
            });
            let users: Vec<_> = (0..USING_THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..USES_PER_THREAD)
                            .filter(|use_index| {
                                let (encrypted, dek) = &keys[use_index % keys.len()];
                                let used = block_on(cache.with_key(&provider, encrypted, |key| {
                                    let before = key.value().ref_sensitive_value() == dek;
                                    thread::yield_now();
                                    before && key.value().ref_sensitive_value() == dek
                                }));
                                !matches!(used, Ok((true, _)))
                            })
                            .count()
                    })
                })
                .collect();
            let failures: usize = users.into_iter().map(|user| user.join().unwrap()).sum();
            using.store(false, Ordering::Relaxed);
            churn.join().unwrap();
            failures
        });

        assert_eq!(failures, 0);
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cache_unwraps_every_time() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::disabled();
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        cache.invalidate(&provider.kek(), &encrypted);
        cache.clear();

        assert!(!cache.is_enabled());
        assert_eq!(
            [first, second],
            [DekCacheOutcome::Disabled, DekCacheOutcome::Disabled]
        );
        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[test]
    fn a_zero_ttl_is_refused() {
        let result = DekCache::new(DekCacheOptions::new().with_ttl(Duration::ZERO));

        assert!(
            matches!(&result, Err(KmsAeadError::SystemError(error))
                if error.public.code == "INVALID_DEK_CACHE_TTL"),
            "{result:?}"
        );
    }
}
