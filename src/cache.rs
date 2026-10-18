//! The cache of plaintext data encryption keys, [`DekCache`], which the store-less envelope and
//! the keyring share.

use std::collections::HashMap;
use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
#[cfg(test)]
use std::sync::Weak;
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use rsb_derive::Builder;
use tokio::sync::OnceCell;

use crate::errors::KmsAeadSystemError;
#[cfg(feature = "deterministic")]
use crate::{checked_deterministic_key, DeterministicAlgorithm, DeterministicDataEncryptionKey};
use crate::{
    DataEncryptionKey, DekBinding, EncryptedDataEncryptionKey, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

const DEFAULT_MAX_ENTRIES: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is not zero");

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
/// [`KekRef`] equality is therefore the cache's trust boundary. A local provider's `KekRef` is
/// [`KekProvider::Local`](crate::KekProvider::Local) and its id, so a local KEK id must name one
/// set of KEK material: two [`LocalKmsProvider`](crate::providers::LocalKmsProvider)s with one
/// id share their entries.
///
/// - A key reaches a caller only inside the closure of [`with_key`](Self::with_key), and stays
///   intact until the closure returns, whatever leaves the cache meanwhile.
/// - Concurrent misses for one key make one provider call, and every caller receives its result:
///   the key, or the error. When the caller making the call is cancelled, one of the callers
///   waiting on it makes the call instead.
/// - A failed unwrap leaves no entry, so that under a KMS outage every call fails as fast as the
///   KMS does.
/// - An entry is inserted by the miss that unwraps its key, before the unwrap, and serves lookups
///   for [`ttl`](DekCacheOptions::ttl) after that, however often it is used. An unwrap under way
///   counts against [`max_entries`](DekCacheOptions::max_entries).
///
/// # Key lifetime
///
/// A key is dropped, which zeroizes its bytes, when its entry leaves the cache: once the entry
/// is evicted for capacity, invalidated, cleared or purged after it expired. A `with_key` call
/// that looked the key up before its entry left keeps it until its closure returns, and a call
/// waiting on an unwrap that started before an [`invalidate`](Self::invalidate) or a
/// [`clear`](Self::clear) receives that unwrap's key, which is not cached.
///
/// A lookup never returns an entry older than the TTL. The cache runs no thread and no task of
/// its own: the expired entries of both purposes are dropped at the next call on the cache, for
/// either purpose, at [`purge_expired`](Self::purge_expired), or when the last clone of the cache
/// is dropped. With no calls, the bytes of an expired key stay in memory, so an application whose
/// process can sit idle while it holds keys, and that needs the TTL to bound their lifetime in
/// memory, calls `purge_expired` on a timer of its own.
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
pub struct DekCache(pub(crate) Option<Arc<Shared>>);

/// What every clone of an enabled cache shares.
pub(crate) struct Shared {
    options: DekCacheOptions,
    randomized: Table<DataEncryptionKey>,
    #[cfg(feature = "deterministic")]
    deterministic: Table<DeterministicDataEncryptionKey>,
}

/// The entries of one purpose. A change publishes a new snapshot under the write lock, and a
/// lookup holds the read lock only to clone the current one.
type Table<K> = RwLock<Arc<Snapshot<K>>>;

/// The entries of one purpose at one moment, never changed once a table holds it.
struct Snapshot<K> {
    slots: HashMap<CacheKey, Arc<Slot<K>>>,
    /// The slot created first: every slot lives for the same TTL, so it is the next to expire,
    /// and the one evicted when the table is full.
    oldest: Option<Arc<Slot<K>>>,
}

/// An entry: the key, or the unwrap under way that the concurrent misses of the key share.
struct Slot<K> {
    dek: OnceCell<KmsAeadResult<Arc<K>>>,
    created_at: Instant,
}

/// The provider's KEK and the wrapped key's bytes. Wrapped keys are not secret, so they hash and
/// compare in variable time.
type CacheKey = (KekRef, Vec<u8>);

/// The snapshot `table` holds.
///
/// A snapshot is replaced only once its successor is built, so a panic under a table's lock
/// leaves a whole snapshot behind: a poisoned lock is recovered, here and in [`publish`].
fn load<K>(table: &Table<K>) -> Arc<Snapshot<K>> {
    Arc::clone(&table.read().unwrap_or_else(PoisonError::into_inner))
}

/// Replaces the snapshot `table` holds with the one `derive` builds from it, unless it builds
/// none. The replaced snapshot is dropped before this returns, unless a lookup still holds it.
fn publish<K>(table: &Table<K>, derive: impl FnOnce(&Snapshot<K>) -> Option<Snapshot<K>>) {
    let mut current = table.write().unwrap_or_else(PoisonError::into_inner);
    if let Some(derived) = derive(&current) {
        *current = Arc::new(derived);
    }
}

impl Shared {
    /// Runs `use_key` with the key cached under `cache_key` in `table`, or with the key
    /// `unwrap_key` returns on a miss, which stays cached unless its slot left the table
    /// meanwhile.
    async fn with_key<K, T, Fut>(
        &self,
        table: &Table<K>,
        cache_key: CacheKey,
        unwrap_key: impl FnOnce() -> Fut,
        use_key: impl FnOnce(&K) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        Fut: Future<Output = KmsAeadResult<K>>,
    {
        let now = Instant::now();
        self.purge_expired(now);
        let (ttl, max_entries) = (self.options.ttl, self.options.max_entries);
        let cached = load(table).live(&cache_key, ttl, now).map(Arc::clone);
        let slot = cached.unwrap_or_else(|| {
            let created = Arc::new(Slot {
                dek: OnceCell::new(),
                created_at: now,
            });
            // Of concurrent misses, the slot published first wins, and they all wait on it.
            let mut slot = Arc::clone(&created);
            publish(table, |snapshot| {
                match snapshot.live(&cache_key, ttl, now) {
                    Some(published) => {
                        slot = Arc::clone(published);
                        None
                    }
                    None => Some(snapshot.with(cache_key.clone(), created, max_entries)),
                }
            });
            slot
        });

        let mut unwrapped_here = false;
        let unwrapped = slot
            .dek
            .get_or_init(|| {
                unwrapped_here = true;
                async move { unwrap_key().await.map(Arc::new) }
            })
            .await
            .clone();
        let outcome = if unwrapped_here {
            DekCacheOutcome::Miss
        } else {
            DekCacheOutcome::Hit
        };
        match unwrapped {
            Ok(dek) => Ok((use_key(&dek), outcome)),
            Err(error) => {
                // The caller that made the failed unwrap removes its slot, unless the slot has
                // already left the table, so that no failure is served from the cache.
                if unwrapped_here {
                    publish(table, |snapshot| {
                        let failed = snapshot.slots.get(&cache_key);
                        let failed = failed.filter(|failed| Arc::ptr_eq(failed, &slot));
                        failed.and_then(|_| snapshot.without(&cache_key))
                    });
                }
                Err(error)
            }
        }
    }

    fn purge_expired(&self, now: Instant) {
        self.purge(&self.randomized, now);
        #[cfg(feature = "deterministic")]
        self.purge(&self.deterministic, now);
    }

    fn purge<K>(&self, table: &Table<K>, now: Instant) {
        let ttl = self.options.ttl;
        if load(table).has_expired(ttl, now) {
            publish(table, |snapshot| snapshot.unexpired(ttl, now));
        }
    }

    /// Caches `key`, which `kek` has just wrapped into `encrypted`, as an unwrap of `encrypted`
    /// would have, so that the first lookup of a new store-less DEK is a hit. Kept off the public
    /// API: a key cached under the wrong wrapped bytes would seal values that no unwrap opens.
    pub(crate) fn insert(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        _binding: Option<&DekBinding>,
        key: DataEncryptionKey,
    ) {
        let now = Instant::now();
        self.purge_expired(now);
        let slot = Arc::new(Slot {
            dek: OnceCell::from(Ok(Arc::new(key))),
            created_at: now,
        });
        let cache_key = (kek.clone(), encrypted.wrapped().to_vec());
        publish(&self.randomized, |snapshot| {
            Some(snapshot.with(cache_key, slot, self.options.max_entries))
        });
    }
}

impl<K> Snapshot<K> {
    fn live(&self, cache_key: &CacheKey, ttl: Duration, now: Instant) -> Option<&Arc<Slot<K>>> {
        self.slots
            .get(cache_key)
            .filter(|slot| !slot.is_expired(ttl, now))
    }

    fn has_expired(&self, ttl: Duration, now: Instant) -> bool {
        self.oldest
            .as_ref()
            .is_some_and(|oldest| oldest.is_expired(ttl, now))
    }

    /// This snapshot with `slot` under `cache_key`, which evicts the oldest slot of a snapshot
    /// that already holds `max_entries`.
    fn with(&self, cache_key: CacheKey, slot: Arc<Slot<K>>, max_entries: NonZeroUsize) -> Self {
        let mut slots = self.slots.clone();
        slots.remove(&cache_key);
        if let Some(oldest) = self.oldest.as_ref() {
            if slots.len() >= max_entries.get() {
                slots.retain(|_, cached| !Arc::ptr_eq(cached, oldest));
            }
        }
        slots.insert(cache_key, slot);
        slots.into()
    }

    /// This snapshot without the slot of `cache_key`, or `None` when it holds none.
    fn without(&self, cache_key: &CacheKey) -> Option<Self> {
        self.slots.contains_key(cache_key).then(|| {
            let mut slots = self.slots.clone();
            slots.remove(cache_key);
            slots.into()
        })
    }

    /// This snapshot without the slots older than `ttl` at `now`, or `None` when it holds none.
    fn unexpired(&self, ttl: Duration, now: Instant) -> Option<Self> {
        self.has_expired(ttl, now).then(|| {
            let mut slots = self.slots.clone();
            slots.retain(|_, slot| !slot.is_expired(ttl, now));
            slots.into()
        })
    }
}

impl<K> From<HashMap<CacheKey, Arc<Slot<K>>>> for Snapshot<K> {
    fn from(slots: HashMap<CacheKey, Arc<Slot<K>>>) -> Self {
        let oldest = slots.values().min_by_key(|slot| slot.created_at).cloned();
        Self { slots, oldest }
    }
}

impl<K> Default for Snapshot<K> {
    fn default() -> Self {
        HashMap::new().into()
    }
}

impl<K> Slot<K> {
    fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= ttl
    }
}

impl DekCache {
    /// A cache with `options`.
    ///
    /// # Errors
    ///
    /// `INVALID_DEK_CACHE_TTL` when the TTL is zero.
    pub fn new(options: DekCacheOptions) -> KmsAeadResult<Self> {
        if options.ttl.is_zero() {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_CACHE_TTL",
                "A DEK cache TTL of zero caches nothing: use DekCache::disabled",
            ));
        }
        Ok(Self(Some(Arc::new(Shared {
            options,
            randomized: Table::default(),
            #[cfg(feature = "deterministic")]
            deterministic: Table::default(),
        }))))
    }

    /// A cache that holds nothing: every [`with_key`](Self::with_key) calls the provider, and
    /// [`invalidate`](Self::invalidate), [`clear`](Self::clear) and
    /// [`purge_expired`](Self::purge_expired) do nothing.
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
        binding: Option<&DekBinding>,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let unwrap_key = || provider.decrypt_data_encryption_key(encrypted, binding);
        match &self.0 {
            Some(shared) => {
                let cache_key = (provider.kek().clone(), encrypted.wrapped().to_vec());
                shared
                    .with_key(&shared.randomized, cache_key, unwrap_key, use_key)
                    .await
            }
            None => Ok((use_key(&unwrap_key().await?), DekCacheOutcome::Disabled)),
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
        binding: Option<&DekBinding>,
        use_key: impl FnOnce(&DeterministicDataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let unwrap_key = || async {
            let key = provider
                .decrypt_data_encryption_key(encrypted, binding)
                .await?;
            checked_deterministic_key(key, algorithm)
        };
        match &self.0 {
            Some(shared) => {
                let cache_key = (provider.kek().clone(), encrypted.wrapped().to_vec());
                shared
                    .with_key(&shared.deterministic, cache_key, unwrap_key, use_key)
                    .await
            }
            None => Ok((use_key(&unwrap_key().await?), DekCacheOutcome::Disabled)),
        }
    }

    /// Drops the entries of both purposes for `encrypted` under `kek`. The next
    /// [`with_key`](Self::with_key) of the key calls the provider, and an unwrap of it under way
    /// returns its key to its callers without caching it.
    pub fn invalidate(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        _binding: Option<&DekBinding>,
    ) {
        if let Some(shared) = &self.0 {
            shared.purge_expired(Instant::now());
            let cache_key = (kek.clone(), encrypted.wrapped().to_vec());
            publish(&shared.randomized, |snapshot| snapshot.without(&cache_key));
            #[cfg(feature = "deterministic")]
            publish(&shared.deterministic, |snapshot| {
                snapshot.without(&cache_key)
            });
        }
    }

    /// Drops the expired entries of both purposes, which zeroizes their keys once no
    /// [`with_key`](Self::with_key) call holds them. Every call on the cache does this first. An
    /// application whose process can sit idle while the cache holds keys calls it from a timer of
    /// its own, on whatever runtime it uses, to drop them at the TTL; see "Key lifetime" on
    /// [`DekCache`].
    pub fn purge_expired(&self) {
        if let Some(shared) = &self.0 {
            shared.purge_expired(Instant::now());
        }
    }

    /// Drops every entry. The unwraps under way return their keys to their callers without
    /// caching them. A store-less renewal under way may still cache its new DEK after `clear`
    /// returns, since the renewal started before the clear.
    pub fn clear(&self) {
        if let Some(shared) = &self.0 {
            publish(&shared.randomized, |_| Some(Snapshot::default()));
            #[cfg(feature = "deterministic")]
            publish(&shared.deterministic, |_| Some(Snapshot::default()));
        }
    }
}

/// The options of an enabled cache, never its entries.
impl Debug for DekCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DekCache")
            .field(&self.0.as_ref().map(|shared| &shared.options))
            .finish()
    }
}

#[cfg(test)]
impl<K> Snapshot<K> {
    /// The key cached under `cache_key`, as a `Weak` that stops upgrading once the key is
    /// dropped, and its bytes with it zeroized.
    fn cached(&self, cache_key: &CacheKey) -> Option<Weak<K>> {
        let unwrapped = self.slots.get(cache_key)?.dek.get()?;
        unwrapped.as_ref().ok().map(Arc::downgrade)
    }
}

#[cfg(test)]
impl DekCache {
    /// The randomized key cached for `encrypted` under `kek`, as [`Snapshot::cached`] gives it.
    pub(crate) fn cached_dek(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DataEncryptionKey>> {
        let shared = self.0.as_ref()?;
        load(&shared.randomized).cached(&(kek.clone(), encrypted.wrapped().to_vec()))
    }

    /// The deterministic key cached for `encrypted` under `kek`, as [`Snapshot::cached`] gives
    /// it.
    #[cfg(feature = "deterministic")]
    fn cached_deterministic_dek(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DeterministicDataEncryptionKey>> {
        let shared = self.0.as_ref()?;
        load(&shared.deterministic).cached(&(kek.clone(), encrypted.wrapped().to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use futures::executor::block_on;

    use super::*;
    use crate::errors::KmsAeadError;
    use crate::test_provider::{
        let_spawned_tasks_wait, CountingKmsProvider, TestKmsProvider, CONCURRENT_CALLS,
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
                tokio::spawn(
                    async move { cache.with_key(&*provider, &encrypted, None, |_| ()).await },
                )
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
                tokio::spawn(
                    async move { cache.with_key(&*provider, &encrypted, None, |_| ()).await },
                )
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

        let failed = cache.with_key(&failing, &encrypted, None, |_| ()).await;
        let ((), first) = cache.with_key(&working, &encrypted, None, |_| ()).await?;
        let ((), second) = cache.with_key(&working, &encrypted, None, |_| ()).await?;

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

        let ((), first) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        tokio::time::sleep(SHORT_TTL * 2).await;
        let ((), third) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;

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
            cache.with_key(&provider, &encrypted, None, |_| ()).await?;
            randomized.push(cache.cached_dek(provider.kek(), &encrypted).unwrap());
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
                    .with_deterministic_key(&provider, algorithm, &encrypted, None, |_| ())
                    .await?;
                deterministic.push(
                    cache
                        .cached_deterministic_dek(provider.kek(), &encrypted)
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

        let ((), first) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        let cached = cache.cached_dek(provider.kek(), &encrypted).unwrap();
        cache.invalidate(provider.kek(), &encrypted, None);
        let zeroized = cached.strong_count() == 0;
        let ((), third) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;

        assert!(zeroized);
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

        cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        cache
            .with_deterministic_key(&provider, algorithm, &encrypted, None, |_| ())
            .await?;
        let randomized = cache.cached_dek(provider.kek(), &encrypted).unwrap();
        let deterministic = cache
            .cached_deterministic_dek(provider.kek(), &encrypted)
            .unwrap();
        cache.invalidate(provider.kek(), &encrypted, None);
        let ((), outcome) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, None, |_| ())
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

        let ((), randomized) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        let ((), deterministic) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, None, |_| ())
            .await?;
        let ((), again) = cache
            .with_deterministic_key(&provider, algorithm, &encrypted, None, |_| ())
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

        let ((), first) = cache.with_key(&orders, &encrypted, None, |_| ()).await?;
        let ((), second) = cache.with_key(&orders, &encrypted, None, |_| ()).await?;
        let ((), other_kek) = cache.with_key(&billing, &encrypted, None, |_| ()).await?;

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
    async fn clear_zeroizes_every_key() -> KmsAeadResult<()> {
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let encrypted: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new(vec![byte; 64], None))
            .collect();

        let mut cached = Vec::new();
        for encrypted in &encrypted {
            cache.with_key(&provider, encrypted, None, |_| ()).await?;
            cached.push(cache.cached_dek(provider.kek(), encrypted).unwrap());
        }
        #[cfg(feature = "deterministic")]
        let deterministic = {
            let algorithm = DeterministicAlgorithm::Aes256Siv;
            cache
                .with_deterministic_key(&provider, algorithm, &encrypted[0], None, |_| ())
                .await?;
            cache
                .cached_deterministic_dek(provider.kek(), &encrypted[0])
                .unwrap()
        };
        cache.clear();

        assert!(cached.iter().all(|dek| dek.strong_count() == 0));
        #[cfg(feature = "deterministic")]
        assert_eq!(deterministic.strong_count(), 0);
        Ok(())
    }

    #[test]
    fn purge_expired_zeroizes_an_expired_key_without_a_runtime() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        assert!(tokio::runtime::Handle::try_current().is_err());
        block_on(cache.with_key(&provider, &encrypted, None, |_| ()))?;
        let cached = cache.cached_dek(provider.kek(), &encrypted).unwrap();
        thread::sleep(SHORT_TTL);
        let held_until_purged = cached.strong_count();
        cache.purge_expired();

        assert_eq!([held_until_purged, cached.strong_count()], [1, 0]);
        Ok(())
    }

    #[cfg(feature = "deterministic")]
    #[tokio::test]
    async fn a_randomized_lookup_drops_an_expired_deterministic_key() -> KmsAeadResult<()> {
        let orders = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let billing = EncryptedDataEncryptionKey::new(BILLING_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        cache
            .with_deterministic_key(
                &provider,
                DeterministicAlgorithm::Aes256Siv,
                &orders,
                None,
                |_| (),
            )
            .await?;
        let deterministic = cache
            .cached_deterministic_dek(provider.kek(), &orders)
            .unwrap();
        tokio::time::sleep(SHORT_TTL).await;
        let held_until_lookup = deterministic.strong_count();
        cache.with_key(&provider, &billing, None, |_| ()).await?;

        assert_eq!([held_until_lookup, deterministic.strong_count()], [1, 0]);
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
                async move { cache.with_key(&*provider, &encrypted, None, |_| ()).await }
            });
            let_spawned_tasks_wait().await;
            if clear {
                cache.clear();
            } else {
                cache.invalidate(provider.kek(), &encrypted, None);
            }
            provider.open_gate();
            let ((), leader) = in_flight.await.unwrap()?;
            let ((), after) = cache.with_key(&*provider, &encrypted, None, |_| ()).await?;
            outcomes.push(([leader, after], provider.unwraps()));
            cache.clear();
        }

        let expected = ([DekCacheOutcome::Miss, DekCacheOutcome::Miss], 2);
        assert_eq!(outcomes, [expected; 2]);
        Ok(())
    }

    #[tokio::test]
    async fn a_waiter_unwraps_when_the_unwrapping_caller_is_cancelled() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::Working,
            ORDERS_KEK,
        ));

        let [unwrapping, waiting] = [(); 2].map(|()| {
            let (cache, provider, encrypted) =
                (cache.clone(), Arc::clone(&provider), encrypted.clone());
            tokio::spawn(async move { cache.with_key(&*provider, &encrypted, None, |_| ()).await })
        });
        let_spawned_tasks_wait().await;
        unwrapping.abort();
        let_spawned_tasks_wait().await;
        provider.open_gate();
        let cancelled = unwrapping.await.is_err_and(|error| error.is_cancelled());
        let ((), took_over) = waiting.await.unwrap()?;
        let ((), after) = cache.with_key(&*provider, &encrypted, None, |_| ()).await?;

        assert!(cancelled);
        assert_eq!(
            [took_over, after],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(provider.unwraps(), 2);
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
                    cache.invalidate(provider.kek(), &keys[0].0, None);
                    cache.clear();
                }
            });
            let users: Vec<_> = (0..USING_THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..USES_PER_THREAD)
                            .filter(|use_index| {
                                let (encrypted, dek) = &keys[use_index % keys.len()];
                                let used =
                                    block_on(cache.with_key(&provider, encrypted, None, |key| {
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

    #[test]
    fn lookups_racing_removals_get_only_live_keys_and_drop_the_removed() -> KmsAeadResult<()> {
        const LOOKUP_THREADS: usize = 4;
        const LOOKUPS_PER_THREAD: usize = 20_000;
        const CLEAR_EVERY: usize = 8;
        let ttl = Duration::from_micros(500);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(ttl))?;
        let started = Instant::now();
        let provider = CountingKmsProvider::new(TestKmsProvider::Stamping(started), ORDERS_KEK);
        let keys: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new(vec![byte; 32], None))
            .collect();
        let looking_up = AtomicBool::new(true);

        let (failures, invalidated) = thread::scope(|scope| {
            let churn = scope.spawn(|| {
                let mut invalidated = Vec::new();
                let rounds = keys.iter().cycle().enumerate();
                for (round, encrypted) in rounds.take_while(|_| looking_up.load(Ordering::Relaxed))
                {
                    invalidated.extend(cache.cached_dek(provider.kek(), encrypted));
                    cache.invalidate(provider.kek(), encrypted, None);
                    cache.purge_expired();
                    if round % CLEAR_EVERY == 0 {
                        cache.clear();
                    }
                    thread::sleep(Duration::from_micros(200));
                }
                invalidated
            });
            let lookups: Vec<_> = (0..LOOKUP_THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..LOOKUPS_PER_THREAD)
                            .filter(|lookup| {
                                let encrypted = &keys[lookup % keys.len()];
                                let looked_up_at = Instant::now();
                                let served =
                                    block_on(cache.with_key(&provider, encrypted, None, |key| {
                                        let stamped = key.value().ref_sensitive_value();
                                        let split = stamped.split_last_chunk::<8>();
                                        split.is_some_and(|(wrapped, nanos)| {
                                            let since =
                                                Duration::from_nanos(u64::from_le_bytes(*nanos));
                                            let age = looked_up_at
                                                .saturating_duration_since(started + since);
                                            wrapped == encrypted.wrapped() && age < ttl
                                        })
                                    }));
                                !matches!(served, Ok((true, _)))
                            })
                            .count()
                    })
                })
                .collect();
            let failures: usize = lookups
                .into_iter()
                .map(|lookup| lookup.join().unwrap())
                .sum();
            looking_up.store(false, Ordering::Relaxed);
            (failures, churn.join().unwrap())
        });

        assert_eq!(failures, 0);
        assert!(!invalidated.is_empty());
        assert!(invalidated.iter().all(|key| key.strong_count() == 0));
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cache_unwraps_every_time() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::disabled();
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, None, |_| ()).await?;
        cache.invalidate(provider.kek(), &encrypted, None);
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
