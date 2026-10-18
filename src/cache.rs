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
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekRef, KmsAeadEncryptionProvider, KmsAeadResult,
};

/// The settings of an enabled [`DekCache`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct DekCacheOptions {
    /// How long an entry serves lookups after it was inserted, however often it is used:
    /// [`DEFAULT_TTL`](Self::DEFAULT_TTL) by default. Longer than zero.
    #[default = "Self::DEFAULT_TTL"]
    pub ttl: Duration,
    /// The entries the cache holds at most: [`DEFAULT_MAX_ENTRIES`](Self::DEFAULT_MAX_ENTRIES)
    /// by default. Past it, the oldest entry is evicted.
    #[default = "Self::DEFAULT_MAX_ENTRIES"]
    pub max_entries: NonZeroUsize,
}

impl DekCacheOptions {
    /// The default [`ttl`](Self::ttl): 15 minutes.
    pub const DEFAULT_TTL: Duration = Duration::from_secs(15 * 60);
    /// The default [`max_entries`](Self::max_entries): 1024.
    pub const DEFAULT_MAX_ENTRIES: NonZeroUsize =
        NonZeroUsize::new(1024).expect("1024 is not zero");
}

/// Where the key of a [`DekCache::with_key`] call came from. Its `Display` is the value of the
/// `dek_cache` span field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DekCacheOutcome {
    /// From the cache, or from a concurrent call that unwrapped the same key.
    Hit,
    /// Unwrapped by the provider for this call. It is cached unless a live entry of another KEK
    /// holds the same wrapped bytes.
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
/// An entry holds the key a provider unwrapped from a wrapped key's bytes, with the provider's
/// [`KekRef`], and serves only a lookup that names the same KEK. A cache shared by the providers
/// of several KEKs therefore never returns a key unwrapped under one KEK to a caller that passed
/// the provider of another: that caller's provider asks its KMS, which refuses a key wrapped
/// under a foreign KEK. Such a call leaves the live entry as it is and caches nothing. The key
/// version a wrapped key records is not part of the match.
///
/// [`KekRef`] equality is therefore the cache's trust boundary. A local provider's `KekRef` is
/// [`KekProvider::Local`](crate::KekProvider::Local) and its id, so a local KEK id must name one
/// set of KEK material: two [`LocalKmsProvider`](crate::providers::LocalKmsProvider)s with one
/// id share their entries.
///
/// Keys of randomized and deterministic algorithms share the entries: the same wrapped bytes
/// unwrap to the same key whatever the caller seals with it. An entry holds the key a serialized
/// Tink key carries, and the cipher a key is used with checks its length.
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
/// - A hit allocates nothing. A miss copies the table of entries, whose size
///   [`max_entries`](DekCacheOptions::max_entries) bounds.
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
/// its own: the expired entries are dropped at the next call on the cache, at
/// [`purge_expired`](Self::purge_expired), or when the last clone of the cache is dropped. With
/// no calls, the bytes of an expired key stay in memory, so an application whose process can sit
/// idle while it holds keys, and that needs the TTL to bound their lifetime in memory, calls
/// `purge_expired` on a timer of its own.
///
/// A KMS key that is disabled, or an IAM grant that is revoked, reaches the keys this cache
/// holds only when their entries expire, or at [`invalidate`](Self::invalidate) or
/// [`clear`](Self::clear): until then those keys keep serving lookups without a KMS call.
///
/// # Defaults
///
/// [`DekCacheOptions::new`] gives a TTL of 15 minutes and 1024 entries. The per-call envelope
/// has no cache unless it is given one; the store-less envelope and the keyring use
/// `DekCache::new(DekCacheOptions::new())` unless they are given another.
#[derive(Clone)]
pub struct DekCache(pub(crate) Option<Arc<EnabledCache>>);

/// What every clone of an enabled cache shares. A change publishes a new snapshot of the entries
/// under the write lock, and a lookup holds the read lock only to clone the current one.
pub(crate) struct EnabledCache {
    options: DekCacheOptions,
    entries: RwLock<Arc<Snapshot>>,
}

/// The entries at one moment, never changed once the cache holds it. They are keyed by the
/// wrapped key alone, which a lookup borrows.
#[derive(Default)]
struct Snapshot {
    slots: HashMap<EncryptedDataEncryptionKey, Arc<Slot>>,
    /// The slot created first: every slot lives for the same TTL, so it is the next to expire,
    /// and the one evicted when the table is full.
    oldest: Option<Arc<Slot>>,
}

/// An entry: the key, or the unwrap under way that the concurrent misses of the key share, and
/// the KEK that unwrap names.
struct Slot {
    kek: KekRef,
    dek: OnceCell<KmsAeadResult<Arc<DataEncryptionKey>>>,
    created_at: Instant,
}

impl EnabledCache {
    /// The current snapshot.
    ///
    /// A snapshot is replaced only once its successor is built, so a panic under the lock leaves
    /// a whole snapshot behind: a poisoned lock is recovered, here and in
    /// [`publish`](Self::publish).
    fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(&self.entries.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Replaces the current snapshot with the one `derive` builds from it, unless it builds none.
    /// The replaced snapshot is dropped before this returns, unless a lookup still holds it.
    fn publish(&self, derive: impl FnOnce(&Snapshot) -> Option<Snapshot>) {
        let mut current = self.entries.write().unwrap_or_else(PoisonError::into_inner);
        if let Some(derived) = derive(&current) {
            *current = Arc::new(derived);
        }
    }

    /// Runs `use_key` with the key cached for `encrypted` under `kek`, or with the key
    /// `unwrap_key` returns on a miss, which stays cached unless its slot left the table
    /// meanwhile. A live slot for `encrypted` under another KEK is neither used nor replaced: the
    /// call unwraps without caching.
    async fn with_key<T, Fut>(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        unwrap_key: impl FnOnce() -> Fut,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        Fut: Future<Output = KmsAeadResult<DataEncryptionKey>>,
    {
        let now = Instant::now();
        self.purge_expired(now);
        let (ttl, max_entries) = (self.options.ttl, self.options.max_entries);
        let cached = self.snapshot().live(encrypted, ttl, now).map(Arc::clone);
        let slot = cached.unwrap_or_else(|| {
            let created = Arc::new(Slot {
                kek: kek.clone(),
                dek: OnceCell::new(),
                created_at: now,
            });
            // Of concurrent misses, the slot published first wins, and they all wait on it.
            let mut slot = Arc::clone(&created);
            self.publish(|snapshot| match snapshot.live(encrypted, ttl, now) {
                Some(published) => {
                    slot = Arc::clone(published);
                    None
                }
                None => Some(snapshot.with(encrypted.clone(), created, max_entries)),
            });
            slot
        });
        if !slot.serves(kek) {
            drop(slot);
            return Ok((use_key(&unwrap_key().await?), DekCacheOutcome::Miss));
        }

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
                    self.publish(|snapshot| {
                        let failed = snapshot.slots.get(encrypted);
                        let failed = failed.filter(|failed| Arc::ptr_eq(failed, &slot));
                        failed.and_then(|_| snapshot.without(encrypted))
                    });
                }
                Err(error)
            }
        }
    }

    fn purge_expired(&self, now: Instant) {
        let ttl = self.options.ttl;
        if self.snapshot().has_expired(ttl, now) {
            self.publish(|snapshot| snapshot.unexpired(ttl, now));
        }
    }

    /// Runs `use_key` with the key cached for `encrypted` under `kek`, or returns `None`,
    /// without calling a provider, when the cache holds no such key.
    pub(crate) fn with_cached_key<T>(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> Option<T> {
        let now = Instant::now();
        self.purge_expired(now);
        let snapshot = self.snapshot();
        let slot = snapshot
            .live(encrypted, self.options.ttl, now)
            .filter(|slot| slot.serves(kek))?;
        let dek = slot.dek.get()?.as_ref().ok()?;
        Some(use_key(dek))
    }

    /// Caches `key`, which `kek` has just wrapped into `encrypted`, as an unwrap of `encrypted`
    /// would have, so that the first lookup of a new store-less DEK is a hit. Kept off the public
    /// API: a key cached under the wrong wrapped bytes would seal values that no unwrap opens. A
    /// live entry of another KEK for the same bytes is kept.
    pub(crate) fn insert(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        key: DataEncryptionKey,
    ) {
        let now = Instant::now();
        self.purge_expired(now);
        let (ttl, max_entries) = (self.options.ttl, self.options.max_entries);
        let slot = Arc::new(Slot {
            kek: kek.clone(),
            dek: OnceCell::from(Ok(Arc::new(key))),
            created_at: now,
        });
        self.publish(|snapshot| match snapshot.live(encrypted, ttl, now) {
            Some(live) if !live.serves(kek) => None,
            _ => Some(snapshot.with(encrypted.clone(), slot, max_entries)),
        });
    }
}

impl Snapshot {
    fn live(
        &self,
        encrypted: &EncryptedDataEncryptionKey,
        ttl: Duration,
        now: Instant,
    ) -> Option<&Arc<Slot>> {
        self.slots
            .get(encrypted)
            .filter(|slot| !slot.is_expired(ttl, now))
    }

    fn has_expired(&self, ttl: Duration, now: Instant) -> bool {
        self.oldest
            .as_ref()
            .is_some_and(|oldest| oldest.is_expired(ttl, now))
    }

    /// This snapshot with `slot` for `encrypted`, which evicts the oldest slot of a snapshot that
    /// already holds `max_entries`.
    fn with(
        &self,
        encrypted: EncryptedDataEncryptionKey,
        slot: Arc<Slot>,
        max_entries: NonZeroUsize,
    ) -> Self {
        let mut slots = self.slots.clone();
        slots.remove(&encrypted);
        if let Some(oldest) = self.oldest.as_ref() {
            if slots.len() >= max_entries.get() {
                slots.retain(|_, cached| !Arc::ptr_eq(cached, oldest));
            }
        }
        slots.insert(encrypted, slot);
        slots.into()
    }

    /// This snapshot without the slot of `encrypted`, or `None` when it holds none.
    fn without(&self, encrypted: &EncryptedDataEncryptionKey) -> Option<Self> {
        self.slots.contains_key(encrypted).then(|| {
            let mut slots = self.slots.clone();
            slots.remove(encrypted);
            slots.into()
        })
    }

    /// This snapshot without the slot of `encrypted` under `kek`, or `None` when it holds none.
    fn without_entry(&self, encrypted: &EncryptedDataEncryptionKey, kek: &KekRef) -> Option<Self> {
        self.slots
            .get(encrypted)
            .filter(|slot| slot.serves(kek))
            .and_then(|_| self.without(encrypted))
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

impl From<HashMap<EncryptedDataEncryptionKey, Arc<Slot>>> for Snapshot {
    fn from(slots: HashMap<EncryptedDataEncryptionKey, Arc<Slot>>) -> Self {
        let oldest = slots.values().min_by_key(|slot| slot.created_at).cloned();
        Self { slots, oldest }
    }
}

impl Slot {
    fn is_expired(&self, ttl: Duration, now: Instant) -> bool {
        now.saturating_duration_since(self.created_at) >= ttl
    }

    /// Whether this slot holds the unwrap of a call that names `kek`, the only call it serves.
    fn serves(&self, kek: &KekRef) -> bool {
        self.kek == *kek
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
        Ok(Self(Some(Arc::new(EnabledCache {
            options,
            entries: RwLock::default(),
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
    /// The provider's error, `INVALID_KEY_FORMAT` when the unwrapped key is not a serialized Tink
    /// key, and without the `legacy-formats` feature
    /// [`KmsAeadError::LegacyFormat`](crate::errors::KmsAeadError::LegacyFormat) for a key
    /// wrapped by 0.29 or earlier. Every caller waiting on the same unwrap receives the error,
    /// and nothing is cached. The errors of `use_key` come back in its own return value.
    pub async fn with_key<P, T>(
        &self,
        provider: &P,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        // A wrapped value of the same KEK that is no data encryption key, such as an exported
        // keyset, unwraps too, and the decoding of a serialized Tink key keeps it out.
        let unwrap_key = || async { encrypted.unwrap_with(provider).await.map(|(key, _)| key) };
        match &self.0 {
            Some(enabled) => {
                enabled
                    .with_key(provider.kek(), encrypted, unwrap_key, use_key)
                    .await
            }
            None => Ok((use_key(&unwrap_key().await?), DekCacheOutcome::Disabled)),
        }
    }

    /// Drops the entry for `encrypted` under `kek`; an entry of the same wrapped bytes under
    /// another KEK stays. The next [`with_key`](Self::with_key) of the key calls the provider,
    /// and an unwrap of it under way returns its key to its callers without caching it.
    pub fn invalidate(&self, kek: &KekRef, encrypted: &EncryptedDataEncryptionKey) {
        if let Some(enabled) = &self.0 {
            enabled.purge_expired(Instant::now());
            enabled.publish(|snapshot| snapshot.without_entry(encrypted, kek));
        }
    }

    /// Drops the expired entries, which zeroizes their keys once no [`with_key`](Self::with_key)
    /// call holds them. Every call on the cache does this first. An application whose process can
    /// sit idle while the cache holds keys calls it from a timer of its own, on whatever runtime
    /// it uses, to drop them at the TTL; see "Key lifetime" on [`DekCache`].
    pub fn purge_expired(&self) {
        if let Some(enabled) = &self.0 {
            enabled.purge_expired(Instant::now());
        }
    }

    /// Drops every entry. The unwraps under way return their keys to their callers without
    /// caching them. A store-less renewal under way may still cache its new DEK after `clear`
    /// returns, since the renewal started before the clear.
    pub fn clear(&self) {
        if let Some(enabled) = &self.0 {
            enabled.publish(|_| Some(Snapshot::default()));
        }
    }
}

/// The options of an enabled cache, never its entries.
impl Debug for DekCache {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("DekCache")
            .field(&self.0.as_ref().map(|enabled| &enabled.options))
            .finish()
    }
}

#[cfg(test)]
impl DekCache {
    /// The key cached for `encrypted` under `kek`, as a `Weak` that stops upgrading once the key
    /// is dropped, and its bytes with it zeroized.
    pub(crate) fn cached_dek(
        &self,
        kek: &KekRef,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DataEncryptionKey>> {
        let snapshot = self.0.as_ref()?.snapshot();
        let slot = snapshot
            .slots
            .get(encrypted)
            .filter(|slot| slot.serves(kek))?;
        slot.dek.get()?.as_ref().ok().map(Arc::downgrade)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::thread;

    use futures::executor::block_on;

    use super::*;
    use crate::errors::KmsAeadError;
    use crate::formats::TinkKeyType;
    use crate::test_provider::{
        let_spawned_tasks_wait, wrapped_by_test_provider, CountingKmsProvider, TestKmsProvider,
        CONCURRENT_CALLS,
    };
    use crate::ValueStruct;

    const ORDERS_KEK: &str = "orders";
    const BILLING_KEK: &str = "billing";
    const ORDERS_DEK: [u8; 32] = [0x42; 32];
    const BILLING_DEK: [u8; 32] = [0x24; 32];
    const ORDERS_DETERMINISTIC_DEK: [u8; 64] = [0x42; 64];
    const SHORT_TTL: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn n_concurrent_misses_make_one_unwrap() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
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
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
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
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
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
    async fn an_unwrapped_key_that_is_no_tink_key_is_refused_and_not_cached() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(vec![0x42; 100]);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        for _ in 0..2 {
            let result = cache.with_key(&provider, &encrypted, |_| ()).await;
            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_KEY_FORMAT"),
                "{:?}",
                result.as_ref().err()
            );
        }

        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_deterministic_key_is_cached() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesSiv, &ORDERS_DETERMINISTIC_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;

        assert_eq!(
            [first, second],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn an_entry_expires_after_ttl() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
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
    async fn capacity_evicts_the_oldest_entry() -> KmsAeadResult<()> {
        let max_entries = NonZeroUsize::new(2).unwrap();
        let cache = DekCache::new(DekCacheOptions::new().with_max_entries(max_entries))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let mut cached = Vec::new();
        for byte in 1..=3 {
            let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &[byte; 32]);
            cache.with_key(&provider, &encrypted, |_| ()).await?;
            cached.push(cache.cached_dek(provider.kek(), &encrypted).unwrap());
        }

        let live: Vec<_> = cached.iter().map(|dek| dek.strong_count() > 0).collect();
        assert_eq!(live, [false, true, true]);

        Ok(())
    }

    #[tokio::test]
    async fn invalidate_forces_the_next_unwrap() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let cached = cache.cached_dek(provider.kek(), &encrypted).unwrap();
        cache.invalidate(provider.kek(), &encrypted);
        let zeroized = cached.strong_count() == 0;
        let ((), third) = cache.with_key(&provider, &encrypted, |_| ()).await?;

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

    #[tokio::test]
    async fn cache_is_namespaced_by_kek() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let orders = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let billing = CountingKmsProvider::new(TestKmsProvider::Working, BILLING_KEK);

        let ((), first) = cache.with_key(&orders, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&orders, &encrypted, |_| ()).await?;
        let ((), other_kek) = cache.with_key(&billing, &encrypted, |_| ()).await?;
        let ((), kept) = cache.with_key(&orders, &encrypted, |_| ()).await?;

        assert_eq!(
            [first, second, other_kek, kept],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit
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
            .map(|byte| wrapped_by_test_provider(TinkKeyType::AesGcm, &[byte; 32]))
            .collect();

        let mut cached = Vec::new();
        for encrypted in &encrypted {
            cache.with_key(&provider, encrypted, |_| ()).await?;
            cached.push(cache.cached_dek(provider.kek(), encrypted).unwrap());
        }
        cache.clear();

        assert!(cached.iter().all(|dek| dek.strong_count() == 0));
        Ok(())
    }

    #[test]
    fn purge_expired_zeroizes_an_expired_key_without_a_runtime() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        assert!(tokio::runtime::Handle::try_current().is_err());
        block_on(cache.with_key(&provider, &encrypted, |_| ()))?;
        let cached = cache.cached_dek(provider.kek(), &encrypted).unwrap();
        thread::sleep(SHORT_TTL);
        let held_until_purged = cached.strong_count();
        cache.purge_expired();

        assert_eq!([held_until_purged, cached.strong_count()], [1, 0]);
        Ok(())
    }

    #[tokio::test]
    async fn an_unwrap_in_flight_does_not_reinsert_after_invalidate() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
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
                cache.invalidate(provider.kek(), &encrypted);
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

    #[tokio::test]
    async fn a_waiter_unwraps_when_the_unwrapping_caller_is_cancelled() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::Working,
            ORDERS_KEK,
        ));

        let [unwrapping, waiting] = [(); 2].map(|()| {
            let (cache, provider, encrypted) =
                (cache.clone(), Arc::clone(&provider), encrypted.clone());
            tokio::spawn(async move { cache.with_key(&*provider, &encrypted, |_| ()).await })
        });
        let_spawned_tasks_wait().await;
        unwrapping.abort();
        let_spawned_tasks_wait().await;
        provider.open_gate();
        let cancelled = unwrapping.await.is_err_and(|error| error.is_cancelled());
        let ((), took_over) = waiting.await.unwrap()?;
        let ((), after) = cache.with_key(&*provider, &encrypted, |_| ()).await?;

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
            .map(|dek| (wrapped_by_test_provider(TinkKeyType::AesGcm, &dek), dek));
        let using = AtomicBool::new(true);

        let failures = thread::scope(|scope| {
            let churn = scope.spawn(|| {
                while using.load(Ordering::Relaxed) {
                    cache.invalidate(provider.kek(), &keys[0].0);
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

    #[test]
    fn lookups_racing_removals_get_only_live_keys_and_drop_the_removed() -> KmsAeadResult<()> {
        const LOOKUP_THREADS: usize = 4;
        const LOOKUPS_PER_THREAD: usize = 20_000;
        const CLEAR_EVERY: usize = 8;
        let ttl = Duration::from_micros(500);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(ttl))?;
        let started = Instant::now();
        let provider = CountingKmsProvider::new(TestKmsProvider::Stamping(started), ORDERS_KEK);
        // The start of a serialized 32-byte AesGcmKey, whose last 8 bytes are the stamp.
        let keys: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new([&[0x1a, 0x20][..], &[byte; 24]].concat()))
            .collect();
        let looking_up = AtomicBool::new(true);

        let (failures, invalidated) = thread::scope(|scope| {
            let churn = scope.spawn(|| {
                let mut invalidated = Vec::new();
                let rounds = keys.iter().cycle().enumerate();
                for (round, encrypted) in rounds.take_while(|_| looking_up.load(Ordering::Relaxed))
                {
                    invalidated.extend(cache.cached_dek(provider.kek(), encrypted));
                    cache.invalidate(provider.kek(), encrypted);
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
                                    block_on(cache.with_key(&provider, encrypted, |key| {
                                        let stamped = key.value().ref_sensitive_value();
                                        let split = stamped.split_last_chunk::<8>();
                                        split.is_some_and(|(wrapped, nanos)| {
                                            let since =
                                                Duration::from_nanos(u64::from_le_bytes(*nanos));
                                            let age = looked_up_at
                                                .saturating_duration_since(started + since);
                                            wrapped == &encrypted.value()[2..] && age < ttl
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
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::disabled();
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        let ((), second) = cache.with_key(&provider, &encrypted, |_| ()).await?;
        cache.invalidate(provider.kek(), &encrypted);
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
