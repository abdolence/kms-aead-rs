//! The cache of plaintext data encryption keys, [`DekCache`], which the store-less envelope and
//! the keyring share.

use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex, PoisonError, RwLock, Weak};
use std::time::Duration;

use moka::future::Cache;
use moka::ops::compute::Op;
use moka::policy::EvictionPolicy;
use rsb_derive::Builder;
use secret_vault_value::SecretValue;
use tokio::runtime::Handle;
use tokio::task::JoinHandle;
use tokio::time::MissedTickBehavior;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
#[cfg(feature = "deterministic")]
use crate::{
    checked_deterministic_key, DeterministicAlgorithm, DeterministicCipher,
    DeterministicCipherText, DeterministicDataEncryptionKey,
};
use crate::{
    AeadCipher, Cipher, CipherText, DataEncryptionKey, EncryptedDataEncryptionKey, KekRef,
    KmsAeadEncryptionProvider, KmsAeadResult,
};

const DEFAULT_MAX_ENTRIES: NonZeroUsize = NonZeroUsize::new(1024).expect("1024 is not zero");

/// The longest TTL the cache's map accepts.
const MAX_TTL: Duration = Duration::from_secs(1000 * 365 * 24 * 60 * 60);

/// The shortest period of the reaper, since tokio's interval refuses a period of zero.
const MIN_REAPER_PERIOD: Duration = Duration::from_millis(1);

/// How many times [`DekCache::unwrap`] looks a key up when each lookup finds a revoked slot,
/// which takes a concurrent invalidation of the same key every time.
const LOOKUP_ATTEMPTS: usize = 3;

/// The settings of an enabled [`DekCache`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct DekCacheOptions {
    /// How long an entry serves lookups after it was inserted, however often it is used: 15
    /// minutes by default. Longer than zero and at most 1000 years.
    #[default = "Duration::from_secs(15 * 60)"]
    pub ttl: Duration,
    /// The entries of each purpose, randomized and deterministic, the cache holds at most: 1024
    /// by default. Past it, the least recently used entry of that purpose is evicted.
    #[default = "DEFAULT_MAX_ENTRIES"]
    pub max_entries: NonZeroUsize,
}

/// Where a key [`DekCache::unwrap`] returned came from. Its `Display` is the value of the
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
/// - Concurrent misses for one key make one provider call, and every caller receives its result:
///   the key, or the error.
/// - A failed unwrap leaves no entry, so that under a KMS outage every call fails as fast as the
///   KMS does.
/// - An entry serves lookups for [`ttl`](DekCacheOptions::ttl) after it was inserted, however
///   often it is used.
///
/// # Zeroization
///
/// Every key lives in a [`DekSlot`]. Once an entry expires, is evicted for capacity, invalidated
/// or cleared, the cache revokes its slot, which zeroizes the key bytes in place whoever still
/// holds the slot. [`invalidate`](Self::invalidate) and [`clear`](Self::clear) revoke before
/// they return.
///
/// Expired entries are revoked by a reaper task, which the first call that inserts an entry
/// inside a tokio runtime spawns on that runtime, and which runs every quarter of the TTL until
/// the cache is dropped or the runtime shuts down: the bytes of a key are gone `ttl * 5 / 4`
/// after it was inserted at most. The runtime needs its time driver, as `#[tokio::main]` enables
/// it. Without a reaper, an expired entry is revoked when its key is looked up again, by the
/// maintenance the cache runs during its later calls, and by `invalidate` and `clear`.
///
/// # Defaults
///
/// [`DekCacheOptions::new`] gives a TTL of 15 minutes and 1024 entries per purpose. The per-call
/// envelope has no cache unless it is given one; the store-less envelope and the keyring use
/// `DekCache::new(DekCacheOptions::new())` unless they are given another.
#[derive(Clone)]
pub struct DekCache(Option<Arc<EnabledCache>>);

/// The maps and the reaper of an enabled cache.
struct EnabledCache {
    options: DekCacheOptions,
    randomized: SlotMap<DataEncryptionKey>,
    #[cfg(feature = "deterministic")]
    deterministic: SlotMap<DeterministicDataEncryptionKey>,
    reaper: Mutex<Option<JoinHandle<()>>>,
}

impl EnabledCache {
    /// Spawns the reaper on the caller's tokio runtime, once. Outside a runtime it spawns
    /// nothing, and a later call inside one spawns it.
    fn start_reaper(self: &Arc<Self>) {
        let mut reaper = self.reaper.lock().unwrap_or_else(PoisonError::into_inner);
        if reaper.is_some() {
            return;
        }
        if let Ok(runtime) = Handle::try_current() {
            let period = (self.options.ttl / 4).max(MIN_REAPER_PERIOD);
            *reaper = Some(runtime.spawn(Self::reap(Arc::downgrade(self), period)));
        }
    }

    /// Runs the maintenance of `cache` every `period` until the cache is dropped, so that the
    /// expired entries leave the maps and their slots are revoked with no lookup to trigger it.
    async fn reap(cache: Weak<Self>, period: Duration) {
        let mut ticks = tokio::time::interval(period);
        ticks.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            ticks.tick().await;
            let Some(cache) = cache.upgrade() else {
                return;
            };
            cache.run_pending_tasks().await;
        }
    }

    async fn run_pending_tasks(&self) {
        self.randomized.entries.run_pending_tasks().await;
        #[cfg(feature = "deterministic")]
        self.deterministic.entries.run_pending_tasks().await;
    }
}

impl Drop for EnabledCache {
    fn drop(&mut self) {
        let reaper = self
            .reaper
            .get_mut()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(reaper) = reaper.take() {
            reaper.abort();
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

/// The slots of one purpose.
struct SlotMap<K> {
    entries: Cache<CacheKey, Arc<DekSlot<K>>>,
}

impl<K> SlotMap<K>
where
    K: Send + Sync + 'static,
{
    fn new(options: &DekCacheOptions) -> Self {
        let entries = Cache::builder()
            .max_capacity(u64::try_from(options.max_entries.get()).unwrap_or(u64::MAX))
            .time_to_live(options.ttl)
            // LRU admits every new entry. TinyLFU, the default, can refuse a key just unwrapped
            // when the map is full, which would revoke the slot before its caller uses it.
            .eviction_policy(EvictionPolicy::lru())
            // moka drops a removed entry only when its own collection runs, which a quiet
            // process may never do, so every slot is revoked as it leaves the map, whatever the
            // cause: expiry, capacity, replacement or invalidation.
            .eviction_listener(|_, slot: Arc<DekSlot<K>>, _| slot.revoke())
            .build();
        Self { entries }
    }

    /// The live slot of `key`, unwrapped through `unwrap_key` on a miss. Concurrent misses
    /// share one call of `unwrap_key` and its result; a failed call leaves no entry.
    async fn get_or_unwrap<F, Fut>(
        &self,
        key: CacheKey,
        unwrap_key: F,
    ) -> KmsAeadResult<(Arc<DekSlot<K>>, DekCacheOutcome)>
    where
        F: Fn() -> Fut,
        Fut: Future<Output = KmsAeadResult<K>>,
    {
        for _ in 0..LOOKUP_ATTEMPTS {
            let mut unwrapped = false;
            let slot = self
                .entries
                .try_get_with(key.clone(), async {
                    unwrapped = true;
                    Ok::<_, KmsAeadError>(Arc::new(DekSlot::live(unwrap_key().await?)))
                })
                .await
                .map_err(Arc::unwrap_or_clone)?;
            if !slot.is_revoked() {
                let outcome = if unwrapped {
                    DekCacheOutcome::Miss
                } else {
                    DekCacheOutcome::Hit
                };
                return Ok((slot, outcome));
            }
            self.remove_revoked(&key, &slot).await;
        }
        Err(KmsAeadEncryptionError::dek_revoked())
    }

    /// Removes `revoked` from the map if the map still holds it under `key`, as it does between
    /// the revocations of [`clear`](Self::clear) and its invalidation. A slot that replaced it
    /// stays.
    async fn remove_revoked(&self, key: &CacheKey, revoked: &Arc<DekSlot<K>>) {
        self.entries
            .entry_by_ref(key)
            .and_compute_with(|entry| {
                std::future::ready(match entry {
                    Some(entry) if Arc::ptr_eq(entry.value(), revoked) => Op::Remove,
                    _ => Op::Nop,
                })
            })
            .await;
    }

    async fn invalidate(&self, key: &CacheKey) {
        if let Some(slot) = self.entries.remove(key).await {
            slot.revoke();
        }
        self.entries.run_pending_tasks().await;
    }

    /// Revokes the slots the map lists, then invalidates every entry; the maintenance that
    /// follows removes the expired entries the map no longer lists, and revokes their slots.
    async fn clear(&self) {
        for (_, slot) in self.entries.iter() {
            slot.revoke();
        }
        self.entries.invalidate_all();
        self.entries.run_pending_tasks().await;
    }
}

impl DekCache {
    /// A cache with `options`.
    ///
    /// # Errors
    ///
    /// `INVALID_DEK_CACHE_TTL` when the TTL is zero or longer than 1000 years.
    pub fn new(options: DekCacheOptions) -> KmsAeadResult<Self> {
        if options.ttl.is_zero() || options.ttl > MAX_TTL {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_CACHE_TTL",
                &format!(
                    "A DEK cache TTL of {:?} is not longer than zero and at most 1000 years",
                    options.ttl
                ),
            ));
        }
        Ok(Self(Some(Arc::new(EnabledCache {
            randomized: SlotMap::new(&options),
            #[cfg(feature = "deterministic")]
            deterministic: SlotMap::new(&options),
            reaper: Mutex::new(None),
            options,
        }))))
    }

    /// A cache that holds nothing: every [`unwrap`](Self::unwrap) calls the provider and returns
    /// a slot no cache holds, and [`invalidate`](Self::invalidate) and [`clear`](Self::clear) do
    /// nothing.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Whether the cache holds keys: `false` only for [`disabled`](Self::disabled).
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    /// The key `encrypted` wraps under `provider.kek()`, unwrapped by `provider` on a miss.
    ///
    /// The returned slot can be revoked at any time after this returns: the caller uses it for
    /// the operation at hand and does not keep it.
    ///
    /// # Errors
    ///
    /// The provider's error, which every concurrent caller for the same key receives.
    pub async fn unwrap<P>(
        &self,
        provider: &P,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<(Arc<DekSlot<DataEncryptionKey>>, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + ?Sized,
    {
        let unwrap_key = || provider.decrypt_data_encryption_key(encrypted);
        self.unwrap_into(
            |cache| &cache.randomized,
            provider.kek(),
            encrypted,
            unwrap_key,
        )
        .await
    }

    /// The deterministic key `encrypted` wraps under `provider.kek()`, unwrapped by `provider` on
    /// a miss, as [`unwrap`](Self::unwrap) does for randomized keys. The two purposes are cached
    /// apart, so the same wrapped key unwrapped for both is two entries.
    ///
    /// # Errors
    ///
    /// The provider's error, and `INVALID_KEY_LENGTH` when the unwrapped key does not fit
    /// `algorithm`, which every concurrent caller for the same key receives.
    #[cfg(feature = "deterministic")]
    pub async fn unwrap_deterministic<P>(
        &self,
        provider: &P,
        algorithm: DeterministicAlgorithm,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<(
        Arc<DekSlot<DeterministicDataEncryptionKey>>,
        DekCacheOutcome,
    )>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + ?Sized,
    {
        let unwrap_key = || async {
            let key = provider.decrypt_data_encryption_key(encrypted).await?;
            checked_deterministic_key(key, algorithm)
        };
        self.unwrap_into(
            |cache| &cache.deterministic,
            provider.kek(),
            encrypted,
            unwrap_key,
        )
        .await
    }

    /// Removes the entries of both purposes for `encrypted` under `kek` and revokes their slots
    /// before it returns. The next unwrap of the key calls the provider.
    pub async fn invalidate(&self, kek: &KekRef, encrypted: &EncryptedDataEncryptionKey) {
        if let Some(cache) = &self.0 {
            let key = CacheKey::new(kek.clone(), encrypted);
            cache.randomized.invalidate(&key).await;
            #[cfg(feature = "deterministic")]
            cache.deterministic.invalidate(&key).await;
        }
    }

    /// Removes every entry and revokes every slot before it returns.
    pub async fn clear(&self) {
        if let Some(cache) = &self.0 {
            cache.randomized.clear().await;
            #[cfg(feature = "deterministic")]
            cache.deterministic.clear().await;
        }
    }

    /// The slot of the key `encrypted` wraps under `kek`, from `map` of an enabled cache, and
    /// from `unwrap_key` on a miss or when the cache is disabled. A miss starts the reaper.
    async fn unwrap_into<K, F, Fut>(
        &self,
        map: fn(&EnabledCache) -> &SlotMap<K>,
        kek: KekRef,
        encrypted: &EncryptedDataEncryptionKey,
        unwrap_key: F,
    ) -> KmsAeadResult<(Arc<DekSlot<K>>, DekCacheOutcome)>
    where
        K: Send + Sync + 'static,
        F: Fn() -> Fut,
        Fut: Future<Output = KmsAeadResult<K>>,
    {
        let Some(cache) = &self.0 else {
            let slot = Arc::new(DekSlot::live(unwrap_key().await?));
            return Ok((slot, DekCacheOutcome::Disabled));
        };
        let found = map(cache)
            .get_or_unwrap(CacheKey::new(kek, encrypted), unwrap_key)
            .await?;
        if found.1 == DekCacheOutcome::Miss {
            cache.start_reaper();
        }
        Ok(found)
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

/// One plaintext data encryption key, held by a [`DekCache`] or by a store-less envelope for the
/// key it encrypts under.
///
/// The cache revokes a slot when its entry leaves the cache: the slot drops its key, whose
/// buffer is zeroized in place as it is freed, whoever holds the slot, and every later use fails
/// with `DEK_REVOKED`. A use already under way when the revocation comes finishes first: a use
/// holds the key for one synchronous seal or open, never across an `.await`.
pub struct DekSlot<K> {
    state: RwLock<SlotState<K>>,
}

enum SlotState<K> {
    Live(K),
    Revoked,
}

impl DekSlot<DataEncryptionKey> {
    /// Seals `plain_text` under the slot's key, as [`AeadCipher`] does.
    ///
    /// # Errors
    ///
    /// `DEK_REVOKED` when the slot was revoked, and the errors of
    /// [`AeadEncryption::encrypt_value`](crate::AeadEncryption::encrypt_value).
    pub fn encrypt_value(
        &self,
        cipher: &AeadCipher,
        aad: &[u8],
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherText> {
        self.with_key(|key| cipher.seal(aad, plain_text, key))
    }

    /// Opens `cipher_text` under the slot's key, as [`AeadCipher`] does.
    ///
    /// # Errors
    ///
    /// `DEK_REVOKED` when the slot was revoked, and the errors of
    /// [`AeadEncryption::decrypt_value`](crate::AeadEncryption::decrypt_value).
    pub fn decrypt_value(
        &self,
        cipher: &AeadCipher,
        aad: &[u8],
        cipher_text: &CipherText,
    ) -> KmsAeadResult<SecretValue> {
        self.with_key(|key| cipher.open(aad, cipher_text, key))
    }
}

#[cfg(feature = "deterministic")]
impl DekSlot<DeterministicDataEncryptionKey> {
    /// Seals `plain_text` under the slot's key, as [`DeterministicCipher::encrypt_value`] does.
    ///
    /// # Errors
    ///
    /// `DEK_REVOKED` when the slot was revoked, and the errors of
    /// [`DeterministicCipher::encrypt_value`].
    pub fn encrypt_value(
        &self,
        cipher: &DeterministicCipher,
        aad: &[u8],
        plain_text: &SecretValue,
    ) -> KmsAeadResult<DeterministicCipherText> {
        self.with_key(|key| cipher.encrypt_value(aad, plain_text, key))
    }

    /// Opens `cipher_text` under the slot's key, as [`DeterministicCipher::decrypt_value`] does.
    ///
    /// # Errors
    ///
    /// `DEK_REVOKED` when the slot was revoked, and the errors of
    /// [`DeterministicCipher::decrypt_value`].
    pub fn decrypt_value(
        &self,
        cipher: &DeterministicCipher,
        aad: &[u8],
        cipher_text: &DeterministicCipherText,
    ) -> KmsAeadResult<SecretValue> {
        self.with_key(|key| cipher.decrypt_value(aad, cipher_text, key))
    }
}

impl<K> DekSlot<K> {
    /// Runs `use_key` under the slot's read guard, so that a revocation waits for it.
    fn with_key<T>(&self, use_key: impl FnOnce(&K) -> KmsAeadResult<T>) -> KmsAeadResult<T> {
        match &*self.state.read().unwrap_or_else(PoisonError::into_inner) {
            SlotState::Live(key) => use_key(key),
            SlotState::Revoked => Err(KmsAeadEncryptionError::dek_revoked()),
        }
    }
}

/// The life cycle of a slot, which only kms-aead drives: a slot is made live with a key and
/// revoked once.
pub(crate) trait SlotLifecycle<K> {
    fn live(key: K) -> Self;

    /// Drops the key, after any use under way, which zeroizes its bytes. Revoking twice is
    /// revoking once.
    fn revoke(&self);

    fn is_revoked(&self) -> bool;
}

impl<K> SlotLifecycle<K> for DekSlot<K> {
    fn live(key: K) -> Self {
        Self {
            state: RwLock::new(SlotState::Live(key)),
        }
    }

    fn revoke(&self) {
        *self.state.write().unwrap_or_else(PoisonError::into_inner) = SlotState::Revoked;
    }

    fn is_revoked(&self) -> bool {
        matches!(
            *self.state.read().unwrap_or_else(PoisonError::into_inner),
            SlotState::Revoked
        )
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::errors::KmsAeadError;
    use crate::test_provider::{CountingKmsProvider, TestKmsProvider};
    #[cfg(feature = "deterministic")]
    use crate::DeterministicAlgorithm;
    #[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
    use crate::{test_provider::TEST_BACKEND, AeadAlgorithm};

    const ORDERS_KEK: &str = "orders";
    const BILLING_KEK: &str = "billing";
    /// The test provider's wrapped key is the key itself, and 64 bytes fit both purposes.
    const ORDERS_DEK: [u8; 64] = [0x42; 64];
    const SHORT_TTL: Duration = Duration::from_millis(200);
    /// How long a test waits for the reaper, far past `SHORT_TTL` plus its period.
    const REAPER_DEADLINE: Duration = Duration::from_secs(5);
    const CONCURRENT_CALLS: usize = 16;

    /// The key bytes a slot holds, read through its lock. A revoked slot holds none: it dropped
    /// its key, whose `SecretValue` zeroized the buffer as it was freed.
    fn slot_bytes(slot: &DekSlot<DataEncryptionKey>) -> Option<Vec<u8>> {
        match &*slot.state.read().unwrap() {
            SlotState::Live(key) => Some(key.value().ref_sensitive_value().clone()),
            SlotState::Revoked => None,
        }
    }

    /// Lets every spawned task of a current-thread runtime run until it waits on something.
    async fn let_spawned_tasks_wait() {
        for _ in 0..CONCURRENT_CALLS * 4 {
            tokio::task::yield_now().await;
        }
    }

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
                tokio::spawn(async move { cache.unwrap(&*provider, &encrypted).await })
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(provider.unwraps(), 1);
        provider.open_gate();

        let mut slots = Vec::new();
        let mut misses = 0;
        for lookup in lookups {
            let (slot, outcome) = lookup.await.unwrap()?;
            misses += usize::from(outcome == DekCacheOutcome::Miss);
            slots.push(slot);
        }
        assert_eq!(misses, 1);
        assert!(slots.iter().all(|slot| Arc::ptr_eq(slot, &slots[0])));
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
                tokio::spawn(async move { cache.unwrap(&*provider, &encrypted).await })
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

        let failed = cache.unwrap(&failing, &encrypted).await;
        let (_, first) = cache.unwrap(&working, &encrypted).await?;
        let (_, second) = cache.unwrap(&working, &encrypted).await?;

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

        let (_, first) = cache.unwrap(&provider, &encrypted).await?;
        let (_, second) = cache.unwrap(&provider, &encrypted).await?;
        tokio::time::sleep(SHORT_TTL * 2).await;
        let (_, third) = cache.unwrap(&provider, &encrypted).await?;

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
            randomized.push(cache.unwrap(&provider, &encrypted).await?.0);
        }
        cache.0.as_ref().unwrap().run_pending_tasks().await;

        let revoked: Vec<_> = randomized.iter().map(|slot| slot.is_revoked()).collect();
        assert_eq!(revoked, [true, false, false]);

        #[cfg(feature = "deterministic")]
        {
            let mut deterministic = Vec::new();
            for byte in 4..=5 {
                let encrypted = EncryptedDataEncryptionKey::new(vec![byte; 64], None);
                let algorithm = DeterministicAlgorithm::Aes256Siv;
                let (slot, _) = cache
                    .unwrap_deterministic(&provider, algorithm, &encrypted)
                    .await?;
                deterministic.push(slot);
            }
            cache.0.as_ref().unwrap().run_pending_tasks().await;

            assert!(!randomized[1].is_revoked() && !randomized[2].is_revoked());
            assert!(deterministic.iter().all(|slot| !slot.is_revoked()));
        }
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_forces_the_next_unwrap() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let (_, first) = cache.unwrap(&provider, &encrypted).await?;
        let (_, second) = cache.unwrap(&provider, &encrypted).await?;
        cache.invalidate(&provider.kek(), &encrypted).await;
        let (_, third) = cache.unwrap(&provider, &encrypted).await?;

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

        let (randomized, _) = cache.unwrap(&provider, &encrypted).await?;
        let (deterministic, _) = cache
            .unwrap_deterministic(&provider, algorithm, &encrypted)
            .await?;
        cache.invalidate(&provider.kek(), &encrypted).await;
        let (_, outcome) = cache
            .unwrap_deterministic(&provider, algorithm, &encrypted)
            .await?;

        assert!(randomized.is_revoked() && deterministic.is_revoked());
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

        let (_, randomized) = cache.unwrap(&provider, &encrypted).await?;
        let (_, deterministic) = cache
            .unwrap_deterministic(&provider, algorithm, &encrypted)
            .await?;
        let (_, again) = cache
            .unwrap_deterministic(&provider, algorithm, &encrypted)
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

        let (orders_slot, first) = cache.unwrap(&orders, &encrypted).await?;
        let (_, second) = cache.unwrap(&orders, &encrypted).await?;
        let (billing_slot, other_kek) = cache.unwrap(&billing, &encrypted).await?;

        assert_eq!(
            [first, second, other_kek],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(billing.unwraps(), 1);
        assert!(!Arc::ptr_eq(&orders_slot, &billing_slot));
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_zeroizes_the_dek_bytes() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let (slot, _) = cache.unwrap(&provider, &encrypted).await?;
        assert_eq!(slot_bytes(&slot), Some(ORDERS_DEK.to_vec()));
        cache.invalidate(&provider.kek(), &encrypted).await;

        assert_eq!(slot_bytes(&slot), None);
        Ok(())
    }

    #[tokio::test]
    async fn clear_zeroizes_every_slot() -> KmsAeadResult<()> {
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let encrypted: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new(vec![byte; 64], None))
            .collect();

        let mut slots = Vec::new();
        for encrypted in &encrypted {
            slots.push(cache.unwrap(&provider, encrypted).await?.0);
        }
        #[cfg(feature = "deterministic")]
        let (deterministic, _) = cache
            .unwrap_deterministic(&provider, DeterministicAlgorithm::Aes256Siv, &encrypted[0])
            .await?;
        cache.clear().await;

        for slot in &slots {
            assert_eq!(slot_bytes(slot), None);
        }
        #[cfg(feature = "deterministic")]
        assert!(deterministic.is_revoked());
        Ok(())
    }

    /// Without a runtime, so that no reaper revokes the expired entry before `clear` does.
    #[test]
    fn clear_zeroizes_an_expired_slot() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        futures::executor::block_on(async {
            let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
            let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

            let (expired, _) = cache.unwrap(&provider, &encrypted).await?;
            std::thread::sleep(SHORT_TTL * 2);
            cache.clear().await;

            assert_eq!(slot_bytes(&expired), None);
            Ok(())
        })
    }

    #[tokio::test]
    async fn an_expired_slot_is_zeroized_without_traffic() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let (slot, _) = cache.unwrap(&provider, &encrypted).await?;
        let deadline = Instant::now() + REAPER_DEADLINE;
        while !slot.is_revoked() && Instant::now() < deadline {
            tokio::time::sleep(SHORT_TTL / 10).await;
        }

        assert_eq!(slot_bytes(&slot), None);
        Ok(())
    }

    #[test]
    fn without_a_runtime_an_expired_slot_is_zeroized_on_access() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        assert!(tokio::runtime::Handle::try_current().is_err());
        futures::executor::block_on(async {
            let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
            let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

            let (expired, _) = cache.unwrap(&provider, &encrypted).await?;
            std::thread::sleep(SHORT_TTL * 2);
            assert_eq!(slot_bytes(&expired), Some(ORDERS_DEK.to_vec()));
            let (renewed, outcome) = cache.unwrap(&provider, &encrypted).await?;

            assert_eq!(outcome, DekCacheOutcome::Miss);
            assert_eq!(slot_bytes(&expired), None);
            assert_eq!(slot_bytes(&renewed), Some(ORDERS_DEK.to_vec()));
            Ok(())
        })
    }

    #[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
    #[test]
    fn an_in_flight_use_finishes_or_fails_closed_on_revoke() -> KmsAeadResult<()> {
        const AAD: &[u8] = b"orders/1042";
        const SEALING_THREADS: usize = 4;
        const SEALS_PER_THREAD: usize = 64;

        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK[..32].to_vec(), None);
        let cipher = AeadCipher::new(TEST_BACKEND, AeadAlgorithm::Aes256Gcm)?;
        let plain_text = SecretValue::new(vec![0x5A; 1 << 20]);
        let (slot, _) = futures::executor::block_on(cache.unwrap(&provider, &encrypted))?;

        let sealed: Vec<_> = std::thread::scope(|scope| {
            let sealers: Vec<_> = (0..SEALING_THREADS)
                .map(|_| {
                    scope.spawn(|| {
                        (0..SEALS_PER_THREAD)
                            .map(|_| slot.encrypt_value(&cipher, AAD, &plain_text))
                            .collect::<Vec<_>>()
                    })
                })
                .collect();
            std::thread::sleep(Duration::from_millis(5));
            futures::executor::block_on(cache.invalidate(&provider.kek(), &encrypted));
            sealers
                .into_iter()
                .flat_map(|sealer| sealer.join().unwrap())
                .collect()
        });
        let after = slot.encrypt_value(&cipher, AAD, &plain_text);

        let key = DataEncryptionKey::from(SecretValue::new(ORDERS_DEK[..32].to_vec()));
        for result in sealed {
            match result {
                Ok(cipher_text) => assert_eq!(cipher.open(AAD, &cipher_text, &key)?, plain_text),
                Err(error) => assert!(
                    matches!(&error, KmsAeadError::EncryptionError(error)
                        if error.public.code == "DEK_REVOKED"),
                    "{error:?}"
                ),
            }
        }
        assert!(
            matches!(&after, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "DEK_REVOKED"),
            "{:?}",
            after.as_ref().err()
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_revoked_slot_is_never_returned() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let (listed, _) = cache.unwrap(&provider, &encrypted).await?;
        // Revoked and still listed, as between the revocations of `clear` and its invalidation.
        listed.revoke();
        let (returned, outcome) = cache.unwrap(&provider, &encrypted).await?;
        let (_, again) = cache.unwrap(&provider, &encrypted).await?;

        assert!(!returned.is_revoked());
        assert_eq!(
            [outcome, again],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(provider.unwraps(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cache_unwraps_every_time() -> KmsAeadResult<()> {
        let encrypted = EncryptedDataEncryptionKey::new(ORDERS_DEK.to_vec(), None);
        let cache = DekCache::disabled();
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let (first_slot, first) = cache.unwrap(&provider, &encrypted).await?;
        let (second_slot, second) = cache.unwrap(&provider, &encrypted).await?;
        cache.invalidate(&provider.kek(), &encrypted).await;
        cache.clear().await;

        assert!(!cache.is_enabled());
        assert_eq!(
            [first, second],
            [DekCacheOutcome::Disabled, DekCacheOutcome::Disabled]
        );
        assert_eq!(provider.unwraps(), 2);
        assert!(!Arc::ptr_eq(&first_slot, &second_slot));
        assert_eq!(slot_bytes(&first_slot), Some(ORDERS_DEK.to_vec()));
        Ok(())
    }

    #[test]
    fn a_ttl_out_of_range_is_refused() {
        for ttl in [Duration::ZERO, Duration::MAX] {
            let result = DekCache::new(DekCacheOptions::new().with_ttl(ttl));

            assert!(
                matches!(&result, Err(KmsAeadError::SystemError(error))
                    if error.public.code == "INVALID_DEK_CACHE_TTL"),
                "{ttl:?}: {result:?}"
            );
        }
    }
}
