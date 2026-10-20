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

/// Where the key of a [`DekCache::with_dek`] call came from. Its `Display` is the value of the
/// `dek_cache` span field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DekCacheOutcome {
    /// From the cache, or from a concurrent call that decrypted the same key.
    Hit,
    /// Decrypted by the provider for this call. It is cached unless a live entry of another KEK
    /// holds the same encrypted bytes.
    Miss,
    /// Decrypted by the provider for this call: the cache is disabled.
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

/// The one cache of plaintext data encryption keys (DEKs) decrypted by a KMS, shared by the
/// store-less envelope and the keyring. `Clone` shares the same cache.
///
/// An entry holds the key a provider decrypted from an encrypted DEK's bytes, with the provider's
/// [`KekRef`], and serves only a lookup that names the same KEK. A cache shared by the providers
/// of several KEKs therefore never returns a key decrypted under one KEK to a caller that passed
/// the provider of another: that caller's provider asks its KMS, which refuses a key encrypted
/// under a foreign KEK. Such a call leaves the live entry as it is and caches nothing. The key
/// version an encrypted DEK records is not part of the match.
///
/// [`KekRef`] equality is therefore the cache's trust boundary. A local provider's `KekRef` is
/// [`KekProvider::Local`](crate::KekProvider::Local) and its id, so a local KEK id must name one
/// set of KEK material: two [`LocalKmsProvider`](crate::providers::LocalKmsProvider)s with one
/// id share their entries.
///
/// Keys of randomised and deterministic algorithms share the entries: the same encrypted bytes
/// decrypt to the same key whatever the caller seals with it. An entry holds the key a serialised
/// Tink key carries, and the cipher a key is used with checks its length.
///
/// - A key reaches a caller only inside the closure of [`with_dek`](Self::with_dek), and stays
///   intact until the closure returns, whatever leaves the cache meanwhile.
/// - Concurrent misses for one key make one provider call, and every caller receives its result:
///   the key, or the error. When the caller making the call is cancelled, one of the callers
///   waiting on it makes the call instead.
/// - A failed decryption leaves no entry, so that under a KMS outage every call fails as fast as
///   the KMS does.
/// - An entry is inserted by the miss that decrypts its key, before the decryption, and serves
///   lookups for [`ttl`](DekCacheOptions::ttl) after that, however often it is used. A decryption
///   under way counts against [`max_entries`](DekCacheOptions::max_entries).
/// - A hit allocates nothing. A miss copies the table of entries, whose size
///   [`max_entries`](DekCacheOptions::max_entries) bounds.
///
/// # Key lifetime
///
/// A key is dropped, which zeroises its bytes, when its entry leaves the cache: once the entry
/// is evicted for capacity, invalidated, cleared or purged after it expired. A `with_dek` call
/// that looked the key up before its entry left keeps it until its closure returns, and a call
/// waiting on a decryption that started before an [`invalidate`](Self::invalidate) or a
/// [`clear`](Self::clear) receives that decryption's key, which is not cached.
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
/// encrypted DEK alone, which a lookup borrows.
#[derive(Default)]
struct Snapshot {
    slots: HashMap<EncryptedDataEncryptionKey, Arc<Slot>>,
    /// The slot created first: every slot lives for the same TTL, so it is the next to expire,
    /// and the one evicted when the table is full.
    oldest: Option<Arc<Slot>>,
}

/// An entry: the key, or the decryption under way that the concurrent misses of the key share, and
/// the KEK that decryption names.
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

    /// Runs `use_dek` with the key cached for `encrypted_dek` under `kek`, or with the key
    /// `decrypt_dek` returns on a miss, which stays cached unless its slot left the table
    /// meanwhile. A live slot for `encrypted_dek` under another KEK is neither used nor replaced:
    /// the call decrypts without caching.
    async fn with_dek<T, Fut>(
        &self,
        kek: &KekRef,
        encrypted_dek: &EncryptedDataEncryptionKey,
        decrypt_dek: impl FnOnce() -> Fut,
        use_dek: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        Fut: Future<Output = KmsAeadResult<DataEncryptionKey>>,
    {
        let now = Instant::now();
        self.purge_expired(now);
        let (ttl, max_entries) = (self.options.ttl, self.options.max_entries);
        let cached = self
            .snapshot()
            .live(encrypted_dek, ttl, now)
            .map(Arc::clone);
        let slot = cached.unwrap_or_else(|| {
            let created = Arc::new(Slot {
                kek: kek.clone(),
                dek: OnceCell::new(),
                created_at: now,
            });
            // Of concurrent misses, the slot published first wins, and they all wait on it.
            let mut slot = Arc::clone(&created);
            self.publish(|snapshot| match snapshot.live(encrypted_dek, ttl, now) {
                Some(published) => {
                    slot = Arc::clone(published);
                    None
                }
                None => Some(snapshot.with(encrypted_dek.clone(), created, max_entries)),
            });
            slot
        });
        if !slot.serves(kek) {
            drop(slot);
            return Ok((use_dek(&decrypt_dek().await?), DekCacheOutcome::Miss));
        }

        let mut decrypted_here = false;
        let decrypted = slot
            .dek
            .get_or_init(|| {
                decrypted_here = true;
                async move { decrypt_dek().await.map(Arc::new) }
            })
            .await
            .clone();
        let outcome = if decrypted_here {
            DekCacheOutcome::Miss
        } else {
            DekCacheOutcome::Hit
        };
        match decrypted {
            Ok(dek) => Ok((use_dek(&dek), outcome)),
            Err(error) => {
                // The caller that made the failed decryption removes its slot, unless the slot has
                // already left the table, so that no failure is served from the cache.
                if decrypted_here {
                    self.publish(|snapshot| {
                        let failed = snapshot.slots.get(encrypted_dek);
                        let failed = failed.filter(|failed| Arc::ptr_eq(failed, &slot));
                        failed.and_then(|_| snapshot.without(encrypted_dek))
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

    /// Runs `use_dek` with the key cached for `encrypted_dek` under `kek`, or returns `None`,
    /// without calling a provider, when the cache holds no such key.
    pub(crate) fn with_cached_dek<T>(
        &self,
        kek: &KekRef,
        encrypted_dek: &EncryptedDataEncryptionKey,
        use_dek: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> Option<T> {
        let now = Instant::now();
        self.purge_expired(now);
        let snapshot = self.snapshot();
        let slot = snapshot
            .live(encrypted_dek, self.options.ttl, now)
            .filter(|slot| slot.serves(kek))?;
        let dek = slot.dek.get()?.as_ref().ok()?;
        Some(use_dek(dek))
    }

    /// Caches `dek`, which `kek` has just encrypted into `encrypted_dek`, as a decryption of
    /// `encrypted_dek` would have, so that the first lookup of a new store-less DEK is a hit. Kept
    /// off the public API: a key cached under the wrong encrypted bytes would seal values that no
    /// decryption opens. A live entry of another KEK for the same bytes is kept.
    pub(crate) fn insert(
        &self,
        kek: &KekRef,
        encrypted_dek: &EncryptedDataEncryptionKey,
        dek: DataEncryptionKey,
    ) {
        let now = Instant::now();
        self.purge_expired(now);
        let (ttl, max_entries) = (self.options.ttl, self.options.max_entries);
        let slot = Arc::new(Slot {
            kek: kek.clone(),
            dek: OnceCell::from(Ok(Arc::new(dek))),
            created_at: now,
        });
        self.publish(|snapshot| match snapshot.live(encrypted_dek, ttl, now) {
            Some(live) if !live.serves(kek) => None,
            _ => Some(snapshot.with(encrypted_dek.clone(), slot, max_entries)),
        });
    }
}

impl Snapshot {
    fn live(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
        ttl: Duration,
        now: Instant,
    ) -> Option<&Arc<Slot>> {
        self.slots
            .get(encrypted_dek)
            .filter(|slot| !slot.is_expired(ttl, now))
    }

    fn has_expired(&self, ttl: Duration, now: Instant) -> bool {
        self.oldest
            .as_ref()
            .is_some_and(|oldest| oldest.is_expired(ttl, now))
    }

    /// This snapshot with `slot` for `encrypted_dek`, which evicts the oldest slot of a snapshot
    /// that already holds `max_entries`.
    fn with(
        &self,
        encrypted_dek: EncryptedDataEncryptionKey,
        slot: Arc<Slot>,
        max_entries: NonZeroUsize,
    ) -> Self {
        let mut slots = self.slots.clone();
        slots.remove(&encrypted_dek);
        if let Some(oldest) = self.oldest.as_ref() {
            if slots.len() >= max_entries.get() {
                slots.retain(|_, cached| !Arc::ptr_eq(cached, oldest));
            }
        }
        slots.insert(encrypted_dek, slot);
        slots.into()
    }

    /// This snapshot without the slot of `encrypted_dek`, or `None` when it holds none.
    fn without(&self, encrypted_dek: &EncryptedDataEncryptionKey) -> Option<Self> {
        self.slots.contains_key(encrypted_dek).then(|| {
            let mut slots = self.slots.clone();
            slots.remove(encrypted_dek);
            slots.into()
        })
    }

    /// This snapshot without the slot of `encrypted_dek` under `kek`, or `None` when it holds none.
    fn without_entry(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
        kek: &KekRef,
    ) -> Option<Self> {
        self.slots
            .get(encrypted_dek)
            .filter(|slot| slot.serves(kek))
            .and_then(|_| self.without(encrypted_dek))
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

    /// Whether this slot holds the decryption of a call that names `kek`, the only call it serves.
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

    /// A cache that holds nothing: every [`with_dek`](Self::with_dek) calls the provider, and
    /// [`invalidate`](Self::invalidate), [`clear`](Self::clear) and
    /// [`purge_expired`](Self::purge_expired) do nothing.
    pub fn disabled() -> Self {
        Self(None)
    }

    /// Whether the cache holds keys: `false` only for [`disabled`](Self::disabled).
    pub fn is_enabled(&self) -> bool {
        self.0.is_some()
    }

    /// Runs `use_dek` with the key that `encrypted_dek` holds under `provider.kek()`, decrypted by
    /// `provider` on a miss, and returns its result with where the key came from.
    ///
    /// `use_dek` runs once, synchronously, after the lookup, and the key stays intact while it
    /// runs. It must not keep the key: a copy taken out of the closure outlives the cache's
    /// control of its lifetime.
    ///
    /// # Errors
    ///
    /// The provider's error, `INVALID_KEY_FORMAT` when the decrypted key is not a serialised Tink
    /// key, and without the `legacy-formats` feature
    /// [`KmsAeadError::LegacyFormat`](crate::errors::KmsAeadError::LegacyFormat) for a key
    /// encrypted by 0.29 or earlier. Every caller waiting on the same decryption receives the
    /// error, and nothing is cached. The errors of `use_dek` come back in its own return value.
    pub async fn with_dek<P, T>(
        &self,
        provider: &P,
        encrypted_dek: &EncryptedDataEncryptionKey,
        use_dek: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KmsAeadResult<(T, DekCacheOutcome)>
    where
        P: KmsAeadEncryptionProvider,
    {
        // An encrypted value of the same KEK that is no data encryption key, such as an exported
        // keyset, decrypts too, and the decoding of the decrypted key keeps it out.
        let decrypt_dek = || async {
            crate::formats::decrypt_dek(encrypted_dek, provider)
                .await
                .map(|(dek, _)| dek)
        };
        match &self.0 {
            Some(enabled) => {
                enabled
                    .with_dek(provider.kek(), encrypted_dek, decrypt_dek, use_dek)
                    .await
            }
            None => Ok((use_dek(&decrypt_dek().await?), DekCacheOutcome::Disabled)),
        }
    }

    /// Drops the entry for `encrypted_dek` under `kek`; an entry of the same encrypted bytes under
    /// another KEK stays. The next [`with_dek`](Self::with_dek) of the key calls the provider,
    /// and a decryption of it under way returns its key to its callers without caching it.
    pub fn invalidate(&self, kek: &KekRef, encrypted_dek: &EncryptedDataEncryptionKey) {
        if let Some(enabled) = &self.0 {
            enabled.purge_expired(Instant::now());
            enabled.publish(|snapshot| snapshot.without_entry(encrypted_dek, kek));
        }
    }

    /// Drops the expired entries, which zeroises their keys once no [`with_dek`](Self::with_dek)
    /// call holds them. Every call on the cache does this first. An application whose process can
    /// sit idle while the cache holds keys calls it from a timer of its own, on whatever runtime
    /// it uses, to drop them at the TTL; see "Key lifetime" on [`DekCache`].
    pub fn purge_expired(&self) {
        if let Some(enabled) = &self.0 {
            enabled.purge_expired(Instant::now());
        }
    }

    /// Drops every entry. The decryptions under way return their keys to their callers without
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
    /// The key cached for `encrypted_dek` under `kek`, as a `Weak` that stops upgrading once the
    /// key is dropped, and its bytes with it zeroised.
    pub(crate) fn cached_dek(
        &self,
        kek: &KekRef,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> Option<Weak<DataEncryptionKey>> {
        let snapshot = self.0.as_ref()?.snapshot();
        let slot = snapshot
            .slots
            .get(encrypted_dek)
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
    use crate::providers::{LocalKekId, LocalKmsProvider};
    use crate::test_provider::{
        encrypted_by_test_provider, let_spawned_tasks_wait, CountingKmsProvider, TestBackend,
        TestKmsProvider, CONCURRENT_CALLS,
    };
    use crate::{AeadAlgorithm, AeadCipher};

    const ORDERS_KEK: &str = "orders";
    const BILLING_KEK: &str = "billing";
    const ORDERS_DEK: [u8; 32] = [0x42; 32];
    const BILLING_DEK: [u8; 32] = [0x24; 32];
    const ORDERS_DETERMINISTIC_DEK: [u8; 64] = [0x42; 64];
    const SHORT_TTL: Duration = Duration::from_millis(200);

    #[tokio::test]
    async fn n_concurrent_misses_make_one_decryption() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::Working,
            ORDERS_KEK,
        ));

        let lookups: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let (cache, provider, encrypted_dek) =
                    (cache.clone(), Arc::clone(&provider), encrypted_dek.clone());
                tokio::spawn(
                    async move { cache.with_dek(&*provider, &encrypted_dek, |_| ()).await },
                )
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(provider.decryptions(), 1);
        provider.open_gate();

        let mut misses = 0;
        for lookup in lookups {
            let ((), outcome) = lookup.await.unwrap()?;
            misses += usize::from(outcome == DekCacheOutcome::Miss);
        }
        assert_eq!(misses, 1);
        assert_eq!(provider.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn waiters_share_the_leaders_error() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::FailingToDecrypt,
            ORDERS_KEK,
        ));

        let lookups: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let (cache, provider, encrypted_dek) =
                    (cache.clone(), Arc::clone(&provider), encrypted_dek.clone());
                tokio::spawn(
                    async move { cache.with_dek(&*provider, &encrypted_dek, |_| ()).await },
                )
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(provider.decryptions(), 1);
        provider.open_gate();

        for lookup in lookups {
            let result = lookup.await.unwrap();
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "TEST_DECRYPT"),
                "{:?}",
                result.as_ref().err()
            );
        }
        assert_eq!(provider.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_failed_decryption_is_not_cached() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let failing = CountingKmsProvider::new(TestKmsProvider::FailingToDecrypt, ORDERS_KEK);
        let working = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let failed = cache.with_dek(&failing, &encrypted_dek, |_| ()).await;
        let ((), first) = cache.with_dek(&working, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&working, &encrypted_dek, |_| ()).await?;

        assert!(
            matches!(&failed, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "TEST_DECRYPT"),
            "{:?}",
            failed.as_ref().err()
        );
        assert_eq!(
            [first, second],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(working.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_decrypted_key_that_is_no_tink_key_is_refused_and_not_cached() -> KmsAeadResult<()> {
        let encrypted_dek = EncryptedDataEncryptionKey::new(vec![0x42; 100]);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        for _ in 0..2 {
            let result = cache.with_dek(&provider, &encrypted_dek, |_| ()).await;
            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_KEY_FORMAT"),
                "{:?}",
                result.as_ref().err()
            );
        }

        assert_eq!(provider.decryptions(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn an_encrypted_dek_read_back_without_its_kek_version_hits_the_same_entry(
    ) -> KmsAeadResult<()> {
        let provider = LocalKmsProvider::<TestBackend>::ephemeral(LocalKekId::try_from(
            ORDERS_KEK.to_string(),
        )?)?;
        let cache = DekCache::new(DekCacheOptions::new())?;
        let (_, encrypted_dek) = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?
            .generate_encrypted_dek(&provider)
            .await?;
        let read_back = EncryptedDataEncryptionKey::from(encrypted_dek.value().to_vec());
        assert_ne!(encrypted_dek.kek_version(), read_back.kek_version());

        let ((), fresh) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let ((), stored) = cache.with_dek(&provider, &read_back, |_| ()).await?;

        assert_eq!(
            [fresh, stored],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_deterministic_key_is_cached() -> KmsAeadResult<()> {
        let encrypted_dek =
            encrypted_by_test_provider(TinkKeyType::AesSiv, &ORDERS_DETERMINISTIC_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;

        assert_eq!(
            [first, second],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(provider.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn an_entry_expires_after_ttl() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        tokio::time::sleep(SHORT_TTL * 2).await;
        let ((), third) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;

        assert_eq!(
            [first, second, third],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(provider.decryptions(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn capacity_evicts_the_oldest_entry() -> KmsAeadResult<()> {
        let max_entries = NonZeroUsize::new(2).unwrap();
        let cache = DekCache::new(DekCacheOptions::new().with_max_entries(max_entries))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let mut cached = Vec::new();
        for byte in 1..=3 {
            let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &[byte; 32]);
            cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
            cached.push(cache.cached_dek(provider.kek(), &encrypted_dek).unwrap());
        }

        let live: Vec<_> = cached.iter().map(|dek| dek.strong_count() > 0).collect();
        assert_eq!(live, [false, true, true]);

        Ok(())
    }

    #[tokio::test]
    async fn invalidate_forces_the_next_decryption() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let cached = cache.cached_dek(provider.kek(), &encrypted_dek).unwrap();
        cache.invalidate(provider.kek(), &encrypted_dek);
        let zeroized = cached.strong_count() == 0;
        let ((), third) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;

        assert!(zeroized);
        assert_eq!(
            [first, second, third],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss
            ]
        );
        assert_eq!(provider.decryptions(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn cache_is_namespaced_by_kek() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let orders = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let billing = CountingKmsProvider::new(TestKmsProvider::Working, BILLING_KEK);

        let ((), first) = cache.with_dek(&orders, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&orders, &encrypted_dek, |_| ()).await?;
        let ((), other_kek) = cache.with_dek(&billing, &encrypted_dek, |_| ()).await?;
        let ((), kept) = cache.with_dek(&orders, &encrypted_dek, |_| ()).await?;

        assert_eq!(
            [first, second, other_kek, kept],
            [
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit,
                DekCacheOutcome::Miss,
                DekCacheOutcome::Hit
            ]
        );
        assert_eq!(billing.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn clear_zeroizes_every_key() -> KmsAeadResult<()> {
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let encrypted_deks: Vec<_> = (1..=3)
            .map(|byte| encrypted_by_test_provider(TinkKeyType::AesGcm, &[byte; 32]))
            .collect();

        let mut cached = Vec::new();
        for encrypted_dek in &encrypted_deks {
            cache.with_dek(&provider, encrypted_dek, |_| ()).await?;
            cached.push(cache.cached_dek(provider.kek(), encrypted_dek).unwrap());
        }
        cache.clear();

        assert!(cached.iter().all(|dek| dek.strong_count() == 0));
        Ok(())
    }

    #[test]
    fn purge_expired_zeroizes_an_expired_key_without_a_runtime() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new().with_ttl(SHORT_TTL))?;
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        assert!(tokio::runtime::Handle::try_current().is_err());
        block_on(cache.with_dek(&provider, &encrypted_dek, |_| ()))?;
        let cached = cache.cached_dek(provider.kek(), &encrypted_dek).unwrap();
        thread::sleep(SHORT_TTL);
        let held_until_purged = cached.strong_count();
        cache.purge_expired();

        assert_eq!([held_until_purged, cached.strong_count()], [1, 0]);
        Ok(())
    }

    #[tokio::test]
    async fn a_decryption_in_flight_does_not_reinsert_after_invalidate() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;

        let mut outcomes = Vec::new();
        for clear in [false, true] {
            let provider = Arc::new(CountingKmsProvider::gated(
                TestKmsProvider::Working,
                ORDERS_KEK,
            ));
            let in_flight = tokio::spawn({
                let (cache, provider, encrypted_dek) =
                    (cache.clone(), Arc::clone(&provider), encrypted_dek.clone());
                async move { cache.with_dek(&*provider, &encrypted_dek, |_| ()).await }
            });
            let_spawned_tasks_wait().await;
            if clear {
                cache.clear();
            } else {
                cache.invalidate(provider.kek(), &encrypted_dek);
            }
            provider.open_gate();
            let ((), leader) = in_flight.await.unwrap()?;
            let ((), after) = cache.with_dek(&*provider, &encrypted_dek, |_| ()).await?;
            outcomes.push(([leader, after], provider.decryptions()));
            cache.clear();
        }

        let expected = ([DekCacheOutcome::Miss, DekCacheOutcome::Miss], 2);
        assert_eq!(outcomes, [expected; 2]);
        Ok(())
    }

    #[tokio::test]
    async fn a_waiter_decrypts_when_the_decrypting_caller_is_cancelled() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::new(DekCacheOptions::new())?;
        let provider = Arc::new(CountingKmsProvider::gated(
            TestKmsProvider::Working,
            ORDERS_KEK,
        ));

        let [decrypting, waiting] = [(); 2].map(|()| {
            let (cache, provider, encrypted_dek) =
                (cache.clone(), Arc::clone(&provider), encrypted_dek.clone());
            tokio::spawn(async move { cache.with_dek(&*provider, &encrypted_dek, |_| ()).await })
        });
        let_spawned_tasks_wait().await;
        decrypting.abort();
        let_spawned_tasks_wait().await;
        provider.open_gate();
        let cancelled = decrypting.await.is_err_and(|error| error.is_cancelled());
        let ((), took_over) = waiting.await.unwrap()?;
        let ((), after) = cache.with_dek(&*provider, &encrypted_dek, |_| ()).await?;

        assert!(cancelled);
        assert_eq!(
            [took_over, after],
            [DekCacheOutcome::Miss, DekCacheOutcome::Hit]
        );
        assert_eq!(provider.decryptions(), 2);
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
        let keys = [ORDERS_DEK, BILLING_DEK].map(|dek_bytes| {
            (
                encrypted_by_test_provider(TinkKeyType::AesGcm, &dek_bytes),
                dek_bytes,
            )
        });
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
                                let (encrypted_dek, dek_bytes) = &keys[use_index % keys.len()];
                                let used =
                                    block_on(cache.with_dek(&provider, encrypted_dek, |dek| {
                                        let before = dek.value().ref_sensitive_value() == dek_bytes;
                                        thread::yield_now();
                                        before && dek.value().ref_sensitive_value() == dek_bytes
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
        // The start of a serialised 32-byte AesGcmKey, whose last 8 bytes are the stamp.
        let encrypted_deks: Vec<_> = (1..=3)
            .map(|byte| EncryptedDataEncryptionKey::new([&[0x1a, 0x20][..], &[byte; 24]].concat()))
            .collect();
        let looking_up = AtomicBool::new(true);

        let (failures, invalidated) = thread::scope(|scope| {
            let churn = scope.spawn(|| {
                let mut invalidated = Vec::new();
                let rounds = encrypted_deks.iter().cycle().enumerate();
                for (round, encrypted_dek) in
                    rounds.take_while(|_| looking_up.load(Ordering::Relaxed))
                {
                    invalidated.extend(cache.cached_dek(provider.kek(), encrypted_dek));
                    cache.invalidate(provider.kek(), encrypted_dek);
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
                                let encrypted_dek = &encrypted_deks[lookup % encrypted_deks.len()];
                                let looked_up_at = Instant::now();
                                let served =
                                    block_on(cache.with_dek(&provider, encrypted_dek, |dek| {
                                        let stamped = dek.value().ref_sensitive_value();
                                        let split = stamped.split_last_chunk::<8>();
                                        split.is_some_and(|(dek_bytes, nanos)| {
                                            let since =
                                                Duration::from_nanos(u64::from_le_bytes(*nanos));
                                            let age = looked_up_at
                                                .saturating_duration_since(started + since);
                                            dek_bytes == &encrypted_dek.value()[2..] && age < ttl
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
        assert!(invalidated.iter().all(|dek| dek.strong_count() == 0));
        Ok(())
    }

    #[tokio::test]
    async fn disabled_cache_decrypts_every_time() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &ORDERS_DEK);
        let cache = DekCache::disabled();
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);

        let ((), first) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        let ((), second) = cache.with_dek(&provider, &encrypted_dek, |_| ()).await?;
        cache.invalidate(provider.kek(), &encrypted_dek);
        cache.clear();

        assert!(!cache.is_enabled());
        assert_eq!(
            [first, second],
            [DekCacheOutcome::Disabled, DekCacheOutcome::Disabled]
        );
        assert_eq!(provider.decryptions(), 2);
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
