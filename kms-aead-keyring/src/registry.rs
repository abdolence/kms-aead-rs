//! [`KeyringRegistry`]: the keyrings of an application on one store, each opened once, and the
//! shutdown of the work they run.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use kms_aead::backends::AeadBackend;
use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead::{KekRef, KmsAeadEncryptionProvider};
use rsb_derive::Builder;
use tokio::sync::{watch, OnceCell};
use tokio::task::JoinSet;
use tokio::time::Instant;

use crate::errors::{KekMismatchError, KeyringError, KeyringResult};
use crate::record_cache::RecordCache;
use crate::spans;
use crate::store::{join_until, KeyringStore, Stored};
#[cfg(feature = "admin")]
use crate::{store::Swap, KeyringAdmin, KeyringAlgorithms};
use crate::{Keyring, KeyringId, KeyringOptions, KeyringRecord};

/// The keyrings of one application on one store: the store, with its connections and its
/// listener, one [`DekCache`], and every keyring opened through it, which is loaded and watched
/// once however many parts of the application open it. `Clone` shares all of it.
///
/// [`open`](Self::open) returns a [`Keyring`] handle with the provider the call names, so that
/// each keyring can have a KEK of its own, and `B` is the AEAD backend of every handle. With the
/// `admin` feature, `create`, `open_or_create` and `admin` return a `KeyringAdmin` the same way.
/// A second open of an open keyring, through any of them, reads nothing from the store and shares
/// the first one's cached record and watch. A keyring stays open until the registry shuts down.
///
/// Where the store has push, a task on the current tokio runtime follows the change signals of
/// each open keyring. [`shutdown`](Self::shutdown) stops those tasks and the store's listener,
/// and is awaited before the last clone is dropped: a registry dropped while it still runs them
/// aborts them and logs a `WARN`.
pub struct KeyringRegistry<S: KeyringStore, B> {
    inner: Arc<RegistryInner<S>>,
    backend: PhantomData<fn() -> B>,
}

struct RegistryInner<S: KeyringStore> {
    store: Arc<S>,
    dek_cache: DekCache,
    record_ttl: Duration,
    reload_min_interval: Duration,
    watch: bool,
    keyring_options: KeyringOptions,
    keyrings: OpenKeyrings<S>,
    follow_tasks: FollowTasks,
    /// `true` once a shutdown has begun. The follow tasks stop on it, and no watch starts after
    /// it.
    stop: watch::Sender<bool>,
}

/// The open keyrings by id. An empty cell is an open in progress, or one that failed and whose
/// callers are about to remove it.
struct OpenKeyrings<S: KeyringStore>(Mutex<HashMap<KeyringId, KeyringCell<S>>>);

/// The record cache of one keyring, set by its first open that succeeds.
type KeyringCell<S> = Arc<OnceCell<Arc<RecordCache<S>>>>;

/// Removes the cell of `id` from the map when it is dropped, if the cell is still empty and no
/// other open holds it: failed and cancelled opens then leave no entry.
struct ReleaseCell<'a, S: KeyringStore> {
    keyrings: &'a OpenKeyrings<S>,
    id: &'a KeyringId,
}

/// The follow tasks of the open keyrings, kept until they are joined.
#[derive(Default)]
struct FollowTasks {
    tasks: tokio::sync::Mutex<JoinSet<()>>,
    /// Set by the first follow task and cleared by a shutdown that joined every task: whether a
    /// drop of the registry is the misuse `Drop` reports.
    started: AtomicBool,
}

/// How a [`KeyringRegistry`] caches the records of its keyrings, and the options of the handles
/// it returns.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringRegistryOptions {
    /// How long a cached record serves without a store call:
    /// [`DEFAULT_RECORD_TTL`](Self::DEFAULT_RECORD_TTL) by default. The first call after it
    /// revalidates with a conditional read, while the other calls keep using the cached record.
    /// Where the store has no push, it bounds how late a process sees a change, such as a
    /// compromised flag.
    #[default = "Self::DEFAULT_RECORD_TTL"]
    pub record_ttl: Duration,
    /// The least time between two store reads that an unknown key id or a change signal
    /// triggers: [`DEFAULT_RELOAD_MIN_INTERVAL`](Self::DEFAULT_RELOAD_MIN_INTERVAL) by default.
    /// Values with random key ids, and a writer that can send change signals, then cost at most
    /// one store read per interval.
    #[default = "Self::DEFAULT_RELOAD_MIN_INTERVAL"]
    pub reload_min_interval: Duration,
    /// Whether to follow the store's change signals, where it has them:
    /// [`DEFAULT_WATCH`](Self::DEFAULT_WATCH) by default.
    #[default = "Self::DEFAULT_WATCH"]
    pub watch: bool,
    /// The cache of decrypted keys, which may be shared with other registries and envelopes, or
    /// `None`, the default, for `DekCache::new(DekCacheOptions::new())`, with kms-aead's
    /// [`DekCacheOptions::DEFAULT_TTL`] and [`DekCacheOptions::DEFAULT_MAX_ENTRIES`].
    pub dek_cache: Option<DekCache>,
    /// The options of every handle the registry returns, which
    /// [`Keyring::with_options`] replaces on one handle: [`KeyringOptions::new`] by default.
    #[default = "KeyringOptions::new()"]
    pub keyring: KeyringOptions,
}

impl KeyringRegistryOptions {
    /// The default [`record_ttl`](Self::record_ttl): 5 minutes.
    pub const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(5 * 60);
    /// The default [`reload_min_interval`](Self::reload_min_interval): 5 seconds.
    pub const DEFAULT_RELOAD_MIN_INTERVAL: Duration = Duration::from_secs(5);
    /// The default [`watch`](Self::watch): `true`, following the store's change signals.
    pub const DEFAULT_WATCH: bool = true;
}

impl<S: KeyringStore, B> Clone for KeyringRegistry<S, B> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            backend: PhantomData,
        }
    }
}

impl<S, B> KeyringRegistry<S, B>
where
    S: KeyringStore,
    B: AeadBackend,
{
    /// The registry of the keyrings in `store`. It does no I/O: the first open of a keyring
    /// reads the store.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] when `options.dek_cache` is `None` and kms-aead refuses the
    /// DEK cache of its default options.
    pub fn new(store: S, options: KeyringRegistryOptions) -> KeyringResult<Self> {
        let dek_cache = match options.dek_cache {
            Some(dek_cache) => dek_cache,
            None => DekCache::new(DekCacheOptions::new())?,
        };
        Ok(Self {
            inner: Arc::new(RegistryInner {
                store: Arc::new(store),
                dek_cache,
                record_ttl: options.record_ttl,
                reload_min_interval: options.reload_min_interval,
                watch: options.watch,
                keyring_options: options.keyring,
                keyrings: OpenKeyrings(Mutex::default()),
                follow_tasks: FollowTasks::default(),
                stop: watch::Sender::new(false),
            }),
            backend: PhantomData,
        })
    }

    /// A handle on the keyring `id` with `provider`, which decrypts the record's keys. The first
    /// open of `id` loads its record and starts following the store's change signals.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::RecordMissing`] when the store holds no record,
    /// [`KeyringError::RecordInvalid`] when it holds an invalid one, and
    /// [`KeyringError::KekMismatch`] when the provider's KEK is not the one the record names,
    /// which leaves the keyring and its other handles as they were.
    pub async fn open<P>(&self, provider: P, id: KeyringId) -> KeyringResult<Keyring<S, P, B>>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    {
        let store = &*self.inner.store;
        let cache = self
            .inner
            .cache(&id, provider.kek(), async || {
                RecordCache::read(store, &id)
                    .await?
                    .ok_or_else(|| KeyringError::RecordMissing(id.clone()))
            })
            .await?;
        Ok(Keyring::new(
            cache,
            provider,
            self.inner.keyring_options.clone(),
        ))
    }

    /// The cache of the decrypted keys of every keyring the registry opens, which the
    /// application's timer calls [`DekCache::purge_expired`] on when the process can sit idle
    /// while it holds keys.
    pub fn dek_cache(&self) -> &DekCache {
        &self.inner.dek_cache
    }

    /// Stops the follow task of every open keyring and the store's listener, and waits for both.
    ///
    /// - A revalidation read in flight finishes and is taken; waits, retry delays and connection
    ///   attempts stop at once.
    /// - The open keyrings' keys are evicted from the [`DekCache`], and no other key is.
    /// - Handles keep serving from their cached records, which their TTL revalidates without
    ///   push. Later opens work too, and start no watch.
    /// - A registry that never watched, or that was shut down already, returns at once.
    /// - A cancelled call leaves the tasks it did not join to the next call.
    ///
    /// Await it before the registry is dropped.
    ///
    /// # Errors
    ///
    /// None: the result is always `Ok`, whatever the tasks did.
    pub async fn shutdown(&self) -> KeyringResult<()> {
        self.inner.shutdown_with(None).await;
        Ok(())
    }

    /// Shuts down as [`shutdown`](Self::shutdown) does, and aborts what still runs after
    /// `timeout`, at once for a zero timeout, with a `WARN` that counts the aborted follow
    /// tasks. An abort can interrupt:
    ///
    /// - a revalidation read in flight, which is then dropped before anything is taken, so the
    ///   cached record stays;
    /// - a store listener between two events, or during a connection attempt, whose connection is
    ///   then dropped.
    ///
    /// Neither leaves a half-written state.
    ///
    /// # Errors
    ///
    /// None: the result is always `Ok`, also after an abort.
    pub async fn shutdown_with_timeout(&self, timeout: Duration) -> KeyringResult<()> {
        self.inner.shutdown_with(Some(timeout)).await;
        Ok(())
    }
}

/// The administrative entry points, with the `admin` feature: each returns a [`KeyringAdmin`] on
/// a keyring that is then open in the registry, as [`open`](Self::open) leaves it.
#[cfg(feature = "admin")]
impl<S, B> KeyringRegistry<S, B>
where
    S: KeyringStore,
    B: AeadBackend,
{
    /// An administrative handle on the keyring `id` with `provider`, opened as
    /// [`open`](Self::open) opens it, and sharing its record cache and watch with the keyring's
    /// [`Keyring`] handles.
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub async fn admin<P>(&self, provider: P, id: KeyringId) -> KeyringResult<KeyringAdmin<S, P, B>>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    {
        Ok(KeyringAdmin::new(self.open(provider, id).await?))
    }

    /// Creates the record of the keyring `id`, with one active version of each purpose
    /// `algorithms` names an algorithm for, and returns an administrative handle on it. Encrypts
    /// one key per version and writes the record, so it needs the KMS's encrypt right and write
    /// access to the store.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors; [`KeyringError::RecordExists`] when the store
    /// already holds a record, and when the keyring is open, before any call to the store or the
    /// KMS; `UNSUPPORTED_ALGORITHM` from kms-aead when `B` does not implement an algorithm of
    /// `algorithms`; and [`KeyringError::DeterministicDisabled`] for a deterministic algorithm
    /// without the `deterministic` feature.
    pub async fn create<P>(
        &self,
        provider: P,
        id: KeyringId,
        algorithms: KeyringAlgorithms,
    ) -> KeyringResult<KeyringAdmin<S, P, B>>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    {
        let store = &*self.inner.store;
        let mut created = false;
        let cache = self
            .inner
            .cache(&id, provider.kek(), async || {
                let record = algorithms.new_record::<P, B>(id.clone(), &provider).await?;
                match store.compare_and_swap(&record, None).await? {
                    Swap::Written(revision) => {
                        created = true;
                        Ok(Stored { record, revision })
                    }
                    Swap::Conflict => Err(KeyringError::RecordExists(id.clone())),
                }
            })
            .await?;
        if !created {
            return Err(KeyringError::RecordExists(id));
        }
        Ok(KeyringAdmin::new(Keyring::new(
            cache,
            provider,
            self.inner.keyring_options.clone(),
        )))
    }

    /// An administrative handle on the keyring `id` as [`admin`](Self::admin) returns, after
    /// creating its record as [`create`](Self::create) does when the store holds none. When
    /// another process creates it at the same time, opens that one.
    ///
    /// # Errors
    ///
    /// The errors of [`open`](Self::open) and [`create`](Self::create), but not
    /// `RecordMissing` or `RecordExists`.
    pub async fn open_or_create<P>(
        &self,
        provider: P,
        id: KeyringId,
        algorithms: KeyringAlgorithms,
    ) -> KeyringResult<KeyringAdmin<S, P, B>>
    where
        P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    {
        let store = &*self.inner.store;
        let cache = self
            .inner
            .cache(&id, provider.kek(), async || {
                if let Some(stored) = RecordCache::read(store, &id).await? {
                    return Ok(stored);
                }
                let record = algorithms.new_record::<P, B>(id.clone(), &provider).await?;
                match store.compare_and_swap(&record, None).await? {
                    Swap::Written(revision) => Ok(Stored { record, revision }),
                    Swap::Conflict => RecordCache::read(store, &id)
                        .await?
                        .ok_or_else(|| KeyringError::RecordMissing(id.clone())),
                }
            })
            .await?;
        Ok(KeyringAdmin::new(Keyring::new(
            cache,
            provider,
            self.inner.keyring_options.clone(),
        )))
    }
}

impl<S: KeyringStore> RegistryInner<S> {
    /// The record cache of `id`, which the first caller builds from the record `load` returns,
    /// checked against `kek`, and which the callers of the same id wait for and share. Every
    /// caller checks `kek` against the record, so a wrong KEK fails only its own call.
    async fn cache(
        &self,
        id: &KeyringId,
        kek: &KekRef,
        load: impl AsyncFnOnce() -> KeyringResult<Stored<S::Revision>>,
    ) -> KeyringResult<Arc<RecordCache<S>>> {
        // Declared before `cell`, so that it runs after `cell` is dropped, on a cancellation too:
        // it then counts only the opens still holding the cell.
        let _release = ReleaseCell {
            keyrings: &self.keyrings,
            id,
        };
        let cell = self.keyrings.cell(id);
        let cache = cell
            .get_or_try_init(async || {
                let stored = load().await?;
                stored.record.check_kek(kek)?;
                let cache = Arc::new(RecordCache::new(
                    Arc::clone(&self.store),
                    kek.clone(),
                    self.dek_cache.clone(),
                    self.record_ttl,
                    self.reload_min_interval,
                    stored,
                ));
                if self.watch {
                    self.follow(&cache).await;
                }
                Ok::<_, KeyringError>(cache)
            })
            .await?;
        cache.record().check_kek(kek)?;
        Ok(Arc::clone(cache))
    }

    /// Starts the task that follows the store's change signals for `cache`'s keyring, unless a
    /// shutdown has begun. Without push, without a tokio runtime, or when the listener does not
    /// start, with a `WARN` for the last two, the record TTL alone bounds how late a change is
    /// seen.
    async fn follow(&self, cache: &Arc<RecordCache<S>>) {
        if *self.stop.borrow() {
            return;
        }
        // Checked before `watch`, since a store's listener may spawn a task of its own, and
        // `tokio::spawn` panics outside a runtime.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            spans::watch_without_runtime(cache.id());
            return;
        };
        let watch = match self.store.watch(cache.id()).await {
            Ok(Some(watch)) => watch,
            Ok(None) => return,
            Err(error) => {
                spans::watch_failed(cache.id(), &error);
                return;
            }
        };
        let mut tasks = self.follow_tasks.tasks.lock().await;
        // Checked again under the lock: a shutdown that began meanwhile joins only the tasks it
        // finds there, and this one would outlive it.
        if *self.stop.borrow() {
            return;
        }
        while tasks.try_join_next().is_some() {}
        tasks.spawn_on(
            RecordCache::follow(
                Arc::downgrade(cache),
                cache.id().clone(),
                self.reload_min_interval,
                watch,
                self.stop.subscribe(),
            ),
            &runtime,
        );
        self.follow_tasks.started.store(true, Ordering::SeqCst);
    }

    /// Stops the follow tasks, then the store, so that no follow task sees its watch end during
    /// an orderly shutdown, and evicts the open keyrings' keys. Work still running at the end of
    /// `timeout` is aborted.
    async fn shutdown_with(&self, timeout: Option<Duration>) {
        let deadline = timeout.and_then(|timeout| Instant::now().checked_add(timeout));
        self.stop.send_replace(true);
        self.follow_tasks.join(deadline).await;
        let remaining = deadline.map(|deadline| deadline.saturating_duration_since(Instant::now()));
        self.store.shutdown(remaining).await;
        for cache in self.keyrings.caches() {
            cache.evict_deks();
        }
    }
}

/// Reports a registry dropped without its shutdown, which aborts the follow tasks. Nothing else
/// is done here: no task is spawned and nothing blocks.
impl<S: KeyringStore> Drop for RegistryInner<S> {
    fn drop(&mut self) {
        if self.follow_tasks.owns_background_work() {
            spans::registry_dropped_without_shutdown(self.keyrings.len());
        }
    }
}

impl<S: KeyringStore> OpenKeyrings<S> {
    /// The map stays consistent through a panic elsewhere: no code under the lock panics
    /// between two changes of it.
    fn lock(&self) -> MutexGuard<'_, HashMap<KeyringId, KeyringCell<S>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The cell of `id`, added empty when the map has none.
    fn cell(&self, id: &KeyringId) -> KeyringCell<S> {
        Arc::clone(self.lock().entry(id.clone()).or_default())
    }

    /// The record caches of the open keyrings.
    fn caches(&self) -> Vec<Arc<RecordCache<S>>> {
        self.lock()
            .values()
            .filter_map(|cell| cell.get().cloned())
            .collect()
    }

    fn len(&self) -> usize {
        self.lock().len()
    }
}

impl<S: KeyringStore> Drop for ReleaseCell<'_, S> {
    fn drop(&mut self) {
        let mut keyrings = self.keyrings.lock();
        // The map's own reference is the only one left once every open of the id has dropped
        // its clone, so the last open to fail removes the cell.
        if keyrings
            .get(self.id)
            .is_some_and(|cell| !cell.initialized() && Arc::strong_count(cell) == 1)
        {
            keyrings.remove(self.id);
        }
    }
}

impl FollowTasks {
    /// Joins every follow task, and aborts those still running at `deadline`, at once when it
    /// has passed, with one `WARN` for the aborted ones.
    async fn join(&self, deadline: Option<Instant>) {
        let mut tasks = self.tasks.lock().await;
        let aborted = join_until(&mut tasks, deadline).await;
        if aborted > 0 {
            spans::shutdown_aborted(aborted);
        }
        self.started.store(false, Ordering::SeqCst);
    }

    /// Whether a follow task was started and no shutdown has joined it since.
    fn owns_background_work(&self) -> bool {
        self.started.load(Ordering::SeqCst)
    }
}

impl KeyringRecord {
    /// Fails with `KekMismatch` unless `kek` is the KEK the record names.
    fn check_kek(&self, kek: &KekRef) -> KeyringResult<()> {
        if self.kek() == kek {
            return Ok(());
        }
        Err(KeyringError::KekMismatch(Box::new(KekMismatchError {
            keyring: self.id().clone(),
            recorded: self.kek().clone(),
            provider: kek.clone(),
        })))
    }
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::sync::atomic::Ordering;

    use futures_util::future::try_join_all;

    use super::*;
    use crate::test_support::{
        email_of, TestAdmin, TestProvider, TestRegistry, TestResult, TestStore, TENANT,
    };
    use crate::testing::MemoryKeyringStore;
    use crate::{KeyId, Purpose};

    const ALICE: &str = "alice@example.com";

    const OTHER_TENANT: KeyringId = KeyringId::from_static("tenant-43");

    /// The keyring `TENANT`, created in a memory store by the administrative job's registry, and
    /// an application's registry over a counting store on the same memory, whose loads and
    /// revalidations take `delay`.
    struct Fixture {
        store: TestStore,
        provider: TestProvider,
        admin: TestAdmin<MemoryKeyringStore>,
        registry: TestRegistry<TestStore>,
    }

    impl Fixture {
        async fn new(delay: Duration, options: KeyringRegistryOptions) -> KeyringResult<Self> {
            let memory = MemoryKeyringStore::new();
            let provider = TestProvider::new("tenant-42-kek")?;
            let admin = TestRegistry::new(
                memory.clone(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(provider.clone(), TENANT, KeyringAlgorithms::new())
            .await?;
            let store = TestStore::new(&memory, delay);
            Ok(Self {
                registry: TestRegistry::new(store.clone(), options)?,
                store,
                provider,
                admin,
            })
        }
    }

    #[tokio::test]
    async fn an_admin_handle_shares_the_record_cache_of_the_open_keyring() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let admin = fixture
            .registry
            .admin(fixture.provider.clone(), TENANT)
            .await?;

        assert_eq!(
            (
                fixture.store.calls.loads.load(Ordering::SeqCst),
                fixture.store.calls.watches.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        let staged = admin.rotate(Purpose::Randomized).await?;
        assert!(keyring.record().version(staged).is_some());
        fixture.registry.shutdown().await?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn concurrent_opens_of_one_keyring_load_once() -> TestResult {
        let fixture =
            Fixture::new(Duration::from_millis(10), KeyringRegistryOptions::new()).await?;

        try_join_all((0..8).map(|_| fixture.registry.open(fixture.provider.clone(), TENANT)))
            .await?;

        assert_eq!(
            (
                fixture.store.calls.loads.load(Ordering::SeqCst),
                fixture.store.calls.watches.load(Ordering::SeqCst)
            ),
            (1, 1)
        );
        fixture.registry.shutdown().await?;
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_or_cancelled_open_leaves_no_entry() -> TestResult {
        let fixture = Fixture::new(
            Duration::from_secs(1),
            KeyringRegistryOptions::new().with_watch(false),
        )
        .await?;
        let provider = &fixture.provider;

        let cancelled = tokio::time::timeout(
            Duration::from_millis(10),
            fixture.registry.open(provider.clone(), TENANT),
        )
        .await;
        assert!(cancelled.is_err());
        assert_eq!(fixture.registry.inner.keyrings.len(), 0);
        let missing = fixture.registry.open(provider.clone(), OTHER_TENANT).await;
        assert!(matches!(missing, Err(KeyringError::RecordMissing(_))));
        assert_eq!(fixture.registry.inner.keyrings.len(), 0);

        let encryptions = provider.calls.encryptions.load(Ordering::SeqCst);
        fixture
            .registry
            .open_or_create(provider.clone(), OTHER_TENANT, KeyringAlgorithms::new())
            .await?;
        assert_eq!(
            provider.calls.encryptions.load(Ordering::SeqCst),
            encryptions + 1
        );
        assert_eq!(fixture.registry.inner.keyrings.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_provider_with_another_kek_is_refused() -> TestResult {
        let fixture = Fixture::new(
            Duration::ZERO,
            KeyringRegistryOptions::new().with_watch(false),
        )
        .await?;
        let first = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let other = TestProvider::new("another-kek")?;

        let refused = fixture.registry.open(other.clone(), TENANT).await;
        assert!(matches!(
            refused,
            Err(KeyringError::KekMismatch(error))
                if &error.provider == other.kek() && &error.recorded == fixture.provider.kek()
        ));
        let aad = email_of("42")?;
        let value = fixture
            .admin
            .keyring()
            .encrypt(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(first.decrypt(&aad, &value).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn create_of_an_open_keyring_is_record_exists() -> TestResult {
        let fixture = Fixture::new(
            Duration::ZERO,
            KeyringRegistryOptions::new().with_watch(false),
        )
        .await?;
        fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let encryptions = fixture.provider.calls.encryptions.load(Ordering::SeqCst);

        let created = fixture
            .registry
            .create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
            .await;

        assert!(matches!(created, Err(KeyringError::RecordExists(_))));
        assert_eq!(
            fixture.provider.calls.encryptions.load(Ordering::SeqCst),
            encryptions
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_waits_for_an_in_flight_revalidation() -> TestResult {
        let fixture = Fixture::new(Duration::from_secs(2), KeyringRegistryOptions::new()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        // The follow task's first revalidation now takes 2 seconds, and sees this write.
        tokio::time::sleep(Duration::from_millis(1)).await;
        let staged = fixture.admin.rotate(Purpose::Randomized).await?;

        fixture.registry.shutdown().await?;

        assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
        assert!(keyring.record().version(staged).is_some());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_during_the_rate_limit_wait_returns_at_once() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        let _keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        // A signal inside the reload interval, which the follow task waits out.
        fixture.admin.rotate(Purpose::Randomized).await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let started = Instant::now();

        fixture.registry.shutdown().await?;

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_timeout_aborts_a_stuck_revalidation() -> TestResult {
        let fixture = Fixture::new(Duration::from_secs(60), KeyringRegistryOptions::new()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let staged = fixture.admin.rotate(Purpose::Randomized).await?;
        let started = Instant::now();

        fixture
            .registry
            .shutdown_with_timeout(Duration::from_secs(1))
            .await?;

        assert_eq!(started.elapsed(), Duration::from_secs(1));
        assert!(keyring.record().version(staged).is_none());
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_zero_timeout_aborts_without_polling() -> TestResult {
        let fixture = Fixture::new(Duration::from_secs(60), KeyringRegistryOptions::new()).await?;
        let _keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let started = Instant::now();

        fixture
            .registry
            .shutdown_with_timeout(Duration::ZERO)
            .await?;

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert!(fixture
            .registry
            .inner
            .follow_tasks
            .tasks
            .lock()
            .await
            .is_empty());
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_twice_is_a_no_op() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        let _keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        fixture.registry.shutdown().await?;
        let calls = &fixture.store.calls;
        let before = (
            calls.loads.load(Ordering::SeqCst),
            calls.revalidations.load(Ordering::SeqCst),
        );
        let started = Instant::now();

        fixture.registry.shutdown().await?;

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(
            (
                calls.loads.load(Ordering::SeqCst),
                calls.revalidations.load(Ordering::SeqCst)
            ),
            before
        );
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_of_a_registry_that_never_watched_is_a_no_op() -> TestResult {
        let fixture = Fixture::new(
            Duration::ZERO,
            KeyringRegistryOptions::new().with_watch(false),
        )
        .await?;
        let _keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let started = Instant::now();

        fixture.registry.shutdown().await?;

        assert_eq!(started.elapsed(), Duration::ZERO);
        assert_eq!(fixture.store.calls.watches.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_cancelled_shutdown_still_joins() -> TestResult {
        let fixture = Fixture::new(Duration::from_secs(2), KeyringRegistryOptions::new()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let staged = fixture.admin.rotate(Purpose::Randomized).await?;

        let cancelled =
            tokio::time::timeout(Duration::from_secs(1), fixture.registry.shutdown()).await;
        assert!(cancelled.is_err());
        assert!(fixture.registry.inner.follow_tasks.owns_background_work());
        fixture.registry.shutdown().await?;

        assert!(keyring.record().version(staged).is_some());
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        Ok(())
    }

    #[tokio::test]
    async fn shutdown_evicts_the_open_keyrings_deks() -> TestResult {
        let dek_cache = DekCache::new(DekCacheOptions::new())?;
        let options = KeyringRegistryOptions::new()
            .with_watch(false)
            .with_dek_cache(dek_cache.clone());
        let fixture = Fixture::new(Duration::ZERO, options.clone()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let other = TestRegistry::new(MemoryKeyringStore::new(), options)?
            .create(
                fixture.provider.clone(),
                OTHER_TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        let aad = email_of("42")?;
        let value = keyring.encrypt(&aad, &ALICE.to_string()).await?;
        let other_value = other.keyring().encrypt(&aad, &ALICE.to_string()).await?;
        let decryptions = &fixture.provider.calls.decryptions;
        let before = decryptions.load(Ordering::SeqCst);

        fixture.registry.shutdown().await?;

        other.keyring().decrypt(&aad, &other_value).await?;
        assert_eq!(decryptions.load(Ordering::SeqCst), before);
        keyring.decrypt(&aad, &value).await?;
        assert_eq!(decryptions.load(Ordering::SeqCst), before + 1);
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn a_watch_that_ends_leaves_the_keyring_on_the_ttl() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        fixture
            .store
            .calls
            .listener_stopped
            .store(true, Ordering::SeqCst);
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
        let admin = &fixture.admin;
        admin
            .promote(admin.rotate(Purpose::Randomized).await?)
            .await?;

        tokio::time::advance(KeyringRegistryOptions::DEFAULT_RECORD_TTL).await;
        let value = keyring
            .encrypt(&email_of("42")?, &ALICE.to_string())
            .await?;

        assert_eq!(value.key_id(), KeyId::new(2));
        assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
        fixture.registry.shutdown().await?;
        Ok(())
    }

    #[tokio::test]
    async fn a_handle_serves_after_shutdown() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        let keyring = fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        let aad = email_of("42")?;
        let before = keyring.encrypt(&aad, &ALICE.to_string()).await?;

        fixture.registry.shutdown().await?;

        let after = keyring.encrypt(&aad, &ALICE.to_string()).await?;
        assert_eq!(keyring.decrypt(&aad, &before).await?, ALICE);
        assert_eq!(keyring.decrypt(&aad, &after).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn owns_background_work_until_shutdown() -> TestResult {
        let fixture = Fixture::new(Duration::ZERO, KeyringRegistryOptions::new()).await?;
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await?;
        assert!(fixture.registry.inner.follow_tasks.owns_background_work());

        fixture.registry.shutdown().await?;
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        fixture
            .registry
            .open_or_create(
                fixture.provider.clone(),
                OTHER_TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        assert!(!fixture.registry.inner.follow_tasks.owns_background_work());
        assert_eq!(fixture.store.calls.watches.load(Ordering::SeqCst), 1);

        let unwatched = Fixture::new(
            Duration::ZERO,
            KeyringRegistryOptions::new().with_watch(false),
        )
        .await?;
        unwatched
            .registry
            .open(unwatched.provider.clone(), TENANT)
            .await?;
        assert!(!unwatched.registry.inner.follow_tasks.owns_background_work());
        Ok(())
    }
}
