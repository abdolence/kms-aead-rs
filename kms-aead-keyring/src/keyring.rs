//! [`Keyring`]: field encryption under the key versions of one keyring record.

use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use kms_aead::cache::{DekCache, DekCacheOptions, DekCacheOutcome};
use kms_aead::{
    AeadAlgorithm, AeadBackend, AeadCipher, CipherText, DataEncryptionKey, DeterministicAlgorithm,
    EncryptedDataEncryptionKey, KmsAeadEncryptionProvider,
};
use rsb_derive::Builder;
use secret_vault_value::SecretValue;
use tokio::task::AbortHandle;

use crate::errors::{
    KekMismatchError, KeyVersionCompromisedError, KeyVersionError, KeyringError, KeyringResult,
    RecordInvalidReason,
};
use crate::record::{withdrawn_deks, NewVersion, RecordEdit};
use crate::record_cache::RecordCache;
use crate::spans;
use crate::store::{KeyringStore, Stored, Swap};
use crate::{
    Algorithms, Compromise, Encrypted, FieldAad, KeyAlgorithm, KeyId, KeyVersion, KeyVersionState,
    KeyringId, KeyringRecord, Plaintext, Purpose,
};

/// Field encryption under the key versions of one keyring, whose record lives in a
/// [`KeyringStore`] and is cached in the process.
///
/// `encrypt` seals under the active version of the purpose, and `decrypt` opens under the
/// version the value names, without a call to the store while the cached record is younger than
/// [`record_ttl`](KeyringOptions::record_ttl), and without a call to the KMS while the
/// version's key is in the [`DekCache`]. Every unwrap of `encrypt` and `decrypt` goes through
/// that cache, which drops expired keys only when it is called: a process that can sit idle
/// while it holds keys, and needs the cache's TTL to bound their time in memory, calls
/// [`DekCache::purge_expired`] on [`dek_cache`](Self::dek_cache) from a timer of its own.
///
/// The administrative calls, `create`, `rotate`, `mark_compromised`, `retire`, `reinstate`,
/// `destroy`, `rewrap` and `change_algorithm`, write the record, and `create`, `rotate`,
/// `mark_compromised`, `rewrap` and `change_algorithm` also wrap keys, so they need the KMS's
/// encrypt right. They run under an administrative principal, in a job, while the serving
/// processes only decrypt keys and read the store.
///
/// Where the store has push, a task on the current tokio runtime follows the record's change
/// signals for as long as the keyring lives.
pub struct Keyring<S: KeyringStore, P> {
    cache: Arc<RecordCache<S>>,
    provider: P,
    backend: AeadBackend,
    compromised_reads: CompromisedReadPolicy,
    cas_retries: u32,
    _watch: Option<WatchTask>,
}

impl<S, P> Keyring<S, P>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
{
    /// Opens the keyring `id` from `store`: loads its record once and starts following the
    /// store's change signals. `provider` unwraps the record's keys and `backend` runs the
    /// AEAD.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::RecordMissing`] when the store holds no record,
    /// [`KeyringError::RecordInvalid`] when it holds an invalid one, and
    /// [`KeyringError::KekMismatch`] when the provider's KEK is not the one the record names.
    pub async fn open(
        store: S,
        provider: P,
        backend: AeadBackend,
        id: KeyringId,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let stored = RecordCache::read(&store, &id)
            .await?
            .ok_or(KeyringError::RecordMissing(id))?;
        Self::start(store, provider, backend, options, stored).await
    }

    /// Creates the record of the keyring `id`, with one active version of each purpose `policy`
    /// names an algorithm for, and opens it. Wraps one key per version, so it needs the KMS's
    /// encrypt right.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors, [`KeyringError::RecordExists`] when the store
    /// already holds a record, `UNSUPPORTED_ALGORITHM` from kms-aead when `backend` does not
    /// implement the policy's algorithm, and [`KeyringError::DeterministicDisabled`] for a
    /// deterministic algorithm without the `deterministic` feature.
    pub async fn create(
        store: S,
        provider: P,
        backend: AeadBackend,
        id: KeyringId,
        policy: KeyringPolicy,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let record = policy.new_record(id, &provider, backend).await?;
        match store.compare_and_swap(&record, None).await? {
            Swap::Written(revision) => {
                Self::start(
                    store,
                    provider,
                    backend,
                    options,
                    Stored { record, revision },
                )
                .await
            }
            Swap::Conflict => Err(KeyringError::RecordExists(record.id().clone())),
        }
    }

    /// Opens the keyring `id`, or creates it as [`create`](Self::create) does when the store
    /// holds no record. When another process creates it at the same time, opens that one.
    ///
    /// # Errors
    ///
    /// The errors of [`open`](Self::open) and [`create`](Self::create), but not
    /// `RecordMissing` or `RecordExists`.
    pub async fn open_or_create(
        store: S,
        provider: P,
        backend: AeadBackend,
        id: KeyringId,
        policy: KeyringPolicy,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let stored = match RecordCache::read(&store, &id).await? {
            Some(stored) => stored,
            None => {
                let record = policy.new_record(id.clone(), &provider, backend).await?;
                match store.compare_and_swap(&record, None).await? {
                    Swap::Written(revision) => Stored { record, revision },
                    Swap::Conflict => RecordCache::read(&store, &id)
                        .await?
                        .ok_or(KeyringError::RecordMissing(id))?,
                }
            }
        };
        Self::start(store, provider, backend, options, stored).await
    }

    /// The keyring's id.
    pub fn id(&self) -> &KeyringId {
        self.cache.id()
    }

    /// The cache of the unwrapped keys of this keyring's versions.
    pub fn dek_cache(&self) -> &DekCache {
        self.cache.dek_cache()
    }

    /// The cached record, as the keyring currently uses it.
    pub fn record(&self) -> Arc<KeyringRecord> {
        self.cache.record()
    }

    /// Reads the record from the store now, past the TTL and the rate limit, and takes it: for
    /// operators and tests.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::RecordMissing`] when the store holds no record,
    /// [`KeyringError::RecordInvalid`], and [`KeyringError::RecordRegressed`] when the stored
    /// record moves a version backwards from the cached one. The cached record stays in use in
    /// every case.
    pub async fn reload(&self) -> KeyringResult<Arc<KeyringRecord>> {
        self.cache.reload().await
    }

    /// Seals `value` with `aad` under the active randomized version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the keyring has none, which follows a
    /// `mark_compromised` whose new key could not be wrapped; [`KeyringError::Plaintext`] when
    /// the value does not encode; and the provider's error when the version's key is not in the
    /// [`DekCache`] and cannot be unwrapped.
    pub async fn encrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T>> {
        let span = spans::encrypt(self.id(), Purpose::Randomized, self.backend);
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let (version, dek) = record
                .active_dek(Purpose::Randomized)
                .ok_or_else(|| KeyringError::no_active_version(self.id(), Purpose::Randomized))?;
            spans::record_sealing_version(version);
            let cipher = self.cipher(version)?;
            let plaintext = value.to_plaintext()?;
            let sealed = self
                .with_cached_key(&record, dek, |key| {
                    cipher.encrypt_value(&aad.bytes, &plaintext, key)
                })
                .await??;
            Ok(Encrypted::new(version.key_id(), &sealed.0))
        })
        .await
    }

    /// Opens `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::KeyVersionUnknown`] when the record has no such version, also after
    ///   one reload, which runs at most once per
    ///   [`reload_min_interval`](KeyringOptions::reload_min_interval);
    /// - [`KeyringError::KeyVersionRetired`] and [`KeyringError::KeyVersionDestroyed`];
    /// - [`KeyringError::KeyVersionCompromised`] under [`CompromisedReadPolicy::Block`], before
    ///   any unwrap;
    /// - [`KeyringError::Kms`] with code `DECRYPT` when the value is not authentic under the
    ///   version's key and `aad`, and the provider's error when the key cannot be unwrapped;
    /// - [`KeyringError::Plaintext`] when the bytes do not decode as `T`.
    pub async fn decrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T>,
    ) -> KeyringResult<T> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            if let Some(compromise) = compromise {
                match self.compromised_reads {
                    CompromisedReadPolicy::Block => {
                        return Err(KeyringError::KeyVersionCompromised(
                            KeyVersionCompromisedError {
                                keyring: self.id().clone(),
                                key_id: version.key_id(),
                                compromise: compromise.clone(),
                            },
                        ));
                    }
                    CompromisedReadPolicy::Allow => {
                        spans::compromised_read_allowed(self.id(), version.key_id())
                    }
                }
            }
            T::from_plaintext(self.open_cached(&record, version, dek, aad, value).await?)
        })
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy: the call for a sweep, and for a reader
    /// that handles untrusted values itself. A compromised version's key is unwrapped through
    /// the provider, never through the [`DekCache`], so that it does not return to the cache.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), without `KeyVersionCompromised`.
    pub async fn decrypt_with_status<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T>,
    ) -> KeyringResult<Decrypted<T>> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            let (plaintext, trust) = match compromise {
                None => (
                    self.open_cached(&record, version, dek, aad, value).await?,
                    KeyTrust::Trusted,
                ),
                Some(compromise) => (
                    self.open_uncached(version, dek, aad, value).await?,
                    KeyTrust::Compromised(compromise.clone()),
                ),
            };
            Ok(Decrypted {
                value: T::from_plaintext(plaintext)?,
                key_id: version.key_id(),
                trust,
            })
        })
        .await
    }

    /// Creates a new active version of `purpose` with the record's algorithm for it; the
    /// version it replaces decrypts only. Processes on the old record keep sealing under the
    /// previous version until their record refreshes, and those values decrypt.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors, [`KeyringError::NoAlgorithm`] for a purpose the
    /// record names no algorithm for, [`KeyringError::RecordRegressed`] when the stored record
    /// moves backwards from the cached one, and [`KeyringError::RecordConflict`] after
    /// [`cas_retries`](KeyringOptions::cas_retries) conflicts.
    pub async fn rotate(&self, purpose: Purpose) -> KeyringResult<Rotation> {
        spans::in_span(spans::rotate(self.id(), purpose), async {
            let rotation = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let algorithm = edit
                        .record()
                        .algorithms()
                        .of(purpose)
                        .ok_or_else(|| KeyringError::no_algorithm(self.id(), purpose))?;
                    self.rotate_record(edit, algorithm).await
                })
                .await?;
            spans::record_rotation(rotation.previous, rotation.current);
            Ok(rotation)
        })
        .await
    }

    /// Makes `algorithm` the one new versions of its purpose use, and rotates that purpose.
    ///
    /// # Errors
    ///
    /// As [`rotate`](Self::rotate), and `UNSUPPORTED_ALGORITHM` from kms-aead when the backend
    /// does not implement `algorithm`.
    pub async fn change_algorithm(&self, algorithm: KeyAlgorithm) -> KeyringResult<Rotation> {
        spans::in_span(spans::rotate(self.id(), algorithm.purpose()), async {
            let rotation = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.set_algorithm(algorithm, Timestamp::now());
                    self.rotate_record(edit, algorithm).await
                })
                .await?;
            spans::record_rotation(rotation.previous, rotation.current);
            Ok(rotation)
        })
        .await
    }

    /// Flags the version `key_id` compromised, for good, and drops its key from this process's
    /// [`DekCache`] before returning; other processes drop it when their record refreshes.
    ///
    /// For the active version, it also rotates in the same write and returns the rotation. When
    /// the KMS cannot wrap the new key, during an outage or without the encrypt right, it writes
    /// the flag alone, logs a `WARN` naming the error and returns `Ok(None)`: the purpose then
    /// has no active version, and `encrypt` fails with `NoActiveVersion` until
    /// [`rotate`](Self::rotate) succeeds. For any other version it returns `Ok(None)`.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::KeyVersionUnknown`],
    /// [`KeyringError::InvalidTransition`] for a destroyed or already compromised version, and
    /// the errors of a write as for [`rotate`](Self::rotate).
    pub async fn mark_compromised(
        &self,
        key_id: KeyId,
        note: Option<String>,
    ) -> KeyringResult<Option<Rotation>> {
        spans::in_span(spans::mark_compromised(self.id(), key_id), async {
            let rotation = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let record = edit.record();
                    let replacement = match record.version(key_id).map(KeyVersion::state) {
                        Some(KeyVersionState::Active) => self.replacement(record, key_id).await,
                        _ => None,
                    };
                    let now = Timestamp::now();
                    edit.mark_compromised(
                        key_id,
                        Compromise::new(now, note.clone()),
                        replacement,
                        now,
                    )
                })
                .await?;
            if let Some(rotation) = &rotation {
                spans::record_rotation(None, rotation.current);
            }
            Ok(rotation)
        })
        .await
    }

    /// Moves a decrypt-only version to `Retired`, once a sweep found no value left under it:
    /// reads under it fail from then on, and [`reinstate`](Self::reinstate) undoes it.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::KeyVersionUnknown`],
    /// [`KeyringError::InvalidTransition`] for any version that is not decrypt-only, and the
    /// errors of a write as for [`rotate`](Self::rotate).
    pub async fn retire(&self, key_id: KeyId) -> KeyringResult<()> {
        spans::in_span(spans::retire(self.id(), key_id), async {
            self.cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.retire(key_id, Timestamp::now())
                })
                .await
        })
        .await
    }

    /// Moves a retired version back to `DecryptOnly`, for a value that turned up after all. A
    /// compromised flag stays.
    ///
    /// # Errors
    ///
    /// As [`retire`](Self::retire), for any version that is not retired.
    pub async fn reinstate(&self, key_id: KeyId) -> KeyringResult<()> {
        spans::in_span(spans::reinstate(self.id(), key_id), async {
            self.cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.reinstate(key_id, Timestamp::now())
                })
                .await
        })
        .await
    }

    /// Removes a retired version's wrapped key from the record: the values under it can never
    /// be read again, from this record. The version stays, so that its id is never reused.
    ///
    /// # Errors
    ///
    /// As [`retire`](Self::retire), for any version that is not retired.
    pub async fn destroy(&self, key_id: KeyId) -> KeyringResult<()> {
        spans::in_span(spans::destroy(self.id(), key_id), async {
            self.cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.destroy(key_id, Timestamp::now())
                })
                .await
        })
        .await
    }

    /// Unwraps and wraps again the key of every version that holds one, so that all of them sit
    /// under the KEK's current version after the KEK rotated in the KMS. No value changes. The
    /// keys are unwrapped through the provider, never through the [`DekCache`]. Returns the
    /// number of versions wrapped again.
    ///
    /// # Errors
    ///
    /// The provider's errors, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn rewrap(&self) -> KeyringResult<usize> {
        spans::in_span(spans::rewrap(self.id()), async {
            let versions = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let deks = edit.record().wrapped_deks();
                    for (key_id, dek) in &deks {
                        let key = self.provider.decrypt_data_encryption_key(dek, None).await?;
                        let rewrapped = self
                            .provider
                            .encrypt_data_encryption_key(&key, None)
                            .await?;
                        edit.replace_dek(*key_id, rewrapped, Timestamp::now())?;
                    }
                    Ok(deks.len())
                })
                .await?;
            spans::record_versions(versions);
            Ok(versions)
        })
        .await
    }

    async fn start(
        store: S,
        provider: P,
        backend: AeadBackend,
        options: KeyringOptions,
        stored: Stored<S::Revision>,
    ) -> KeyringResult<Self> {
        let kek = provider.kek();
        if stored.record.kek() != kek {
            return Err(KeyringError::KekMismatch(KekMismatchError {
                keyring: stored.record.id().clone(),
                recorded: stored.record.kek().clone(),
                provider: kek.clone(),
            }));
        }
        let dek_cache = match options.dek_cache {
            Some(dek_cache) => dek_cache,
            None => DekCache::new(DekCacheOptions::new())?,
        };
        let cache = Arc::new(RecordCache::new(
            store,
            kek.clone(),
            dek_cache,
            options.record_ttl,
            options.reload_min_interval,
            stored,
        ));
        let watch = if options.watch {
            WatchTask::start(&cache).await
        } else {
            None
        };
        Ok(Self {
            cache,
            provider,
            backend,
            compromised_reads: options.compromised_reads,
            cas_retries: options.cas_retries,
            _watch: watch,
        })
    }

    /// The version `key_id` of `record`, its wrapped key and its compromised flag, or the error
    /// of a read under it: unknown, retired or destroyed.
    fn readable<'r>(
        &self,
        record: &'r KeyringRecord,
        key_id: KeyId,
    ) -> KeyringResult<(
        &'r KeyVersion,
        &'r EncryptedDataEncryptionKey,
        Option<&'r Compromise>,
    )> {
        let Some(version) = record.version(key_id) else {
            spans::record_unknown_version();
            return Err(KeyringError::key_version_unknown(self.id(), key_id));
        };
        spans::record_key_state(version);
        let Some((dek, compromise)) = version.readable_dek() else {
            spans::read_refused(self.id(), version);
            let error = KeyVersionError {
                keyring: self.id().clone(),
                key_id,
            };
            return Err(match version.state() {
                KeyVersionState::Destroyed => KeyringError::KeyVersionDestroyed(error),
                _ => KeyringError::KeyVersionRetired(error),
            });
        };
        Ok((version, dek, compromise))
    }

    fn cipher(&self, version: &KeyVersion) -> KeyringResult<AeadCipher> {
        match version.algorithm() {
            KeyAlgorithm::Randomized(algorithm) => Ok(AeadCipher::new(self.backend, algorithm)?),
            KeyAlgorithm::Deterministic(_) => Err(KeyringError::record_invalid(
                self.id(),
                RecordInvalidReason::PurposeMismatch(version.key_id()),
            )),
        }
    }

    /// Opens `value` with `aad` under `version` of `record`, whose wrapped key is `dek`, with
    /// the key through the [`DekCache`].
    async fn open_cached<T>(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        aad: &FieldAad,
        value: &Encrypted<T>,
    ) -> KeyringResult<SecretValue> {
        let cipher = self.cipher(version)?;
        let body = CipherText(value.body().to_vec());
        Ok(self
            .with_cached_key(record, dek, |key| {
                cipher.decrypt_value(&aad.bytes, &body, key)
            })
            .await??)
    }

    /// Runs `use_key` with the key `dek` wraps, through the [`DekCache`], and records where the
    /// key came from on the current span. `record` is the record `dek` was read from.
    ///
    /// A refresh evicts the keys it takes out of use once, when it takes the new record. A call
    /// that read `dek` from the record before and unwraps it after that eviction caches it
    /// again, so on a miss the key is evicted here when the cached record has since withdrawn
    /// it.
    async fn with_cached_key<T>(
        &self,
        record: &KeyringRecord,
        dek: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KeyringResult<T> {
        let (result, outcome) = self
            .dek_cache()
            .with_key(&self.provider, dek, None, use_key)
            .await?;
        spans::record_dek_cache(outcome);
        if outcome == DekCacheOutcome::Miss {
            let current = self.cache.record();
            if !std::ptr::eq(record, &*current)
                && withdrawn_deks(record, &current).any(|withdrawn| withdrawn == dek)
            {
                self.dek_cache().invalidate(self.provider.kek(), dek, None);
            }
        }
        Ok(result)
    }

    /// A new version to replace the active version `key_id` that is being flagged compromised,
    /// or `None`, with a `WARN`, when its key cannot be wrapped: the flag goes in without it.
    async fn replacement(&self, record: &KeyringRecord, key_id: KeyId) -> Option<NewVersion> {
        let purpose = key_id.purpose();
        let new = match record.algorithms().of(purpose) {
            Some(algorithm) => NewVersion::generate(algorithm, &self.provider, self.backend).await,
            None => Err(KeyringError::no_algorithm(self.id(), purpose)),
        };
        new.inspect_err(|error| spans::compromised_without_rotation(self.id(), key_id, error))
            .ok()
    }

    /// Opens `value` with a key the provider unwraps for this call only, which never enters the
    /// [`DekCache`].
    async fn open_uncached<T>(
        &self,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        aad: &FieldAad,
        value: &Encrypted<T>,
    ) -> KeyringResult<SecretValue> {
        let cipher = self.cipher(version)?;
        let key = self.provider.decrypt_data_encryption_key(dek, None).await?;
        spans::record_dek_cache_bypassed();
        Ok(cipher.decrypt_value(&aad.bytes, &CipherText(value.body().to_vec()), &key)?)
    }

    async fn rotate_record(
        &self,
        edit: &mut RecordEdit,
        algorithm: KeyAlgorithm,
    ) -> KeyringResult<Rotation> {
        let new = NewVersion::generate(algorithm, &self.provider, self.backend).await?;
        edit.rotate(new, Timestamp::now())
    }
}

impl NewVersion {
    /// A new key for `algorithm`, from the KMS generator when the provider uses one and from
    /// the CSPRNG otherwise, wrapped by `provider`.
    async fn generate<P>(
        algorithm: KeyAlgorithm,
        provider: &P,
        backend: AeadBackend,
    ) -> KeyringResult<Self>
    where
        P: KmsAeadEncryptionProvider + Sync,
    {
        let dek = match algorithm {
            KeyAlgorithm::Randomized(algorithm) => {
                let (_, dek) = AeadCipher::new(backend, algorithm)?
                    .generate_wrapped_key(provider, None)
                    .await?;
                dek
            }
            KeyAlgorithm::Deterministic(algorithm) => {
                Self::wrapped_deterministic_key(algorithm, provider).await?
            }
        };
        Ok(Self { algorithm, dek })
    }

    #[cfg(feature = "deterministic")]
    async fn wrapped_deterministic_key<P>(
        algorithm: DeterministicAlgorithm,
        provider: &P,
    ) -> KeyringResult<EncryptedDataEncryptionKey>
    where
        P: KmsAeadEncryptionProvider + Sync,
    {
        let (_, dek) = kms_aead::DeterministicCipher::new(algorithm)?
            .generate_wrapped_key(provider, None)
            .await?;
        Ok(dek)
    }

    #[cfg(not(feature = "deterministic"))]
    async fn wrapped_deterministic_key<P>(
        algorithm: DeterministicAlgorithm,
        provider: &P,
    ) -> KeyringResult<EncryptedDataEncryptionKey>
    where
        P: KmsAeadEncryptionProvider + Sync,
    {
        let _ = (algorithm, provider);
        Err(KeyringError::DeterministicDisabled)
    }
}

/// Stops the task that follows the store's change signals when the keyring is dropped.
struct WatchTask(AbortHandle);

impl WatchTask {
    /// Starts following the store's signals for `cache`'s keyring, or returns `None`, with a
    /// `WARN` for a failure, when the store has no push, its listener does not start, or no
    /// tokio runtime runs the call: the record TTL alone then bounds how late a change is seen.
    async fn start<S: KeyringStore>(cache: &Arc<RecordCache<S>>) -> Option<Self> {
        let watch = match cache.store().watch(cache.id()).await {
            Ok(watch) => watch?,
            Err(error) => {
                spans::watch_failed(cache.id(), &error);
                return None;
            }
        };
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) => {
                let task = runtime.spawn(RecordCache::follow(
                    Arc::downgrade(cache),
                    cache.id().clone(),
                    cache.reload_min_interval(),
                    watch,
                ));
                Some(Self(task.abort_handle()))
            }
            Err(_) => {
                spans::watch_without_runtime(cache.id());
                None
            }
        }
    }
}

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl KeyringPolicy {
    /// The record of a new keyring `id` under this policy, with one active version per purpose
    /// it names an algorithm for, each wrapped by `provider`.
    async fn new_record<P>(
        &self,
        id: KeyringId,
        provider: &P,
        backend: AeadBackend,
    ) -> KeyringResult<KeyringRecord>
    where
        P: KmsAeadEncryptionProvider + Sync,
    {
        let now = Timestamp::now();
        let algorithms = Algorithms::new(self.randomized_algorithm, self.deterministic_algorithm);
        let mut edit = RecordEdit::from(KeyringRecord::new(
            id,
            provider.kek().clone(),
            algorithms,
            now,
        ));
        for purpose in [Purpose::Randomized, Purpose::Deterministic] {
            if let Some(algorithm) = algorithms.of(purpose) {
                edit.rotate(
                    NewVersion::generate(algorithm, provider, backend).await?,
                    now,
                )?;
            }
        }
        edit.finish()
    }
}

/// What a rotation did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// The purpose rotated.
    pub purpose: Purpose,
    /// The version that was active before, and decrypts only now.
    pub previous: Option<KeyId>,
    /// The new active version.
    pub current: KeyId,
}

/// The algorithms of a new keyring.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringPolicy {
    /// The algorithm of randomized versions: AES-256-GCM by default, the one Tink and BigQuery
    /// read.
    #[default = "AeadAlgorithm::Aes256Gcm"]
    pub randomized_algorithm: AeadAlgorithm,
    /// The algorithm of deterministic versions, or `None`, the default, for a keyring without
    /// them. Creating one needs the `deterministic` feature.
    pub deterministic_algorithm: Option<DeterministicAlgorithm>,
}

/// How a [`Keyring`] caches its record and writes it.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringOptions {
    /// How long the cached record serves without a store call: 5 minutes by default. The first
    /// call after it revalidates with a conditional read, while the other calls keep using the
    /// cached record. Where the store has no push, it bounds how late a process sees a change,
    /// such as a compromised flag.
    #[default = "Duration::from_secs(5 * 60)"]
    pub record_ttl: Duration,
    /// The least time between two store reads that an unknown key id or a change signal
    /// triggers: 5 seconds by default. Values with random key ids, and a writer that can send
    /// change signals, then cost at most one store read per interval.
    #[default = "Duration::from_secs(5)"]
    pub reload_min_interval: Duration,
    /// Whether to follow the store's change signals, where it has them: `true` by default.
    #[default = "true"]
    pub watch: bool,
    /// The conflicts an administrative write retries before it fails with `RecordConflict`: 5
    /// by default.
    #[default = "5"]
    pub cas_retries: u32,
    /// What `decrypt` does with a value under a compromised version: `Block` by default.
    #[default = "CompromisedReadPolicy::Block"]
    pub compromised_reads: CompromisedReadPolicy,
    /// The cache of unwrapped keys, which may be shared with other keyrings and envelopes, or
    /// `None`, the default, for `DekCache::new(DekCacheOptions::new())`: a TTL of 15 minutes
    /// and 1024 keys.
    pub dek_cache: Option<DekCache>,
}

/// What [`Keyring::decrypt`] does with a value whose version is compromised. A leaked key
/// forges values under its id, so such a value is untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompromisedReadPolicy {
    /// Fails with `KeyVersionCompromised`, decided on the cached record before any unwrap, so
    /// that the key a compromised flag evicted does not come back into the [`DekCache`].
    Block,
    /// Decrypts, with one `WARN` event per value. The read goes through the [`DekCache`], which
    /// is the availability the policy exists for, so it caches again the key that the
    /// compromised flag evicted.
    Allow,
}

/// A decrypted value, with the version that opened it and whether that version is trusted.
pub struct Decrypted<T> {
    /// The value.
    pub value: T,
    /// The version that opened it.
    pub key_id: KeyId,
    /// Whether the version is compromised.
    pub trust: KeyTrust,
}

/// Whether the version that opened a value is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyTrust {
    /// The version is not compromised.
    Trusted,
    /// The version is compromised: whoever holds its leaked key can have sealed the value, so
    /// re-sealing it does not make it trusted.
    Compromised(Compromise),
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests;
