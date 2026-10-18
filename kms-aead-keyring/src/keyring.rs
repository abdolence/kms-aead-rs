//! [`Keyring`]: field encryption under the key versions of one keyring record.

use std::marker::PhantomData;
use std::sync::Arc;
use std::time::Duration;

use jiff::Timestamp;
use kms_aead::backends::AeadBackend;
use kms_aead::cache::{DekCache, DekCacheOptions, DekCacheOutcome};
use kms_aead::formats::{Envelope, Randomized};
use kms_aead::{
    AeadAlgorithm, AeadCipher, BeaconAlgorithm, BeaconMac, DataEncryptionKey,
    DeterministicAlgorithm, Encrypted, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider,
    Plaintext,
};
use rsb_derive::Builder;
use tokio::task::AbortHandle;

use crate::errors::{
    InteropRequirement, KekMismatchError, KeyVersionCompromisedError, KeyVersionError,
    KeyringError, KeyringResult, RecordInvalidReason,
};
use crate::purpose::unreserved;
use crate::record::{withdrawn_deks, NewVersion, RecordEdit};
use crate::record_cache::RecordCache;
use crate::spans::{self, LoadReason};
use crate::store::{KeyringStore, Stored, Swap};
use crate::{
    Algorithms, Compromise, FieldAad, Interop, KeyAlgorithm, KeyId, KeyVersion, KeyVersionState,
    KeyringId, KeyringRecord, Purpose,
};

mod beacon;

#[cfg(feature = "deterministic")]
mod deterministic;

mod export;
pub use export::{EncryptedKeyset, KeysetSelection};

/// Field encryption under the key versions of one keyring, whose record lives in the store `S`
/// and is cached in the process, with keys encrypted by the provider `P` and AEAD on the backend
/// `B`.
///
/// `encrypt` seals under the active version of the purpose, and `decrypt` opens under the
/// version the value names, without a call to the store while the cached record is younger than
/// [`record_ttl`](KeyringOptions::record_ttl), and without a call to the KMS while the
/// version's key is in the [`DekCache`]. Every decryption of `encrypt` and `decrypt` goes through
/// that cache, which drops expired keys only when it is called: a process that can sit idle
/// while it holds keys, and needs the cache's TTL to bound their time in memory, calls
/// [`DekCache::purge_expired`] on [`dek_cache`](Self::dek_cache) from a timer of its own.
///
/// The administrative calls, `create`, `rotate`, `promote`, `mark_compromised`, `retire`,
/// `reinstate`, `destroy`, `reencrypt_deks` and `change_algorithm`, write the record, and `create`,
/// `rotate`, `mark_compromised`, `reencrypt_deks` and `change_algorithm` also encrypt DEKs, so they
/// need the KMS's encrypt right. They run under an administrative principal, in a job, while the
/// serving processes only decrypt keys and read the store.
///
/// Where the store has push, a task on the current tokio runtime follows the record's change
/// signals for as long as the keyring lives.
pub struct Keyring<S: KeyringStore, P, B> {
    cache: Arc<RecordCache<S>>,
    provider: P,
    compromised_reads: CompromisedReadPolicy,
    cas_retries: u32,
    _watch: Option<WatchTask>,
    backend: PhantomData<B>,
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// Opens the keyring `id` from `store`: loads its record once and starts following the
    /// store's change signals. `provider` decrypts the record's keys.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::RecordMissing`] when the store holds no record,
    /// [`KeyringError::RecordInvalid`] when it holds an invalid one, and
    /// [`KeyringError::KekMismatch`] when the provider's KEK is not the one the record names.
    pub async fn open(
        store: S,
        provider: P,
        id: KeyringId,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let stored = RecordCache::read(&store, &id)
            .await?
            .ok_or(KeyringError::RecordMissing(id))?;
        Self::start(store, provider, options, stored).await
    }

    /// Creates the record of the keyring `id`, with one active version of each purpose `policy`
    /// names an algorithm for, and opens it. Encrypts one key per version, so it needs the KMS's
    /// encrypt right.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors, [`KeyringError::RecordExists`] when the store
    /// already holds a record, `UNSUPPORTED_ALGORITHM` from kms-aead when `B` does not implement
    /// the policy's algorithm, and [`KeyringError::DeterministicDisabled`] for a deterministic
    /// algorithm without the `deterministic` feature.
    pub async fn create(
        store: S,
        provider: P,
        id: KeyringId,
        policy: KeyringPolicy,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let record = policy.new_record::<P, B>(id, &provider).await?;
        match store.compare_and_swap(&record, None).await? {
            Swap::Written(revision) => {
                Self::start(store, provider, options, Stored { record, revision }).await
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
        id: KeyringId,
        policy: KeyringPolicy,
        options: KeyringOptions,
    ) -> KeyringResult<Self> {
        let stored = match RecordCache::read(&store, &id).await? {
            Some(stored) => stored,
            None => {
                let record = policy.new_record::<P, B>(id.clone(), &provider).await?;
                match store.compare_and_swap(&record, None).await? {
                    Swap::Written(revision) => Stored { record, revision },
                    Swap::Conflict => RecordCache::read(&store, &id)
                        .await?
                        .ok_or(KeyringError::RecordMissing(id))?,
                }
            }
        };
        Self::start(store, provider, options, stored).await
    }

    /// The keyring's id.
    pub fn id(&self) -> &KeyringId {
        self.cache.id()
    }

    /// The cache of the decrypted keys of this keyring's versions.
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
        self.cache.reload(LoadReason::Forced).await
    }

    /// Seals `value` with `aad` under the active randomised version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the keyring has none, which follows a
    /// `mark_compromised` whose new key could not be encrypted; [`KeyringError::Interop`] when
    /// sealing breaks the [`Interop`] requirement `aad` carries; [`KeyringError::KmsAead`] with
    /// code `INVALID_PLAINTEXT` when the value does not encode; and the provider's error when
    /// the version's key is not in the [`DekCache`] and cannot be decrypted.
    pub async fn encrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T, Randomized>> {
        let span = spans::encrypt(self.id(), Purpose::Randomized, Some(B::NAME));
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let (version, encrypted_dek) = record
                .active_dek(Purpose::Randomized)
                .ok_or_else(|| KeyringError::no_active_version(self.id(), Purpose::Randomized))?;
            spans::record_sealing_version(version);
            self.check_interop(aad.interop, version)?;
            let cipher = self.cipher(version)?;
            let (sealed, outcome) = self
                .with_cached_dek(&record, version.id(), encrypted_dek, |dek| {
                    cipher.encrypt(version.id(), &aad.bytes, value, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(sealed?)
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
    ///   any decryption;
    /// - [`KeyringError::KmsAead`] with code `DECRYPT` when the value is not authentic under the
    ///   version's key and `aad`, and the provider's error when the key cannot be decrypted;
    /// - [`KeyringError::ReservedKeyId`] and [`KeyringError::KeyPurposeMismatch`], before any
    ///   store or KMS call, when the value's key id is reserved or deterministic;
    /// - [`KeyringError::KmsAead`] with code `INVALID_PLAINTEXT` when the bytes do not decode as `T`.
    pub async fn decrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<T> {
        let key_id = Purpose::Randomized.check(value.key_id())?;
        spans::in_span(
            spans::decrypt(self.id(), Purpose::Randomized, key_id),
            async {
                let (record, reload) = self.cache.find(key_id).await;
                spans::record_reload(reload);
                let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                self.apply_read_policy(version, compromise)?;
                self.open_cached(&record, version, encrypted_dek, aad, value)
                    .await
            },
        )
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy: the call for a sweep, and for a reader
    /// that handles untrusted values itself. A compromised version's key is decrypted through
    /// the provider, never through the [`DekCache`], so that it does not return to the cache.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), without `KeyVersionCompromised`.
    pub async fn decrypt_with_trust<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<Decrypted<T>> {
        let key_id = Purpose::Randomized.check(value.key_id())?;
        spans::in_span(
            spans::decrypt(self.id(), Purpose::Randomized, key_id),
            async {
                let (record, reload) = self.cache.find(key_id).await;
                spans::record_reload(reload);
                let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                let (opened, trust) = match compromise {
                    None => (
                        self.open_cached(&record, version, encrypted_dek, aad, value)
                            .await?,
                        KeyTrust::Trusted,
                    ),
                    Some(compromise) => (
                        self.open_uncached(version, encrypted_dek, aad, value)
                            .await?,
                        KeyTrust::Compromised(compromise.clone()),
                    ),
                };
                Ok(Decrypted {
                    value: opened,
                    key_id: version.id(),
                    trust,
                })
            },
        )
        .await
    }

    /// Stages a new version of `purpose`, with the record's algorithm for it, and returns its
    /// key id. The version is [`Pending`](KeyVersionState::Pending): every process decrypts under
    /// it once its record refreshes, and none encrypts under it until
    /// [`promote`](Self::promote) makes it active.
    ///
    /// Promote it only after the longest time any process may run without a successful refresh
    /// of its record, from [`staged_at`](KeyVersion::staged_at): a process that has not seen the
    /// pending version reads a value under it as an unknown key id, and reloads its record first.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors, [`KeyringError::NoAlgorithm`] for a purpose the
    /// record names no algorithm for, [`KeyringError::InvalidTransition`] with
    /// [`Transition::Rotate`](crate::Transition::Rotate) naming the pending version when the
    /// purpose has one already, [`KeyringError::RecordRegressed`] when the stored record moves
    /// backwards from the cached one, and [`KeyringError::RecordConflict`] after
    /// [`cas_retries`](KeyringOptions::cas_retries) conflicts.
    pub async fn rotate(&self, purpose: Purpose) -> KeyringResult<KeyId> {
        spans::in_span(spans::rotate(self.id(), purpose), async {
            let algorithm = self.algorithm_of(&self.record(), purpose)?;
            let new = self.new_version(algorithm).await?;
            let staged = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let algorithm = self.algorithm_of(edit.record(), purpose)?;
                    let new = if algorithm == new.algorithm {
                        new.clone()
                    } else {
                        // Another writer changed the purpose's algorithm since the key was made.
                        self.new_version(algorithm).await?
                    };
                    edit.stage(new, Timestamp::now())
                })
                .await?;
            spans::record_rotation(None, staged);
            Ok(staged)
        })
        .await
    }

    /// Makes the pending version `key_id` the active version of its purpose; the version it
    /// replaces decrypts only. Processes on the old record keep sealing under the previous
    /// version until their record refreshes, and those values decrypt.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`], before any store call, for a reserved key id; the
    /// store's errors, [`KeyringError::KeyVersionUnknown`], [`KeyringError::InvalidTransition`]
    /// for a version that is not pending, and the errors of a write as for
    /// [`rotate`](Self::rotate).
    pub async fn promote(&self, key_id: KeyId) -> KeyringResult<Rotation> {
        unreserved(key_id)?;
        spans::in_span(spans::promote(self.id(), key_id), async {
            let rotation = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.promote(key_id, Timestamp::now())
                })
                .await?;
            spans::record_rotation(rotation.previous, rotation.current);
            Ok(rotation)
        })
        .await
    }

    /// Makes `algorithm` the one new versions of its purpose use, and stages a version of it as
    /// [`rotate`](Self::rotate) does, returning its key id.
    ///
    /// # Errors
    ///
    /// As [`rotate`](Self::rotate), and `UNSUPPORTED_ALGORITHM` from kms-aead when the backend
    /// does not implement `algorithm`.
    pub async fn change_algorithm(&self, algorithm: KeyAlgorithm) -> KeyringResult<KeyId> {
        spans::in_span(spans::rotate(self.id(), algorithm.purpose()), async {
            let new = self.new_version(algorithm).await?;
            let staged = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let now = Timestamp::now();
                    edit.set_algorithm(algorithm, now);
                    edit.stage(new.clone(), now)
                })
                .await?;
            spans::record_rotation(None, staged);
            Ok(staged)
        })
        .await
    }

    /// Flags the version `key_id` compromised, for good, and drops its key from this process's
    /// [`DekCache`] before returning; other processes drop it when their record refreshes.
    ///
    /// For the active version, it also adds a new version in the same write, active at once
    /// rather than pending, and returns the rotation: every encryption under the compromised key
    /// stops as soon as each process refreshes, and the processes that have not seen the new
    /// version yet reload their record when they read a value under it. A pending version of the
    /// purpose stays pending. When the KMS cannot encrypt the new key, during an outage or without
    /// the encrypt right, it writes the flag alone, logs a `WARN` naming the error and returns
    /// `Ok(None)`: the purpose then has no active version, and `encrypt` fails with
    /// `NoActiveVersion` until a version is promoted. For any other version it returns
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`], before any store call, for a reserved key id; the
    /// store's errors, [`KeyringError::KeyVersionUnknown`],
    /// [`KeyringError::InvalidTransition`] for a pending, destroyed or already compromised
    /// version, and the errors of a write as for [`rotate`](Self::rotate). A pending version
    /// never sealed a value: [`destroy`](Self::destroy) it instead.
    pub async fn mark_compromised(
        &self,
        key_id: KeyId,
        note: Option<String>,
    ) -> KeyringResult<Option<Rotation>> {
        unreserved(key_id)?;
        spans::in_span(spans::mark_compromised(self.id(), key_id), async {
            // `None` when the cached record has no active `key_id`, and `Some(None)` when the
            // replacement's key could not be encrypted, which is not tried again in the write.
            let cached = self.record();
            let prepared = match cached.version(key_id) {
                Some(version) if version.state() == KeyVersionState::Active => {
                    Some(self.replacement(&cached, version).await)
                }
                _ => None,
            };
            let rotation = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let record = edit.record();
                    let replacement = match record.version(key_id) {
                        Some(version) if version.state() == KeyVersionState::Active => {
                            match &prepared {
                                Some(Some(new))
                                    if record.algorithms().of(new.algorithm.purpose())
                                        == Some(new.algorithm) =>
                                {
                                    Some(new.clone())
                                }
                                Some(None) => None,
                                // The record changed since the cached one: another writer
                                // promoted this version or changed its purpose's algorithm.
                                _ => self.replacement(record, version).await,
                            }
                        }
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
    /// [`KeyringError::ReservedKeyId`], before any store call, for a reserved key id; the
    /// store's errors, [`KeyringError::KeyVersionUnknown`],
    /// [`KeyringError::InvalidTransition`] for any version that is not decrypt-only, and the
    /// errors of a write as for [`rotate`](Self::rotate).
    pub async fn retire(&self, key_id: KeyId) -> KeyringResult<()> {
        unreserved(key_id)?;
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
        unreserved(key_id)?;
        spans::in_span(spans::reinstate(self.id(), key_id), async {
            self.cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.reinstate(key_id, Timestamp::now())
                })
                .await
        })
        .await
    }

    /// Removes a retired or pending version's encrypted DEK from the record: the values under it
    /// can never be read again, from this record. The version stays, so that its id is never
    /// reused.
    ///
    /// # Errors
    ///
    /// As [`retire`](Self::retire), for any version that is neither retired nor pending.
    pub async fn destroy(&self, key_id: KeyId) -> KeyringResult<()> {
        unreserved(key_id)?;
        spans::in_span(spans::destroy(self.id(), key_id), async {
            self.cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    edit.destroy(key_id, Timestamp::now())
                })
                .await
        })
        .await
    }

    /// Decrypts and encrypts again the key of every version that holds one, so that all of them sit
    /// under the KEK's current version after the KEK rotated in the KMS. No value changes. The
    /// keys are decrypted through the provider, never through the [`DekCache`]. Returns the
    /// number of versions encrypted again.
    ///
    /// # Errors
    ///
    /// The provider's errors, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn reencrypt_deks(&self) -> KeyringResult<usize> {
        spans::in_span(spans::reencrypt_deks(self.id()), async {
            let mut reencrypted = Vec::new();
            for (_, encrypted_dek) in self.record().encrypted_deks() {
                let new_encrypted_dek = self.reencrypted(&encrypted_dek).await?;
                reencrypted.push((encrypted_dek, new_encrypted_dek));
            }
            let versions = self
                .cache
                .write(self.cas_retries, async |edit: &mut RecordEdit| {
                    let encrypted_deks = edit.record().encrypted_deks();
                    for (key_id, encrypted_dek) in &encrypted_deks {
                        let prepared = reencrypted
                            .iter()
                            .find(|(held, _)| held == encrypted_dek)
                            .map(|(_, new_encrypted_dek)| new_encrypted_dek.clone());
                        let new_encrypted_dek = match prepared {
                            Some(new_encrypted_dek) => new_encrypted_dek,
                            // A version that another writer added or encrypted again meanwhile.
                            None => self.reencrypted(encrypted_dek).await?,
                        };
                        edit.replace_dek(*key_id, new_encrypted_dek, Timestamp::now())?;
                    }
                    Ok(encrypted_deks.len())
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
        options: KeyringOptions,
        stored: Stored<S::Revision>,
    ) -> KeyringResult<Self> {
        let kek = provider.kek();
        if stored.record.kek() != kek {
            return Err(KeyringError::KekMismatch(Box::new(KekMismatchError {
                keyring: stored.record.id().clone(),
                recorded: stored.record.kek().clone(),
                provider: kek.clone(),
            })));
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
            compromised_reads: options.compromised_reads,
            cas_retries: options.cas_retries,
            _watch: watch,
            backend: PhantomData,
        })
    }

    /// The version `key_id` of `record`, its encrypted DEK and its compromised flag, or the error
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
        let Some((encrypted_dek, compromise)) = version.readable_dek() else {
            spans::read_refused(self.id(), version);
            return Err(self.unreadable(version));
        };
        Ok((version, encrypted_dek, compromise))
    }

    /// The error of a read under `version`, which holds no readable key: `KeyVersionDestroyed`
    /// or `KeyVersionRetired`.
    fn unreadable(&self, version: &KeyVersion) -> KeyringError {
        let error = KeyVersionError {
            keyring: self.id().clone(),
            key_id: version.id(),
        };
        match version.state() {
            KeyVersionState::Destroyed => KeyringError::KeyVersionDestroyed(error),
            _ => KeyringError::KeyVersionRetired(error),
        }
    }

    /// Fails with `KeyVersionCompromised` for a compromised version under
    /// [`CompromisedReadPolicy::Block`], and logs the read under `Allow`.
    fn apply_read_policy(
        &self,
        version: &KeyVersion,
        compromise: Option<&Compromise>,
    ) -> KeyringResult<()> {
        match (compromise, self.compromised_reads) {
            (None, _) => Ok(()),
            (Some(compromise), CompromisedReadPolicy::Block) => Err(
                KeyringError::KeyVersionCompromised(KeyVersionCompromisedError {
                    keyring: self.id().clone(),
                    key_id: version.id(),
                    compromise: compromise.clone(),
                }),
            ),
            (Some(_), CompromisedReadPolicy::Allow) => {
                spans::compromised_read_allowed(self.id(), version.id());
                Ok(())
            }
        }
    }

    /// Fails with the first requirement of `interop` that sealing under `version` breaks. The
    /// AAD requirement holds by construction: an AAD that SQL cannot rebuild carries no
    /// [`Interop`].
    fn check_interop(&self, interop: Option<Interop>, version: &KeyVersion) -> KeyringResult<()> {
        let Some(interop) = interop else {
            return Ok(());
        };
        let kek = self.provider.kek();
        if interop.key_type(version.algorithm()).is_none() {
            return Err(KeyringError::interop(
                self.id(),
                interop,
                InteropRequirement::Algorithm(version.algorithm()),
            ));
        }
        match interop.key_uri(kek) {
            Some(_) => Ok(()),
            None => Err(KeyringError::interop(
                self.id(),
                interop,
                InteropRequirement::Kek(kek.provider().clone()),
            )),
        }
    }

    fn cipher(&self, version: &KeyVersion) -> KeyringResult<AeadCipher<B>> {
        match version.algorithm() {
            KeyAlgorithm::Randomized(algorithm) => Ok(AeadCipher::new(algorithm)?),
            KeyAlgorithm::Deterministic(_) | KeyAlgorithm::Beacon(_) => {
                Err(KeyringError::record_invalid(
                    self.id(),
                    RecordInvalidReason::PurposeMismatch(version.id()),
                ))
            }
        }
    }

    /// Opens `value` with `aad` under `version` of `record`, whose encrypted DEK is
    /// `encrypted_dek`, with the key through the [`DekCache`].
    async fn open_cached<T: Plaintext>(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        encrypted_dek: &EncryptedDataEncryptionKey,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<T> {
        let cipher = self.cipher(version)?;
        let (opened, outcome) = self
            .with_cached_dek(record, version.id(), encrypted_dek, |dek| {
                cipher.decrypt(&aad.bytes, value, dek)
            })
            .await?;
        spans::record_dek_cache(outcome);
        Ok(opened?)
    }

    /// Runs `use_dek` with the key that `encrypted_dek` holds, through the [`DekCache`], and
    /// returns its result and where the key came from, for the caller to record. `record` is the
    /// record `encrypted_dek` was read from, as the encrypted DEK of `key_id`.
    ///
    /// A refresh evicts the keys it takes out of use once, when it takes the new record. A call
    /// that read `encrypted_dek` from the record before and decrypts it after that eviction caches
    /// it again, so on a miss the key is evicted here when the cached record has since withdrawn
    /// it.
    async fn with_cached_dek<T>(
        &self,
        record: &KeyringRecord,
        key_id: KeyId,
        encrypted_dek: &EncryptedDataEncryptionKey,
        use_dek: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KeyringResult<(T, DekCacheOutcome)> {
        let (result, outcome) = self
            .dek_cache()
            .with_dek(&self.provider, encrypted_dek, use_dek)
            .await?;
        if outcome == DekCacheOutcome::Miss {
            let current = self.cache.record();
            if !std::ptr::eq(record, &*current)
                && withdrawn_deks(record, &current)
                    .any(|withdrawn| withdrawn == (key_id, encrypted_dek))
            {
                self.dek_cache()
                    .invalidate(self.provider.kek(), encrypted_dek);
            }
        }
        Ok((result, outcome))
    }

    /// Runs `use_dek` with the key that `encrypted_dek` holds, which the provider decrypts for this
    /// call only and which never enters the [`DekCache`].
    async fn with_uncached_dek<T>(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
        use_dek: impl FnOnce(&DataEncryptionKey) -> T,
    ) -> KeyringResult<T> {
        let (result, _) = DekCache::disabled()
            .with_dek(&self.provider, encrypted_dek, use_dek)
            .await?;
        spans::record_dek_cache_bypassed();
        Ok(result)
    }

    /// A new version to replace `replaced`, the active version of `record` being flagged
    /// compromised, or `None`, with a `WARN`, when its key cannot be encrypted: the flag goes in
    /// without it.
    async fn replacement(
        &self,
        record: &KeyringRecord,
        replaced: &KeyVersion,
    ) -> Option<NewVersion> {
        let new = match self.algorithm_of(record, replaced.algorithm().purpose()) {
            Ok(algorithm) => self.new_version(algorithm).await,
            Err(error) => Err(error),
        };
        new.inspect_err(|error| {
            spans::compromised_without_rotation(self.id(), replaced.id(), error)
        })
        .ok()
    }

    /// Opens `value` with a key the provider decrypts for this call only, which never enters the
    /// [`DekCache`].
    async fn open_uncached<T: Plaintext>(
        &self,
        version: &KeyVersion,
        encrypted_dek: &EncryptedDataEncryptionKey,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<T> {
        let cipher = self.cipher(version)?;
        Ok(self
            .with_uncached_dek(encrypted_dek, |dek| cipher.decrypt(&aad.bytes, value, dek))
            .await??)
    }

    /// The algorithm `record` names for new versions of `purpose`, or `NoAlgorithm`.
    fn algorithm_of(
        &self,
        record: &KeyringRecord,
        purpose: Purpose,
    ) -> KeyringResult<KeyAlgorithm> {
        record
            .algorithms()
            .of(purpose)
            .ok_or_else(|| KeyringError::no_algorithm(self.id(), purpose))
    }

    /// A new version of `algorithm`, with its key encrypted. Made before a write takes the record,
    /// so that no KMS call runs while the record is held, and a conflict retries with the same key.
    async fn new_version(&self, algorithm: KeyAlgorithm) -> KeyringResult<NewVersion> {
        NewVersion::generate::<P, B>(algorithm, &self.provider).await
    }

    /// `encrypted_dek` decrypted through the provider and encrypted again. What the KMS decrypts
    /// is the serialised Tink key it encrypted, so it is encrypted again as it is.
    async fn reencrypted(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KeyringResult<EncryptedDataEncryptionKey> {
        let dek = self
            .provider
            .decrypt_data_encryption_key(encrypted_dek)
            .await?;
        Ok(self.provider.encrypt_data_encryption_key(&dek).await?)
    }

    /// Opens `value`, an envelope value of kms-aead's `KmsAeadEnvelope` written per call or
    /// store-less, with the `aad` the application gave it and the `algorithm` of the envelope
    /// that wrote it: the read of a record whose [`SealMarker`](crate::sweep::SealMarker) says
    /// [`Envelope`](crate::sweep::SealFormat::Envelope), until a sweep re-seals it. A value stored as hex
    /// is read with `Encrypted::try_from_hex_string`.
    ///
    /// The value's key is decrypted by this keyring's provider, so it must have been encrypted by
    /// the keyring's KEK, and through the keyring's [`DekCache`], where a store-less envelope's
    /// values share one entry. It reads Tink's KMS envelope, the layout kms-aead 0.30 writes; a
    /// value in a layout of kms-aead 0.29 or earlier is upgraded first, with kms-aead's
    /// `KmsAeadEnvelope::upgrade_legacy_value`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] with the errors of `Encrypted::separate` when the value is not in
    /// Tink's KMS envelope, `UNSUPPORTED_ALGORITHM` when `B` does not implement `algorithm`, the
    /// provider's error when the key does not decrypt, `INVALID_KEY_FORMAT` when what it decrypts
    /// is not a serialised Tink key, code `DECRYPT` when the value is not authentic under it and
    /// `aad`, and `INVALID_PLAINTEXT` when the bytes do not decode as `T`.
    pub async fn decrypt_envelope<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Envelope>,
        algorithm: AeadAlgorithm,
    ) -> KeyringResult<T> {
        spans::in_span(spans::decrypt_envelope(self.id()), async {
            let (bare, encrypted_dek) = value.separate()?;
            let cipher = AeadCipher::<B>::new(algorithm)?;
            let (opened, outcome) = self
                .dek_cache()
                .with_dek(&self.provider, &encrypted_dek, |dek| {
                    cipher.decrypt_bare(aad, &bare, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(opened?)
        })
        .await
    }
}

impl NewVersion {
    /// A version with a new key for `algorithm`, from the KMS generator when the provider uses
    /// one and from the CSPRNG of `B` otherwise, encrypted by `provider`.
    async fn generate<P, B>(algorithm: KeyAlgorithm, provider: &P) -> KeyringResult<Self>
    where
        P: KmsAeadEncryptionProvider + Sync,
        B: AeadBackend,
    {
        let encrypted_dek = match algorithm {
            KeyAlgorithm::Randomized(algorithm) => {
                let (_, encrypted_dek) = AeadCipher::<B>::new(algorithm)?
                    .generate_encrypted_dek(provider)
                    .await?;
                encrypted_dek
            }
            #[cfg(feature = "deterministic")]
            KeyAlgorithm::Deterministic(algorithm) => {
                let (_, encrypted_dek) = kms_aead::DeterministicCipher::<B>::new(algorithm)?
                    .generate_encrypted_dek(provider)
                    .await?;
                encrypted_dek
            }
            #[cfg(not(feature = "deterministic"))]
            KeyAlgorithm::Deterministic(_) => return Err(KeyringError::DeterministicDisabled),
            KeyAlgorithm::Beacon(algorithm) => {
                let (_, encrypted_dek) = BeaconMac::<B>::new(algorithm)
                    .generate_encrypted_dek(provider)
                    .await?;
                encrypted_dek
            }
        };
        Ok(Self {
            algorithm,
            encrypted_dek,
        })
    }
}

/// Stops the task that follows the store's change signals when the keyring is dropped.
struct WatchTask(AbortHandle);

impl WatchTask {
    /// Starts following the store's signals for `cache`'s keyring, or returns `None`, with a
    /// `WARN` for a failure, when the store has no push, its listener does not start, or no
    /// tokio runtime runs the call: the record TTL alone then bounds how late a change is seen.
    async fn start<S: KeyringStore>(cache: &Arc<RecordCache<S>>) -> Option<Self> {
        // Checked before `watch`, since a store's listener may spawn a task of its own, and
        // `tokio::spawn` panics outside a runtime.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            spans::watch_without_runtime(cache.id());
            return None;
        };
        let watch = match cache.store().watch(cache.id()).await {
            Ok(watch) => watch?,
            Err(error) => {
                spans::watch_failed(cache.id(), &error);
                return None;
            }
        };
        let task = runtime.spawn(RecordCache::follow(
            Arc::downgrade(cache),
            cache.id().clone(),
            cache.reload_min_interval(),
            watch,
        ));
        Some(Self(task.abort_handle()))
    }
}

impl Drop for WatchTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

impl KeyringPolicy {
    /// The record of a new keyring `id` under this policy, with one active version per purpose
    /// it names an algorithm for, each encrypted by `provider`.
    async fn new_record<P, B>(&self, id: KeyringId, provider: &P) -> KeyringResult<KeyringRecord>
    where
        P: KmsAeadEncryptionProvider + Sync,
        B: AeadBackend,
    {
        let now = Timestamp::now();
        let algorithms = Algorithms::new(
            self.randomized_algorithm,
            self.deterministic_algorithm,
            self.beacon_algorithm,
        );
        let mut edit = RecordEdit::from(KeyringRecord::new(
            id,
            provider.kek().clone(),
            algorithms,
            now,
        ));
        for purpose in Purpose::ALL {
            if let Some(algorithm) = algorithms.of(purpose) {
                let new = NewVersion::generate::<P, B>(algorithm, provider).await?;
                let key_id = edit.stage(new, now)?;
                edit.promote(key_id, now)?;
            }
        }
        edit.finish()
    }
}

/// What a promotion, or the replacement of a compromised active version, did.
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
    /// The algorithm of randomised versions:
    /// [`DEFAULT_RANDOMIZED_ALGORITHM`](Self::DEFAULT_RANDOMIZED_ALGORITHM) by default.
    #[default = "Self::DEFAULT_RANDOMIZED_ALGORITHM"]
    pub randomized_algorithm: AeadAlgorithm,
    /// The algorithm of deterministic versions, or `None`, the default, for a keyring without
    /// them. Creating one needs the `deterministic` feature.
    pub deterministic_algorithm: Option<DeterministicAlgorithm>,
    /// The algorithm of beacon versions, or `None`, the default, for a keyring without them.
    pub beacon_algorithm: Option<BeaconAlgorithm>,
}

impl KeyringPolicy {
    /// The default [`randomized_algorithm`](Self::randomized_algorithm): AES-256-GCM, the one
    /// Tink and BigQuery read.
    pub const DEFAULT_RANDOMIZED_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;
}

/// How a [`Keyring`] caches its record and writes it.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringOptions {
    /// How long the cached record serves without a store call:
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
    /// The conflicts an administrative write retries before it fails with `RecordConflict`:
    /// [`DEFAULT_CAS_RETRIES`](Self::DEFAULT_CAS_RETRIES) by default.
    #[default = "Self::DEFAULT_CAS_RETRIES"]
    pub cas_retries: u32,
    /// What `decrypt` does with a value under a compromised version:
    /// [`DEFAULT_COMPROMISED_READS`](Self::DEFAULT_COMPROMISED_READS) by default.
    #[default = "Self::DEFAULT_COMPROMISED_READS"]
    pub compromised_reads: CompromisedReadPolicy,
    /// The cache of decrypted keys, which may be shared with other keyrings and envelopes, or
    /// `None`, the default, for `DekCache::new(DekCacheOptions::new())`, with kms-aead's
    /// [`DekCacheOptions::DEFAULT_TTL`] and [`DekCacheOptions::DEFAULT_MAX_ENTRIES`].
    pub dek_cache: Option<DekCache>,
}

impl KeyringOptions {
    /// The default [`record_ttl`](Self::record_ttl): 5 minutes.
    pub const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(5 * 60);
    /// The default [`reload_min_interval`](Self::reload_min_interval): 5 seconds.
    pub const DEFAULT_RELOAD_MIN_INTERVAL: Duration = Duration::from_secs(5);
    /// The default [`watch`](Self::watch): `true`, following the store's change signals.
    pub const DEFAULT_WATCH: bool = true;
    /// The default [`cas_retries`](Self::cas_retries): 5.
    pub const DEFAULT_CAS_RETRIES: u32 = 5;
    /// The default [`compromised_reads`](Self::compromised_reads):
    /// [`CompromisedReadPolicy::Block`].
    pub const DEFAULT_COMPROMISED_READS: CompromisedReadPolicy = CompromisedReadPolicy::Block;
}

/// What [`Keyring::decrypt`] does with a value whose version is compromised. A leaked key
/// forges values under its id, so such a value is untrusted data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompromisedReadPolicy {
    /// Fails with `KeyVersionCompromised`, decided on the cached record before any decryption, so
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
