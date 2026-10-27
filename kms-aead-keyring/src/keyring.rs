//! [`Keyring`]: field encryption under the key versions of one keyring record.

use std::sync::Arc;

use kms_aead::backends::AeadBackend;
use kms_aead::cache::{DekCache, DekCacheOutcome};
use kms_aead::formats::{Envelope, Format, Randomized};
use kms_aead::{
    AeadAlgorithm, AeadCipher, DataEncryptionKey, Encrypted, EncryptedDataEncryptionKey,
    KmsAeadDecryptionProvider, Plaintext,
};
use rsb_derive::Builder;

use crate::errors::{
    InteropRequirement, KeyVersionCompromisedError, KeyVersionError, KeyringError, KeyringResult,
    RecordInvalidReason,
};
use crate::metrics::KeyringCall;
use crate::record_cache::{RecordCache, VersionLookup};
use crate::spans::{self, LoadReason};
use crate::store::KeyringStore;
use crate::sweep::ReencryptOutcome;
use crate::{
    Compromise, FieldAad, Interop, KeyAlgorithm, KeyId, KeyVersion, KeyVersionState, KeyringId,
    KeyringRecord, Purpose,
};

#[cfg(feature = "admin")]
mod admin;
#[cfg(feature = "admin")]
pub use admin::{DekReencryption, EncryptedKeyset, KeyringAdmin, KeysetSelection, Rotation};

mod beacon;

mod mac;
pub use mac::MacVerified;

#[cfg(feature = "deterministic")]
mod deterministic;

mod encryptor;
pub use encryptor::Encryptor;

#[cfg(feature = "stream")]
mod stream;

/// A handle on one keyring of a [`KeyringRegistry`](crate::KeyringRegistry), for field
/// encryption under the keyring's key versions: its record lives in the store `S` and is cached
/// in the process, its keys are encrypted by the provider `P`, and AEAD runs on the backend `B`.
///
/// An [`Encryptor`] from [`encryptor`](Self::encryptor) encrypts the fields of one write under the
/// active versions of one record, and `decrypt` decrypts under the version the value names, without
/// a call to the store while the cached record is younger than
/// [`record_ttl`](crate::KeyringRegistryOptions::record_ttl), and without a call to the KMS while
/// the version's key is in the [`DekCache`]. Every decryption of a key for encrypting or for
/// `decrypt` goes through that cache, which drops expired keys only when it is called: a process
/// that can sit idle while it holds keys, and needs the cache's TTL to bound their time in memory,
/// calls [`DekCache::purge_expired`] on [`dek_cache`](Self::dek_cache) from a timer of its own.
///
/// The handles of one keyring share its cached record, so a write through a `KeyringAdmin` of the
/// same registry is seen by all of them at once. Each handle has its own provider and
/// [`KeyringOptions`]. Dropping a handle leaves the keyring open in the registry.
///
/// Its calls need the KMS's decrypt right and read access to the store, and nothing more: a
/// `Keyring` never encrypts a DEK and never writes the record. The calls that do, the lifecycle
/// and the keyset exports, are on `KeyringAdmin`, which the `admin` feature adds, so that an
/// application built without the feature reaches none of them:
///
/// ```compile_fail,E0599
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::KmsAeadDecryptionProvider;
/// use kms_aead_keyring::store::KeyringStore;
/// use kms_aead_keyring::{KeyId, Keyring, KeyringResult, Purpose};
///
/// async fn rotate<S, P, B>(keyring: &Keyring<S, P, B>) -> KeyringResult<KeyId>
/// where
///     S: KeyringStore,
///     P: KmsAeadDecryptionProvider + 'static,
///     B: AeadBackend,
/// {
///     keyring.rotate(Purpose::Randomized).await
/// }
/// ```
pub struct Keyring<S: KeyringStore, P, B> {
    cache: Arc<RecordCache<S, B>>,
    provider: P,
    options: KeyringOptions,
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// A handle on the keyring `cache` holds, with `provider`, whose KEK the record names.
    pub(crate) fn new(cache: Arc<RecordCache<S, B>>, provider: P, options: KeyringOptions) -> Self {
        Self {
            cache,
            provider,
            options,
        }
    }

    /// The handle with `options` instead of the registry's
    /// [`keyring`](crate::KeyringRegistryOptions::keyring) options. The keyring's other handles
    /// keep their own.
    pub fn with_options(self, options: KeyringOptions) -> Self {
        Self { options, ..self }
    }

    /// The keyring's id.
    pub fn id(&self) -> &KeyringId {
        self.cache.id()
    }

    /// The cache of the decrypted keys of this keyring's versions.
    pub fn dek_cache(&self) -> &DekCache {
        self.cache.dek_cache()
    }

    /// The cached record, as the keyring currently uses it. Its
    /// [`encryption_marker`](KeyringRecord::encryption_marker) is the bound of a sweep's query; a
    /// write stores the marker of its [`Encryptor`]'s record instead.
    pub fn record(&self) -> Arc<KeyringRecord> {
        self.cache.record()
    }

    /// Reads the record from the store now, past the TTL and the rate limit, and takes it: for
    /// operators and tests.
    ///
    /// # Errors
    ///
    /// The store's errors, [`KeyringError::RecordInvalid`], and
    /// [`KeyringError::RecordRegressed`] when the stored record moves a version backwards from
    /// the cached one: the cached record stays in use. [`KeyringError::RecordMissing`] when the
    /// store holds no record, which destroys every version of the cached one, or held none at an
    /// earlier read, see [`KeyringRegistry`](crate::KeyringRegistry).
    pub async fn reload(&self) -> KeyringResult<Arc<KeyringRecord>> {
        self.cache.reload(LoadReason::Forced).await
    }

    /// Decrypts `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::KeyVersionUnknown`] when the record has no such version, also after
    ///   one reload, which runs at most once per
    ///   [`reload_min_interval`](crate::KeyringRegistryOptions::reload_min_interval);
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
        let call = KeyringCall::new(
            self.cache.keyring_attribute(),
            "decrypt",
            Purpose::Randomized,
            B::NAME,
        );
        call.decrypted(value, async {
            let key_id = Purpose::Randomized.check(value.key_id())?;
            spans::in_span(
                spans::decrypt(self.id(), Purpose::Randomized, key_id),
                async {
                    let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
                    spans::record_reload(reload);
                    let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                    call.version(version);
                    self.apply_read_policy(version, compromise)?;
                    self.decrypt_cached(&record, version, encrypted_dek, aad, value)
                        .await
                },
            )
            .await
        })
        .await
    }

    /// Decrypts `value` with `aad` and reports which version decrypted it and whether that version
    /// is compromised, without applying the read policy: the call for a sweep, and for a reader
    /// that handles untrusted values itself. A compromised version's key is decrypted through the
    /// provider, never through the [`DekCache`], so that it does not return to the cache.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), without `KeyVersionCompromised`.
    pub async fn decrypt_with_trust<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<Decrypted<T>> {
        let call = KeyringCall::new(
            self.cache.keyring_attribute(),
            "decrypt",
            Purpose::Randomized,
            B::NAME,
        );
        call.decrypted(value, async {
            let key_id = Purpose::Randomized.check(value.key_id())?;
            spans::in_span(
                spans::decrypt(self.id(), Purpose::Randomized, key_id),
                async {
                    let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
                    spans::record_reload(reload);
                    let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                    call.version(version);
                    let (decrypted, trust) = match compromise {
                        None => (
                            self.decrypt_cached(&record, version, encrypted_dek, aad, value)
                                .await?,
                            KeyTrust::Trusted,
                        ),
                        Some(compromise) => (
                            self.decrypt_uncached(version, encrypted_dek, aad, value)
                                .await?,
                            KeyTrust::Compromised(compromise.clone()),
                        ),
                    };
                    Ok(Decrypted {
                        value: decrypted,
                        key_id: version.id(),
                        trust,
                    })
                },
            )
            .await
        })
        .await
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
        match (compromise, self.options.compromised_reads) {
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

    /// Fails with the first requirement of `interop` that encrypting under `version` breaks. The
    /// AAD requirement holds by construction: an AAD that SQL cannot rebuild carries no
    /// [`Interop`].
    fn check_interop(
        &self,
        interop: Option<Interop>,
        record: &KeyringRecord,
        version: &KeyVersion,
    ) -> KeyringResult<()> {
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
            Some(_) if !self.is_asymmetric_kek(record) => Ok(()),
            _ => Err(KeyringError::interop(
                self.id(),
                interop,
                InteropRequirement::Kek(kek.provider().clone()),
            )),
        }
    }

    /// Whether the KEK is asymmetric: the provider encrypts DEKs with a public key, or `record`
    /// holds a DEK encrypted with one, so that an application holding a plain KMS provider decides
    /// as the administration does. The BigQuery and Tink readers decrypt a keyset with their KMS's
    /// symmetric decryption, so no keyset of such a KEK decrypts under either.
    pub(crate) fn is_asymmetric_kek(&self, record: &KeyringRecord) -> bool {
        self.provider.encrypts_with_public_key() || record.holds_public_key_encrypted_dek()
    }

    fn cipher(&self, version: &KeyVersion) -> KeyringResult<AeadCipher<B>> {
        match version.algorithm() {
            KeyAlgorithm::Randomized(algorithm) => Ok(AeadCipher::new(algorithm)?),
            KeyAlgorithm::Deterministic(_) | KeyAlgorithm::Beacon(_) | KeyAlgorithm::Mac(_) => {
                Err(KeyringError::record_invalid(
                    self.id(),
                    RecordInvalidReason::PurposeMismatch(version.id()),
                ))
            }
        }
    }

    /// Decrypts `value` with `aad` under `version` of `record`, whose encrypted DEK is
    /// `encrypted_dek`, with the key through the [`DekCache`].
    async fn decrypt_cached<T: Plaintext>(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        encrypted_dek: &EncryptedDataEncryptionKey,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<T> {
        let cipher = self.cipher(version)?;
        let (decrypted, outcome) = self
            .with_cached_dek(record, version.id(), encrypted_dek, |dek| {
                cipher.decrypt(&aad.bytes, value, dek)
            })
            .await?;
        spans::record_dek_cache(outcome);
        Ok(decrypted?)
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
                && record
                    .withdrawn_deks(&current)
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

    /// Decrypts `value` with a key the provider decrypts for this call only, which never enters the
    /// [`DekCache`].
    async fn decrypt_uncached<T: Plaintext>(
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

    /// Decrypts `value`, an envelope value of kms-aead's `KmsAeadEnvelope` written per call or
    /// store-less, so that a sweep can encrypt it again as a keyring value with
    /// [`Encryptor::encrypt`]; a keyring never writes envelope values. The `aad` is the one the
    /// application gave it and the `algorithm` that of the envelope that wrote it: the read of a
    /// record whose [`EncryptionMarker`](crate::sweep::EncryptionMarker) is
    /// [`EncryptionMarker::ENVELOPE`](crate::sweep::EncryptionMarker::ENVELOPE), until a sweep
    /// re-encrypts it. A value stored as hex is read with `Encrypted::try_from_hex_string`.
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
    pub async fn decrypt_envelope_for_migration<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Envelope>,
        algorithm: AeadAlgorithm,
    ) -> KeyringResult<T> {
        let call =
            KeyringCall::envelope_migration(self.cache.keyring_attribute(), B::NAME, algorithm);
        let decryption = spans::in_span(spans::decrypt_envelope_for_migration(self.id()), async {
            let (bare, encrypted_dek) = value.separate()?;
            let cipher = AeadCipher::<B>::new(algorithm)?;
            let (decrypted, outcome) = self
                .dek_cache()
                .with_dek(&self.provider, &encrypted_dek, |dek| {
                    cipher.decrypt_bare(aad, &bare, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(decrypted?)
        });
        call.decrypted(value, decryption).await
    }
}

/// How a [`Keyring`] handle reads values under a compromised version, and how the writes of a
/// `KeyringAdmin` that holds it retry. The handles of one keyring may differ in them; the record
/// cache they share is configured by [`KeyringRegistryOptions`](crate::KeyringRegistryOptions).
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringOptions {
    /// The conflicts a write of a `KeyringAdmin` retries before it fails with `RecordConflict`:
    /// [`DEFAULT_CAS_RETRIES`](Self::DEFAULT_CAS_RETRIES) by default.
    #[default = "Self::DEFAULT_CAS_RETRIES"]
    pub cas_retries: u32,
    /// What `decrypt` does with a value under a compromised version:
    /// [`DEFAULT_COMPROMISED_READS`](Self::DEFAULT_COMPROMISED_READS) by default.
    #[default = "Self::DEFAULT_COMPROMISED_READS"]
    pub compromised_reads: CompromisedReadPolicy,
}

impl KeyringOptions {
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

/// A decrypted value, with the version that decrypted it and whether that version is trusted.
#[non_exhaustive]
pub struct Decrypted<T> {
    /// The value.
    pub value: T,
    /// The version that decrypted it.
    pub key_id: KeyId,
    /// Whether the version is compromised.
    pub trust: KeyTrust,
}

/// A value encrypted again under the active version of its purpose, by [`Encryptor::reencrypt`] or
/// `Encryptor::reencrypt_deterministic`, with the trust of the version the old value was read
/// under.
#[non_exhaustive]
pub struct Reencrypted<T, F: Format> {
    /// The value under the active version, to write in place of the old one.
    pub value: Encrypted<T, F>,
    /// Whether the version the old value was read under is compromised: a value forged under a
    /// leaked key reads as trusted once it is re-encrypted, so the caller decides before it writes.
    pub trust: KeyTrust,
}

impl<T, F: Format> Reencrypted<T, F> {
    /// The sweep outcome of this re-encryption: [`ReencryptOutcome::Reencrypted`], with
    /// `from_compromised` set when [`trust`](Self::trust) is [`KeyTrust::Compromised`].
    ///
    /// A re-encryption that found the value current returns no `Reencrypted`; the outcome of the
    /// `Option` that `Encryptor::reencrypt` returns is `ReencryptOutcome::from(&option)`.
    ///
    /// ```
    /// use kms_aead_keyring::formats::Randomized;
    /// use kms_aead_keyring::sweep::ReencryptOutcome;
    /// use kms_aead_keyring::{Encrypted, Reencrypted};
    ///
    /// fn to_write(
    ///     reencrypted: Reencrypted<String, Randomized>,
    /// ) -> (Encrypted<String, Randomized>, ReencryptOutcome) {
    ///     let outcome = reencrypted.outcome();
    ///     (reencrypted.value, outcome)
    /// }
    /// ```
    pub fn outcome(&self) -> ReencryptOutcome {
        ReencryptOutcome::Reencrypted {
            from_compromised: matches!(self.trust, KeyTrust::Compromised(_)),
        }
    }
}

/// Whether the version that decrypted a value is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyTrust {
    /// The version is not compromised.
    Trusted,
    /// The version is compromised: whoever holds its leaked key can have encrypted the value, so
    /// re-encrypting it does not make it trusted.
    Compromised(Compromise),
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests;
