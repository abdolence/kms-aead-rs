use std::future::Future;
use std::num::NonZeroU64;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use rsb_derive::Builder;
use secret_vault_value::SecretValue;
use tracing::Span;

use crate::cache::{DekCache, DekCacheOptions, DekCacheOutcome};
use crate::errors::{KmsAeadError, KmsAeadSystemError};
use crate::formats::Envelope;
use crate::{
    spans, AeadAlgorithm, AeadBackend, AeadCipher, Beacon, BeaconAlgorithm, BeaconBits, BeaconMac,
    CipherText, CipherTextWithEncryptedKey, DataEncryptionKey, Encrypted,
    EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadResult, Plaintext, ValueStruct,
};

/// The most encryptions a [`DekReusePolicy`] allows under one DEK. NIST SP 800-38D, section 8.3,
/// allows 2^32 invocations of authenticated encryption under one key with random 96-bit IVs, the
/// nonces every [`AeadAlgorithm`] draws.
const MAX_USES: u64 = 1 << 32;

/// Envelope encryption: AEAD under data encryption keys (DEKs) on the backend `B`, and the DEKs
/// wrapped by a key encryption key (KEK) through the provider `P`.
///
/// Every call returns the errors of [`AeadCipher`] for the AEAD step and the errors of the
/// provider for the KMS step, with the codes the provider reports. A call that makes no KMS call
/// is not `async`.
///
/// [`encrypt_value`](Self::encrypt_value) runs in one of two modes, both writing Tink's KMS
/// envelope format, [`CipherTextWithEncryptedKey`], which Tink's `KmsEnvelopeAead` reads with the
/// same KMS key and algorithm:
///
/// - per call, the default: a new DEK per value, one KMS wrap per value;
/// - store-less, with a [`DekReusePolicy`] in the options: one DEK for many values, renewed by
///   the policy and whenever the DEK leaves the envelope's cache, one KMS wrap per renewal.
///
/// [`encrypt_field`](Self::encrypt_field) and [`decrypt_field`](Self::decrypt_field) do the same
/// for a value of a [`Plaintext`] type, held as an [`Encrypted<T, Envelope>`](Encrypted).
///
/// `decrypt_value`, the `*_with_encrypted_dek` calls and a store-less `encrypt_value` unwrap
/// through the envelope's [`DekCache`], which is disabled in a per-call envelope unless the
/// options give it one; see [`KmsAeadEnvelopeOptions`].
///
/// Every call opens one `DEBUG` span, with the KMS call as a child span when it makes one.
pub struct KmsAeadEnvelope<P, B> {
    pub(crate) provider: P,
    pub(crate) cipher: AeadCipher<B>,
    dek_cache: DekCache,
    dek_reuse: Option<DekReuse>,
}

/// The settings of a [`KmsAeadEnvelope`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KmsAeadEnvelopeOptions {
    /// The AEAD algorithm, [`DEFAULT_ALGORITHM`](Self::DEFAULT_ALGORITHM) by default. The
    /// envelope format does not record the algorithm, so the writer and the reader of a value
    /// must be configured with the same one. Every Tink implementation reads AES-128-GCM,
    /// AES-256-GCM and AES-256-GCM-SIV envelopes; Tink for Java and Go also read
    /// ChaCha20-Poly1305, and Tink for C++ and Python do not.
    #[default = "Self::DEFAULT_ALGORITHM"]
    pub algorithm: AeadAlgorithm,
    /// Store-less mode: `encrypt_value` reuses one DEK until the policy renews it. `None`, the
    /// default, encrypts every value under a new DEK.
    pub dek_reuse: Option<DekReusePolicy>,
    /// The cache the envelope unwraps DEKs through. `None`, the default, is
    /// [`DekCache::disabled`] per call and `DekCache::new(DekCacheOptions::new())` in store-less
    /// mode, which needs an enabled cache. A cache passed here may be shared with other
    /// envelopes.
    pub dek_cache: Option<DekCache>,
}

impl KmsAeadEnvelopeOptions {
    /// The default [`algorithm`](Self::algorithm): AES-256-GCM, which every Tink implementation
    /// reads in a KMS envelope. The default of every release before 0.30 was ChaCha20-Poly1305,
    /// and the values sealed under it open only with ChaCha20-Poly1305 configured.
    pub const DEFAULT_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;
}

/// When a store-less envelope renews the data encryption key (DEK) it encrypts under: at the
/// first encryption past `max_age` or past `max_uses`, whichever comes first.
///
/// A renewal makes one KMS wrap call, and the values under the previous DEK stay readable, since
/// each value carries its wrapped DEK.
///
/// The envelope keeps only the wrapped DEK. Its plaintext lives in the envelope's [`DekCache`],
/// and the first encryption after it has left the cache renews it: past the cache's TTL,
/// whatever `max_age`, after the cache evicts it for capacity, or after [`DekCache::invalidate`]
/// with `envelope.provider().kek()` or [`DekCache::clear`]. In a cache shared with readers, size
/// [`max_entries`](crate::cache::DekCacheOptions::max_entries) above the number of distinct DEKs
/// read per TTL, or give the writer a cache of its own.
///
/// The cache zeroizes the expired DEK at its next call or at [`DekCache::purge_expired`], so a
/// writer that falls quiet leaves the DEK in memory until then: a process that can sit idle calls
/// `purge_expired` on a timer to drop it at the TTL. The values sealed while the cache holds the
/// DEK are readable by whoever reads the process's memory in that window.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct DekReusePolicy {
    /// The age at which the DEK is renewed: [`DEFAULT_MAX_AGE`](Self::DEFAULT_MAX_AGE) by
    /// default, and longer than zero.
    #[default = "Self::DEFAULT_MAX_AGE"]
    pub max_age: Duration,
    /// The encryptions under one DEK: [`DEFAULT_MAX_USES`](Self::DEFAULT_MAX_USES) by default,
    /// and 2^32 at most. Every [`AeadAlgorithm`] seals each value with a random 96-bit nonce,
    /// which NIST SP 800-38D allows for 2^32 values under one AES-GCM key.
    #[default = "Self::DEFAULT_MAX_USES"]
    pub max_uses: NonZeroU64,
}

impl DekReusePolicy {
    /// The default [`max_age`](Self::max_age): 24 hours.
    pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
    /// The default [`max_uses`](Self::max_uses): 2^24.
    pub const DEFAULT_MAX_USES: NonZeroU64 = NonZeroU64::new(1 << 24).expect("2^24 is not zero");
}

/// The DEK a store-less envelope encrypts under, renewed by its policy. Its plaintext lives in
/// the envelope's cache, never here.
struct DekReuse {
    policy: DekReusePolicy,
    current: RwLock<Option<Arc<CurrentDek>>>,
    /// Held across a renewal's KMS calls, so that one writer renews at a time. It holds the error
    /// of the last attempt when that attempt failed.
    ///
    /// Neither tokio's mutex nor the error is unwind safe, and the assertion keeps the envelope
    /// so. A panic in `renew`, the provider's code, leaves the state a cancelled renewal leaves:
    /// tokio releases the guard without poisoning, and nothing under it is written before `renew`
    /// returns. What runs after `renew` only counts, clones and stores.
    renewal: AssertUnwindSafe<tokio::sync::Mutex<Option<KmsAeadError>>>,
    /// The renewal attempts that ended, which tells a writer whether one ended while it waited
    /// for `renewal`. A cancelled attempt does not end.
    ended_renewals: AtomicU64,
}

/// The DEK in use: the wrapped form every value under it carries, and what the policy counts.
struct CurrentDek {
    encrypted: EncryptedDataEncryptionKey,
    created_at: Instant,
    uses: AtomicU64,
}

impl DekReuse {
    /// The reuse of `policy`, which must be in range, with its DEK in `dek_cache`, which must be
    /// enabled.
    fn new(policy: DekReusePolicy, dek_cache: &DekCache) -> KmsAeadResult<Self> {
        if policy.max_age.is_zero() || policy.max_uses.get() > MAX_USES {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_REUSE_POLICY",
                &format!(
                    "A DEK reuse policy needs a max_age longer than zero and a max_uses of 2^32 at \
                     most: {policy:?}"
                ),
            ));
        }
        if !dek_cache.is_enabled() {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_REUSE_POLICY",
                "Store-less mode keeps its DEK in the DEK cache, which is disabled",
            ));
        }
        Ok(Self {
            policy,
            current: RwLock::new(None),
            renewal: AssertUnwindSafe(tokio::sync::Mutex::new(None)),
            ended_renewals: AtomicU64::new(0),
        })
    }

    /// The DEK to encrypt one value under, wrapped by `renew` when the policy renews the current
    /// one. A writer that waited while an attempt failed returns that attempt's error rather than
    /// calling the KMS again; a writer arriving after it retries.
    async fn claim_or_renew<F, Fut>(&self, renew: F) -> KmsAeadResult<Arc<CurrentDek>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = KmsAeadResult<EncryptedDataEncryptionKey>>,
    {
        if let Some(dek) = self.claim() {
            return Ok(dek);
        }
        let ended_on_arrival = self.ended_renewals.load(Ordering::Relaxed);
        let mut last_failure = self.renewal.lock().await;
        if let Some(dek) = self.claim() {
            return Ok(dek);
        }
        if self.ended_renewals.load(Ordering::Relaxed) != ended_on_arrival {
            if let Some(error) = &*last_failure {
                return Err(error.clone());
            }
        }
        let renewed = renew().await;
        self.ended_renewals.fetch_add(1, Ordering::Relaxed);
        match renewed {
            Ok(encrypted) => {
                *last_failure = None;
                let dek = Arc::new(CurrentDek {
                    encrypted,
                    created_at: Instant::now(),
                    uses: AtomicU64::new(1),
                });
                *self.current.write().unwrap_or_else(PoisonError::into_inner) =
                    Some(Arc::clone(&dek));
                Ok(dek)
            }
            Err(error) => {
                *last_failure = Some(error.clone());
                Err(error)
            }
        }
    }

    /// Ends the use of `dek`, so that the next claim renews, unless another writer renewed it
    /// already.
    fn retire(&self, dek: &Arc<CurrentDek>) {
        let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
        if current
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, dek))
        {
            *current = None;
        }
    }

    /// The current DEK with one of its uses taken, or `None` when the policy renews it.
    fn claim(&self) -> Option<Arc<CurrentDek>> {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        let dek = current.as_ref()?;
        let usable = dek.created_at.elapsed() < self.policy.max_age
            && dek.uses.fetch_add(1, Ordering::Relaxed) < self.policy.max_uses.get();
        usable.then(|| Arc::clone(dek))
    }
}

impl<P, B> KmsAeadEnvelope<P, B>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    /// An envelope on the backend `B` with the default options: AES-256-GCM, a DEK per value,
    /// no cache.
    ///
    /// # Errors
    ///
    /// None today: every backend implements AES-256-GCM.
    pub fn new(provider: P) -> KmsAeadResult<Self> {
        Self::with_options(provider, KmsAeadEnvelopeOptions::new())
    }

    /// An envelope on the backend `B` with `options`.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `B` does not implement the algorithm of `options`,
    /// `INVALID_DEK_REUSE_POLICY` for a reuse policy with a zero `max_age` or a `max_uses` over
    /// 2^32, or beside [`DekCache::disabled`], and the errors of [`DekCache::new`] for the
    /// default cache of store-less mode.
    pub fn with_options(provider: P, options: KmsAeadEnvelopeOptions) -> KmsAeadResult<Self> {
        let dek_cache = match options.dek_cache {
            Some(dek_cache) => dek_cache,
            None if options.dek_reuse.is_some() => DekCache::new(DekCacheOptions::new())?,
            None => DekCache::disabled(),
        };
        let dek_reuse = options
            .dek_reuse
            .map(|policy| DekReuse::new(policy, &dek_cache))
            .transpose()?;
        Ok(Self {
            provider,
            cipher: AeadCipher::new(options.algorithm)?,
            dek_cache,
            dek_reuse,
        })
    }

    /// The algorithm this envelope seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.cipher.algorithm()
    }

    /// The provider this envelope wraps and unwraps DEKs with.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// The cache this envelope unwraps DEKs through, for [`DekCache::invalidate`] and
    /// [`DekCache::clear`]. Pass `envelope.provider().kek()` to `invalidate`: a
    /// [`KekRef`](crate::KekRef) built by hand that differs from it matches no entry.
    pub fn dek_cache(&self) -> &DekCache {
        &self.dek_cache
    }

    /// Encrypts `plain_text` under a new DEK, or under the reused DEK of a store-less envelope,
    /// and returns it with the wrapped DEK in one [`CipherTextWithEncryptedKey`]. A new DEK
    /// costs one KMS call to wrap it, and one more for the key material when the provider uses
    /// the KMS generator.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
    /// material of the wrong length, and `INVALID_CIPHER_TEXT_FORMAT` when the wrapped key is
    /// longer than the 4,096 bytes Tink reads.
    pub async fn encrypt_value(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        spans::in_span(self.encrypt_span(self.mode()), self.seal(aad, plain_text)).await
    }

    /// Unwraps the DEK stored in `cipher_text`, through the envelope's [`DekCache`], and opens
    /// the value with it. With the deprecated `legacy-formats` feature it also reads the layouts
    /// written by 0.29 and earlier, and logs one `WARN` event the first time the process reads
    /// each of them.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, the errors of [`CipherTextWithEncryptedKey::separate`]
    /// when `cipher_text` cannot be read, and of [`DekCache::with_key`] when its wrapped key
    /// does not unwrap to a key. With `legacy-formats`, `INVALID_CIPHER_TEXT_FORMAT` and
    /// `INVALID_KEY_VERSION` on a legacy value that cannot be read take the place of
    /// `LEGACY_FORMAT`.
    pub async fn decrypt_value(
        &self,
        aad: &[u8],
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        spans::in_span(self.decrypt_span(self.mode()), self.open(aad, cipher_text)).await
    }

    /// Encrypts `value`, as [`Plaintext`] encodes it, as [`encrypt_value`](Self::encrypt_value)
    /// encrypts a value: under a new DEK, or under the reused DEK of a store-less envelope.
    ///
    /// # Errors
    ///
    /// The errors of `encrypt_value`, and `INVALID_PLAINTEXT` when `value` does not encode.
    pub async fn encrypt_field<T: Plaintext>(
        &self,
        aad: &[u8],
        value: &T,
    ) -> KmsAeadResult<Encrypted<T, Envelope>> {
        spans::in_span(self.encrypt_span(self.mode()), async {
            let sealed = self.seal(aad, &value.to_plaintext()?).await?;
            Encrypted::try_from(sealed.into_value())
        })
        .await
    }

    /// Opens `field` as [`decrypt_value`](Self::decrypt_value) opens a value, unwrapping its DEK
    /// through the envelope's [`DekCache`], and decodes the plaintext as a `T`.
    ///
    /// # Errors
    ///
    /// The errors of `decrypt_value`, and `INVALID_PLAINTEXT` when the plaintext is not an
    /// encoding of `T`.
    pub async fn decrypt_field<T: Plaintext>(
        &self,
        aad: &[u8],
        field: &Encrypted<T, Envelope>,
    ) -> KmsAeadResult<T> {
        spans::in_span(self.decrypt_span(self.mode()), async {
            let value = CipherTextWithEncryptedKey(field.value().clone());
            T::from_plaintext(self.open(aad, &value).await?)
        })
        .await
    }

    /// Encrypts `plain_text` under a plaintext DEK the caller holds, such as one from
    /// [`generate_new_dek`](Self::generate_new_dek), without calling the KMS.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::encrypt_value`].
    pub fn encrypt_value_with_dek(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        spans::in_scope(self.encrypt_span("caller_dek"), || {
            self.cipher.encrypt_value(aad, plain_text, dek)
        })
    }

    /// Unwraps `dek`, through the envelope's [`DekCache`], and encrypts `plain_text` under it.
    /// The caller stores the wrapped DEK beside the returned cipher text.
    ///
    /// # Errors
    ///
    /// The errors of the provider's unwrap and of [`AeadCipher::encrypt_value`].
    pub async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        spans::in_span(self.encrypt_span("caller_dek"), async {
            self.with_dek(dek, |key| self.cipher.encrypt_value(aad, plain_text, key))
                .await
        })
        .await
    }

    /// Opens `cipher_text` with a plaintext DEK the caller holds, without calling the KMS.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::decrypt_value`].
    pub fn decrypt_value_with_dek(
        &self,
        aad: &[u8],
        cipher_text: &CipherText,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        spans::in_scope(self.decrypt_span("caller_dek"), || {
            self.cipher.decrypt_value(aad, cipher_text, dek)
        })
    }

    /// Unwraps `dek`, through the envelope's [`DekCache`], and opens `cipher_text` with it.
    ///
    /// # Errors
    ///
    /// The errors of the provider's unwrap and of [`AeadCipher::decrypt_value`].
    pub async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &[u8],
        cipher_text: &CipherText,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        spans::in_span(self.decrypt_span("caller_dek"), async {
            self.with_dek(dek, |key| self.cipher.decrypt_value(aad, cipher_text, key))
                .await
        })
        .await
    }

    /// The beacon of `value` under the HMAC-SHA256 beacon key `wrapped_key`, whose id is
    /// `key_id`, for the field `context`, keeping `bits` bits: [`BeaconMac::compute`] with the key
    /// unwrapped through the envelope's [`DekCache`]. A beacon key comes from
    /// [`BeaconMac::generate_wrapped_key`] with this envelope's [`provider`](Self::provider).
    ///
    /// `context` names the field and never a row. Rotating a beacon key is the application's:
    /// it keeps both keys while it re-indexes, writes beacons under the new one, and queries with
    /// a beacon under each, until no stored beacon names the old key.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the unwrapped key is not a serialized
    /// Tink key, and the errors of [`BeaconMac::compute`].
    pub async fn beacon<T: Plaintext>(
        &self,
        key_id: u32,
        wrapped_key: &EncryptedDataEncryptionKey,
        context: &[u8],
        bits: BeaconBits,
        value: &T,
    ) -> KmsAeadResult<Beacon<T>> {
        let mac = BeaconMac::<B>::new(BeaconAlgorithm::HmacSha256);
        let span = spans::beacon(mac.algorithm(), B::NAME, &self.dek_cache);
        spans::in_span(
            span,
            self.with_dek(wrapped_key, |key| {
                mac.compute(key_id, context, bits, value, key)
            }),
        )
        .await
    }

    /// Generates a new DEK, from the KMS generator when the provider uses one and from the
    /// backend's CSPRNG otherwise, and wraps it with the KMS as Tink does, so that
    /// [`CipherTextWithEncryptedKey::join`] can store it with values sealed under it.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::generate_wrapped_key`].
    pub async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let span = spans::generate_dek("randomized", self.cipher.algorithm(), B::NAME);
        spans::in_span(span, self.cipher.generate_wrapped_key(&self.provider)).await
    }

    /// Encrypts `plain_text` as `encrypt_value` does, in the span of the caller.
    async fn seal(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        match &self.dek_reuse {
            Some(dek_reuse) => {
                // The cache holds the only plaintext copy of the DEK, so a renewal caches it.
                // Once it has left the cache, expired, invalidated or cleared, the writer renews
                // instead of unwrapping it again, so that `invalidate` and `clear` end its use.
                let renew = || async {
                    let (dek, encrypted) = self.cipher.generate_wrapped_key(&self.provider).await?;
                    if let Some(enabled) = &self.dek_cache.0 {
                        enabled.insert(self.provider.kek(), &encrypted, dek);
                    }
                    Ok(encrypted)
                };
                let dek = dek_reuse.claim_or_renew(renew).await?;
                let sealed = self.dek_cache.0.as_ref().and_then(|enabled| {
                    enabled.with_cached_key(self.provider.kek(), &dek.encrypted, |key| {
                        self.cipher.encrypt_value(aad, plain_text, key)
                    })
                });
                let (dek, cipher_text) = match sealed {
                    Some(cipher_text) => {
                        spans::record_dek_cache(DekCacheOutcome::Hit);
                        (dek, cipher_text?)
                    }
                    None => {
                        dek_reuse.retire(&dek);
                        let dek = dek_reuse.claim_or_renew(renew).await?;
                        let cipher_text = self
                            .with_dek(&dek.encrypted, |key| {
                                self.cipher.encrypt_value(aad, plain_text, key)
                            })
                            .await?;
                        (dek, cipher_text)
                    }
                };
                CipherTextWithEncryptedKey::join(&cipher_text, &dek.encrypted)
            }
            None => {
                let (dek, encrypted_dek) = self.cipher.generate_wrapped_key(&self.provider).await?;
                let cipher_text = self.cipher.encrypt_value(aad, plain_text, &dek)?;
                CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)
            }
        }
    }

    /// Opens `value` as `decrypt_value` does, in the span of the caller.
    async fn open(
        &self,
        aad: &[u8],
        value: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        #[cfg(feature = "legacy-formats")]
        let (cipher_text, encrypted_dek) =
            value.separate_any_layout(self.provider.kek().provider())?;
        #[cfg(not(feature = "legacy-formats"))]
        let (cipher_text, encrypted_dek) = value.separate()?;
        self.with_dek(&encrypted_dek, |key| {
            self.cipher.decrypt_value(aad, &cipher_text, key)
        })
        .await
    }

    /// Runs `use_key` with the DEK `encrypted` wraps, through the cache, and records on the
    /// current span where the key came from, whether `use_key` succeeds or not. A failed unwrap
    /// records a miss. Without a cache nothing is recorded: the span records `disabled` when it
    /// opens, and a field recorded twice is exported twice.
    async fn with_dek<T>(
        &self,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> KmsAeadResult<T>,
    ) -> KmsAeadResult<T> {
        let result = self
            .dek_cache
            .with_key(&self.provider, encrypted, use_key)
            .await;
        if self.dek_cache.is_enabled() {
            spans::record_dek_cache(match &result {
                Ok((_, outcome)) => *outcome,
                Err(_) => DekCacheOutcome::Miss,
            });
        }
        let (used, _) = result?;
        used
    }

    /// The `mode` span field of `encrypt_value` and `decrypt_value`.
    fn mode(&self) -> &'static str {
        if self.dek_reuse.is_some() {
            "store_less"
        } else {
            "per_call"
        }
    }

    fn encrypt_span(&self, mode: &str) -> Span {
        spans::aead_encrypt(mode, self.cipher.algorithm(), B::NAME, &self.dek_cache)
    }

    fn decrypt_span(&self, mode: &str) -> Span {
        spans::aead_decrypt(mode, self.cipher.algorithm(), B::NAME, &self.dek_cache)
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod tests {
    use rvstruct::ValueStruct;

    use super::*;
    #[cfg(not(feature = "legacy-formats"))]
    use crate::errors::KmsAeadLegacyFormat;
    use crate::formats::TinkKeyType;
    use crate::test_provider::{
        let_spawned_tasks_wait, wrapped_by_test_provider, CountingKmsProvider, TestBackend,
        TestKmsProvider, CONCURRENT_CALLS,
    };

    type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;
    type CountingEnvelope = KmsAeadEnvelope<CountingKmsProvider, TestBackend>;

    const AAD: &[u8] = b"orders/1042";
    const PLAIN_TEXT: &str = "4111 1111 1111 1111";
    const ORDERS_KEK: &str = "orders";

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt_value(AAD, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let (dek, encrypted_dek) = encryption.generate_new_dek().await?;
        let ciphertext = encryption.encrypt_value_with_dek(AAD, &plaintext, &dek)?;

        assert_eq!(
            encryption.decrypt_value_with_dek(AAD, &ciphertext, &dek)?,
            plaintext
        );
        assert_eq!(
            encryption
                .decrypt_value_with_encrypted_dek(AAD, &ciphertext, &encrypted_dek)
                .await?,
            plaintext
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_new_dek_is_wrapped_as_its_tink_key() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;

        let (dek, encrypted_dek) = encryption.generate_new_dek().await?;

        assert_eq!(
            encrypted_dek,
            wrapped_by_test_provider(TinkKeyType::AesGcm, dek.value().ref_sensitive_value())
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_encrypted_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let (_dek, encrypted_dek) = encryption.generate_new_dek().await?;
        let ciphertext = encryption
            .encrypt_value_with_encrypted_dek(AAD, &plaintext, &encrypted_dek)
            .await?;
        let decrypted = encryption
            .decrypt_value_with_encrypted_dek(AAD, &ciphertext, &encrypted_dek)
            .await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_provider_encrypt_failure() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::FailingToWrap)?;

        let result = encryption
            .encrypt_value(AAD, &SecretValue::from("secret"))
            .await;

        assert!(
            matches!(&result, Err(e) if e.code() == "TEST_WRAP"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_provider_decrypt_failure() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let ciphertext = encryption
            .encrypt_value(AAD, &SecretValue::from("secret"))
            .await?;
        let failing_encryption = Envelope::new(TestKmsProvider::FailingToUnwrap)?;

        let result = failing_encryption.decrypt_value(AAD, &ciphertext).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "TEST_UNWRAP"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_chacha20_poly1305_algorithm() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt_value(AAD, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_encryptions() -> KmsAeadResult<()> {
        let encryption = Arc::new(Envelope::new(TestKmsProvider::Working)?);

        let handles: Vec<_> = (0..10)
            .map(|i| {
                let encryption = Arc::clone(&encryption);
                tokio::spawn(async move {
                    let aad = format!("aad-{i}");
                    let plaintext = SecretValue::from(format!("secret-{i}"));
                    let ciphertext = encryption.encrypt_value(aad.as_bytes(), &plaintext).await?;
                    let decrypted = encryption
                        .decrypt_value(aad.as_bytes(), &ciphertext)
                        .await?;
                    assert_eq!(decrypted, plaintext);
                    Ok::<_, KmsAeadError>(())
                })
            })
            .collect();

        for handle in handles {
            handle.await.unwrap()?;
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_corrupted_cipher_text_with_key_fails() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let ciphertext = encryption
            .encrypt_value(AAD, &SecretValue::from("secret"))
            .await?;

        let mut corrupted = ciphertext.value().clone();
        corrupted[20] ^= 0x01;
        let result = encryption
            .decrypt_value(AAD, &CipherTextWithEncryptedKey::from(corrupted))
            .await;

        assert!(result.is_err(), "Decryption of corrupted data should fail");
        Ok(())
    }

    #[tokio::test]
    async fn new_dek_takes_the_key_material_of_the_kms_generator() -> KmsAeadResult<()> {
        let material = SecretValue::new((0..32).collect());
        let encryption = Envelope::with_options(
            TestKmsProvider::Generating(material.clone()),
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
        )?;

        let (dek, _) = encryption.generate_new_dek().await?;

        assert_eq!(dek.value(), &material);
        Ok(())
    }

    #[tokio::test]
    async fn new_dek_falls_back_to_the_backend_without_a_kms_generator() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm),
        )?;

        let (first, _) = encryption.generate_new_dek().await?;
        let (second, _) = encryption.generate_new_dek().await?;

        assert_eq!(first.value().ref_sensitive_value().len(), 16);
        assert_ne!(first, second);
        Ok(())
    }

    #[tokio::test]
    async fn generate_key_material_of_the_wrong_length_fails() -> KmsAeadResult<()> {
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
        let provider = TestKmsProvider::Generating(SecretValue::new(vec![0x42; 64]));

        let result = cipher.generate_wrapped_key(&provider).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
            "{:?}",
            result.err()
        );
        Ok(())
    }

    // The same secret under the AAD `fixture-aad`, with the test provider's raw key as the
    // wrapped key, in the layouts of 0.28.1, of 0.29 and of 32-bit targets before 0.24.0, sealed
    // with ChaCha20-Poly1305, the default of those releases.
    const FIXTURE_AAD: &[u8] = b"fixture-aad";
    #[cfg(feature = "legacy-formats")]
    const FIXTURE_SECRET: &str = "fixture-secret";
    const ENVELOPE_FROM_0_28_1: &str = "000000000000002089548688c2a8d0d11b8547aa1e9a1c79fbaddcb5a4866e56af813d65b041d60672aba785e3857369ab75d33b8672d013a8e721a538876b0d59090f06c6c3a698acf2113a29e1f90ed89e";
    const ENVELOPE_FROM_0_29: &str = "0100002089548688c2a8d0d11b8547aa1e9a1c79fbaddcb5a4866e56af813d65b041d60672aba785e3857369ab75d33b8672d013a8e721a538876b0d59090f06c6c3a698acf2113a29e1f90ed89e";
    const ENVELOPE_FROM_0_23_0_ON_32_BIT: &str = "00000020e8efcd9417d41f8dee5dc6b8cfde7b209951fb80e60e0b8240a9fa688f815e1501a12b36821b4aa097fbe86573df02d8fe8d34235bdb9b3731107e946d0021d7d2ea089f87d4bea034a2";

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    async fn envelopes_from_0_29_and_earlier_decrypt() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;
        for envelope_hex in [
            ENVELOPE_FROM_0_28_1,
            ENVELOPE_FROM_0_29,
            ENVELOPE_FROM_0_23_0_ON_32_BIT,
        ] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let secret = encryption.decrypt_value(FIXTURE_AAD, &envelope).await?;
            assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
        }
        Ok(())
    }

    #[cfg(not(feature = "legacy-formats"))]
    #[tokio::test]
    async fn envelopes_from_0_29_and_earlier_need_legacy_formats() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;
        for (envelope_hex, format) in [
            (
                ENVELOPE_FROM_0_28_1,
                KmsAeadLegacyFormat::LengthPrefixedEnvelope,
            ),
            (ENVELOPE_FROM_0_29, KmsAeadLegacyFormat::EnvelopeV1),
            (
                ENVELOPE_FROM_0_23_0_ON_32_BIT,
                KmsAeadLegacyFormat::RawWrappedKey,
            ),
        ] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let result = encryption.decrypt_value(FIXTURE_AAD, &envelope).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error)) if error.format == format),
                "{format:?}: {result:?}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn envelopes_from_0_29_and_earlier_upgrade_to_tink() -> KmsAeadResult<()> {
        let encryption = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;
        for envelope_hex in [
            ENVELOPE_FROM_0_28_1,
            ENVELOPE_FROM_0_29,
            ENVELOPE_FROM_0_23_0_ON_32_BIT,
        ] {
            let legacy = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());

            let upgraded = encryption
                .upgrade_legacy_value(FIXTURE_AAD, &legacy)
                .await?
                .expect("a legacy value is upgraded");

            let (cipher_text, encrypted_dek) = upgraded.separate()?;
            let sealed_len = 12 + FIXTURE_SECRET.len() + 16;
            assert_eq!(encrypted_dek.value()[..2], [0x12, 0x20]);
            assert_eq!(
                cipher_text.value()[..],
                legacy.value()[legacy.value().len() - sealed_len..]
            );
            assert_eq!(
                encryption.decrypt_value(FIXTURE_AAD, &upgraded).await?,
                SecretValue::from(FIXTURE_SECRET)
            );
            assert_eq!(
                encryption
                    .upgrade_legacy_value(FIXTURE_AAD, &upgraded)
                    .await?,
                None
            );
        }
        assert_eq!(encryption.provider.wraps(), 3);
        Ok(())
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn a_value_that_does_not_open_is_not_upgraded() -> KmsAeadResult<()> {
        let legacy = CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_FROM_0_29).unwrap());
        let aes_256_gcm = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
        )?;
        let chacha20_poly1305 = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;

        let under_another_algorithm = aes_256_gcm.upgrade_legacy_value(FIXTURE_AAD, &legacy).await;
        let under_another_aad = chacha20_poly1305
            .upgrade_legacy_value(b"another-aad", &legacy)
            .await;

        assert!(
            matches!(&under_another_algorithm, Err(e) if e.code() == "DECRYPT"),
            "{under_another_algorithm:?}"
        );
        assert!(
            matches!(&under_another_aad, Err(e) if e.code() == "DECRYPT"),
            "{under_another_aad:?}"
        );
        assert_eq!(aes_256_gcm.provider.wraps(), 0);
        assert_eq!(chacha20_poly1305.provider.wraps(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn per_call_envelope_has_no_cache_by_default() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let envelope = CountingEnvelope::new(provider)?;

        let value = envelope
            .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            let decrypted = envelope.decrypt_value(AAD, &value).await?;
            assert_eq!(decrypted, SecretValue::from(PLAIN_TEXT));
        }

        assert_eq!(envelope.provider.unwraps(), 2);
        assert!(!envelope.dek_cache().is_enabled());
        Ok(())
    }

    #[tokio::test]
    async fn an_explicit_cache_overrides_the_default_of_the_mode() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )?;

        let value = envelope
            .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            envelope.decrypt_value(AAD, &value).await?;
        }

        assert_eq!(envelope.provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn store_less_mode_needs_an_enabled_cache() {
        let result = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new())
                .with_dek_cache(DekCache::disabled()),
        );

        assert!(
            matches!(&result, Err(KmsAeadError::SystemError(error))
                if error.public.code == "INVALID_DEK_REUSE_POLICY"),
            "{:?}",
            result.as_ref().err()
        );
    }

    #[tokio::test]
    async fn reuse_policy_out_of_range_is_refused() -> KmsAeadResult<()> {
        let refused = [
            DekReusePolicy::new().with_max_age(Duration::ZERO),
            DekReusePolicy::new().with_max_uses(NonZeroU64::new((1 << 32) + 1).unwrap()),
        ];
        for policy in refused {
            let result = CountingEnvelope::with_options(
                CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
                KmsAeadEnvelopeOptions::new().with_dek_reuse(policy.clone()),
            );
            assert!(
                matches!(&result, Err(KmsAeadError::SystemError(error))
                    if error.public.code == "INVALID_DEK_REUSE_POLICY"),
                "{policy:?}: {:?}",
                result.as_ref().err()
            );
        }

        CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(
                DekReusePolicy::new().with_max_uses(NonZeroU64::new(1 << 32).unwrap()),
            ),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypted_dek_calls_unwrap_through_the_cache() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )?;

        let (_, encrypted_dek) = envelope.generate_new_dek().await?;
        let value = envelope
            .encrypt_value_with_encrypted_dek(AAD, &SecretValue::from(PLAIN_TEXT), &encrypted_dek)
            .await?;
        let decrypted = envelope
            .decrypt_value_with_encrypted_dek(AAD, &value, &encrypted_dek)
            .await?;

        assert_eq!(decrypted, SecretValue::from(PLAIN_TEXT));
        assert_eq!(envelope.provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn reuse_renews_by_count() -> KmsAeadResult<()> {
        let policy = DekReusePolicy::new().with_max_uses(NonZeroU64::new(3).unwrap());
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(policy),
        )?;

        let mut wrapped_deks = Vec::new();
        for _ in 0..7 {
            let value = envelope
                .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
                .await?;
            wrapped_deks.push(value.separate()?.1);
        }

        let renewals: Vec<_> = wrapped_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [false, false, true, false, false, true]);
        assert_eq!(envelope.provider.wraps(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn reuse_renews_by_age() -> KmsAeadResult<()> {
        let max_age = Duration::from_millis(200);
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new().with_max_age(max_age)),
        )?;

        let mut wrapped_deks = Vec::new();
        for pause in [Duration::ZERO, max_age, Duration::ZERO] {
            let value = envelope
                .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
                .await?;
            wrapped_deks.push(value.separate()?.1);
            tokio::time::sleep(pause).await;
        }

        let renewals: Vec<_> = wrapped_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [false, true]);
        assert_eq!(envelope.provider.wraps(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn renewal_is_single_flight() -> KmsAeadResult<()> {
        let envelope = Arc::new(CountingEnvelope::with_options(
            CountingKmsProvider::gated(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?);

        let encryptions: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let envelope = Arc::clone(&envelope);
                tokio::spawn(async move {
                    envelope
                        .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
                        .await
                })
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(envelope.provider.wraps(), 1);
        envelope.provider.open_gate();

        let mut wrapped_deks = Vec::new();
        for encryption in encryptions {
            wrapped_deks.push(encryption.await.unwrap()?.separate()?.1);
        }
        assert!(wrapped_deks.iter().all(|dek| *dek == wrapped_deks[0]));
        assert_eq!(envelope.provider.wraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn reused_dek_values_decrypt_after_renewal() -> KmsAeadResult<()> {
        let policy = DekReusePolicy::new().with_max_uses(NonZeroU64::new(2).unwrap());
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(policy),
        )?;

        let mut values = Vec::new();
        for index in 0..5 {
            let plain_text = SecretValue::from(format!("{PLAIN_TEXT}/{index}"));
            values.push((envelope.encrypt_value(AAD, &plain_text).await?, plain_text));
        }
        for _ in 0..2 {
            for (value, plain_text) in &values {
                assert_eq!(envelope.decrypt_value(AAD, value).await?, *plain_text);
            }
        }

        assert_eq!(envelope.provider.wraps(), 3);
        assert_eq!(envelope.provider.unwraps(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_quiet_writer_key_is_zeroized_by_purge_expired() -> KmsAeadResult<()> {
        let ttl = Duration::from_millis(200);
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new())
                .with_dek_cache(DekCache::new(DekCacheOptions::new().with_ttl(ttl))?),
        )?;

        let first = envelope
            .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        let (_, writer_dek) = first.separate()?;
        let cached = envelope
            .dek_cache()
            .cached_dek(envelope.provider.kek(), &writer_dek);
        tokio::time::sleep(ttl).await;
        envelope.dek_cache().purge_expired();
        let zeroized = cached.is_some_and(|dek| dek.strong_count() == 0);
        let after_ttl = envelope
            .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;

        assert!(zeroized);
        assert_ne!(after_ttl.separate()?.1, writer_dek);
        assert_eq!(envelope.provider.wraps(), 2);
        assert_eq!(envelope.provider.unwraps(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_makes_the_writer_renew() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?;
        let plain_text = SecretValue::from(PLAIN_TEXT);

        let first = envelope
            .encrypt_value(AAD, &plain_text)
            .await?
            .separate()?
            .1;
        envelope
            .dek_cache()
            .invalidate(envelope.provider().kek(), &first);
        let after_invalidate = envelope
            .encrypt_value(AAD, &plain_text)
            .await?
            .separate()?
            .1;
        envelope.dek_cache().clear();
        let after_clear = envelope
            .encrypt_value(AAD, &plain_text)
            .await?
            .separate()?
            .1;

        assert_ne!(after_invalidate, first);
        assert_ne!(after_clear, after_invalidate);
        assert_eq!(envelope.provider.wraps(), 3);
        assert_eq!(envelope.provider.unwraps(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn renewal_failure_is_shared_with_queued_writers() -> KmsAeadResult<()> {
        let envelope = Arc::new(CountingEnvelope::with_options(
            CountingKmsProvider::gated(TestKmsProvider::FailingToWrap, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?);

        let encryptions: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let envelope = Arc::clone(&envelope);
                tokio::spawn(async move {
                    envelope
                        .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
                        .await
                })
            })
            .collect();
        let_spawned_tasks_wait().await;
        envelope.provider.open_gate();
        let mut results = Vec::new();
        for encryption in encryptions {
            results.push(encryption.await.unwrap());
        }
        let wraps_of_one_attempt = envelope.provider.wraps();
        results.push(
            envelope
                .encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT))
                .await,
        );

        for result in &results {
            assert!(
                matches!(result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "TEST_WRAP"),
                "{:?}",
                result.as_ref().err()
            );
        }
        assert_eq!(wraps_of_one_attempt, 1);
        assert_eq!(envelope.provider.wraps(), 2);
        Ok(())
    }

    /// An application newtype, sealed as the UTF-8 bytes of the `String` it holds.
    #[derive(Debug, PartialEq)]
    struct Email(String);

    impl Plaintext for Email {
        fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
            self.0.to_plaintext()
        }

        fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
            String::from_plaintext(plaintext).map(Email)
        }
    }

    /// `value` written by `encrypt_field` and read back by `decrypt_field`.
    async fn through_a_field<T: Plaintext>(envelope: &Envelope, value: &T) -> KmsAeadResult<T> {
        let field = envelope.encrypt_field(AAD, value).await?;
        envelope.decrypt_field(AAD, &field).await
    }

    #[tokio::test]
    async fn every_plaintext_type_round_trips_through_a_field() -> KmsAeadResult<()> {
        let envelope = Envelope::new(TestKmsProvider::Working)?;

        let card = PLAIN_TEXT.to_string();
        assert_eq!(through_a_field(&envelope, &card).await?, card);
        let bytes = vec![0x00, 0xFF, 0x7F];
        assert_eq!(through_a_field(&envelope, &bytes).await?, bytes);
        let secret = SecretValue::from(PLAIN_TEXT);
        assert_eq!(through_a_field(&envelope, &secret).await?, secret);
        assert!(through_a_field(&envelope, &true).await?);
        assert!(!through_a_field(&envelope, &false).await?);
        assert_eq!(through_a_field(&envelope, &i32::MIN).await?, i32::MIN);
        assert_eq!(through_a_field(&envelope, &i64::MIN).await?, i64::MIN);
        assert_eq!(through_a_field(&envelope, &u32::MAX).await?, u32::MAX);
        assert_eq!(through_a_field(&envelope, &u64::MAX).await?, u64::MAX);
        #[cfg(feature = "serde-json")]
        {
            let plan = crate::Json(vec![("plan".to_string(), 3u32)]);
            assert_eq!(through_a_field(&envelope, &plan).await?, plan);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_newtype_field_is_the_envelope_of_its_string() -> KmsAeadResult<()> {
        let envelope = Envelope::new(TestKmsProvider::Working)?;
        let email = Email("alice@example.com".to_string());

        let field: Encrypted<Email, crate::formats::Envelope> =
            envelope.encrypt_field(AAD, &email).await?;
        let stored = Encrypted::<Email, crate::formats::Envelope>::try_from(field.into_value())?;

        assert_eq!(envelope.decrypt_field(AAD, &stored).await?, email);
        assert_eq!(
            envelope
                .decrypt_value(AAD, &CipherTextWithEncryptedKey(stored.into_value()))
                .await?,
            SecretValue::from("alice@example.com")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_beacon_unwraps_its_key_through_the_cache() -> KmsAeadResult<()> {
        let encryption = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )?;
        let mac = BeaconMac::<TestBackend>::new(BeaconAlgorithm::HmacSha256);
        let (key, wrapped) = mac.generate_wrapped_key(encryption.provider()).await?;
        let email = "alice@example.com".to_string();

        let beacon = encryption
            .beacon(7, &wrapped, b"user/email", BeaconBits::DEFAULT, &email)
            .await?;
        let again = encryption
            .beacon(7, &wrapped, b"user/email", BeaconBits::DEFAULT, &email)
            .await?;
        let other_field = encryption
            .beacon(7, &wrapped, b"user/name", BeaconBits::DEFAULT, &email)
            .await?;

        assert_eq!(beacon, again);
        assert_eq!(
            beacon,
            mac.compute(7, b"user/email", BeaconBits::DEFAULT, &email, &key)?
        );
        assert_ne!(beacon, other_field);
        assert_eq!(encryption.provider().unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn store_less_fields_reuse_the_dek_through_the_cache() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?;
        let card = PLAIN_TEXT.to_string();

        let first = envelope.encrypt_field(AAD, &card).await?;
        let second = envelope.encrypt_field(AAD, &card).await?;

        assert_eq!(envelope.decrypt_field(AAD, &first).await?, card);
        assert_eq!(envelope.decrypt_field(AAD, &second).await?, card);
        assert_eq!(envelope.provider.wraps(), 1);
        assert_eq!(envelope.provider.unwraps(), 0);
        Ok(())
    }

    #[test]
    fn envelope_is_unwind_safe() {
        fn unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        unwind_safe::<Envelope>();
    }
}
