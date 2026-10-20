use std::future::Future;
use std::num::NonZeroU64;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use rsb_derive::Builder;
use secret_vault_value::SecretValue;
use tracing::Span;

use crate::aead_cipher::AeadKeyBytesOps;
use crate::backends::AeadBackend;
use crate::cache::{DekCache, DekCacheOptions, DekCacheOutcome};
use crate::errors::{KmsAeadError, KmsAeadLegacyFormatError, KmsAeadSystemError};
use crate::formats::{Bare, Envelope};
use crate::metrics::{self, Measurement};
use crate::{
    spans, AeadAlgorithm, AeadCipher, Beacon, BeaconAlgorithm, BeaconBits, BeaconMac,
    DataEncryptionKey, Encrypted, EncryptedDataEncryptionKey, KeyId, KmsAeadEncryptionProvider,
    KmsAeadResult, Plaintext,
};

/// The most encryptions a [`DekReusePolicy`] allows under one DEK. NIST SP 800-38D, section 8.3,
/// allows 2^32 invocations of authenticated encryption under one key with random 96-bit IVs, the
/// nonces every [`AeadAlgorithm`] draws.
const MAX_ENCRYPTIONS_PER_DEK: u64 = 1 << 32;

/// The most plaintext bytes a [`DekReusePolicy`] allows under one AES-GCM DEK: 2^48 blocks of 16
/// bytes. RFC 8452, section 9: "in order to limit the adversary's advantage to 2^-32, at most
/// 2^48 blocks can be encrypted overall" under one key of a standard mode such as AES-GCM.
const MAX_BYTES_PER_AES_GCM_DEK: u64 = 1 << 52;

/// Envelope encryption: AEAD under data encryption keys (DEKs) on the backend `B`, and the DEKs
/// encrypted by a key encryption key (KEK) through the provider `P`.
///
/// Every call returns the errors of [`AeadCipher`] for the AEAD step and the errors of the
/// provider for the KMS step, with the codes the provider reports. A call that makes no KMS call
/// is not `async`.
///
/// [`encrypt`](Self::encrypt) seals a value of a [`Plaintext`] type into an
/// [`Encrypted<T, Envelope>`](Encrypted), Tink's KMS envelope format, which Tink's
/// `KmsEnvelopeAead` reads with the same KMS key and algorithm, and [`decrypt`](Self::decrypt)
/// reads it back as a `T`. It runs in one of two modes:
///
/// - per call, the default: a new DEK per value, one KMS encryption per value;
/// - store-less, with a [`DekReusePolicy`] in the options: one DEK for many values, renewed by
///   the policy and whenever the DEK leaves the envelope's cache, one KMS encryption per renewal.
///
/// `decrypt`, the `*_with_encrypted_dek` calls and a store-less `encrypt` decrypt through the
/// envelope's [`DekCache`], which is disabled in a per-call envelope unless the options give it
/// one; see [`KmsAeadEnvelopeOptions`].
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
    /// Store-less mode: `encrypt` reuses one DEK until the policy renews it. `None`, the
    /// default, encrypts every value under a new DEK.
    pub dek_reuse: Option<DekReusePolicy>,
    /// The cache the envelope decrypts DEKs through. `None`, the default, is
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
/// first encryption past `max_age`, past `max_uses` or past `max_bytes`, whichever comes first.
///
/// `max_bytes` counts the plaintext bytes sealed under the DEK. A value that would take the count
/// past `max_bytes` renews the DEK before it is sealed, and a value longer than `max_bytes` alone
/// is sealed under a new DEK of its own, which encrypts that value only, as the per-call envelope
/// does, and leaves the current DEK in use.
///
/// A renewal makes one KMS encryption call, and the values under the previous DEK stay readable,
/// since each value carries its encrypted DEK.
///
/// The envelope keeps only the encrypted DEK. Its plaintext lives in the envelope's [`DekCache`],
/// and the first encryption after it has left the cache renews it: past the cache's TTL,
/// whatever `max_age`, after the cache evicts it for capacity, or after [`DekCache::invalidate`]
/// with `envelope.provider().kek()` or [`DekCache::clear`]. In a cache shared with readers, size
/// [`max_entries`](crate::cache::DekCacheOptions::max_entries) above the number of distinct DEKs
/// read per TTL, or give the writer a cache of its own.
///
/// The cache zeroises the expired DEK at its next call or at [`DekCache::purge_expired`], so a
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
    /// The plaintext bytes under one DEK. `None`, the default, takes the default of the
    /// algorithm:
    ///
    /// - AES-128-GCM and AES-256-GCM:
    ///   [`DEFAULT_MAX_BYTES_AES_GCM`](Self::DEFAULT_MAX_BYTES_AES_GCM), and 2^52 at most, the
    ///   2^48 blocks RFC 8452, section 9, allows under one AES-GCM key for an adversary advantage
    ///   of 2^-32;
    /// - AES-256-GCM-SIV and ChaCha20-Poly1305: no limit beyond `max_uses`. RFC 8452, section 9,
    ///   bounds AES-GCM-SIV with random nonces at 2^32 values of up to 8 GiB each for an
    ///   advantage of 2^-32, and ChaCha20-Poly1305 has no confidentiality limit beyond the
    ///   security of ChaCha20 itself (draft-irtf-cfrg-aead-limits, section 6.3).
    ///
    /// The bounds count blocks of plaintext and AAD, and one more block per value. The count of
    /// bytes leaves those out, along with the rounding of each value up to whole 16-byte blocks:
    /// at the default `max_uses` and an AAD of 16 bytes or less, at most 3 × 2^24 blocks beside
    /// the 2^34 blocks of the default.
    pub max_bytes: Option<NonZeroU64>,
}

impl DekReusePolicy {
    /// The default [`max_age`](Self::max_age): 24 hours.
    pub const DEFAULT_MAX_AGE: Duration = Duration::from_secs(24 * 60 * 60);
    /// The default [`max_uses`](Self::max_uses): 2^24.
    pub const DEFAULT_MAX_USES: NonZeroU64 = NonZeroU64::new(1 << 24).expect("2^24 is not zero");
    /// The default [`max_bytes`](Self::max_bytes) for AES-128-GCM and AES-256-GCM: 2^38 bytes,
    /// 256 GiB, below the 2^38.5 bytes of TLS 1.3. RFC 8446, section 5.5: "For AES-GCM, up to
    /// 2^24.5 full-size records (about 24 million) may be encrypted on a given connection while
    /// keeping a safety margin of approximately 2^-57 for Authenticated Encryption (AE)
    /// security", with full-size records of 2^14 bytes. Luykx and Paterson, "Limits on
    /// Authenticated Encryption Use in TLS", table 1, give the same 2^24.5 records for a
    /// confidentiality advantage of 2^-60.
    pub const DEFAULT_MAX_BYTES_AES_GCM: NonZeroU64 =
        NonZeroU64::new(1 << 38).expect("2^38 is not zero");
}

/// The DEK a store-less envelope encrypts under, renewed by its policy. Its plaintext lives in
/// the envelope's cache, never here.
struct DekReuse {
    policy: DekReusePolicy,
    /// The `max_bytes` of the policy with the default of the algorithm applied, `None` for no
    /// limit.
    max_bytes: Option<NonZeroU64>,
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

/// The DEK in use: the encrypted form every value under it carries, and what the policy counts.
struct CurrentDek {
    encrypted_dek: EncryptedDataEncryptionKey,
    created_at: Instant,
    uses: AtomicU64,
    /// The plaintext bytes sealed and claimed under the DEK, counted only under a `max_bytes`.
    bytes: AtomicU64,
}

impl DekReuse {
    /// The reuse of `policy` under `algorithm`, which must be in range for it, with its DEK in
    /// `dek_cache`, which must be enabled.
    fn new(
        policy: DekReusePolicy,
        algorithm: AeadAlgorithm,
        dek_cache: &DekCache,
    ) -> KmsAeadResult<Self> {
        let (max_bytes, max_bytes_bound) = match algorithm {
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => (
                Some(
                    policy
                        .max_bytes
                        .unwrap_or(DekReusePolicy::DEFAULT_MAX_BYTES_AES_GCM),
                ),
                MAX_BYTES_PER_AES_GCM_DEK,
            ),
            AeadAlgorithm::Aes256GcmSiv | AeadAlgorithm::ChaCha20Poly1305 => {
                (policy.max_bytes, u64::MAX)
            }
        };
        if policy.max_age.is_zero()
            || policy.max_uses.get() > MAX_ENCRYPTIONS_PER_DEK
            || max_bytes.is_some_and(|max_bytes| max_bytes.get() > max_bytes_bound)
        {
            return Err(KmsAeadSystemError::create(
                "INVALID_DEK_REUSE_POLICY",
                &format!(
                    "A DEK reuse policy needs a max_age longer than zero, a max_uses of 2^32 at \
                     most and, under AES-GCM, a max_bytes of 2^52 at most: {policy:?}"
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
            max_bytes,
            current: RwLock::new(None),
            renewal: AssertUnwindSafe(tokio::sync::Mutex::new(None)),
            ended_renewals: AtomicU64::new(0),
        })
    }

    /// The DEK to encrypt one value of `len` plaintext bytes under, `max_bytes` at most, encrypted by `renew` when the policy renews the current one. A writer that waited while an
    /// attempt failed returns that attempt's error rather than calling the KMS again; a writer
    /// arriving after it retries.
    async fn claim_or_renew<F, Fut>(&self, len: u64, renew: F) -> KmsAeadResult<Arc<CurrentDek>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = KmsAeadResult<EncryptedDataEncryptionKey>>,
    {
        if let Some(dek) = self.claim(len) {
            return Ok(dek);
        }
        let ended_on_arrival = self.ended_renewals.load(Ordering::Relaxed);
        let mut last_failure = self.renewal.lock().await;
        if let Some(dek) = self.claim(len) {
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
            Ok(encrypted_dek) => {
                *last_failure = None;
                let dek = Arc::new(CurrentDek {
                    encrypted_dek,
                    created_at: Instant::now(),
                    uses: AtomicU64::new(1),
                    bytes: AtomicU64::new(len),
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

    /// The current DEK with one of its uses and `len` of its bytes taken, or `None` when the
    /// policy renews it.
    fn claim(&self, len: u64) -> Option<Arc<CurrentDek>> {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        let dek = current.as_ref()?;
        let usable = dek.created_at.elapsed() < self.policy.max_age
            && dek.uses.fetch_add(1, Ordering::Relaxed) < self.policy.max_uses.get()
            && self.max_bytes.is_none_or(|max_bytes| {
                dek.bytes
                    .fetch_add(len, Ordering::Relaxed)
                    .saturating_add(len)
                    <= max_bytes.get()
            });
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
    /// `INVALID_DEK_REUSE_POLICY` for a reuse policy with a zero `max_age`, a `max_uses` over
    /// 2^32 or a `max_bytes` over 2^52 under AES-GCM, or beside [`DekCache::disabled`], and the errors of [`DekCache::new`] for the
    /// default cache of store-less mode.
    pub fn with_options(provider: P, options: KmsAeadEnvelopeOptions) -> KmsAeadResult<Self> {
        let dek_cache = match options.dek_cache {
            Some(dek_cache) => dek_cache,
            None if options.dek_reuse.is_some() => DekCache::new(DekCacheOptions::new())?,
            None => DekCache::disabled(),
        };
        let dek_reuse = options
            .dek_reuse
            .map(|policy| DekReuse::new(policy, options.algorithm, &dek_cache))
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

    /// The provider this envelope encrypts and decrypts DEKs with.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    /// The cache this envelope decrypts DEKs through, for [`DekCache::invalidate`] and
    /// [`DekCache::clear`]. Pass `envelope.provider().kek()` to `invalidate`: a
    /// [`KekRef`](crate::KekRef) built by hand that differs from it matches no entry.
    pub fn dek_cache(&self) -> &DekCache {
        &self.dek_cache
    }

    /// Encrypts `value`, as [`Plaintext`] encodes it, under a new DEK, or under the reused DEK of
    /// a store-less envelope, and returns it with the encrypted DEK in one value. A new DEK costs
    /// one KMS call to encrypt it, and one more for the key material when the provider uses the
    /// KMS generator.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, `INVALID_PLAINTEXT` when `value` does not encode,
    /// `INVALID_KEY_LENGTH` when the KMS generator returns key material of the wrong length, and
    /// `INVALID_CIPHER_TEXT_FORMAT` when the encrypted DEK is longer than the 4,096 bytes Tink
    /// reads.
    pub async fn encrypt<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &T,
    ) -> KmsAeadResult<Encrypted<T, Envelope>> {
        let measurement = Measurement::start(self.call("encrypt", self.mode()));
        let sealed = spans::in_span(self.encrypt_span(self.mode()), async {
            let plain_text = value.to_plaintext()?;
            self.seal(aad.as_ref(), plain_text.ref_sensitive_value())
                .await
        })
        .await;
        measurement.sealed(&sealed);
        sealed
    }

    /// Decrypts the DEK stored in `value`, through the envelope's [`DekCache`], opens the value
    /// with it and decodes the plaintext as a `T`. With the deprecated `legacy-formats` feature,
    /// `value` may hold a layout written by 0.29 or earlier, and the first read of each layout in
    /// the process logs one `WARN` event.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, the errors of [`DekCache::with_dek`] when the encrypted
    /// DEK does not decrypt to a key, and `INVALID_PLAINTEXT` when the plaintext is not an encoding
    /// of `T`. A legacy value passes `TryFrom` on its lengths alone, so with `legacy-formats`
    /// reading one fails here with `INVALID_KEY_VERSION` when its key version is not ASCII
    /// alphanumeric, and with `INVALID_CIPHER_TEXT_FORMAT` when its cipher text is shorter than a
    /// nonce and a tag.
    pub async fn decrypt<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Envelope>,
    ) -> KmsAeadResult<T> {
        let measurement = Measurement::start(self.call("decrypt", self.mode()));
        let opened = spans::in_span(self.decrypt_span(self.mode()), async {
            T::from_plaintext(self.open(aad.as_ref(), value.value()).await?)
        })
        .await;
        measurement.opened(value, &opened);
        opened
    }

    /// Encrypts `value` under a plaintext DEK the caller holds, such as one from
    /// [`generate_encrypted_dek`](Self::generate_encrypted_dek), without calling the KMS.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::encrypt_bare`].
    pub fn encrypt_with_dek<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &T,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<Encrypted<T, Bare>> {
        let measurement = Measurement::start(self.call("encrypt", "caller_dek"));
        let sealed = spans::in_scope(self.encrypt_span("caller_dek"), || {
            self.cipher.encrypt_bare(aad, value, dek)
        });
        measurement.sealed(&sealed);
        sealed
    }

    /// Decrypts `encrypted_dek`, through the envelope's [`DekCache`], and encrypts `value` under
    /// it. The caller stores the encrypted DEK beside the returned value, or joins the two with
    /// [`Encrypted::join`].
    ///
    /// # Errors
    ///
    /// The errors of the provider's decryption and of [`AeadCipher::encrypt_bare`].
    pub async fn encrypt_with_encrypted_dek<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &T,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Encrypted<T, Bare>> {
        let measurement = Measurement::start(self.call("encrypt", "caller_dek"));
        let sealed = spans::in_span(self.encrypt_span("caller_dek"), async {
            self.with_dek(encrypted_dek, |dek| {
                self.cipher.encrypt_bare(aad, value, dek)
            })
            .await
        })
        .await;
        measurement.sealed(&sealed);
        sealed
    }

    /// Opens `value` with a plaintext DEK the caller holds, without calling the KMS, and decodes
    /// the plaintext as a `T`.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::decrypt_bare`].
    pub fn decrypt_with_dek<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Bare>,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<T> {
        let measurement = Measurement::start(self.call("decrypt", "caller_dek"));
        let opened = spans::in_scope(self.decrypt_span("caller_dek"), || {
            self.cipher.decrypt_bare(aad, value, dek)
        });
        measurement.opened(value, &opened);
        opened
    }

    /// Decrypts `encrypted_dek`, through the envelope's [`DekCache`], opens `value` with it and
    /// decodes the plaintext as a `T`.
    ///
    /// # Errors
    ///
    /// The errors of the provider's decryption and of [`AeadCipher::decrypt_bare`].
    pub async fn decrypt_with_encrypted_dek<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Bare>,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<T> {
        let measurement = Measurement::start(self.call("decrypt", "caller_dek"));
        let opened = spans::in_span(self.decrypt_span("caller_dek"), async {
            self.with_dek(encrypted_dek, |dek| {
                self.cipher.decrypt_bare(aad, value, dek)
            })
            .await
        })
        .await;
        measurement.opened(value, &opened);
        opened
    }

    /// The beacon of `value` under the HMAC-SHA256 beacon key `encrypted_dek`, whose id is
    /// `key_id`, for the field `context`, keeping `bits` bits: [`BeaconMac::beacon`] with the key
    /// decrypted through the envelope's [`DekCache`]. A beacon key comes from
    /// [`BeaconMac::generate_encrypted_dek`] with this envelope's [`provider`](Self::provider).
    ///
    /// `context` names the field and never a row. Rotating a beacon key is the application's:
    /// it keeps both keys while it re-indexes, writes beacons under the new one, and queries with
    /// a beacon under each, until no stored beacon names the old key.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the decrypted key is not a serialised
    /// Tink key, and the errors of [`BeaconMac::beacon`].
    pub async fn beacon<T: Plaintext>(
        &self,
        key_id: KeyId,
        context: &(impl AsRef<[u8]> + ?Sized),
        bits: BeaconBits,
        value: &T,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Beacon<T>> {
        let mac = BeaconMac::<B>::new(BeaconAlgorithm::HmacSha256);
        let measurement = Measurement::start(metrics::Call {
            operation: "beacon",
            mode: "caller_dek",
            backend: B::NAME,
            algorithm: Some(mac.algorithm().as_str()),
        });
        let span = spans::beacon(mac.algorithm(), B::NAME, &self.dek_cache);
        let beacon = spans::in_span(
            span,
            self.with_dek(encrypted_dek, |dek| {
                mac.beacon(key_id, context, bits, value, dek)
            }),
        )
        .await;
        measurement.finished(&beacon);
        beacon
    }

    /// Generates a new DEK, from the KMS generator when the provider uses one and from the
    /// backend's CSPRNG otherwise, and encrypts it with the KMS as Tink does, so that
    /// [`Encrypted::join`] can store it with values sealed under it.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::generate_encrypted_dek`].
    pub async fn generate_encrypted_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let measurement = Measurement::start(self.call("generate_dek", "caller_dek"));
        let span = spans::generate_encrypted_dek("randomized", self.cipher.algorithm(), B::NAME);
        let generated =
            spans::in_span(span, self.cipher.generate_encrypted_dek(&self.provider)).await;
        measurement.finished(&generated);
        generated
    }

    /// `value` with its DEK encrypted again under the KEK version the provider encrypts with now,
    /// and its AEAD bytes as they are, so that the KEK version that encrypted it can be disabled
    /// once no stored value needs it. It takes no AAD and opens nothing, so the algorithm and the
    /// AAD of the value play no part, and the value decrypts as before.
    ///
    /// It makes two KMS calls, through the provider and never through the [`DekCache`]: the KMS
    /// decrypts the DEK with the version that encrypted it and encrypts it again with its current
    /// one. The cache is left as it is, so a sweep evicts no entry that serves reads. An entry of
    /// the old encrypted DEK serves until it expires: it holds the same key, and the values not
    /// swept yet still carry it.
    ///
    /// Every call encrypts again, also for a value already under the current version. Values that
    /// share a DEK, as a store-less envelope writes them, each receive an encrypted DEK of their own
    /// here: to keep them sharing one, re-encrypt each distinct encrypted DEK once with
    /// [`reencrypt_encrypted_dek`](Self::reencrypt_encrypted_dek) and [`Encrypted::join`] it with
    /// each of its values.
    ///
    /// # Errors
    ///
    /// The errors of [`Encrypted::separate`] and of the provider, `INVALID_KEY_FORMAT` when the
    /// decrypted key is not a key kms-aead encrypts, and `LEGACY_FORMAT` for a value in a layout of
    /// 0.29 or earlier, with or without `legacy-formats`. `upgrade_legacy_value` rewrites such a
    /// value in Tink's format, with its DEK encrypted under the current version.
    pub async fn reencrypt_dek<T>(
        &self,
        value: &Encrypted<T, Envelope>,
    ) -> KmsAeadResult<Encrypted<T, Envelope>> {
        let measurement = Measurement::start(self.reencrypt_call(self.mode()));
        let reencrypted = spans::in_span(spans::reencrypt_dek(&self.dek_cache), async {
            let (bare, encrypted_dek) = value.separate().map_err(|error| match error {
                KmsAeadError::LegacyFormat(KmsAeadLegacyFormatError { format, .. }) => {
                    KmsAeadLegacyFormatError::refused_by_reencryption(format)
                }
                error => error,
            })?;
            let encrypted_dek =
                crate::formats::reencrypt_encrypted_dek(&encrypted_dek, &self.provider).await?;
            Encrypted::join(&bare, &encrypted_dek)
        })
        .await;
        measurement.finished(&reencrypted);
        reencrypted
    }

    /// `encrypted_dek` encrypted again under the KEK version the provider encrypts with now, as
    /// [`reencrypt_dek`](Self::reencrypt_dek) does for the DEK in a value: two KMS calls, never
    /// through the [`DekCache`], and the same key in the new encrypted DEK. It serves the keys
    /// stored apart from their values, such as those of the `*_with_encrypted_dek` calls, of
    /// beacons and of deterministic fields, and a DEK that many values share.
    ///
    /// The result's [`kek_version`](EncryptedDataEncryptionKey::kek_version) names the KEK version
    /// the KMS encrypted with, which shows a re-encryption that a KMS still propagating a rotation
    /// ran under the old version.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the decrypted key is not a key kms-aead
    /// encrypts, and `LEGACY_FORMAT` for a key in a layout of 0.29 or earlier, with or without
    /// `legacy-formats`. `upgrade_legacy_encrypted_dek` rewrites such a key.
    pub async fn reencrypt_encrypted_dek(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let measurement = Measurement::start(self.reencrypt_call("caller_dek"));
        let reencrypted = spans::in_span(
            spans::reencrypt_dek(&self.dek_cache),
            crate::formats::reencrypt_encrypted_dek(encrypted_dek, &self.provider),
        )
        .await;
        measurement.finished(&reencrypted);
        reencrypted
    }

    /// Seals `plain_text` as `encrypt` does, in the span of the caller.
    async fn seal<T>(
        &self,
        aad: &[u8],
        plain_text: &[u8],
    ) -> KmsAeadResult<Encrypted<T, Envelope>> {
        let len = plain_text.len() as u64;
        let sealed = match &self.dek_reuse {
            Some(dek_reuse)
                if dek_reuse
                    .max_bytes
                    .is_none_or(|max_bytes| len <= max_bytes.get()) =>
            {
                // The cache holds the only plaintext copy of the DEK, so a renewal caches it.
                // Once it has left the cache, expired, invalidated or cleared, the writer renews
                // instead of decrypting it again, so that `invalidate` and `clear` end its use.
                let renew = || async {
                    let (dek, encrypted_dek) =
                        self.cipher.generate_encrypted_dek(&self.provider).await?;
                    if let Some(enabled) = &self.dek_cache.0 {
                        enabled.insert(self.provider.kek(), &encrypted_dek, dek);
                    }
                    Ok(encrypted_dek)
                };
                let current = dek_reuse.claim_or_renew(len, renew).await?;
                let sealed = self.dek_cache.0.as_ref().and_then(|enabled| {
                    enabled.with_cached_dek(self.provider.kek(), &current.encrypted_dek, |dek| {
                        self.seal_envelope(aad, plain_text, dek, &current.encrypted_dek)
                    })
                });
                match sealed {
                    Some(sealed) => {
                        spans::record_dek_cache(DekCacheOutcome::Hit);
                        sealed?
                    }
                    None => {
                        dek_reuse.retire(&current);
                        let current = dek_reuse.claim_or_renew(len, renew).await?;
                        self.with_dek(&current.encrypted_dek, |dek| {
                            self.seal_envelope(aad, plain_text, dek, &current.encrypted_dek)
                        })
                        .await?
                    }
                }
            }
            // Per call, and in store-less mode a value longer than `max_bytes`: a DEK of its own.
            _ => {
                let (dek, encrypted_dek) =
                    self.cipher.generate_encrypted_dek(&self.provider).await?;
                self.seal_envelope(aad, plain_text, &dek, &encrypted_dek)?
            }
        };
        Encrypted::try_from(sealed)
    }

    /// `plain_text` sealed under `dek` behind the envelope header of `encrypted_dek`, in one
    /// buffer: `[w][encrypted DEK][nonce][ciphertext][tag]`.
    fn seal_envelope(
        &self,
        aad: &[u8],
        plain_text: &[u8],
        dek: &DataEncryptionKey,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Vec<u8>> {
        let header = crate::formats::envelope::envelope_header(encrypted_dek)?;
        self.cipher
            .seal(&header, aad, plain_text, dek.value().ref_sensitive_value())
    }

    /// Opens `value` as `decrypt` does, in the span of the caller.
    async fn open(&self, aad: &[u8], value: &[u8]) -> KmsAeadResult<SecretValue> {
        #[cfg(feature = "legacy-formats")]
        let (bare, encrypted_dek) = {
            let stored = crate::formats::legacy::StoredEnvelope::split(value)?;
            (
                stored.bare,
                stored.encrypted_dek(self.provider.kek().provider())?,
            )
        };
        #[cfg(not(feature = "legacy-formats"))]
        let (bare, encrypted_dek) = {
            let (encrypted_dek_bytes, bare) = crate::formats::envelope::split_envelope(value)?;
            (
                bare,
                EncryptedDataEncryptionKey::new(encrypted_dek_bytes.to_vec()),
            )
        };
        self.with_dek(&encrypted_dek, |dek| {
            self.cipher
                .open(aad, bare, 0, dek.value().ref_sensitive_value())
        })
        .await
    }

    /// Runs `use_dek` with the DEK that `encrypted_dek` holds, through the cache, and records on
    /// the current span where the key came from, whether `use_dek` succeeds or not. A failed
    /// decryption records a miss. Without a cache nothing is recorded: the span records `disabled`
    /// when it opens, and a field recorded twice is exported twice.
    async fn with_dek<T>(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
        use_dek: impl FnOnce(&DataEncryptionKey) -> KmsAeadResult<T>,
    ) -> KmsAeadResult<T> {
        let result = self
            .dek_cache
            .with_dek(&self.provider, encrypted_dek, use_dek)
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

    /// The `mode` span field of `encrypt` and `decrypt`.
    fn mode(&self) -> &'static str {
        if self.dek_reuse.is_some() {
            "store_less"
        } else {
            "per_call"
        }
    }

    /// The metric attributes of a call of `operation` in `mode` under the envelope's algorithm.
    fn call(&self, operation: &'static str, mode: &'static str) -> metrics::Call {
        metrics::Call {
            operation,
            mode,
            backend: B::NAME,
            algorithm: Some(self.cipher.algorithm().as_str()),
        }
    }

    /// The metric attributes of a re-encryption in `mode`, in which the algorithm plays no part.
    fn reencrypt_call(&self, mode: &'static str) -> metrics::Call {
        metrics::Call {
            operation: "reencrypt_dek",
            mode,
            backend: B::NAME,
            algorithm: None,
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
    use std::num::NonZeroU32;

    use super::*;
    use crate::errors::KmsAeadLegacyFormat;
    use crate::formats::TinkKeyType;
    use crate::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
    use crate::test_provider::{
        encrypted_by_test_provider, let_spawned_tasks_wait, CountingKmsProvider, TestBackend,
        TestKmsProvider, CONCURRENT_CALLS,
    };
    use crate::{KekProvider, KekRef};

    type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;
    type CountingEnvelope = KmsAeadEnvelope<CountingKmsProvider, TestBackend>;
    type LocalEnvelope = KmsAeadEnvelope<LocalKmsProvider<TestBackend>, TestBackend>;

    const AAD: &[u8] = b"orders/1042";
    const PLAIN_TEXT: &str = "4111 1111 1111 1111";
    const ORDERS_KEK: &str = "orders";

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt(AAD, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let (dek, encrypted_dek) = encryption.generate_encrypted_dek().await?;
        let ciphertext = encryption.encrypt_with_dek(AAD, &plaintext, &dek)?;

        assert_eq!(
            encryption.decrypt_with_dek(AAD, &ciphertext, &dek)?,
            plaintext
        );
        assert_eq!(
            encryption
                .decrypt_with_encrypted_dek(AAD, &ciphertext, &encrypted_dek)
                .await?,
            plaintext
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_new_dek_is_encrypted_as_its_tink_key() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;

        let (dek, encrypted_dek) = encryption.generate_encrypted_dek().await?;

        assert_eq!(
            encrypted_dek,
            encrypted_by_test_provider(TinkKeyType::AesGcm, dek.value().ref_sensitive_value())
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_encrypted_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let plaintext = SecretValue::from("secret message");

        let (_dek, encrypted_dek) = encryption.generate_encrypted_dek().await?;
        let ciphertext = encryption
            .encrypt_with_encrypted_dek(AAD, &plaintext, &encrypted_dek)
            .await?;
        let decrypted = encryption
            .decrypt_with_encrypted_dek(AAD, &ciphertext, &encrypted_dek)
            .await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_provider_encrypt_failure() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::FailingToEncrypt)?;

        let result = encryption.encrypt(AAD, &SecretValue::from("secret")).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "TEST_ENCRYPT"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_provider_decrypt_failure() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working)?;
        let ciphertext = encryption
            .encrypt(AAD, &SecretValue::from("secret"))
            .await?;
        let failing_encryption = Envelope::new(TestKmsProvider::FailingToDecrypt)?;

        let result = failing_encryption.decrypt(AAD, &ciphertext).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "TEST_DECRYPT"),
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

        let ciphertext = encryption.encrypt(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt(AAD, &ciphertext).await?;

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
                    let ciphertext = encryption.encrypt(aad.as_bytes(), &plaintext).await?;
                    let decrypted = encryption.decrypt(aad.as_bytes(), &ciphertext).await?;
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
            .encrypt(AAD, &SecretValue::from("secret"))
            .await?;

        let mut corrupted = ciphertext.into_value();
        corrupted[20] ^= 0x01;
        let result: KmsAeadResult<SecretValue> = encryption
            .decrypt(AAD, &Encrypted::try_from(corrupted)?)
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

        let (dek, _) = encryption.generate_encrypted_dek().await?;

        assert_eq!(dek.value(), &material);
        Ok(())
    }

    #[tokio::test]
    async fn new_dek_falls_back_to_the_backend_without_a_kms_generator() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm),
        )?;

        let (first_dek, _) = encryption.generate_encrypted_dek().await?;
        let (second_dek, _) = encryption.generate_encrypted_dek().await?;

        assert_eq!(first_dek.value().ref_sensitive_value().len(), 16);
        assert_ne!(first_dek, second_dek);
        Ok(())
    }

    #[tokio::test]
    async fn generate_key_material_of_the_wrong_length_fails() -> KmsAeadResult<()> {
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
        let provider = TestKmsProvider::Generating(SecretValue::new(vec![0x42; 64]));

        let result = cipher.generate_encrypted_dek(&provider).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
            "{:?}",
            result.err()
        );
        Ok(())
    }

    // The same secret under the AAD `fixture-aad`, with the test provider's raw key as the
    // encrypted DEK, in the layouts of 0.28.1, of 0.29 and of 32-bit targets before 0.24.0, sealed
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
            let envelope = Encrypted::<SecretValue, crate::formats::Envelope>::try_from(
                hex::decode(envelope_hex).unwrap(),
            )?;
            let secret = encryption.decrypt(FIXTURE_AAD, &envelope).await?;
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
                KmsAeadLegacyFormat::RawEncryptedDek,
            ),
        ] {
            let read = Encrypted::<SecretValue, crate::formats::Envelope>::try_from(
                hex::decode(envelope_hex).unwrap(),
            );
            let result = match read {
                Ok(envelope) => encryption.decrypt(FIXTURE_AAD, &envelope).await,
                Err(error) => Err(error),
            };
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
            let legacy = Encrypted::<SecretValue, crate::formats::Envelope>::try_from(
                hex::decode(envelope_hex).unwrap(),
            )?;

            let upgraded = encryption
                .upgrade_legacy_value(FIXTURE_AAD, &legacy)
                .await?
                .expect("a legacy value is upgraded");

            let (bare, encrypted_dek) = upgraded.separate()?;
            let sealed_len = 12 + FIXTURE_SECRET.len() + 16;
            assert!(encrypted_dek.to_hex_string().starts_with("1220"));
            assert_eq!(
                bare.value(),
                &legacy.value()[legacy.value().len() - sealed_len..]
            );
            assert_eq!(
                encryption.decrypt(FIXTURE_AAD, &upgraded).await?,
                SecretValue::from(FIXTURE_SECRET)
            );
            assert!(encryption
                .upgrade_legacy_value(FIXTURE_AAD, &upgraded)
                .await?
                .is_none());
        }
        assert_eq!(encryption.provider.encryptions(), 3);
        Ok(())
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn a_value_that_does_not_open_is_not_upgraded() -> KmsAeadResult<()> {
        let legacy = Encrypted::<SecretValue, crate::formats::Envelope>::try_from(
            hex::decode(ENVELOPE_FROM_0_29).unwrap(),
        )?;
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
        assert_eq!(aes_256_gcm.provider.encryptions(), 0);
        assert_eq!(chacha20_poly1305.provider.encryptions(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_reencrypted_dek_opens_the_same_bytes_without_the_old_kek_version(
    ) -> KmsAeadResult<()> {
        let [v1, v2] =
            [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
        let kek_id = LocalKekId::try_from(ORDERS_KEK.to_string())?;
        let before_rotation = LocalEnvelope::new(LocalKmsProvider::new(
            kek_id.clone(),
            vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
        )?)?;
        let rotated = LocalEnvelope::new(LocalKmsProvider::new(
            kek_id.clone(),
            vec![
                LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
                LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
            ],
        )?)?;
        let old_version_removed = LocalEnvelope::new(LocalKmsProvider::new(
            kek_id,
            vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
        )?)?;
        let value = before_rotation
            .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;

        let reencrypted = rotated.reencrypt_dek(&value).await?;

        let (bare, _) = value.separate()?;
        let (reencrypted_bare, _) = reencrypted.separate()?;
        assert_eq!(reencrypted_bare.value(), bare.value());
        assert_eq!(
            old_version_removed.decrypt(AAD, &reencrypted).await?,
            SecretValue::from(PLAIN_TEXT)
        );
        Ok(())
    }

    #[tokio::test]
    async fn reencryption_refuses_the_layouts_of_0_29_and_earlier() -> KmsAeadResult<()> {
        let raw_key_value = Encrypted::<SecretValue, crate::formats::Envelope>::try_from(
            hex::decode(ENVELOPE_FROM_0_23_0_ON_32_BIT).unwrap(),
        )?;
        let built_in_kek = CountingEnvelope::new(CountingKmsProvider::with_kek(
            TestKmsProvider::Working,
            KekRef::new(KekProvider::Gcp, ORDERS_KEK),
        ))?;
        // `[0xFF][0x01][k = 0]` before the KMS's encrypted DEK, as 0.29's `to_bytes` wrote it.
        let encrypted_dek_v1 = EncryptedDataEncryptionKey::new(vec![0xFF, 0x01, 0x00, 0x42]);

        let raw_key = Envelope::new(TestKmsProvider::Working)?
            .reencrypt_dek(&raw_key_value)
            .await;
        let layout_v1 = built_in_kek
            .reencrypt_encrypted_dek(&encrypted_dek_v1)
            .await;

        assert!(
            matches!(&raw_key, Err(KmsAeadError::LegacyFormat(error))
                if error.format == KmsAeadLegacyFormat::RawEncryptedDek),
            "{raw_key:?}"
        );
        assert!(
            matches!(&layout_v1, Err(KmsAeadError::LegacyFormat(error))
                if error.format == KmsAeadLegacyFormat::EncryptedDekV1),
            "{layout_v1:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn per_call_envelope_has_no_cache_by_default() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let envelope = CountingEnvelope::new(provider)?;

        let value = envelope
            .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            let decrypted = envelope.decrypt(AAD, &value).await?;
            assert_eq!(decrypted, SecretValue::from(PLAIN_TEXT));
        }

        assert_eq!(envelope.provider.decryptions(), 2);
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
            .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            envelope.decrypt(AAD, &value).await?;
        }

        assert_eq!(envelope.provider.decryptions(), 1);
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
            DekReusePolicy::new().with_max_bytes(NonZeroU64::new((1 << 52) + 1).unwrap()),
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
                DekReusePolicy::new()
                    .with_max_uses(NonZeroU64::new(1 << 32).unwrap())
                    .with_max_bytes(NonZeroU64::new(1 << 52).unwrap()),
            ),
        )?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypted_dek_decrypts_through_the_cache() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )?;

        let (_, encrypted_dek) = envelope.generate_encrypted_dek().await?;
        let value = envelope
            .encrypt_with_encrypted_dek(AAD, &SecretValue::from(PLAIN_TEXT), &encrypted_dek)
            .await?;
        let decrypted = envelope
            .decrypt_with_encrypted_dek(AAD, &value, &encrypted_dek)
            .await?;

        assert_eq!(decrypted, SecretValue::from(PLAIN_TEXT));
        assert_eq!(envelope.provider.decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn reuse_renews_by_count() -> KmsAeadResult<()> {
        let policy = DekReusePolicy::new().with_max_uses(NonZeroU64::new(3).unwrap());
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(policy),
        )?;

        let mut encrypted_deks = Vec::new();
        for _ in 0..7 {
            let value = envelope
                .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
                .await?;
            encrypted_deks.push(value.separate()?.1);
        }

        let renewals: Vec<_> = encrypted_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [false, false, true, false, false, true]);
        assert_eq!(envelope.provider.encryptions(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn reuse_renews_by_bytes() -> KmsAeadResult<()> {
        let max_bytes = NonZeroU64::new(3 * PLAIN_TEXT.len() as u64).unwrap();
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new().with_max_bytes(max_bytes)),
        )?;

        let mut encrypted_deks = Vec::new();
        for _ in 0..7 {
            let value = envelope
                .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
                .await?;
            encrypted_deks.push(value.separate()?.1);
        }

        let renewals: Vec<_> = encrypted_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [false, false, true, false, false, true]);
        assert_eq!(envelope.provider.encryptions(), 3);
        Ok(())
    }

    #[tokio::test]
    async fn a_value_over_the_remaining_bytes_renews_first() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new().with_max_bytes(NonZeroU64::new(10).unwrap())),
        )?;

        let mut encrypted_deks = Vec::new();
        for plain_text in ["six b.", "six b.", "four"] {
            let value = envelope
                .encrypt(AAD, &SecretValue::from(plain_text))
                .await?;
            encrypted_deks.push(value.separate()?.1);
        }

        let renewals: Vec<_> = encrypted_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [true, false]);
        assert_eq!(envelope.provider.encryptions(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn a_value_over_max_bytes_has_a_dek_of_its_own() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new().with_max_bytes(NonZeroU64::new(10).unwrap())),
        )?;

        let mut encrypted_deks = Vec::new();
        for plain_text in ["four", "eleven byte", "four"] {
            let value = envelope
                .encrypt(AAD, &SecretValue::from(plain_text))
                .await?;
            encrypted_deks.push(value.separate()?.1);
        }

        assert_ne!(encrypted_deks[1], encrypted_deks[0]);
        assert_eq!(encrypted_deks[2], encrypted_deks[0]);
        assert_eq!(envelope.provider.encryptions(), 2);
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

        let mut encrypted_deks = Vec::new();
        for pause in [Duration::ZERO, max_age, Duration::ZERO] {
            let value = envelope
                .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
                .await?;
            encrypted_deks.push(value.separate()?.1);
            tokio::time::sleep(pause).await;
        }

        let renewals: Vec<_> = encrypted_deks
            .windows(2)
            .map(|pair| pair[0] != pair[1])
            .collect();
        assert_eq!(renewals, [false, true]);
        assert_eq!(envelope.provider.encryptions(), 2);
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
                tokio::spawn(
                    async move { envelope.encrypt(AAD, &SecretValue::from(PLAIN_TEXT)).await },
                )
            })
            .collect();
        let_spawned_tasks_wait().await;
        assert_eq!(envelope.provider.encryptions(), 1);
        envelope.provider.open_gate();

        let mut encrypted_deks = Vec::new();
        for encryption in encryptions {
            encrypted_deks.push(encryption.await.unwrap()?.separate()?.1);
        }
        assert!(encrypted_deks.iter().all(|dek| *dek == encrypted_deks[0]));
        assert_eq!(envelope.provider.encryptions(), 1);
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
            values.push((envelope.encrypt(AAD, &plain_text).await?, plain_text));
        }
        for _ in 0..2 {
            for (value, plain_text) in &values {
                assert_eq!(envelope.decrypt(AAD, value).await?, *plain_text);
            }
        }

        assert_eq!(envelope.provider.encryptions(), 3);
        assert_eq!(envelope.provider.decryptions(), 0);
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
            .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        let (_, writer_encrypted_dek) = first.separate()?;
        let cached = envelope
            .dek_cache()
            .cached_dek(envelope.provider.kek(), &writer_encrypted_dek);
        tokio::time::sleep(ttl).await;
        envelope.dek_cache().purge_expired();
        let zeroized = cached.is_some_and(|dek| dek.strong_count() == 0);
        let after_ttl = envelope
            .encrypt(AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;

        assert!(zeroized);
        assert_ne!(after_ttl.separate()?.1, writer_encrypted_dek);
        assert_eq!(envelope.provider.encryptions(), 2);
        assert_eq!(envelope.provider.decryptions(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn invalidate_makes_the_writer_renew() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?;
        let plain_text = SecretValue::from(PLAIN_TEXT);

        let first_encrypted_dek = envelope.encrypt(AAD, &plain_text).await?.separate()?.1;
        envelope
            .dek_cache()
            .invalidate(envelope.provider().kek(), &first_encrypted_dek);
        let after_invalidate_encrypted_dek =
            envelope.encrypt(AAD, &plain_text).await?.separate()?.1;
        envelope.dek_cache().clear();
        let after_clear_encrypted_dek = envelope.encrypt(AAD, &plain_text).await?.separate()?.1;

        assert_ne!(after_invalidate_encrypted_dek, first_encrypted_dek);
        assert_ne!(after_clear_encrypted_dek, after_invalidate_encrypted_dek);
        assert_eq!(envelope.provider.encryptions(), 3);
        assert_eq!(envelope.provider.decryptions(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn renewal_failure_is_shared_with_queued_writers() -> KmsAeadResult<()> {
        let envelope = Arc::new(CountingEnvelope::with_options(
            CountingKmsProvider::gated(TestKmsProvider::FailingToEncrypt, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?);

        let encryptions: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let envelope = Arc::clone(&envelope);
                tokio::spawn(
                    async move { envelope.encrypt(AAD, &SecretValue::from(PLAIN_TEXT)).await },
                )
            })
            .collect();
        let_spawned_tasks_wait().await;
        envelope.provider.open_gate();
        let mut results = Vec::new();
        for encryption in encryptions {
            results.push(encryption.await.unwrap());
        }
        let encryptions_of_one_attempt = envelope.provider.encryptions();
        results.push(envelope.encrypt(AAD, &SecretValue::from(PLAIN_TEXT)).await);

        for result in &results {
            assert!(
                matches!(result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "TEST_ENCRYPT"),
                "{:?}",
                result.as_ref().err()
            );
        }
        assert_eq!(encryptions_of_one_attempt, 1);
        assert_eq!(envelope.provider.encryptions(), 2);
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

    /// `value` written by `encrypt` and read back by `decrypt`.
    async fn through_a_field<T: Plaintext>(envelope: &Envelope, value: &T) -> KmsAeadResult<T> {
        let field = envelope.encrypt(AAD, value).await?;
        envelope.decrypt(AAD, &field).await
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
            envelope.encrypt(AAD, &email).await?;
        let stored = Encrypted::<Email, crate::formats::Envelope>::try_from(field.into_value())?;

        assert_eq!(envelope.decrypt(AAD, &stored).await?, email);
        let untyped =
            Encrypted::<SecretValue, crate::formats::Envelope>::try_from(stored.into_value())?;
        assert_eq!(
            envelope.decrypt(AAD, &untyped).await?,
            SecretValue::from("alice@example.com")
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_beacon_decrypts_its_key_through_the_cache() -> KmsAeadResult<()> {
        let encryption = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )?;
        let mac = BeaconMac::<TestBackend>::new(BeaconAlgorithm::HmacSha256);
        let (dek, encrypted_dek) = mac.generate_encrypted_dek(encryption.provider()).await?;
        let key_id = KeyId::new(7);
        let email = "alice@example.com".to_string();

        let beacon = encryption
            .beacon(
                key_id,
                b"user/email",
                BeaconBits::DEFAULT,
                &email,
                &encrypted_dek,
            )
            .await?;
        let again = encryption
            .beacon(
                key_id,
                b"user/email",
                BeaconBits::DEFAULT,
                &email,
                &encrypted_dek,
            )
            .await?;
        let other_field = encryption
            .beacon(
                key_id,
                b"user/name",
                BeaconBits::DEFAULT,
                &email,
                &encrypted_dek,
            )
            .await?;

        assert_eq!(beacon, again);
        assert_eq!(
            beacon,
            mac.beacon(key_id, b"user/email", BeaconBits::DEFAULT, &email, &dek)?
        );
        assert_ne!(beacon, other_field);
        assert_eq!(encryption.provider().decryptions(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn store_less_fields_reuse_the_dek_through_the_cache() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
        )?;
        let card = PLAIN_TEXT.to_string();

        let first = envelope.encrypt(AAD, &card).await?;
        let second = envelope.encrypt(AAD, &card).await?;

        assert_eq!(envelope.decrypt(AAD, &first).await?, card);
        assert_eq!(envelope.decrypt(AAD, &second).await?, card);
        assert_eq!(envelope.provider.encryptions(), 1);
        assert_eq!(envelope.provider.decryptions(), 0);
        Ok(())
    }

    #[test]
    fn envelope_is_unwind_safe() {
        fn unwind_safe<T: std::panic::UnwindSafe + std::panic::RefUnwindSafe>() {}
        unwind_safe::<Envelope>();
    }
}
