use std::future::Future;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use rsb_derive::Builder;
use secret_vault_value::SecretValue;
use tracing::Span;

use crate::cache::{DekCache, DekCacheOptions, DekCacheOutcome};
use crate::errors::{KmsAeadError, KmsAeadSystemError};
use crate::types::EnvelopeLayout;
use crate::{
    spans, AeadAlgorithm, AeadBackend, AeadCipher, CipherText, CipherTextWithEncryptedKey,
    DataEncryptionKey, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadResult,
};

const DEFAULT_MAX_USES: NonZeroU64 = NonZeroU64::new(1 << 24).expect("2^24 is not zero");

/// The most encryptions a [`DekReusePolicy`] allows under one DEK. NIST SP 800-38D, section 8.3,
/// allows 2^32 invocations of authenticated encryption under one key with random 96-bit IVs, the
/// nonces every [`AeadAlgorithm`] draws.
const MAX_USES: u64 = 1 << 32;

/// Envelope encryption: AEAD under data encryption keys (DEKs) on the backend the envelope is
/// built with, and the DEKs wrapped by a key encryption key (KEK) through the provider `P`.
///
/// Every call returns the errors of [`AeadCipher`] for the AEAD step and the errors of the
/// provider for the KMS step, with the codes the provider reports. A call that makes no KMS call
/// is not `async`.
///
/// [`encrypt_value`](Self::encrypt_value) runs in one of two modes, both writing envelope layout
/// v1:
///
/// - per call, the default: a new DEK per value, one KMS wrap per value;
/// - store-less, with a [`DekReusePolicy`] in the options: one DEK for many values, renewed by
///   the policy, one KMS wrap per renewal and one KMS unwrap per TTL of the envelope's cache.
///
/// `decrypt_value`, the `*_with_encrypted_dek` calls and a store-less `encrypt_value` unwrap
/// through the envelope's [`DekCache`], which is disabled in a per-call envelope unless the
/// options give it one; see [`KmsAeadEnvelopeOptions`].
///
/// Every call opens one `DEBUG` span, with the KMS call as a child span when it makes one.
pub struct KmsAeadEnvelope<P> {
    pub(crate) provider: P,
    pub(crate) cipher: AeadCipher,
    dek_cache: DekCache,
    dek_reuse: Option<DekReuse>,
}

/// The settings of a [`KmsAeadEnvelope`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KmsAeadEnvelopeOptions {
    /// The AEAD algorithm, ChaCha20-Poly1305 by default. The envelope layout does not record
    /// the algorithm, so the writer and the reader of a value must be configured with the same
    /// one.
    #[default = "AeadAlgorithm::ChaCha20Poly1305"]
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

/// When a store-less envelope renews the data encryption key (DEK) it encrypts under: at the
/// first encryption past `max_age` or past `max_uses`, whichever comes first.
///
/// A renewal makes one KMS wrap call, and the values under the previous DEK stay readable, since
/// each value carries its wrapped DEK.
///
/// The envelope keeps only the wrapped DEK. Its plaintext lives in the envelope's [`DekCache`],
/// which serves it for the cache's TTL, whatever `max_age`, and the first encryption after that
/// unwraps it again with one KMS call. The cache zeroizes the expired DEK at its next call or at
/// [`DekCache::purge_expired`], so a writer that falls quiet leaves the DEK in memory until
/// then: a process that can sit idle calls `purge_expired` on a timer to drop it at the TTL. The
/// values sealed while the cache holds the DEK are readable by whoever reads the process's
/// memory in that window.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct DekReusePolicy {
    /// The age at which the DEK is renewed: 24 hours by default, and longer than zero.
    #[default = "Duration::from_secs(24 * 60 * 60)"]
    pub max_age: Duration,
    /// The encryptions under one DEK: 2^24 by default, and 2^32 at most. Every
    /// [`AeadAlgorithm`] seals each value with a random 96-bit nonce, which NIST SP 800-38D
    /// allows for 2^32 values under one AES-GCM key.
    #[default = "DEFAULT_MAX_USES"]
    pub max_uses: NonZeroU64,
}

/// The DEK a store-less envelope encrypts under, renewed by its policy. Its plaintext lives in
/// the envelope's cache, never here.
struct DekReuse {
    policy: DekReusePolicy,
    current: RwLock<Option<Arc<CurrentDek>>>,
    /// Held across a renewal's KMS calls, so that one writer renews at a time. It holds the error
    /// of the last attempt when that attempt failed.
    renewal: tokio::sync::Mutex<Option<KmsAeadError>>,
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
            renewal: tokio::sync::Mutex::new(None),
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

    /// The current DEK with one of its uses taken, or `None` when the policy renews it.
    fn claim(&self) -> Option<Arc<CurrentDek>> {
        let current = self.current.read().unwrap_or_else(PoisonError::into_inner);
        let dek = current.as_ref()?;
        let usable = dek.created_at.elapsed() < self.policy.max_age
            && dek.uses.fetch_add(1, Ordering::Relaxed) < self.policy.max_uses.get();
        usable.then(|| Arc::clone(dek))
    }
}

impl<P> KmsAeadEnvelope<P>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    /// An envelope on `backend` with the default options: ChaCha20-Poly1305, a DEK per value, no
    /// cache.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement ChaCha20-Poly1305.
    pub fn new(provider: P, backend: AeadBackend) -> KmsAeadResult<Self> {
        Self::with_options(provider, backend, KmsAeadEnvelopeOptions::new())
    }

    /// An envelope on `backend` with `options`.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement the algorithm of `options`,
    /// `INVALID_DEK_REUSE_POLICY` for a reuse policy with a zero `max_age` or a `max_uses` over
    /// 2^32, or beside [`DekCache::disabled`], and the errors of [`DekCache::new`] for the
    /// default cache of store-less mode.
    pub fn with_options(
        provider: P,
        backend: AeadBackend,
        options: KmsAeadEnvelopeOptions,
    ) -> KmsAeadResult<Self> {
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
            cipher: AeadCipher::new(backend, options.algorithm)?,
            dek_cache,
            dek_reuse,
        })
    }

    /// The algorithm this envelope seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.cipher.algorithm()
    }

    /// The cache this envelope unwraps DEKs through, for [`DekCache::invalidate`] and
    /// [`DekCache::clear`].
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
    /// longer than 65,535 bytes.
    pub async fn encrypt_value(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        spans::in_span(self.encrypt_span(self.mode()), async {
            match &self.dek_reuse {
                Some(dek_reuse) => {
                    // Caching the new DEK under its wrapped bytes saves the first value sealed
                    // under it an unwrap.
                    let dek = dek_reuse
                        .claim_or_renew(|| async {
                            let (dek, encrypted) = self.new_dek().await?;
                            if let Some(shared) = &self.dek_cache.0 {
                                shared.insert(self.provider.kek(), &encrypted, None, dek);
                            }
                            Ok(encrypted)
                        })
                        .await?;
                    let cipher_text = self
                        .with_dek(&dek.encrypted, |key| {
                            self.cipher.encrypt_value(aad, plain_text, key)
                        })
                        .await?;
                    CipherTextWithEncryptedKey::join(&cipher_text, &dek.encrypted)
                }
                None => {
                    let (dek, encrypted_dek) = self.new_dek().await?;
                    let cipher_text = self.cipher.encrypt_value(aad, plain_text, &dek)?;
                    CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)
                }
            }
        })
        .await
    }

    /// Unwraps the DEK stored in `cipher_text`, through the envelope's [`DekCache`], and opens
    /// the value with it.
    ///
    /// # Errors
    ///
    /// Besides the AEAD and KMS errors, `UNKNOWN_CIPHER_TEXT_LAYOUT`,
    /// `INVALID_CIPHER_TEXT_FORMAT` or `INVALID_KEY_VERSION` when `cipher_text` cannot be read
    /// (see [`CipherTextWithEncryptedKey::separate`]).
    pub async fn decrypt_value(
        &self,
        aad: &[u8],
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let format = EnvelopeLayout::try_from(cipher_text)
            .ok()
            .map(EnvelopeLayout::name);
        spans::in_span(self.decrypt_span(self.mode(), format), async {
            let (cipher_text, encrypted_dek) = cipher_text.separate()?;
            self.with_dek(&encrypted_dek, |key| {
                self.cipher.decrypt_value(aad, &cipher_text, key)
            })
            .await
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
        spans::in_scope(self.decrypt_span("caller_dek", None), || {
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
        spans::in_span(self.decrypt_span("caller_dek", None), async {
            self.with_dek(dek, |key| self.cipher.decrypt_value(aad, cipher_text, key))
                .await
        })
        .await
    }

    /// Generates a new DEK, from the KMS generator when the provider uses one and from the
    /// backend's CSPRNG otherwise, and wraps it with the KMS.
    ///
    /// # Errors
    ///
    /// The errors of [`AeadCipher::generate_wrapped_key`].
    pub async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let span =
            spans::generate_dek("randomized", self.cipher.algorithm(), self.cipher.backend());
        spans::in_span(span, self.new_dek()).await
    }

    async fn new_dek(&self) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        // Unbound, so that the values open with kms-aead 0.29 and with any envelope over the
        // same KEK.
        self.cipher.generate_wrapped_key(&self.provider, None).await
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
            .with_key(&self.provider, encrypted, None, use_key)
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
        spans::aead_encrypt(
            mode,
            self.cipher.algorithm(),
            self.cipher.backend(),
            &self.dek_cache,
        )
    }

    fn decrypt_span(&self, mode: &str, format: Option<&str>) -> Span {
        spans::aead_decrypt(
            mode,
            self.cipher.algorithm(),
            self.cipher.backend(),
            &self.dek_cache,
            format,
        )
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
    use crate::test_provider::{
        let_spawned_tasks_wait, CountingKmsProvider, TestKmsProvider, CONCURRENT_CALLS,
        TEST_BACKEND,
    };

    type Envelope = KmsAeadEnvelope<TestKmsProvider>;
    type CountingEnvelope = KmsAeadEnvelope<CountingKmsProvider>;

    const AAD: &[u8] = b"orders/1042";
    const PLAIN_TEXT: &str = "4111 1111 1111 1111";
    const ORDERS_KEK: &str = "orders";

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt_value(AAD, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
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
    async fn test_envelope_encryption_with_encrypted_dek() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
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
        let encryption = Envelope::new(TestKmsProvider::FailingToWrap, TEST_BACKEND)?;

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
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
        let ciphertext = encryption
            .encrypt_value(AAD, &SecretValue::from("secret"))
            .await?;
        let failing_encryption = Envelope::new(TestKmsProvider::FailingToUnwrap, TEST_BACKEND)?;

        let result = failing_encryption.decrypt_value(AAD, &ciphertext).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "TEST_UNWRAP"),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn test_aes_256_gcm_algorithm() -> KmsAeadResult<()> {
        let encryption = Envelope::with_options(
            TestKmsProvider::Working,
            TEST_BACKEND,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
        )?;
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(AAD, &plaintext).await?;
        let decrypted = encryption.decrypt_value(AAD, &ciphertext).await?;

        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn test_concurrent_encryptions() -> KmsAeadResult<()> {
        let encryption = Arc::new(Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?);

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
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
        let cipher = AeadCipher::new(TEST_BACKEND, AeadAlgorithm::Aes256Gcm)?;
        let provider = TestKmsProvider::Generating(SecretValue::new(vec![0x42; 64]));

        let result = cipher.generate_wrapped_key(&provider, None).await;

        assert!(
            matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
            "{:?}",
            result.err()
        );
        Ok(())
    }

    const FIXTURE_AAD: &[u8] = b"fixture-aad";
    #[cfg(feature = "legacy-formats")]
    const FIXTURE_SECRET: &str = "fixture-secret";
    const ENVELOPE_FROM_0_28_1: &str = "000000000000002089548688c2a8d0d11b8547aa1e9a1c79fbaddcb5a4866e56af813d65b041d60672aba785e3857369ab75d33b8672d013a8e721a538876b0d59090f06c6c3a698acf2113a29e1f90ed89e";
    /// 32-bit targets wrote a 4-byte length prefix before 0.24.0.
    const ENVELOPE_FROM_0_23_0_ON_32_BIT: &str = "00000020e8efcd9417d41f8dee5dc6b8cfde7b209951fb80e60e0b8240a9fa688f815e1501a12b36821b4aa097fbe86573df02d8fe8d34235bdb9b3731107e946d0021d7d2ea089f87d4bea034a2";

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_decrypt() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let secret = encryption.decrypt_value(FIXTURE_AAD, &envelope).await?;
            assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
        }
        Ok(())
    }

    #[cfg(not(feature = "legacy-formats"))]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_need_legacy_formats() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let result = encryption.decrypt_value(FIXTURE_AAD, &envelope).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error))
                    if error.format == KmsAeadLegacyFormat::LengthPrefixedEnvelope),
                "{result:?}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn envelopes_from_0_28_1_and_earlier_upgrade_to_layout_v1() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND)?;
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let legacy = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let (cipher_text, encrypted_dek) = legacy.separate()?;
            let current = CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?;

            assert_eq!(encrypted_dek.key_version(), None);
            assert_eq!(legacy.upgrade_legacy_layout()?, Some(current.clone()));
            assert_eq!(current.upgrade_legacy_layout()?, None);
            assert_eq!(
                encryption.decrypt_value(FIXTURE_AAD, &current).await?,
                SecretValue::from(FIXTURE_SECRET)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn per_call_envelope_has_no_cache_by_default() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let envelope = CountingEnvelope::new(provider, TEST_BACKEND)?;

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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
                TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
            TEST_BACKEND,
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
        assert_eq!(after_ttl.separate()?.1, writer_dek);
        assert_eq!(envelope.provider.wraps(), 1);
        assert_eq!(envelope.provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn renewal_failure_is_shared_with_queued_writers() -> KmsAeadResult<()> {
        let envelope = Arc::new(CountingEnvelope::with_options(
            CountingKmsProvider::gated(TestKmsProvider::FailingToWrap, ORDERS_KEK),
            TEST_BACKEND,
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
}
