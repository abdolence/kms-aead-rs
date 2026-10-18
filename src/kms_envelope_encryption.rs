use std::future::Future;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, PoisonError, RwLock};
use std::time::{Duration, Instant};

use crate::cache::{DekCache, DekCacheOptions, InsertDek};
use crate::errors::{KmsAeadError, KmsAeadSystemError};
use crate::spans;
use crate::*;
use async_trait::*;
use rsb_derive::*;
use secret_vault_value::SecretValue;
use tracing::Span;

const DEFAULT_MAX_USES: NonZeroU64 = NonZeroU64::new(1 << 24).expect("2^24 is not zero");

/// The most encryptions a [`DekReusePolicy`] allows under one DEK. NIST SP 800-38D, section 8.3,
/// allows 2^32 invocations of authenticated encryption under one key with random 96-bit IVs, the
/// nonces every [`AeadAlgorithm`] draws.
const MAX_USES: u64 = 1 << 32;

/// Envelope encryption: data encryption keys (DEKs) wrapped by the provider `P`, and AEAD on the
/// backend the envelope is built with. The [`KmsAeadEnvelopeEncryption`] implementation encrypts
/// and decrypts values.
///
/// [`encrypt_value`](KmsAeadEnvelopeEncryption::encrypt_value) runs in one of two modes, both
/// writing envelope layout v1:
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
/// which zeroizes it at most its TTL plus its reaper period after it was cached, whatever
/// `max_age`, and the first encryption after that unwraps it again with one KMS call. The values
/// sealed while the cache holds the DEK are readable by whoever reads the process's memory in
/// that window.
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
    pub async fn new(provider: P, backend: AeadBackend) -> KmsAeadResult<Self> {
        Self::with_options(provider, backend, KmsAeadEnvelopeOptions::new()).await
    }

    /// An envelope on `backend` with `algorithm`, a DEK per value and no cache.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement `algorithm`.
    pub async fn with_algorithm(
        provider: P,
        backend: AeadBackend,
        algorithm: AeadAlgorithm,
    ) -> KmsAeadResult<Self> {
        Self::with_options(
            provider,
            backend,
            KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
        )
        .await
    }

    /// An envelope on `backend` with `options`.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement the algorithm of `options`,
    /// `INVALID_DEK_REUSE_POLICY` for a reuse policy with a zero `max_age` or a `max_uses` over
    /// 2^32, or beside [`DekCache::disabled`], and the errors of [`DekCache::new`] for the
    /// default cache of store-less mode.
    pub async fn with_options(
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

    async fn new_dek(&self) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let dek = self
            .cipher
            .generate_data_encryption_key_with(&self.provider)
            .await?;
        let encrypted_dek = self.provider.encrypt_data_encryption_key(&dek).await?;
        Ok((dek, encrypted_dek))
    }

    /// A new DEK for store-less mode, wrapped once and cached under its wrapped bytes, so that
    /// the first value sealed under it needs no unwrap.
    async fn renew_dek(&self) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let (dek, encrypted) = self.new_dek().await?;
        self.dek_cache
            .insert_dek(self.provider.kek(), &encrypted, dek);
        Ok(encrypted)
    }

    /// Runs `use_key` with the DEK `encrypted` wraps, through the cache, and records on the
    /// current span where the key came from, whether `use_key` succeeds or not.
    async fn with_dek<T>(
        &self,
        encrypted: &EncryptedDataEncryptionKey,
        use_key: impl FnOnce(&DataEncryptionKey) -> KmsAeadResult<T>,
    ) -> KmsAeadResult<T> {
        let (used, outcome) = self
            .dek_cache
            .with_key(&self.provider, encrypted, use_key)
            .await?;
        spans::record_dek_cache(outcome);
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
            self.cipher.backend,
            &self.dek_cache,
        )
    }

    fn decrypt_span(&self, mode: &str, format: Option<&str>) -> Span {
        spans::aead_decrypt(
            mode,
            self.cipher.algorithm(),
            self.cipher.backend,
            &self.dek_cache,
            format,
        )
    }
}

#[async_trait]
impl<Aad, P> KmsAeadEnvelopeEncryption<Aad> for KmsAeadEnvelope<P>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        spans::in_span(self.encrypt_span(self.mode()), async {
            match &self.dek_reuse {
                Some(dek_reuse) => {
                    let dek = dek_reuse.claim_or_renew(|| self.renew_dek()).await?;
                    let cipher_text = self
                        .with_dek(&dek.encrypted, |key| {
                            self.cipher.seal(aad.as_ref(), plain_text, key)
                        })
                        .await?;
                    CipherTextWithEncryptedKey::new(&cipher_text, &dek.encrypted)
                }
                None => {
                    let (dek, encrypted_dek) = self.new_dek().await?;
                    let cipher_text = self.cipher.seal(aad.as_ref(), plain_text, &dek)?;
                    CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)
                }
            }
        })
        .await
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let span = self.decrypt_span(self.mode(), cipher_text.layout_name());
        spans::in_span(span, async {
            let (cipher_text, encrypted_dek) = cipher_text.separate()?;
            self.with_dek(&encrypted_dek, |key| {
                self.cipher.open(aad.as_ref(), &cipher_text, key)
            })
            .await
        })
        .await
    }

    async fn encrypt_value_with_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        spans::in_span(self.encrypt_span("caller_dek"), async {
            self.cipher.seal(aad.as_ref(), plain_text, dek)
        })
        .await
    }

    async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        spans::in_span(self.encrypt_span("caller_dek"), async {
            self.with_dek(dek, |key| self.cipher.seal(aad.as_ref(), plain_text, key))
                .await
        })
        .await
    }

    async fn decrypt_value_with_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        data_encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        spans::in_span(self.decrypt_span("caller_dek", None), async {
            self.cipher
                .open(aad.as_ref(), cipher_text, data_encryption_key)
        })
        .await
    }

    async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        spans::in_span(self.decrypt_span("caller_dek", None), async {
            self.with_dek(encrypted_data_encryption_key, |key| {
                self.cipher.open(aad.as_ref(), cipher_text, key)
            })
            .await
        })
        .await
    }

    async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let span = spans::generate_dek("randomized", self.cipher.algorithm(), self.cipher.backend);
        spans::in_span(span, self.new_dek()).await
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    #[cfg(not(feature = "legacy-formats"))]
    use crate::errors::KmsAeadLegacyFormat;
    use crate::test_provider::{
        let_spawned_tasks_wait, wait_until, CountingKmsProvider, TestKmsProvider, CONCURRENT_CALLS,
        TEST_BACKEND,
    };

    type Envelope = KmsAeadEnvelope<TestKmsProvider>;
    type CountingEnvelope = KmsAeadEnvelope<CountingKmsProvider>;

    const AAD: &str = "orders/1042";
    const PLAIN_TEXT: &str = "4111 1111 1111 1111";
    const ORDERS_KEK: &str = "orders";

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::new(provider, TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::new(provider, TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let (dek, encrypted_dek) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();

        let ciphertext = encryption
            .encrypt_value_with_dek(&aad, &plaintext, &dek)
            .await
            .unwrap();

        let decrypted = encryption
            .decrypt_value_with_dek(&aad, &ciphertext, &dek)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);

        let decrypted2 = encryption
            .decrypt_value_with_encrypted_dek(&aad, &ciphertext, &encrypted_dek)
            .await
            .unwrap();

        assert_eq!(decrypted2, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_encrypted_dek() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::new(provider, TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let (_dek, encrypted_dek) =
            KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
                .await
                .unwrap();

        let ciphertext = encryption
            .encrypt_value_with_encrypted_dek(&aad, &plaintext, &encrypted_dek)
            .await
            .unwrap();

        let decrypted = encryption
            .decrypt_value_with_encrypted_dek(&aad, &ciphertext, &encrypted_dek)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_provider_encrypt_failure() {
        let provider = TestKmsProvider::FailingToWrap;
        let encryption = Envelope::new(provider, TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let result = encryption.encrypt_value(&aad, &plaintext).await;

        assert_eq!(result.unwrap_err().code(), "TEST_WRAP");
    }

    #[tokio::test]
    async fn test_provider_decrypt_failure() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::new(provider.clone(), TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        let failing_provider = TestKmsProvider::FailingToUnwrap;
        let failing_encryption = Envelope::new(failing_provider, TEST_BACKEND).await.unwrap();

        let result = failing_encryption.decrypt_value(&aad, &ciphertext).await;

        assert_eq!(result.unwrap_err().code(), "TEST_UNWRAP");
    }

    #[tokio::test]
    async fn test_aes_256_gcm_algorithm() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::with_algorithm(provider, TEST_BACKEND, AeadAlgorithm::Aes256Gcm)
            .await
            .unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_concurrent_encryptions() {
        use tokio::task;

        let provider = TestKmsProvider::Working;
        let encryption = Arc::new(Envelope::new(provider, TEST_BACKEND).await.unwrap());

        let mut handles = vec![];
        for i in 0..10 {
            let enc = encryption.clone();
            let handle = task::spawn(async move {
                let aad = format!("aad-{}", i);
                let plaintext = SecretValue::from(format!("secret-{}", i).as_bytes().to_vec());

                let ciphertext = enc.encrypt_value(&aad, &plaintext).await.unwrap();
                let decrypted = enc.decrypt_value(&aad, &ciphertext).await.unwrap();

                assert_eq!(decrypted, plaintext);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }

    #[tokio::test]
    async fn test_corrupted_cipher_text_with_key_fails() {
        let provider = TestKmsProvider::Working;
        let encryption = Envelope::new(provider, TEST_BACKEND).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        let mut corrupted = ciphertext.value().to_vec();
        if corrupted.len() > 20 {
            corrupted[20] ^= 0x01;
        }
        let corrupted_ct = CipherTextWithEncryptedKey::from(corrupted);

        let result = encryption.decrypt_value(&aad, &corrupted_ct).await;
        assert!(result.is_err(), "Decryption of corrupted data should fail");
    }

    #[tokio::test]
    async fn new_dek_takes_the_key_material_of_the_kms_generator() {
        let material = SecretValue::new((0..32).collect());
        let encryption = Envelope::with_algorithm(
            TestKmsProvider::Generating(material.clone()),
            TEST_BACKEND,
            AeadAlgorithm::Aes256Gcm,
        )
        .await
        .unwrap();

        let (dek, _) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();

        assert_eq!(dek.value(), &material);
    }

    #[tokio::test]
    async fn new_dek_falls_back_to_the_backend_without_a_kms_generator() {
        let encryption = Envelope::with_algorithm(
            TestKmsProvider::Working,
            TEST_BACKEND,
            AeadAlgorithm::Aes128Gcm,
        )
        .await
        .unwrap();

        let (first, _) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();
        let (second, _) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();

        assert_eq!(first.value().ref_sensitive_value().len(), 16);
        assert_ne!(first, second);
    }

    #[tokio::test]
    async fn generate_key_material_of_the_wrong_length_fails() {
        let cipher = AeadCipher::new(TEST_BACKEND, AeadAlgorithm::Aes256Gcm).unwrap();
        let provider = TestKmsProvider::Generating(SecretValue::new(vec![0x42; 64]));

        let result = cipher.generate_data_encryption_key_with(&provider).await;

        assert_eq!(result.unwrap_err().code(), "INVALID_KEY_LENGTH");
    }

    const FIXTURE_AAD: &str = "fixture-aad";
    #[cfg(feature = "legacy-formats")]
    const FIXTURE_SECRET: &str = "fixture-secret";
    const ENVELOPE_FROM_0_28_1: &str = "000000000000002089548688c2a8d0d11b8547aa1e9a1c79fbaddcb5a4866e56af813d65b041d60672aba785e3857369ab75d33b8672d013a8e721a538876b0d59090f06c6c3a698acf2113a29e1f90ed89e";
    /// 32-bit targets wrote a 4-byte length prefix before 0.24.0.
    const ENVELOPE_FROM_0_23_0_ON_32_BIT: &str = "00000020e8efcd9417d41f8dee5dc6b8cfde7b209951fb80e60e0b8240a9fa688f815e1501a12b36821b4aa097fbe86573df02d8fe8d34235bdb9b3731107e946d0021d7d2ea089f87d4bea034a2";

    async fn decrypt_released_envelope(
        envelope: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND).await?;
        encryption.decrypt_value(&FIXTURE_AAD, envelope).await
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_decrypt() -> KmsAeadResult<()> {
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let secret = decrypt_released_envelope(&envelope).await?;
            assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
        }
        Ok(())
    }

    #[cfg(not(feature = "legacy-formats"))]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_need_legacy_formats() {
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let result = decrypt_released_envelope(&envelope).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error))
                    if error.format == KmsAeadLegacyFormat::LengthPrefixedEnvelope),
                "{result:?}"
            );
        }
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn envelopes_from_0_28_1_and_earlier_upgrade_to_layout_v1() -> KmsAeadResult<()> {
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let legacy = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let (cipher_text, encrypted_dek) = legacy.separate()?;
            let current = CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)?;

            assert_eq!(encrypted_dek.key_version(), None);
            assert_eq!(legacy.upgrade_legacy_layout()?, Some(current.clone()));
            assert_eq!(current.upgrade_legacy_layout()?, None);
            assert_eq!(
                decrypt_released_envelope(&current).await?,
                SecretValue::from(FIXTURE_SECRET)
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn per_call_envelope_has_no_cache_by_default() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK);
        let envelope = CountingEnvelope::new(provider, TEST_BACKEND).await?;

        let value = envelope
            .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            let decrypted = envelope.decrypt_value(&AAD, &value).await?;
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
        )
        .await?;

        let value = envelope
            .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        for _ in 0..2 {
            envelope.decrypt_value(&AAD, &value).await?;
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
        )
        .await;

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
            )
            .await;
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
        )
        .await?;
        Ok(())
    }

    #[tokio::test]
    async fn encrypted_dek_calls_unwrap_through_the_cache() -> KmsAeadResult<()> {
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            TEST_BACKEND,
            KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?),
        )
        .await?;

        let (_, encrypted_dek) =
            KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&envelope).await?;
        let value = envelope
            .encrypt_value_with_encrypted_dek(&AAD, &SecretValue::from(PLAIN_TEXT), &encrypted_dek)
            .await?;
        let decrypted = envelope
            .decrypt_value_with_encrypted_dek(&AAD, &value, &encrypted_dek)
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
        )
        .await?;

        let mut wrapped_deks = Vec::new();
        for _ in 0..7 {
            let value = envelope
                .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
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
        )
        .await?;

        let mut wrapped_deks = Vec::new();
        for pause in [Duration::ZERO, max_age, Duration::ZERO] {
            let value = envelope
                .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
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
        let envelope = Arc::new(
            CountingEnvelope::with_options(
                CountingKmsProvider::gated(TestKmsProvider::Working, ORDERS_KEK),
                TEST_BACKEND,
                KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
            )
            .await?,
        );

        let encryptions: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let envelope = Arc::clone(&envelope);
                tokio::spawn(async move {
                    envelope
                        .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
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
        )
        .await?;

        let mut values = Vec::new();
        for index in 0..5 {
            let plain_text = SecretValue::from(format!("{PLAIN_TEXT}/{index}"));
            values.push((envelope.encrypt_value(&AAD, &plain_text).await?, plain_text));
        }
        for _ in 0..2 {
            for (value, plain_text) in &values {
                assert_eq!(envelope.decrypt_value(&AAD, value).await?, *plain_text);
            }
        }

        assert_eq!(envelope.provider.wraps(), 3);
        assert_eq!(envelope.provider.unwraps(), 0);
        Ok(())
    }

    #[tokio::test]
    async fn a_quiet_writer_key_is_zeroized_at_the_cache_ttl() -> KmsAeadResult<()> {
        let ttl = Duration::from_millis(200);
        let envelope = CountingEnvelope::with_options(
            CountingKmsProvider::new(TestKmsProvider::Working, ORDERS_KEK),
            TEST_BACKEND,
            KmsAeadEnvelopeOptions::new()
                .with_dek_reuse(DekReusePolicy::new())
                .with_dek_cache(DekCache::new(DekCacheOptions::new().with_ttl(ttl))?),
        )
        .await?;

        let first = envelope
            .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;
        let (_, writer_dek) = first.separate()?;
        let cached = envelope
            .dek_cache()
            .cached_dek(&envelope.provider.kek(), &writer_dek);
        wait_until(|| cached.as_ref().is_some_and(|dek| dek.strong_count() == 0));
        let after_ttl = envelope
            .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
            .await?;

        assert!(cached.is_some_and(|dek| dek.strong_count() == 0));
        assert_eq!(after_ttl.separate()?.1, writer_dek);
        assert_eq!(envelope.provider.wraps(), 1);
        assert_eq!(envelope.provider.unwraps(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn renewal_failure_is_shared_with_queued_writers() -> KmsAeadResult<()> {
        let envelope = Arc::new(
            CountingEnvelope::with_options(
                CountingKmsProvider::gated(TestKmsProvider::FailingToWrap, ORDERS_KEK),
                TEST_BACKEND,
                KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
            )
            .await?,
        );

        let encryptions: Vec<_> = (0..CONCURRENT_CALLS)
            .map(|_| {
                let envelope = Arc::clone(&envelope);
                tokio::spawn(async move {
                    envelope
                        .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
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
                .encrypt_value(&AAD, &SecretValue::from(PLAIN_TEXT))
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
