use crate::spans;
use crate::*;
use async_trait::*;
use rsb_derive::*;
use secret_vault_value::SecretValue;
use tracing::Span;

/// Envelope encryption: a data encryption key per value or per caller, wrapped by the provider
/// `P`, and AEAD on the backend the envelope is built with. The [`KmsAeadEnvelopeEncryption`]
/// implementation encrypts and decrypts values.
///
/// Every call opens one `DEBUG` span, with the KMS call as a child span when it makes one.
pub struct KmsAeadEnvelope<P> {
    pub(crate) provider: P,
    pub(crate) cipher: AeadCipher,
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
}

impl<P> KmsAeadEnvelope<P>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
{
    /// An envelope on `backend` with the default options: ChaCha20-Poly1305.
    ///
    /// # Errors
    ///
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement ChaCha20-Poly1305.
    pub async fn new(provider: P, backend: AeadBackend) -> KmsAeadResult<Self> {
        Self::with_options(provider, backend, KmsAeadEnvelopeOptions::new()).await
    }

    /// An envelope on `backend` with `algorithm`.
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
    /// `UNSUPPORTED_ALGORITHM` when `backend` does not implement the algorithm of `options`.
    pub async fn with_options(
        provider: P,
        backend: AeadBackend,
        options: KmsAeadEnvelopeOptions,
    ) -> KmsAeadResult<Self> {
        Ok(Self {
            provider,
            cipher: AeadCipher::new(backend, options.algorithm)?,
        })
    }

    /// The algorithm this envelope seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.cipher.algorithm()
    }

    async fn new_dek(&self) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let dek = self
            .cipher
            .generate_data_encryption_key_with(&self.provider)
            .await?;
        let encrypted_dek = self.provider.encrypt_data_encryption_key(&dek).await?;
        Ok((dek, encrypted_dek))
    }

    fn encrypt_span(&self, mode: &str) -> Span {
        spans::aead_encrypt(mode, self.cipher.algorithm(), self.cipher.backend)
    }

    fn decrypt_span(&self, mode: &str, format: Option<&str>) -> Span {
        spans::aead_decrypt(mode, self.cipher.algorithm(), self.cipher.backend, format)
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
        spans::in_span(self.encrypt_span("per_call"), async {
            let (dek, encrypted_dek) = self.new_dek().await?;
            let cipher_text = self.cipher.seal(aad.as_ref(), plain_text, &dek)?;
            CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)
        })
        .await
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let span = self.decrypt_span("per_call", cipher_text.layout_name());
        spans::in_span(span, async {
            let (cipher_text, encrypted_dek) = cipher_text.separate()?;
            let dek = self
                .provider
                .decrypt_data_encryption_key(&encrypted_dek)
                .await?;
            self.cipher.open(aad.as_ref(), &cipher_text, &dek)
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
            let dek = self.provider.decrypt_data_encryption_key(dek).await?;
            self.cipher.seal(aad.as_ref(), plain_text, &dek)
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
            let dek = self
                .provider
                .decrypt_data_encryption_key(encrypted_data_encryption_key)
                .await?;
            self.cipher.open(aad.as_ref(), cipher_text, &dek)
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
    use crate::errors::{KmsAeadError, KmsAeadLegacyFormat};
    use crate::test_provider::{TestKmsProvider, TEST_BACKEND};
    use std::sync::Arc;

    type Envelope = KmsAeadEnvelope<TestKmsProvider>;

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

    async fn decrypt_released_envelope(envelope_hex: &str) -> KmsAeadResult<SecretValue> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND).await?;
        let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
        encryption.decrypt_value(&FIXTURE_AAD, &envelope).await
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_decrypt() -> KmsAeadResult<()> {
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let secret = decrypt_released_envelope(envelope_hex).await?;
            assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
        }
        Ok(())
    }

    #[cfg(not(feature = "legacy-formats"))]
    #[tokio::test]
    async fn envelopes_from_0_28_1_and_earlier_need_legacy_formats() {
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let result = decrypt_released_envelope(envelope_hex).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error))
                    if error.format == KmsAeadLegacyFormat::LengthPrefixedEnvelope),
                "{result:?}"
            );
        }
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    #[allow(deprecated, reason = "the upgrade goes with the layouts it reads")]
    async fn envelopes_from_0_28_1_and_earlier_upgrade_to_layout_v1() -> KmsAeadResult<()> {
        let encryption = Envelope::new(TestKmsProvider::Working, TEST_BACKEND).await?;
        for envelope_hex in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_23_0_ON_32_BIT] {
            let legacy = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
            let (cipher_text, encrypted_dek) = legacy.separate()?;
            let current = CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)?;

            assert_eq!(encrypted_dek.key_version(), None);
            assert_eq!(legacy.upgrade_legacy_layout()?, Some(current.clone()));
            assert_eq!(current.upgrade_legacy_layout()?, None);
            assert_eq!(
                encryption.decrypt_value(&FIXTURE_AAD, &current).await?,
                SecretValue::from(FIXTURE_SECRET)
            );
        }
        Ok(())
    }
}
