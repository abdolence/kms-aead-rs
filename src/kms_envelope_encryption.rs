use crate::backend::AeadBackend;
use crate::spans;
use crate::*;
use async_trait::*;
use rsb_derive::*;
use secret_vault_value::SecretValue;
use tracing::Span;

/// Envelope encryption: a data encryption key per value or per caller, wrapped by the provider
/// `P`, and AEAD on the backend `B`.
///
/// Name the backend once: `KmsAeadEnvelope::<GcpKmsProvider, Ring>::new(provider).await?`.
pub struct KmsAeadEnvelope<P, B> {
    pub(crate) provider: P,
    pub(crate) cipher: AeadCipher<B>,
}

#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KmsAeadEnvelopeOptions {
    /// The envelope layout does not record the algorithm, so the writer and the reader of a value
    /// must be configured with the same one.
    #[default = "AeadAlgorithm::ChaCha20Poly1305"]
    pub algorithm: AeadAlgorithm,
}

impl<P, B> KmsAeadEnvelope<P, B>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    /// ChaCha20-Poly1305, as in every earlier release.
    pub async fn new(provider: P) -> KmsAeadResult<Self> {
        Self::with_options(provider, KmsAeadEnvelopeOptions::new()).await
    }

    /// Fails with `UNSUPPORTED_ALGORITHM` when `B` does not implement `algorithm`.
    pub async fn with_algorithm(provider: P, algorithm: AeadAlgorithm) -> KmsAeadResult<Self> {
        Self::with_options(
            provider,
            KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
        )
        .await
    }

    /// Fails with `UNSUPPORTED_ALGORITHM` when `B` does not implement the algorithm.
    pub async fn with_options(provider: P, options: KmsAeadEnvelopeOptions) -> KmsAeadResult<Self> {
        Ok(Self {
            provider,
            cipher: AeadCipher::new(options.algorithm)?,
        })
    }

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
        spans::aead_encrypt(mode, self.algorithm(), AeadCipher::<B>::backend_name())
    }

    fn decrypt_span(&self, mode: &str, format: Option<&str>) -> Span {
        spans::aead_decrypt(
            mode,
            self.algorithm(),
            AeadCipher::<B>::backend_name(),
            format,
        )
    }
}

#[async_trait]
impl<Aad, P, B> KmsAeadEnvelopeEncryption<Aad> for KmsAeadEnvelope<P, B>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
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
        let span = spans::generate_dek(
            "randomized",
            self.algorithm(),
            AeadCipher::<B>::backend_name(),
        );
        spans::in_span(span, self.new_dek()).await
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::test_provider::{TestBackend, TestKmsProvider};
    use std::sync::Arc;

    type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        // Generate a DEK
        let (dek, encrypted_dek) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();

        // Encrypt with the DEK
        let ciphertext = encryption
            .encrypt_value_with_dek(&aad, &plaintext, &dek)
            .await
            .unwrap();

        // Decrypt with the same DEK
        let decrypted = encryption
            .decrypt_value_with_dek(&aad, &ciphertext, &dek)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);

        // Also test decrypt with encrypted DEK
        let decrypted2 = encryption
            .decrypt_value_with_encrypted_dek(&aad, &ciphertext, &encrypted_dek)
            .await
            .unwrap();

        assert_eq!(decrypted2, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_encrypted_dek() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        // Generate a DEK
        let (_dek, encrypted_dek) =
            KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
                .await
                .unwrap();

        // Encrypt with encrypted DEK
        let ciphertext = encryption
            .encrypt_value_with_encrypted_dek(&aad, &plaintext, &encrypted_dek)
            .await
            .unwrap();

        // Decrypt with encrypted DEK
        let decrypted = encryption
            .decrypt_value_with_encrypted_dek(&aad, &ciphertext, &encrypted_dek)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_wrong_aad_fails() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad1 = "correct-aad";
        let aad2 = "wrong-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad1, &plaintext).await.unwrap();
        let result = encryption.decrypt_value(&aad2, &ciphertext).await;

        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[tokio::test]
    async fn test_empty_plaintext() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from(vec![]);

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted.ref_sensitive_value().len(), 0);
    }

    #[tokio::test]
    async fn test_large_plaintext() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let large_data = vec![0x42; 100_000]; // 100KB
        let plaintext = SecretValue::from(large_data.clone());

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), large_data.as_slice());
    }

    #[tokio::test]
    async fn test_multiple_encryptions_different_deks() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ct1 = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let ct2 = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        // Different encryptions should produce different ciphertexts (different nonces/DEKs)
        assert_ne!(ct1, ct2);

        // But both should decrypt to the same plaintext
        let decrypted1 = encryption.decrypt_value(&aad, &ct1).await.unwrap();
        let decrypted2 = encryption.decrypt_value(&aad, &ct2).await.unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[tokio::test]
    async fn test_multiple_encryptions_same_dek() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        // Generate a single DEK
        let (dek, _) = KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
            .await
            .unwrap();

        // Encrypt multiple times with same DEK
        let ct1 = encryption
            .encrypt_value_with_dek(&aad, &plaintext, &dek)
            .await
            .unwrap();
        let ct2 = encryption
            .encrypt_value_with_dek(&aad, &plaintext, &dek)
            .await
            .unwrap();

        // Different ciphertexts (different nonces)
        assert_ne!(ct1, ct2);

        // Both decrypt correctly
        let decrypted1 = encryption
            .decrypt_value_with_dek(&aad, &ct1, &dek)
            .await
            .unwrap();
        let decrypted2 = encryption
            .decrypt_value_with_dek(&aad, &ct2, &dek)
            .await
            .unwrap();

        assert_eq!(decrypted1, plaintext);
        assert_eq!(decrypted2, plaintext);
    }

    #[tokio::test]
    async fn test_provider_encrypt_failure() {
        let provider = TestKmsProvider::FailingToWrap;
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let result = encryption.encrypt_value(&aad, &plaintext).await;
        assert!(
            result.is_err(),
            "Should fail when provider fails to encrypt DEK"
        );
    }

    #[tokio::test]
    async fn test_provider_decrypt_failure() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider.clone()).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        // Encrypt successfully
        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        // Create new encryption with failing provider
        let failing_provider = TestKmsProvider::FailingToUnwrap;
        let failing_encryption = Envelope::new(failing_provider).await.unwrap();

        let result = failing_encryption.decrypt_value(&aad, &ciphertext).await;
        assert!(
            result.is_err(),
            "Should fail when provider fails to decrypt DEK"
        );
    }

    #[tokio::test]
    async fn test_aes_256_gcm_algorithm() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::with_algorithm(provider, AeadAlgorithm::Aes256Gcm)
            .await
            .unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_with_options() {
        let provider = TestKmsProvider::new();
        let options = KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm);
        let encryption = Envelope::with_options(provider, options).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_binary_aad() {
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let binary_aad: Vec<u8> = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF];
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption
            .encrypt_value(&binary_aad, &plaintext)
            .await
            .unwrap();
        let decrypted = encryption
            .decrypt_value(&binary_aad, &ciphertext)
            .await
            .unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_concurrent_encryptions() {
        use tokio::task;

        let provider = TestKmsProvider::new();
        let encryption = Arc::new(Envelope::new(provider).await.unwrap());

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
        let provider = TestKmsProvider::new();
        let encryption = Envelope::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        // Corrupt the ciphertext
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
            TestKmsProvider::generating(material.clone()),
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
        let encryption = Envelope::with_algorithm(TestKmsProvider::new(), AeadAlgorithm::Aes128Gcm)
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
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm).unwrap();
        let provider = TestKmsProvider::generating(SecretValue::new(vec![0x42; 64]));

        let result = cipher.generate_data_encryption_key_with(&provider).await;

        assert_eq!(result.unwrap_err().code(), "INVALID_KEY_LENGTH");
    }

    const FIXTURE_AAD: &str = "fixture-aad";
    const FIXTURE_SECRET: &str = "fixture-secret";

    async fn decrypt_released_envelope(envelope_hex: &str) -> KmsAeadResult<SecretValue> {
        let encryption = Envelope::new(TestKmsProvider::new()).await?;
        let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope_hex).unwrap());
        encryption.decrypt_value(&FIXTURE_AAD, &envelope).await
    }

    #[tokio::test]
    async fn envelope_from_0_28_1_decrypts() {
        let secret = decrypt_released_envelope(
            "000000000000002089548688c2a8d0d11b8547aa1e9a1c79fbaddcb5a4866e56af813d65b041d60672aba785e3857369ab75d33b8672d013a8e721a538876b0d59090f06c6c3a698acf2113a29e1f90ed89e",
        )
        .await
        .unwrap();
        assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
    }

    /// 32-bit targets wrote a 4-byte length prefix before 0.24.0.
    #[tokio::test]
    async fn envelope_from_0_23_0_on_32_bit_decrypts() {
        let secret = decrypt_released_envelope(
            "00000020e8efcd9417d41f8dee5dc6b8cfde7b209951fb80e60e0b8240a9fa688f815e1501a12b36821b4aa097fbe86573df02d8fe8d34235bdb9b3731107e946d0021d7d2ea089f87d4bea034a2",
        )
        .await
        .unwrap();
        assert_eq!(secret, SecretValue::from(FIXTURE_SECRET));
    }
}
