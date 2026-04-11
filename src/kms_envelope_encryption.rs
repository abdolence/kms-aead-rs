use crate::ring_encryption::{RingAeadEncryption, RingAeadEncryptionOptions};
use crate::*;
use async_trait::*;
use ring::rand::SystemRandom;
use rsb_derive::*;
use secret_vault_value::SecretValue;

#[async_trait]
pub trait KmsAeadRingEncryptionProvider {
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>;

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey>;

    async fn generate_encryption_key(
        &self,
        aead_encryption: &RingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey>;
}

pub struct KmsAeadRingEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    provider: P,
    aead_encryption: RingAeadEncryption,
}

#[derive(Debug, Clone, Builder)]
pub struct KmsAeadRingEnvelopeEncryptionOptions {
    #[default = "RingAeadEncryptionOptions::new()"]
    pub encryption_options: RingAeadEncryptionOptions,
}

impl<P> KmsAeadRingEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    pub async fn new(provider: P) -> KmsAeadResult<Self> {
        Self::with_algorithm(provider, &ring::aead::CHACHA20_POLY1305).await
    }

    pub async fn with_algorithm(
        provider: P,
        algo: &'static ring::aead::Algorithm,
    ) -> KmsAeadResult<Self> {
        Self::with_algorithm_options(provider, algo, KmsAeadRingEnvelopeEncryptionOptions::new())
            .await
    }

    pub async fn with_options(
        provider: P,
        options: KmsAeadRingEnvelopeEncryptionOptions,
    ) -> KmsAeadResult<Self> {
        Self::with_algorithm_options(provider, &ring::aead::CHACHA20_POLY1305, options).await
    }

    pub async fn with_algorithm_options(
        provider: P,
        algo: &'static ring::aead::Algorithm,
        options: KmsAeadRingEnvelopeEncryptionOptions,
    ) -> KmsAeadResult<Self> {
        let secure_rand = SystemRandom::new();
        let aead_encryption = RingAeadEncryption::with_algorithm_options(
            algo,
            secure_rand,
            options.encryption_options,
        )?;

        Ok(Self {
            provider,
            aead_encryption,
        })
    }

    async fn new_dek(&self) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        let dek = self
            .provider
            .generate_encryption_key(&self.aead_encryption)
            .await?;

        let encrypted_dek = self.provider.encrypt_data_encryption_key(&dek).await?;

        Ok((dek, encrypted_dek))
    }

    async fn encrypt_value_with_new_dek<Aad>(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)>
    where
        Aad: AsRef<[u8]> + Send + Sync + 'static,
    {
        let (new_dek, new_encrypted_dek) = self.new_dek().await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &new_dek)
            .await?;

        Ok((cipher_text, new_encrypted_dek))
    }
}

#[async_trait]
impl<Aad, P> KmsAeadEnvelopeEncryption<Aad> for KmsAeadRingEnvelopeEncryption<P>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        let (cipher_text, dek) = self.encrypt_value_with_new_dek(aad, plain_text).await?;
        Ok(CipherTextWithEncryptedKey::new(&cipher_text, &dek))
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let (cipher_text, encrypted_dek) = cipher_text.separate()?;
        self.decrypt_value_with_encrypted_dek(aad, &cipher_text, &encrypted_dek)
            .await
    }

    async fn encrypt_value_with_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, dek)
            .await?;

        Ok(cipher_text)
    }

    async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        let dek = self.provider.decrypt_data_encryption_key(dek).await?;

        self.encrypt_value_with_dek(aad, plain_text, &dek).await
    }

    async fn decrypt_value_with_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        data_encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        self.aead_encryption
            .decrypt_value(aad, cipher_text, data_encryption_key)
            .await
    }
    async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        let dek = self
            .provider
            .decrypt_data_encryption_key(encrypted_data_encryption_key)
            .await?;

        self.decrypt_value_with_dek(aad, cipher_text, &dek).await
    }

    async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        self.new_dek().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rvstruct::ValueStruct;
    use std::sync::{Arc, Mutex};

    // Mock provider for testing
    #[derive(Clone)]
    struct MockKmsProvider {
        encrypted_keys: Arc<Mutex<Vec<Vec<u8>>>>,
        fail_encrypt: bool,
        fail_decrypt: bool,
    }

    impl MockKmsProvider {
        fn new() -> Self {
            Self {
                encrypted_keys: Arc::new(Mutex::new(Vec::new())),
                fail_encrypt: false,
                fail_decrypt: false,
            }
        }

        fn with_fail_encrypt() -> Self {
            Self {
                encrypted_keys: Arc::new(Mutex::new(Vec::new())),
                fail_encrypt: true,
                fail_decrypt: false,
            }
        }

        fn with_fail_decrypt() -> Self {
            Self {
                encrypted_keys: Arc::new(Mutex::new(Vec::new())),
                fail_encrypt: false,
                fail_decrypt: true,
            }
        }
    }

    #[async_trait]
    impl KmsAeadRingEncryptionProvider for MockKmsProvider {
        async fn encrypt_data_encryption_key(
            &self,
            encryption_key: &DataEncryptionKey,
        ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
            if self.fail_encrypt {
                return Err(crate::errors::KmsAeadEncryptionError::create(
                    "MOCK_ENCRYPT_FAIL",
                    "Mock provider configured to fail encryption",
                ));
            }

            // Simple mock: just clone the key and store it
            let encrypted = encryption_key.value().ref_sensitive_value().to_vec();
            self.encrypted_keys.lock().unwrap().push(encrypted.clone());
            Ok(EncryptedDataEncryptionKey::from(encrypted))
        }

        async fn decrypt_data_encryption_key(
            &self,
            encrypted_key: &EncryptedDataEncryptionKey,
        ) -> KmsAeadResult<DataEncryptionKey> {
            if self.fail_decrypt {
                return Err(crate::errors::KmsAeadEncryptionError::create(
                    "MOCK_DECRYPT_FAIL",
                    "Mock provider configured to fail decryption",
                ));
            }

            // Simple mock: just return the key
            Ok(DataEncryptionKey::from(SecretValue::from(
                encrypted_key.value().clone(),
            )))
        }

        async fn generate_encryption_key(
            &self,
            aead_encryption: &RingAeadEncryption,
        ) -> KmsAeadResult<DataEncryptionKey> {
            aead_encryption.generate_data_encryption_key()
        }
    }

    #[tokio::test]
    async fn test_envelope_encryption_roundtrip() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_envelope_encryption_with_provided_dek() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

        let aad1 = "correct-aad";
        let aad2 = "wrong-aad";
        let plaintext = SecretValue::from("secret message");

        let ciphertext = encryption.encrypt_value(&aad1, &plaintext).await.unwrap();
        let result = encryption.decrypt_value(&aad2, &ciphertext).await;

        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[tokio::test]
    async fn test_empty_plaintext() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from(vec![]);

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted.ref_sensitive_value().len(), 0);
    }

    #[tokio::test]
    async fn test_large_plaintext() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

        let aad = "test-aad";
        let large_data = vec![0x42; 100_000]; // 100KB
        let plaintext = SecretValue::from(large_data.clone());

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), large_data.as_slice());
    }

    #[tokio::test]
    async fn test_multiple_encryptions_different_deks() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
        let provider = MockKmsProvider::with_fail_encrypt();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider.clone())
            .await
            .unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        // Encrypt successfully
        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();

        // Create new encryption with failing provider
        let failing_provider = MockKmsProvider::with_fail_decrypt();
        let failing_encryption = KmsAeadRingEnvelopeEncryption::new(failing_provider)
            .await
            .unwrap();

        let result = failing_encryption.decrypt_value(&aad, &ciphertext).await;
        assert!(
            result.is_err(),
            "Should fail when provider fails to decrypt DEK"
        );
    }

    #[tokio::test]
    async fn test_aes_256_gcm_algorithm() {
        let provider = MockKmsProvider::new();
        let encryption =
            KmsAeadRingEnvelopeEncryption::with_algorithm(provider, &ring::aead::AES_256_GCM)
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
        let provider = MockKmsProvider::new();
        let options = KmsAeadRingEnvelopeEncryptionOptions::new();
        let encryption = KmsAeadRingEnvelopeEncryption::with_options(provider, options)
            .await
            .unwrap();

        let aad = "test-aad";
        let plaintext = SecretValue::from("secret");

        let ciphertext = encryption.encrypt_value(&aad, &plaintext).await.unwrap();
        let decrypted = encryption.decrypt_value(&aad, &ciphertext).await.unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[tokio::test]
    async fn test_binary_aad() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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

        let provider = MockKmsProvider::new();
        let encryption = Arc::new(KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap());

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
    async fn test_dek_generation() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

        let (dek1, encrypted_dek1) =
            KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
                .await
                .unwrap();
        let (dek2, encrypted_dek2) =
            KmsAeadEnvelopeEncryption::<&str>::generate_new_dek(&encryption)
                .await
                .unwrap();

        // DEKs should be different
        assert_ne!(dek1, dek2);
        assert_ne!(encrypted_dek1, encrypted_dek2);

        // DEKs should have correct length for ChaCha20-Poly1305
        assert_eq!(
            dek1.value().ref_sensitive_value().len(),
            ring::aead::CHACHA20_POLY1305.key_len()
        );
    }

    #[tokio::test]
    async fn test_corrupted_cipher_text_with_key_fails() {
        let provider = MockKmsProvider::new();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider).await.unwrap();

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
}
