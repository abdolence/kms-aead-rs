use crate::ring_support::*;
use crate::{AeadEncryption, CipherText, DataEncryptionKey, KmsAeadResult};
use async_trait::*;
use ring::rand::SystemRandom;
use rsb_derive::*;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Builder)]
pub struct RingAeadEncryptionOptions {
    #[default = "RingAeadEncryptionNonceKind::Random"]
    pub nonce_kind: RingAeadEncryptionNonceKind,
}

#[derive(Debug, Clone)]
pub enum RingAeadEncryptionNonceKind {
    Random,
}

pub struct RingAeadEncryption {
    pub algo: &'static ring::aead::Algorithm,
    secure_rand: SystemRandom,
    pub options: RingAeadEncryptionOptions,
}

impl RingAeadEncryption {
    pub fn new() -> KmsAeadResult<Self> {
        Self::with_rand(SystemRandom::new())
    }

    pub fn with_rand(secure_rand: SystemRandom) -> KmsAeadResult<Self> {
        Self::with_algorithm(&ring::aead::CHACHA20_POLY1305, secure_rand)
    }

    pub fn with_algorithm(
        algo: &'static ring::aead::Algorithm,
        secure_rand: SystemRandom,
    ) -> KmsAeadResult<Self> {
        Self::with_algorithm_options(algo, secure_rand, RingAeadEncryptionOptions::new())
    }

    pub fn with_options(
        secure_rand: SystemRandom,
        options: RingAeadEncryptionOptions,
    ) -> KmsAeadResult<Self> {
        Self::with_algorithm_options(&ring::aead::CHACHA20_POLY1305, secure_rand, options)
    }

    pub fn with_algorithm_options(
        algo: &'static ring::aead::Algorithm,
        secure_rand: SystemRandom,
        options: RingAeadEncryptionOptions,
    ) -> KmsAeadResult<Self> {
        Ok(Self {
            algo,
            secure_rand,
            options,
        })
    }

    pub fn generate_data_encryption_key(&self) -> KmsAeadResult<DataEncryptionKey> {
        generate_secret_key(&self.secure_rand, self.algo.key_len())
    }
}

#[async_trait]
impl<Aad> AeadEncryption<Aad> for RingAeadEncryption
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
{
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        let nonce_data = match self.options.nonce_kind {
            RingAeadEncryptionNonceKind::Random => generate_random_nonce(&self.secure_rand)?,
        };

        let encrypted_value = encrypt_with_sealing_key(
            self.algo,
            encryption_key,
            nonce_data.as_slice(),
            ring::aead::Aad::from(aad),
            plain_text.ref_sensitive_value().as_slice(),
        )?;

        let mut encrypted_value_with_nonce: Vec<u8> =
            Vec::with_capacity(nonce_data.len() + encrypted_value.value().len());

        encrypted_value_with_nonce.extend_from_slice(nonce_data.as_slice());

        encrypted_value_with_nonce.extend_from_slice(encrypted_value.value().as_slice());

        Ok(CipherText(encrypted_value_with_nonce))
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        if cipher_text.value().len() < ring::aead::NONCE_LEN {
            return Err(crate::errors::KmsAeadEncryptionError::create(
                "INVALID_CIPHERTEXT",
                "Ciphertext too short to contain nonce",
            ));
        }

        let (nonce_data, encrypted_part) = cipher_text.value().split_at(ring::aead::NONCE_LEN);

        decrypt_with_opening_key(
            self.algo,
            encryption_key,
            nonce_data,
            ring::aead::Aad::from(aad),
            encrypted_part,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CipherText, DataEncryptionKey};
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    pub fn generate_secret_value() -> BoxedStrategy<SecretValue> {
        ("[a-zA-Z0-9]+")
            .prop_map(|(mock_secret_str)| SecretValue::new(mock_secret_str.as_bytes().to_vec()))
            .boxed()
    }

    async fn encryption_test_for(mock_secret_value: SecretValue) {
        let mock_aad: String = "test".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();

        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &mock_secret_value, &secret_key)
            .await
            .unwrap();

        assert_ne!(
            encrypted_value.value(),
            mock_secret_value.ref_sensitive_value()
        );

        let decrypted_value = encryption
            .decrypt_value(&mock_aad, &encrypted_value, &secret_key)
            .await
            .unwrap();
        assert_eq!(
            decrypted_value.ref_sensitive_value(),
            mock_secret_value.ref_sensitive_value()
        );
    }

    #[tokio::test]
    async fn secret_encryption_test() {
        let mut runner = TestRunner::default();
        encryption_test_for(
            generate_secret_value()
                .new_tree(&mut runner)
                .unwrap()
                .current(),
        )
        .await
    }

    #[tokio::test]
    async fn big_secret_encryption_test() {
        for sz in vec![5000, 32768, 65535] {
            encryption_test_for(SecretValue::new("42".repeat(sz).as_bytes().to_vec())).await
        }
    }

    #[tokio::test]
    async fn wrong_secret_name_test_attest() {
        let mock_aad1: String = "test1".to_string();
        let mock_aad2: String = "test2".to_string();

        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();

        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let encrypted_value = encryption
            .encrypt_value(&mock_aad1, &mock_secret_value, &secret_key)
            .await
            .unwrap();
        encryption
            .decrypt_value(&mock_aad2, &encrypted_value, &secret_key)
            .await
            .expect_err("Unable to decrypt data");
    }

    #[tokio::test]
    async fn different_encryption_instances_test() {
        let mock_aad: String = "test1".to_string();
        let mock_secret_value = SecretValue::new("42".repeat(1024).as_bytes().to_vec());

        let secure_rand: SystemRandom = SystemRandom::new();

        let secret_key =
            generate_secret_key(&secure_rand, ring::aead::CHACHA20_POLY1305.key_len()).unwrap();

        let encrypted_value = {
            let encryption = RingAeadEncryption::with_rand(secure_rand.clone()).unwrap();
            encryption
                .encrypt_value(&mock_aad, &mock_secret_value, &secret_key)
                .await
                .unwrap()
        };

        let decrypted_value = {
            let encryption = RingAeadEncryption::with_rand(secure_rand.clone()).unwrap();
            encryption
                .decrypt_value(&mock_aad, &encrypted_value, &secret_key)
                .await
                .unwrap()
        };

        assert_eq!(decrypted_value, mock_secret_value)
    }

    #[tokio::test]
    async fn empty_plaintext_test() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let empty_secret = SecretValue::new(Vec::new());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &empty_secret, &secret_key)
            .await
            .unwrap();

        let decrypted_value = encryption
            .decrypt_value(&mock_aad, &encrypted_value, &secret_key)
            .await
            .unwrap();

        assert_eq!(decrypted_value.ref_sensitive_value().len(), 0);
    }

    #[tokio::test]
    async fn empty_aad_test() {
        let empty_aad = b"";
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&empty_aad, &secret, &secret_key)
            .await
            .unwrap();

        let decrypted_value = encryption
            .decrypt_value(&empty_aad, &encrypted_value, &secret_key)
            .await
            .unwrap();

        assert_eq!(decrypted_value, secret);
    }

    #[tokio::test]
    async fn binary_aad_test() {
        // Test with binary AAD containing null bytes and non-ASCII
        let binary_aad: Vec<u8> = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&binary_aad, &secret, &secret_key)
            .await
            .unwrap();

        let decrypted_value = encryption
            .decrypt_value(&binary_aad, &encrypted_value, &secret_key)
            .await
            .unwrap();

        assert_eq!(decrypted_value, secret);
    }

    #[tokio::test]
    async fn wrong_key_decryption_fails() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand.clone()).unwrap();
        let secret_key1 = encryption.generate_data_encryption_key().unwrap();
        let secret_key2 = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &secret, &secret_key1)
            .await
            .unwrap();

        // Try to decrypt with wrong key
        let result = encryption
            .decrypt_value(&mock_aad, &encrypted_value, &secret_key2)
            .await;

        assert!(result.is_err(), "Decryption with wrong key should fail");
    }

    #[tokio::test]
    async fn truncated_ciphertext_fails() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &secret, &secret_key)
            .await
            .unwrap();

        // Truncate the ciphertext
        let mut truncated = encrypted_value.value().to_vec();
        truncated.truncate(truncated.len() - 5);
        let truncated_cipher = CipherText(truncated);

        let result = encryption
            .decrypt_value(&mock_aad, &truncated_cipher, &secret_key)
            .await;

        assert!(
            result.is_err(),
            "Decryption of truncated ciphertext should fail"
        );
    }

    #[tokio::test]
    async fn modified_ciphertext_fails() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &secret, &secret_key)
            .await
            .unwrap();

        // Flip a bit in the ciphertext (after nonce)
        let mut modified = encrypted_value.value().to_vec();
        if modified.len() > ring::aead::NONCE_LEN + 1 {
            modified[ring::aead::NONCE_LEN + 1] ^= 0x01;
        }
        let modified_cipher = CipherText(modified);

        let result = encryption
            .decrypt_value(&mock_aad, &modified_cipher, &secret_key)
            .await;

        assert!(
            result.is_err(),
            "Decryption of modified ciphertext should fail"
        );
    }

    #[tokio::test]
    async fn modified_nonce_fails() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &secret, &secret_key)
            .await
            .unwrap();

        // Modify the nonce (first bytes)
        let mut modified = encrypted_value.value().to_vec();
        modified[0] ^= 0x01;
        let modified_cipher = CipherText(modified);

        let result = encryption
            .decrypt_value(&mock_aad, &modified_cipher, &secret_key)
            .await;

        assert!(
            result.is_err(),
            "Decryption with modified nonce should fail"
        );
    }

    #[tokio::test]
    async fn too_short_ciphertext_fails() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        // Ciphertext shorter than nonce length
        let short_cipher = CipherText(vec![0u8; ring::aead::NONCE_LEN - 1]);

        let result = encryption
            .decrypt_value(&mock_aad, &short_cipher, &secret_key)
            .await;

        assert!(
            result.is_err(),
            "Decryption of too-short ciphertext should fail"
        );
    }

    #[tokio::test]
    async fn test_aes_256_gcm_algorithm() {
        let mock_aad: String = "test-aad".to_string();
        let secure_rand: SystemRandom = SystemRandom::new();

        let encryption =
            RingAeadEncryption::with_algorithm(&ring::aead::AES_256_GCM, secure_rand).unwrap();

        let secret_key = encryption.generate_data_encryption_key().unwrap();
        let secret = SecretValue::new("test-secret".as_bytes().to_vec());

        let encrypted_value = encryption
            .encrypt_value(&mock_aad, &secret, &secret_key)
            .await
            .unwrap();

        let decrypted_value = encryption
            .decrypt_value(&mock_aad, &encrypted_value, &secret_key)
            .await
            .unwrap();

        assert_eq!(decrypted_value, secret);
    }

    #[test]
    fn test_constant_time_cipher_text_comparison() {
        let cipher1 = CipherText(vec![1, 2, 3, 4, 5]);
        let cipher2 = CipherText(vec![1, 2, 3, 4, 5]);
        let cipher3 = CipherText(vec![1, 2, 3, 4, 6]);

        // PartialEq uses constant-time comparison internally
        assert_eq!(cipher1, cipher2);
        assert_ne!(cipher1, cipher3);
    }

    #[test]
    fn test_constant_time_dek_comparison() {
        let dek1 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 5]));
        let dek2 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 5]));
        let dek3 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 6]));

        // PartialEq uses constant-time comparison internally
        assert_eq!(dek1, dek2);
        assert_ne!(dek1, dek3);
    }

    #[tokio::test]
    async fn concurrent_encryption_test() {
        use tokio::task;

        let secure_rand: SystemRandom = SystemRandom::new();
        let encryption = RingAeadEncryption::with_rand(secure_rand).unwrap();
        let secret_key = encryption.generate_data_encryption_key().unwrap();

        let mut handles = vec![];
        for i in 0..10 {
            let encryption_clone = RingAeadEncryption::with_rand(SystemRandom::new()).unwrap();
            let key_clone = secret_key.clone();
            let handle = task::spawn(async move {
                let secret = SecretValue::new(format!("secret-{}", i).as_bytes().to_vec());
                let aad = format!("aad-{}", i);

                let encrypted = encryption_clone
                    .encrypt_value(&aad, &secret, &key_clone)
                    .await
                    .unwrap();

                let decrypted = encryption_clone
                    .decrypt_value(&aad, &encrypted, &key_clone)
                    .await
                    .unwrap();

                assert_eq!(decrypted, secret);
            });
            handles.push(handle);
        }

        for handle in handles {
            handle.await.unwrap();
        }
    }
}
