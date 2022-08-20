use crate::ring_support::*;
use crate::{AeadEncryption, CipherText, DataEncryptionKey, KmsAeadResult};
use async_trait::*;
use ring::rand::SystemRandom;
use rsb_derive::*;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Builder)]
pub struct RingAeadEncryptionOptions {
    #[default = "RingAeadEncryptionNonceKind::TimeRandom"]
    pub nonce_kind: RingAeadEncryptionNonceKind,
}

#[derive(Debug, Clone)]
pub enum RingAeadEncryptionNonceKind {
    Random,
    TimeRandom,
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
            RingAeadEncryptionNonceKind::TimeRandom => {
                generate_time_random_nonce(&self.secure_rand)?
            }
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
}
