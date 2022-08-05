use crate::ring_encryption_support::*;
use crate::{EncryptedSecretValue, KmsAeadEncryption, KmsAeadResult};
use async_trait::*;
use ring::rand::SystemRandom;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

pub struct KmsAeadRingAeadEncryption {
    algo: &'static ring::aead::Algorithm,
    secret: SecretValue,
    rand: SystemRandom,
}

impl KmsAeadRingAeadEncryption {
    pub fn new(secret: SecretValue) -> KmsAeadResult<Self> {
        Self::with_algorithm(&ring::aead::CHACHA20_POLY1305, secret)
    }

    pub fn with_generated_secret(algo: &'static ring::aead::Algorithm) -> KmsAeadResult<Self> {
        let secure_rand = SystemRandom::new();
        let secret = generate_secret_key(&secure_rand, algo.key_len())?;

        Self::with_algorithm(algo, secret)
    }

    pub fn with_algorithm(
        algo: &'static ring::aead::Algorithm,
        secret: SecretValue,
    ) -> KmsAeadResult<Self> {
        Ok(Self {
            algo,
            secret,
            rand: SystemRandom::new(),
        })
    }
}

#[async_trait]
impl<Aad> KmsAeadEncryption<Aad> for KmsAeadRingAeadEncryption
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
{
    async fn encrypt_value(
        &self,
        aad: Aad,
        secret_value: &SecretValue,
    ) -> KmsAeadResult<EncryptedSecretValue> {
        let nonce_data = generate_nonce(&self.rand)?;

        let encrypted_value = encrypt_with_sealing_key(
            self.algo,
            &self.secret,
            nonce_data.as_slice(),
            ring::aead::Aad::from(aad),
            secret_value.ref_sensitive_value().as_slice(),
        )?;

        let mut encrypted_value_with_nonce: Vec<u8> = Vec::with_capacity(
            nonce_data.len() + encrypted_value.value().ref_sensitive_value().len(),
        );

        encrypted_value_with_nonce.extend_from_slice(nonce_data.as_slice());

        encrypted_value_with_nonce
            .extend_from_slice(encrypted_value.value().ref_sensitive_value().as_slice());

        Ok(EncryptedSecretValue(SecretValue::new(
            encrypted_value_with_nonce,
        )))
    }

    async fn decrypt_value(
        &self,
        aad: Aad,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> KmsAeadResult<SecretValue> {
        let (nonce_data, encrypted_part) = encrypted_secret_value
            .value()
            .ref_sensitive_value()
            .split_at(ring::aead::NONCE_LEN);

        decrypt_with_opening_key(
            self.algo,
            &self.secret,
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
        let encryption = KmsAeadRingAeadEncryption::new(
            generate_secret_key(&secure_rand, ring::aead::CHACHA20_POLY1305.key_len()).unwrap(),
        )
        .unwrap();

        let encrypted_value = encryption
            .encrypt_value(mock_aad.clone(), &mock_secret_value)
            .await
            .unwrap();
        assert_ne!(*encrypted_value.value(), mock_secret_value);

        let decrypted_value = encryption
            .decrypt_value(mock_aad.clone(), &encrypted_value)
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
        let encryption = KmsAeadRingAeadEncryption::new(
            generate_secret_key(&secure_rand, ring::aead::CHACHA20_POLY1305.key_len()).unwrap(),
        )
        .unwrap();

        let encrypted_value = encryption
            .encrypt_value(mock_aad1.clone(), &mock_secret_value)
            .await
            .unwrap();
        encryption
            .decrypt_value(mock_aad2.clone(), &encrypted_value)
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
            let encryption = KmsAeadRingAeadEncryption::new(secret_key.clone()).unwrap();
            encryption
                .encrypt_value(mock_aad.clone(), &mock_secret_value)
                .await
                .unwrap()
        };

        let decrypted_value = {
            let encryption = KmsAeadRingAeadEncryption::new(secret_key.clone()).unwrap();
            encryption
                .decrypt_value(mock_aad.clone(), &encrypted_value)
                .await
                .unwrap()
        };

        assert_eq!(decrypted_value, mock_secret_value)
    }
}
