use crate::ring_encryption_support::*;
use crate::{EncryptedSecretValue, KmsAeadEncryption, KmsAeadResult};
use async_trait::*;
use ring::rand::SystemRandom;
use secret_vault_value::SecretValue;

pub struct KmsAeadRingAeadEncryption {
    algo: &'static ring::aead::Algorithm,
    secret: SecretValue,
    nonce_data: SecretValue,
}

impl KmsAeadRingAeadEncryption {
    pub fn new(secret: SecretValue) -> KmsAeadResult<Self> {
        Self::with_algorithm(&ring::aead::CHACHA20_POLY1305, secret)
    }

    pub fn with_algorithm(
        algo: &'static ring::aead::Algorithm,
        secret: SecretValue,
    ) -> KmsAeadResult<Self> {
        let secure_rand = SystemRandom::new();

        Ok(Self {
            algo,
            secret,
            nonce_data: generate_nonce(&secure_rand)?,
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
        encrypt_with_sealing_key(
            self.algo,
            &self.secret,
            &self.nonce_data,
            ring::aead::Aad::from(aad),
            secret_value,
        )
    }

    async fn decrypt_value(
        &self,
        aad: Aad,
        encrypted_secret_value: &EncryptedSecretValue,
    ) -> KmsAeadResult<SecretValue> {
        decrypt_with_opening_key(
            self.algo,
            &self.secret,
            &self.nonce_data,
            ring::aead::Aad::from(aad),
            encrypted_secret_value,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use rvstruct::*;

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
}
