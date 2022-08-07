use crate::ring_encryption::KmsAeadRingAeadEncryption;
use crate::*;
use async_trait::*;
use ring::rand::SystemRandom;
use secret_vault_value::SecretValue;
use std::sync::Arc;
use tokio::sync::RwLock;

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
        aead_encryption: &KmsAeadRingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey>;
}

pub struct KmsAeadRingEnvelopeEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    provider: P,
    aead_encryption: KmsAeadRingAeadEncryption,
    current_dek: Arc<RwLock<EncryptedDataEncryptionKey>>,
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
        let secure_rand = SystemRandom::new();
        let aead_encryption = KmsAeadRingAeadEncryption::with_algorithm(algo, secure_rand)?;

        let dek = provider.generate_encryption_key(&aead_encryption).await?;
        let current_encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;

        Ok(Self {
            provider,
            aead_encryption,
            current_dek: Arc::new(RwLock::new(current_encrypted_dek)),
        })
    }
}

#[async_trait]
impl<Aad, P> KmsAeadEnvelopeEncryption<Aad> for KmsAeadRingEnvelopeEncryption<P>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    async fn encrypt_value_with_current_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let current_session_key = { self.current_dek.read().await.clone() };

        let session_key = self
            .provider
            .decrypt_data_encryption_key(&current_session_key)
            .await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &session_key)
            .await?;

        Ok((cipher_text, current_session_key))
    }

    async fn encrypt_value_with_new_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let session_key = self
            .provider
            .generate_encryption_key(&self.aead_encryption)
            .await?;

        let new_encrypted_key = self
            .provider
            .encrypt_data_encryption_key(&session_key)
            .await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &session_key)
            .await?;

        Ok((cipher_text, new_encrypted_key))
    }

    async fn decrypt_value_with_current_key(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
    ) -> KmsAeadResult<(SecretValue, EncryptedDataEncryptionKey)> {
        let current_kek = { self.current_dek.read().await.clone() };

        let cipher_text = self
            .decrypt_value_with_key(aad, cipher_text, &current_kek)
            .await?;

        Ok((cipher_text, current_kek))
    }

    async fn decrypt_value_with_key(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        let dek = self
            .provider
            .decrypt_data_encryption_key(encrypted_data_encryption_key)
            .await?;

        self.aead_encryption
            .decrypt_value(aad, cipher_text, &dek)
            .await
    }

    async fn rotate_current_key(
        &self,
    ) -> KmsAeadResult<(EncryptedDataEncryptionKey, EncryptedDataEncryptionKey)> {
        let kek = self
            .provider
            .generate_encryption_key(&self.aead_encryption)
            .await?;

        let new_encrypted_key = self.provider.encrypt_data_encryption_key(&kek).await?;

        let previous_encrypted_key = {
            let mut write_session_secret = self.current_dek.write().await;
            let previous_session_key = write_session_secret.clone();
            *write_session_secret = new_encrypted_key.clone();
            previous_session_key
        };

        Ok((previous_encrypted_key, new_encrypted_key))
    }
}
