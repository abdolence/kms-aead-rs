use crate::ring_encryption::{KmsAeadRingAeadEncryption, KmsAeadRingAeadEncryptionOptions};
use crate::*;
use async_trait::*;
use ring::rand::SystemRandom;
use rsb_derive::*;
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

#[derive(Debug, Clone, Builder)]
pub struct KmsAeadRingEnvelopeEncryptionOptions {
    #[default = "KmsAeadRingAeadEncryptionOptions::new()"]
    pub encryption_options: KmsAeadRingAeadEncryptionOptions,
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

    pub async fn with_algorithm_options(
        provider: P,
        algo: &'static ring::aead::Algorithm,
        options: KmsAeadRingEnvelopeEncryptionOptions,
    ) -> KmsAeadResult<Self> {
        let secure_rand = SystemRandom::new();
        let aead_encryption = KmsAeadRingAeadEncryption::with_algorithm_options(
            algo,
            secure_rand,
            options.encryption_options,
        )?;

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
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey> {
        let (cipher_text, dek) = self.encrypt_value_with_new_key(aad, plain_text).await?;
        Ok(CipherTextWithEncryptedKey::new(&cipher_text, &dek))
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue> {
        let (cipher_text, dek) = cipher_text.separate()?;
        self.decrypt_value_with_key(aad, &cipher_text, &dek).await
    }

    async fn encrypt_value_with_current_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let encrypted_current_dek = { self.current_dek.read().await.clone() };

        let current_dek = self
            .provider
            .decrypt_data_encryption_key(&encrypted_current_dek)
            .await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &current_dek)
            .await?;

        Ok((cipher_text, encrypted_current_dek))
    }

    async fn encrypt_value_with_new_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let dek = self
            .provider
            .generate_encryption_key(&self.aead_encryption)
            .await?;

        let new_encrypted_dek = self.provider.encrypt_data_encryption_key(&dek).await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &dek)
            .await?;

        Ok((cipher_text, new_encrypted_dek))
    }

    async fn decrypt_value_with_current_key(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
    ) -> KmsAeadResult<(SecretValue, EncryptedDataEncryptionKey)> {
        let current_dek = { self.current_dek.read().await.clone() };

        let cipher_text = self
            .decrypt_value_with_key(aad, cipher_text, &current_dek)
            .await?;

        Ok((cipher_text, current_dek))
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
        let dek = self
            .provider
            .generate_encryption_key(&self.aead_encryption)
            .await?;

        let new_encrypted_dek = self.provider.encrypt_data_encryption_key(&dek).await?;

        let previous_encrypted_key = {
            let mut write_current_dek = self.current_dek.write().await;
            let previous_encrypted_dek = write_current_dek.clone();
            *write_current_dek = new_encrypted_dek.clone();
            previous_encrypted_dek
        };

        Ok((previous_encrypted_key, new_encrypted_dek))
    }
}
