use crate::ring_encryption::KmsAeadRingAeadEncryption;
use crate::{
    EncryptedSecretValue, EncryptedSessionKey, KmsAeadEncryption, KmsAeadEnvelopeEncryption,
    KmsAeadResult,
};
use async_trait::*;
use ring::rand::SystemRandom;
use secret_vault_value::SecretValue;
use std::sync::Arc;
use tokio::sync::RwLock;

#[async_trait]
pub trait KmsAeadRingEncryptionProvider {
    async fn encrypt_session_key(
        &self,
        session_key: SecretValue,
    ) -> KmsAeadResult<EncryptedSessionKey>;

    async fn decrypt_session_key(
        &self,
        encrypted_session_secret: &EncryptedSessionKey,
    ) -> KmsAeadResult<SecretValue>;

    async fn generate_secure_key(
        &self,
        aead_encryption: &KmsAeadRingAeadEncryption,
    ) -> KmsAeadResult<SecretValue>;
}

pub struct KmsAeadRingEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    provider: P,
    aead_encryption: KmsAeadRingAeadEncryption,
    current_session_secret: Arc<RwLock<EncryptedSessionKey>>,
}

impl<P> KmsAeadRingEncryption<P>
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

        let session_key = provider.generate_secure_key(&aead_encryption).await?;
        let current_session_secret = provider.encrypt_session_key(session_key).await?;

        Ok(Self {
            provider,
            aead_encryption,
            current_session_secret: Arc::new(RwLock::new(current_session_secret)),
        })
    }
}

#[async_trait]
impl<Aad, P> KmsAeadEnvelopeEncryption<Aad> for KmsAeadRingEncryption<P>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(EncryptedSecretValue, EncryptedSessionKey)> {
        let current_session_key = { self.current_session_secret.read().await.clone() };

        let session_key = self
            .provider
            .decrypt_session_key(&current_session_key)
            .await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &session_key)
            .await?;

        Ok((cipher_text, current_session_key))
    }

    async fn encrypt_value_with_new_session_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(EncryptedSecretValue, EncryptedSessionKey)> {
        let session_key = self
            .provider
            .generate_secure_key(&self.aead_encryption)
            .await?;

        let new_encrypted_key = self
            .provider
            .encrypt_session_key(session_key.clone())
            .await?;

        let cipher_text = self
            .aead_encryption
            .encrypt_value(aad, plain_text, &session_key)
            .await?;

        Ok((cipher_text, new_encrypted_key))
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        encrypted_value: &EncryptedSecretValue,
    ) -> KmsAeadResult<(SecretValue, EncryptedSessionKey)> {
        let current_session_key = { self.current_session_secret.read().await.clone() };

        let cipher_text = self
            .decrypt_value_with_session_key(aad, encrypted_value, &current_session_key)
            .await?;

        Ok((cipher_text, current_session_key))
    }

    async fn decrypt_value_with_session_key(
        &self,
        aad: &Aad,
        encrypted_value: &EncryptedSecretValue,
        encrypted_session_key: &EncryptedSessionKey,
    ) -> KmsAeadResult<SecretValue> {
        let session_key = self
            .provider
            .decrypt_session_key(encrypted_session_key)
            .await?;

        self.aead_encryption
            .decrypt_value(aad, encrypted_value, &session_key)
            .await
    }

    async fn rotate_session_key(
        &self,
    ) -> KmsAeadResult<(EncryptedSessionKey, EncryptedSessionKey)> {
        let session_key = self
            .provider
            .generate_secure_key(&self.aead_encryption)
            .await?;

        let new_encrypted_key = self.provider.encrypt_session_key(session_key).await?;

        let previous_session_key = {
            let mut write_session_secret = self.current_session_secret.write().await;
            let previous_session_key = write_session_secret.clone();
            *write_session_secret = new_encrypted_key.clone();
            previous_session_key
        };

        Ok((previous_session_key, new_encrypted_key))
    }
}
