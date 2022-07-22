use crate::ring_encryption_support::*;
use crate::{EncryptedSecretValue, EncryptedSessionKey, KmsAeadEnvelopeEncryption, KmsAeadResult};
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
}

pub struct KmsAeadRingEncryption<P>
where
    P: KmsAeadRingEncryptionProvider + Send + Sync,
{
    provider: P,
    algo: &'static ring::aead::Algorithm,
    secure_rand: SystemRandom,
    current_session_secret: Arc<RwLock<EncryptedSessionKey>>,
    nonce_data: SecretValue,
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
        let nonce_data = generate_nonce(&secure_rand)?;
        let session_key = generate_secret_key(&secure_rand, algo.key_len())?;
        let current_session_secret = provider.encrypt_session_key(session_key).await?;

        Ok(Self {
            provider,
            algo,
            secure_rand,
            current_session_secret: Arc::new(RwLock::new(current_session_secret)),
            nonce_data,
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
        secret_value: &SecretValue,
    ) -> KmsAeadResult<(EncryptedSecretValue, EncryptedSessionKey)> {
        let current_session_key = { self.current_session_secret.read().await.clone() };
        let session_key = self
            .provider
            .decrypt_session_key(&current_session_key)
            .await?;

        Ok((
            encrypt_with_sealing_key(
                self.algo,
                &session_key,
                &self.nonce_data,
                ring::aead::Aad::from(aad),
                secret_value,
            )?,
            current_session_key,
        ))
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        encrypted_value: &EncryptedSecretValue,
    ) -> KmsAeadResult<(SecretValue, EncryptedSessionKey)> {
        let current_session_key = { self.current_session_secret.read().await.clone() };

        let decrypted = self
            .decrypt_value_with_session_key(aad, encrypted_value, &current_session_key)
            .await?;

        Ok((decrypted, current_session_key))
    }

    async fn decrypt_value_with_session_key(
        &self,
        aad: &Aad,
        encrypted_value: &EncryptedSecretValue,
        encrypted_session_key: &EncryptedSessionKey,
    ) -> KmsAeadResult<SecretValue> {
        let session_key = self
            .provider
            .decrypt_session_key(&encrypted_session_key)
            .await?;

        decrypt_with_opening_key(
            self.algo,
            &session_key,
            &self.nonce_data,
            ring::aead::Aad::from(aad),
            encrypted_value,
        )
    }

    async fn rotate_session_key(
        &self,
    ) -> KmsAeadResult<(EncryptedSessionKey, EncryptedSessionKey)> {
        let session_key = generate_secret_key(&self.secure_rand, self.algo.key_len())?;
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
