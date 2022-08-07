use crate::ring_encryption_support::*;
use crate::{EncryptedSecretValue, EncryptedSessionKey, KmsAeadEnvelopeEncryption, KmsAeadResult};
use async_trait::*;
use ring::rand::SystemRandom;
use rvstruct::ValueStruct;
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
        let session_key = generate_secret_key(&secure_rand, algo.key_len())?;
        let current_session_secret = provider.encrypt_session_key(session_key).await?;

        Ok(Self {
            provider,
            algo,
            secure_rand,
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

        Ok((
            self.encrypt_value_with_session_key(aad, plain_text, &session_key)
                .await?,
            current_session_key,
        ))
    }

    async fn encrypt_value_with_new_session_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(EncryptedSecretValue, EncryptedSessionKey)> {
        let session_key = generate_secret_key(&self.secure_rand, self.algo.key_len())?;
        let new_encrypted_key = self
            .provider
            .encrypt_session_key(session_key.clone())
            .await?;

        Ok((
            self.encrypt_value_with_session_key(aad, plain_text, &session_key)
                .await?,
            new_encrypted_key,
        ))
    }

    async fn encrypt_value_with_session_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        session_key: &SecretValue,
    ) -> KmsAeadResult<EncryptedSecretValue> {
        let nonce_data = generate_nonce(&self.secure_rand)?;

        let encrypted_value = encrypt_with_sealing_key(
            self.algo,
            &session_key,
            nonce_data.as_slice(),
            ring::aead::Aad::from(aad),
            plain_text.ref_sensitive_value().as_slice(),
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
            .decrypt_session_key(encrypted_session_key)
            .await?;

        let (nonce_data, encrypted_part) = encrypted_value
            .value()
            .ref_sensitive_value()
            .split_at(ring::aead::NONCE_LEN);

        decrypt_with_opening_key(
            self.algo,
            &session_key,
            nonce_data,
            ring::aead::Aad::from(aad),
            encrypted_part,
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
