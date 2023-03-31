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
