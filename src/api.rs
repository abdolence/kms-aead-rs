use crate::*;
use async_trait::*;
use secret_vault_value::SecretValue;

#[async_trait]
pub trait KmsAeadEncryption<Aad> {
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;
}

#[async_trait]
pub trait KmsAeadEnvelopeEncryption<Aad> {
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey>;

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue>;

    async fn encrypt_value_with_current_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)>;

    async fn encrypt_value_with_new_key(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)>;

    async fn decrypt_value_with_current_key(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
    ) -> KmsAeadResult<(SecretValue, EncryptedDataEncryptionKey)>;

    async fn decrypt_value_with_key(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    async fn rotate_current_key(
        &self,
    ) -> KmsAeadResult<(EncryptedDataEncryptionKey, EncryptedDataEncryptionKey)>;
}
