use crate::*;
use async_trait::*;
use secret_vault_value::SecretValue;

/// A trait that defines the encryption and decryption of a value using a data encryption key
/// and additional authenticated data (AEAD).
#[async_trait]
pub trait AeadEncryption<Aad> {
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

/// A trait that defines the envelope encryption and decryption of a value using
/// a data encryption key (DEK), a key encryption key (KEK) from KMS providers,
/// and additional authenticated data (AEAD).
#[async_trait]
pub trait KmsAeadEnvelopeEncryption<Aad> {
    /// Encrypts the plain text using a new data encryption key.
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
    ) -> KmsAeadResult<CipherTextWithEncryptedKey>;

    /// Decrypts the cipher text using the cipher text with corresponding encrypted data encryption key.
    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Encrypts the plain text using the provided data encryption key.
    async fn encrypt_value_with_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Encrypts the plain text using the provided encrypted data encryption key.
    async fn encrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<CipherText>;

    /// Decrypts the cipher text using the provided encrypted data encryption key.
    async fn decrypt_value_with_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        data_encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Decrypts the cipher text using the provided encrypted data encryption key.
    async fn decrypt_value_with_encrypted_dek(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encrypted_data_encryption_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<SecretValue>;

    /// Generates a new data encryption key and encrypts it using the KMS provider.
    async fn generate_new_dek(
        &self,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>;
}
