use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::backend::{AeadBackendOps, Failure, Nonce};
use crate::errors::{KmsAeadEncryptionError, KmsAeadUnsupportedAlgorithmError};
use crate::{
    checked_key_material, AeadAlgorithm, AeadBackend, CipherText, DataEncryptionKey, DekBinding,
    EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadResult,
};

/// Randomized authenticated encryption with associated data (AEAD) under a data encryption key
/// the caller holds, with the backend and the algorithm it was made with, without a KMS.
///
/// Values are `[nonce][ciphertext][tag]`, with a random nonce. The AAD is authenticated but not
/// encrypted: a value opens only with the AAD it was sealed with.
///
/// It does no I/O and opens no span: it runs once per value, inside the caller's span.
#[derive(Debug, Clone)]
pub struct AeadCipher {
    /// Read as a field, never through a method: in a build without a backend feature the type
    /// has no value, and a call returning one makes the code after it unreachable.
    pub(crate) backend: AeadBackend,
    algorithm: AeadAlgorithm,
}

impl AeadCipher {
    /// A cipher for `algorithm` on `backend`.
    ///
    /// # Errors
    ///
    /// [`KmsAeadError::UnsupportedAlgorithm`](crate::errors::KmsAeadError::UnsupportedAlgorithm),
    /// code `UNSUPPORTED_ALGORITHM`, when `backend` does not implement `algorithm`: ring has no
    /// AES-256-GCM-SIV.
    pub fn new(backend: AeadBackend, algorithm: AeadAlgorithm) -> KmsAeadResult<Self> {
        let ops: &dyn AeadBackendOps = backend.into();
        if ops.supports(algorithm) {
            Ok(Self { backend, algorithm })
        } else {
            Err(KmsAeadUnsupportedAlgorithmError::create(algorithm, backend))
        }
    }

    /// The algorithm this cipher seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// A new key of `algorithm().key_len()` bytes from the backend's CSPRNG.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn generate_key(&self) -> KmsAeadResult<DataEncryptionKey> {
        let ops: &dyn AeadBackendOps = self.backend.into();
        let mut key = SecretValue::new(vec![0; self.algorithm.key_len()]);
        ops.fill_random(key.ref_sensitive_value_mut())
            .map_err(|_| {
                KmsAeadEncryptionError::create(
                    "RANDOM_GENERATOR",
                    "Unable to generate a random key",
                )
            })?;
        Ok(DataEncryptionKey::from(key))
    }

    /// A new key and the same key wrapped by `provider` with `binding`, to store. The key comes
    /// from the KMS generator when the provider is configured to use one, and from the backend's
    /// CSPRNG otherwise.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material
    /// of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
    pub async fn generate_wrapped_key<P>(
        &self,
        provider: &P,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let key = match checked_key_material(provider, self.algorithm.key_len()).await? {
            Some(material) => DataEncryptionKey::from(material),
            None => self.generate_key()?,
        };
        let encrypted_key = provider.encrypt_data_encryption_key(&key, binding).await?;
        Ok((key, encrypted_key))
    }

    /// Seals `plain_text` with `key` and a fresh random nonce, so that sealing the same input
    /// twice gives different cipher texts.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when the key does not have the length of the algorithm,
    /// `RANDOM_GENERATOR` when the random nonce cannot be generated, and `ENCRYPT_KEY` or
    /// `ENCRYPT` when the backend refuses the key or fails to seal.
    pub fn encrypt_value(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        let ops: &dyn AeadBackendOps = self.backend.into();
        let key = self.key_bytes(key)?;
        let plain_text = plain_text.ref_sensitive_value();

        let mut nonce: Nonce = [0; AeadAlgorithm::NONCE_LEN];
        ops.fill_random(&mut nonce).map_err(|_| {
            KmsAeadEncryptionError::create("RANDOM_GENERATOR", "Unable to generate a random nonce")
        })?;

        // Allocated once at its final size, since growing it would leave a copy of the plaintext
        // in freed memory, and zeroized if sealing fails.
        let mut buffer = SecretValue::new(Vec::with_capacity(
            AeadAlgorithm::NONCE_LEN + plain_text.len() + AeadAlgorithm::TAG_LEN,
        ));
        let value = buffer.ref_sensitive_value_mut();
        value.extend_from_slice(&nonce);
        value.extend_from_slice(plain_text);
        let tag = ops
            .seal_in_place(
                self.algorithm,
                key,
                &nonce,
                aad,
                &mut value[AeadAlgorithm::NONCE_LEN..],
            )
            .map_err(|failure| match failure {
                Failure::Key => {
                    KmsAeadEncryptionError::create("ENCRYPT_KEY", "Unable to create a sealing key")
                }
                Failure::Operation => {
                    KmsAeadEncryptionError::create("ENCRYPT", "Unable to encrypt data")
                }
            })?;
        value.extend_from_slice(&tag);
        Ok(CipherText(std::mem::take(value)))
    }

    /// Opens a value [`encrypt_value`](Self::encrypt_value) sealed with the same key and AAD,
    /// into a buffer the returned `SecretValue` owns, so that no other copy of the plaintext
    /// exists.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when the key does not have the length of the algorithm,
    /// `INVALID_CIPHER_TEXT_FORMAT` when the value is shorter than a nonce and a tag,
    /// `DECRYPT_KEY` when the backend refuses the key, and `DECRYPT` when the value is not
    /// authentic under the key, the nonce and the AAD.
    pub fn decrypt_value(
        &self,
        aad: &[u8],
        cipher_text: &CipherText,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        let ops: &dyn AeadBackendOps = self.backend.into();
        let key = self.key_bytes(key)?;
        let (nonce, sealed) = cipher_text
            .value()
            .split_first_chunk::<{ AeadAlgorithm::NONCE_LEN }>()
            .filter(|(_, sealed)| sealed.len() >= AeadAlgorithm::TAG_LEN)
            .ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "INVALID_CIPHER_TEXT_FORMAT",
                    &format!(
                        "A cipher text of {} bytes is too short to hold a nonce and a tag",
                        cipher_text.value().len()
                    ),
                )
            })?;

        let mut plain_text = SecretValue::new(sealed.to_vec());
        let plain_text_len = ops
            .open_in_place(
                self.algorithm,
                key,
                nonce,
                aad,
                plain_text.ref_sensitive_value_mut(),
            )
            .map_err(|failure| match failure {
                Failure::Key => {
                    KmsAeadEncryptionError::create("DECRYPT_KEY", "Unable to create an opening key")
                }
                Failure::Operation => {
                    KmsAeadEncryptionError::create("DECRYPT", "Unable to decrypt data")
                }
            })?;
        plain_text
            .ref_sensitive_value_mut()
            .truncate(plain_text_len);
        Ok(plain_text)
    }

    /// The key, checked against the algorithm before any backend sees it: a key of another
    /// length, such as a 64-byte deterministic key, is never cut or padded to fit.
    fn key_bytes<'k>(&self, key: &'k DataEncryptionKey) -> KmsAeadResult<&'k [u8]> {
        let key = key.value().ref_sensitive_value();
        if key.len() == self.algorithm.key_len() {
            Ok(key)
        } else {
            Err(KmsAeadEncryptionError::invalid_key_length(
                key.len(),
                self.algorithm,
                self.algorithm.key_len(),
            ))
        }
    }
}
