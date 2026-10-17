use async_trait::async_trait;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::backend::{AeadBackendOps, Failure, Nonce};
use crate::errors::{KmsAeadEncryptionError, KmsAeadUnsupportedAlgorithmError};
use crate::{
    checked_key_material, AeadAlgorithm, AeadBackend, AeadEncryption, Cipher, CipherText,
    DataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadResult,
};

/// Randomized AEAD with the backend and the algorithm it was made with, without a KMS. The
/// [`AeadEncryption`] implementation seals and opens values.
///
/// It does no I/O and opens no span: it runs once per value, inside the caller's span.
#[derive(Debug, Clone)]
pub struct AeadCipher {
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

    /// The backend this cipher seals and opens on.
    pub fn backend(&self) -> AeadBackend {
        self.backend
    }

    /// The algorithm this cipher seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// A new key of `algorithm().key_len()` bytes from the backend's CSPRNG.
    ///
    /// # Errors
    ///
    /// `ENCRYPTION` when the CSPRNG fails.
    pub fn generate_data_encryption_key(&self) -> KmsAeadResult<DataEncryptionKey> {
        let ops: &dyn AeadBackendOps = self.backend.into();
        let mut key = SecretValue::new(vec![0; self.algorithm.key_len()]);
        ops.fill_random(key.ref_sensitive_value_mut())
            .map_err(|_| {
                KmsAeadEncryptionError::create("ENCRYPTION", "Unable to initialise a random key")
            })?;
        Ok(DataEncryptionKey::from(key))
    }

    /// A new key from the KMS generator of `provider` when it is configured to use one, and from
    /// the backend's CSPRNG otherwise. Calls the KMS only in the first case.
    ///
    /// # Errors
    ///
    /// The provider's error when the KMS call fails, `INVALID_KEY_LENGTH` when the KMS returns a
    /// key of another length, and `ENCRYPTION` when the CSPRNG fails.
    pub async fn generate_data_encryption_key_with<P>(
        &self,
        provider: &P,
    ) -> KmsAeadResult<DataEncryptionKey>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        match checked_key_material(provider, self.algorithm.key_len()).await? {
            Some(material) => Ok(DataEncryptionKey::from(material)),
            None => self.generate_data_encryption_key(),
        }
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

/// Values are `[nonce][ciphertext][tag]`, with a random nonce.
impl Cipher for AeadCipher {
    fn seal(
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
            KmsAeadEncryptionError::create("ENCRYPTION", "Unable to initialise a random nonce")
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

    fn open(
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
                    "INVALID_CIPHERTEXT",
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
}

#[async_trait]
impl<Aad> AeadEncryption<Aad> for AeadCipher
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
{
    async fn encrypt_value(
        &self,
        aad: &Aad,
        plain_text: &SecretValue,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        self.seal(aad.as_ref(), plain_text, encryption_key)
    }

    async fn decrypt_value(
        &self,
        aad: &Aad,
        cipher_text: &CipherText,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
        self.open(aad.as_ref(), cipher_text, encryption_key)
    }
}
