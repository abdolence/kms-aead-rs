use std::marker::PhantomData;

use async_trait::async_trait;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::backend::sealed::{Failure, Nonce, Token};
use crate::backend::AeadBackend;
use crate::errors::{KmsAeadEncryptionError, KmsAeadUnsupportedAlgorithmError};
use crate::{
    checked_key_material, AeadAlgorithm, AeadEncryption, CipherText, DataEncryptionKey,
    KmsAeadEncryptionProvider, KmsAeadResult,
};

/// Randomized AEAD with the algorithm it was made with, on the backend `B`, without a KMS.
///
/// It does no I/O and opens no span: it runs once per value, inside the caller's span.
#[derive(Debug, Clone)]
pub struct AeadCipher<B> {
    algorithm: AeadAlgorithm,
    backend: PhantomData<fn() -> B>,
}

impl<B: AeadBackend> AeadCipher<B> {
    /// Fails with `UNSUPPORTED_ALGORITHM` when `B` does not implement `algorithm`.
    pub fn new(algorithm: AeadAlgorithm) -> KmsAeadResult<Self> {
        if B::supports(Token::new(), algorithm) {
            Ok(Self {
                algorithm,
                backend: PhantomData,
            })
        } else {
            Err(KmsAeadUnsupportedAlgorithmError::create(
                algorithm,
                Self::backend_name(),
            ))
        }
    }

    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// `algorithm().key_len()` bytes from `B`'s CSPRNG.
    pub fn generate_data_encryption_key(&self) -> KmsAeadResult<DataEncryptionKey> {
        let mut key = SecretValue::new(vec![0; self.algorithm.key_len()]);
        B::fill_random(Token::new(), key.ref_sensitive_value_mut()).map_err(|_| {
            KmsAeadEncryptionError::create("ENCRYPTION", "Unable to initialise a random key")
        })?;
        Ok(DataEncryptionKey::from(key))
    }

    /// A key from the KMS generator of `provider` when it is configured to use one, and from
    /// `B`'s CSPRNG otherwise. Fails with `INVALID_KEY_LENGTH` when the KMS returns a key of
    /// another length.
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

    /// The value of the `backend` span field.
    pub(crate) fn backend_name() -> &'static str {
        B::name(Token::new())
    }

    /// `[nonce][ciphertext][tag]` with a random nonce.
    pub(crate) fn seal(
        &self,
        aad: &[u8],
        plain_text: &SecretValue,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<CipherText> {
        let key = self.key_bytes(key)?;
        let plain_text = plain_text.ref_sensitive_value();

        let mut nonce: Nonce = [0; AeadAlgorithm::NONCE_LEN];
        B::fill_random(Token::new(), &mut nonce).map_err(|_| {
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
        let tag = B::seal_in_place(
            Token::new(),
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

    /// Opens `[nonce][ciphertext][tag]` into a buffer the returned `SecretValue` owns, so that
    /// no other copy of the plaintext exists.
    pub(crate) fn open(
        &self,
        aad: &[u8],
        cipher_text: &CipherText,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<SecretValue> {
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
        let plain_text_len = B::open_in_place(
            Token::new(),
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
            Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!(
                    "A key of {} bytes does not fit {}, which takes {} bytes",
                    key.len(),
                    self.algorithm,
                    self.algorithm.key_len()
                ),
            ))
        }
    }
}

#[async_trait]
impl<Aad, B> AeadEncryption<Aad> for AeadCipher<B>
where
    Aad: AsRef<[u8]> + Send + Sync + 'static,
    B: AeadBackend,
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
