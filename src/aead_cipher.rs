use std::marker::PhantomData;

use secret_vault_value::SecretValue;

use crate::backends::AeadBackend;
use crate::backends::{Failure, Nonce};
use crate::errors::{KmsAeadEncryptionError, KmsAeadUnsupportedAlgorithmError};
use crate::formats::{tink_output_prefix, Bare, Randomized, TINK_OUTPUT_PREFIX_LEN};
use crate::types::checked_key_bytes;
use crate::{
    AeadAlgorithm, DataEncryptionKey, Encrypted, KeyId, KmsAeadEncryptionProvider, KmsAeadResult,
    KmsEncryptedDek, Plaintext,
};

/// Randomised authenticated encryption with associated data (AEAD) under a data encryption key
/// the caller holds, on the backend `B` and with the algorithm it was made with, without a KMS.
///
/// Every value is sealed with a random nonce, so that sealing the same input twice gives
/// different values. [`encrypt`](Self::encrypt) writes it in Tink's layout of a key named by a
/// [`KeyId`], an [`Encrypted<T, Randomized>`](Encrypted), and
/// [`encrypt_bare`](Self::encrypt_bare) without the key id, an [`Encrypted<T, Bare>`](Encrypted).
/// The AAD is authenticated but not encrypted: a value opens only with the AAD it was sealed
/// with.
///
/// It does no I/O and opens no span: it runs once per value, inside the caller's span.
#[derive(Debug, Clone)]
pub struct AeadCipher<B> {
    algorithm: AeadAlgorithm,
    backend: PhantomData<B>,
}

impl<B: AeadBackend> AeadCipher<B> {
    /// A cipher for `algorithm` on the backend `B`.
    ///
    /// # Errors
    ///
    /// [`KmsAeadError::UnsupportedAlgorithm`](crate::errors::KmsAeadError::UnsupportedAlgorithm),
    /// code `UNSUPPORTED_ALGORITHM`, when `B` does not implement `algorithm`: ring has no
    /// AES-256-GCM-SIV.
    pub fn new(algorithm: AeadAlgorithm) -> KmsAeadResult<Self> {
        if B::supports(algorithm) {
            Ok(Self {
                algorithm,
                backend: PhantomData,
            })
        } else {
            Err(KmsAeadUnsupportedAlgorithmError::create(algorithm, B::NAME))
        }
    }

    /// The algorithm this cipher seals and opens with.
    pub fn algorithm(&self) -> AeadAlgorithm {
        self.algorithm
    }

    /// A new data encryption key of `algorithm().key_len()` bytes from the backend's CSPRNG. It
    /// makes no KMS call.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn generate_dek(&self) -> KmsAeadResult<DataEncryptionKey> {
        B::generate_random_bytes(self.algorithm.key_len()).map(DataEncryptionKey::from)
    }

    /// A new data encryption key and the same key encrypted by `provider`, to store, with the KEK
    /// version that encrypted it. The key comes from the KMS generator when the provider is
    /// configured to use one, and from the backend's CSPRNG otherwise. It is encrypted as Tink
    /// encrypts a data encryption key, serialised as the Tink key of the algorithm, or raw under an
    /// Azure KEK, so that [`Encrypted::join`](crate::Encrypted::join) can store it with the values
    /// sealed under it.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material
    /// of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
    pub async fn generate_encrypted_dek<P>(
        &self,
        provider: &P,
    ) -> KmsAeadResult<(DataEncryptionKey, KmsEncryptedDek)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        crate::formats::generate_encrypted_dek::<B, P>(
            self.algorithm.into(),
            self.algorithm.key_len(),
            provider,
        )
        .await
    }

    /// `value`, as [`Plaintext`] encodes it, sealed under `dek` with a fresh random nonce, in
    /// Tink's layout of a key with the output prefix TINK and the id `key_id`:
    ///
    /// ```text
    /// [0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]
    /// ```
    ///
    /// Tink's AEAD opens it with a keyset that holds `dek` as the key `key_id` of the cipher's
    /// algorithm, and so does BigQuery's `AEAD.DECRYPT_STRING` or `AEAD.DECRYPT_BYTES` under
    /// AES-256-GCM. `key_id` is not authenticated.
    ///
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when `value` does not encode, `INVALID_KEY_LENGTH` when the key does
    /// not have the length of the algorithm, `RANDOM_GENERATOR` when the random nonce cannot be
    /// generated, and `ENCRYPT_KEY` or `ENCRYPT` when the backend refuses the key or fails to seal.
    pub fn encrypt<T: Plaintext>(
        &self,
        key_id: KeyId,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &T,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<Encrypted<T, Randomized>> {
        let plain_text = value.to_plaintext()?;
        let sealed = self.seal(
            &tink_output_prefix(key_id),
            aad.as_ref(),
            plain_text.ref_sensitive_value(),
            dek.value().ref_sensitive_value(),
        )?;
        Encrypted::try_from(sealed)
    }

    /// Opens `value`, sealed under `dek` and `aad` by [`encrypt`](Self::encrypt) or by Tink, and
    /// decodes the plaintext as a `T`. The caller picks `dek` by
    /// [`value.key_id()`](Encrypted::key_id).
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when the key does not have the length of the algorithm, `DECRYPT_KEY`
    /// when the backend refuses the key, `DECRYPT` when the value is not authentic under the key,
    /// the nonce and the AAD, and `INVALID_PLAINTEXT` when the plaintext is not an encoding of
    /// `T`.
    pub fn decrypt<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Randomized>,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<T> {
        T::from_plaintext(self.open(
            aad.as_ref(),
            value.value(),
            TINK_OUTPUT_PREFIX_LEN,
            dek.value().ref_sensitive_value(),
        )?)
    }

    /// `value`, as [`Plaintext`] encodes it, sealed under `dek` with a fresh random nonce, with no
    /// framing: `[nonce: 12][ciphertext][tag: 16]`, Tink's output under a key with the output
    /// prefix RAW.
    ///
    /// # Errors
    ///
    /// The errors of [`encrypt`](Self::encrypt).
    pub fn encrypt_bare<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &T,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<Encrypted<T, Bare>> {
        let plain_text = value.to_plaintext()?;
        let sealed = self.seal(
            &[],
            aad.as_ref(),
            plain_text.ref_sensitive_value(),
            dek.value().ref_sensitive_value(),
        )?;
        Encrypted::try_from(sealed)
    }

    /// Opens `value`, sealed under `dek` and `aad` by [`encrypt_bare`](Self::encrypt_bare), and
    /// decodes the plaintext as a `T`.
    ///
    /// # Errors
    ///
    /// The errors of [`decrypt`](Self::decrypt).
    pub fn decrypt_bare<T: Plaintext>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Bare>,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<T> {
        T::from_plaintext(self.open(
            aad.as_ref(),
            value.value(),
            0,
            dek.value().ref_sensitive_value(),
        )?)
    }
}

/// Sealing and opening under raw key bytes, which the envelope, the local KMS and the legacy
/// upgrades run on. Crate-private, so that the public methods of [`AeadCipher`] take typed keys
/// only.
pub(crate) trait AeadKeyBytesOps {
    /// `prefix`, then `plain_text` sealed under `key` with a fresh random nonce:
    /// `[prefix][nonce][ciphertext][tag]`.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when `key` does not have the length of the algorithm,
    /// `RANDOM_GENERATOR` when the random nonce cannot be generated, and `ENCRYPT_KEY` or
    /// `ENCRYPT` when the backend refuses the key or fails to seal.
    fn seal(
        &self,
        prefix: &[u8],
        aad: &[u8],
        plain_text: &[u8],
        key: &[u8],
    ) -> KmsAeadResult<Vec<u8>>;

    /// Opens the `[nonce][ciphertext][tag]` after the first `prefix_len` bytes of `value` under
    /// `key`, into a buffer the returned `SecretValue` owns.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when `key` does not have the length of the algorithm,
    /// `INVALID_CIPHER_TEXT_FORMAT` when the bytes after the prefix are shorter than a nonce and a
    /// tag, `DECRYPT_KEY` when the backend refuses the key, and `DECRYPT` when the value is not
    /// authentic under the key, the nonce and the AAD.
    fn open(
        &self,
        aad: &[u8],
        value: &[u8],
        prefix_len: usize,
        key: &[u8],
    ) -> KmsAeadResult<SecretValue>;
}

impl<B: AeadBackend> AeadKeyBytesOps for AeadCipher<B> {
    fn seal(
        &self,
        prefix: &[u8],
        aad: &[u8],
        plain_text: &[u8],
        key: &[u8],
    ) -> KmsAeadResult<Vec<u8>> {
        let key = checked_key_bytes(key, self.algorithm, self.algorithm.key_len())?;

        let mut nonce: Nonce = [0; AeadAlgorithm::NONCE_LEN];
        B::fill_random(&mut nonce).map_err(|_| {
            KmsAeadEncryptionError::create("RANDOM_GENERATOR", "Unable to generate a random nonce")
        })?;

        // Allocated once at its final size, since growing it would leave a copy of the plaintext
        // in freed memory, and zeroised if sealing fails.
        let mut buffer = SecretValue::new(Vec::with_capacity(
            prefix.len() + AeadAlgorithm::NONCE_LEN + plain_text.len() + AeadAlgorithm::TAG_LEN,
        ));
        let value = buffer.ref_sensitive_value_mut();
        value.extend_from_slice(prefix);
        value.extend_from_slice(&nonce);
        value.extend_from_slice(plain_text);
        let tag = B::seal_in_place(
            self.algorithm,
            key,
            &nonce,
            aad,
            &mut value[prefix.len() + AeadAlgorithm::NONCE_LEN..],
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
        Ok(std::mem::take(value))
    }

    fn open(
        &self,
        aad: &[u8],
        value: &[u8],
        prefix_len: usize,
        key: &[u8],
    ) -> KmsAeadResult<SecretValue> {
        let key = checked_key_bytes(key, self.algorithm, self.algorithm.key_len())?;
        let (nonce, sealed) = value
            .get(prefix_len..)
            .and_then(|after_prefix| {
                after_prefix.split_first_chunk::<{ AeadAlgorithm::NONCE_LEN }>()
            })
            .filter(|(_, sealed)| sealed.len() >= AeadAlgorithm::TAG_LEN)
            .ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "INVALID_CIPHER_TEXT_FORMAT",
                    &format!(
                        "A cipher text of {} bytes is too short to hold a nonce and a tag",
                        value.len()
                    ),
                )
            })?;

        let mut plain_text = SecretValue::new(sealed.to_vec());
        let plain_text_len = B::open_in_place(
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

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::errors::KmsAeadError;
    use crate::test_provider::TestBackend;

    const ALICE: &str = "alice@example.com";
    const EMAIL_AAD: &[u8] = b"user/42/email";
    const KEY_ID: KeyId = KeyId::new(7);

    /// `alice@example.com` sealed by Tink 1.16.1 for Python with a keyset of one AES-256-GCM key
    /// with the TINK prefix: key id 7, the bytes 0 to 31 as the key, `user/42/email` as the
    /// associated data.
    const TINK_VALUE: [u8; 50] = [
        0x01, 0x00, 0x00, 0x00, 0x07, 0x11, 0x0a, 0xc1, 0x1b, 0x7b, 0x32, 0x08, 0x0d, 0xe3, 0x83,
        0xa3, 0xb8, 0xbc, 0x9e, 0x0d, 0xac, 0xcf, 0x01, 0x2a, 0xc0, 0x0b, 0xb3, 0x76, 0xb1, 0x4c,
        0xcd, 0xb7, 0xeb, 0x05, 0x00, 0xc7, 0x7a, 0xea, 0x67, 0xeb, 0x9b, 0x37, 0x35, 0xaa, 0xd6,
        0x0e, 0x53, 0x4b, 0x10, 0xbe,
    ];

    #[test]
    fn a_field_is_the_key_id_prefix_and_the_aead_cipher_output() -> KmsAeadResult<()> {
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
        let dek = cipher.generate_dek()?;

        let field = cipher.encrypt(KEY_ID, EMAIL_AAD, &ALICE.to_string(), &dek)?;

        let bytes = field.value();
        assert_eq!(bytes[..5], [0x01, 0x00, 0x00, 0x00, 0x07]);
        assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);
        assert_eq!(field.key_id(), KEY_ID);
        let bare = Encrypted::<String, Bare>::try_from(bytes[5..].to_vec())?;
        assert_eq!(cipher.decrypt_bare(EMAIL_AAD, &bare, &dek)?, ALICE);
        assert_eq!(cipher.decrypt(EMAIL_AAD, &field, &dek)?, ALICE);
        Ok(())
    }

    #[test]
    fn a_value_sealed_by_tink_decrypts() -> KmsAeadResult<()> {
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
        let dek = DataEncryptionKey::from(SecretValue::new((0u8..32).collect()));

        let value = Encrypted::<String, Randomized>::try_from(TINK_VALUE.to_vec())?;

        assert_eq!(value.key_id(), KEY_ID);
        assert_eq!(cipher.decrypt(EMAIL_AAD, &value, &dek)?, ALICE);
        Ok(())
    }

    #[test]
    fn a_plaintext_that_is_no_encoding_of_the_type_is_refused() -> KmsAeadResult<()> {
        let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
        let dek = cipher.generate_dek()?;
        let field = cipher.encrypt(KEY_ID, EMAIL_AAD, &vec![0xFF_u8], &dek)?;

        let as_string = Encrypted::<String, Randomized>::try_from(field.into_value())?;
        let result = cipher.decrypt(EMAIL_AAD, &as_string, &dek);

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{result:?}"
        );
        Ok(())
    }
}
