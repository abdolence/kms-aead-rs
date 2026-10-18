use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

use rvstruct::*;
use secret_vault_value::SecretValue;
use subtle::ConstantTimeEq;

use crate::errors::*;
use crate::KmsAeadResult;

/// A value sealed by an [`AeadAlgorithm`](crate::AeadAlgorithm): `[nonce][ciphertext][tag]`.
/// It holds no key, so it is not a storage form for envelope encryption without the encrypted DEK
/// that opens it.
#[derive(Clone, ValueStruct)]
pub struct CipherText(pub Vec<u8>);

/// The length only.
impl Debug for CipherText {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherText")
            .field("len", &self.0.len())
            .finish()
    }
}

impl CipherText {
    /// The lowercase hex of the value.
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &Self) -> bool {
        self.value().ct_eq(other.value()).into()
    }
}

/// A plaintext data encryption key, zeroised on drop and shown as `***` by `Debug`. Equality
/// compares in constant time.
///
/// The ciphers take the key's own bytes. A provider's
/// [`encrypt_data_encryption_key`](crate::KmsAeadEncryptionProvider::encrypt_data_encryption_key)
/// receives the key as Tink serialises it, which is what the KMS encrypts, and the Azure provider
/// the raw key.
#[derive(Debug, Clone)]
pub struct DataEncryptionKey(SecretValue);

impl DataEncryptionKey {
    /// The key bytes.
    pub fn value(&self) -> &SecretValue {
        &self.0
    }
}

/// The bytes of `dek`, checked against `algorithm`, whose keys have `key_len` bytes, before any
/// cipher sees them: a key of another length, such as a 64-byte deterministic key, is never cut
/// or padded to fit.
///
/// # Errors
///
/// `INVALID_KEY_LENGTH` when `dek` has another length.
pub(crate) fn checked_key_bytes(
    dek: &DataEncryptionKey,
    algorithm: impl Display,
    key_len: usize,
) -> KmsAeadResult<&[u8]> {
    let key = dek.value().ref_sensitive_value();
    if key.len() == key_len {
        Ok(key)
    } else {
        Err(KmsAeadEncryptionError::create(
            "INVALID_KEY_LENGTH",
            &format!(
                "A key of {} bytes does not fit {algorithm}, which takes {key_len} bytes",
                key.len()
            ),
        ))
    }
}

impl From<SecretValue> for DataEncryptionKey {
    fn from(value: SecretValue) -> Self {
        Self(value)
    }
}

impl PartialEq for DataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.value()
            .as_sensitive_bytes()
            .ct_eq(other.value().as_sensitive_bytes())
            .into()
    }
}

/// A data encryption key encrypted by a KMS: the bytes the provider returned, which are also the
/// bytes to store and the bytes the provider decrypts. They are the KMS ciphertext of the key as
/// Tink serialises it, or of the raw key for Azure, and they name the KMS key version that
/// encrypted it where the KMS needs one to decrypt; the formats chapter of the book lists each
/// provider's bytes.
///
/// Equality compares in constant time. `Debug` shows the length only.
#[derive(Clone, ValueStruct)]
pub struct EncryptedDataEncryptionKey(Vec<u8>);

impl EncryptedDataEncryptionKey {
    /// The lowercase hex of the bytes.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.0)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX` when `encoded` is not hex.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        hex::decode(encoded).map(Self).map_err(|error| {
            let reason = match error {
                // The character may be a byte of a value stored in plain text, so it stays out.
                hex::FromHexError::InvalidHexCharacter { index, .. } => {
                    format!("the character at position {index} is not a hex digit")
                }
                other => other.to_string(),
            };
            KmsAeadEncryptionError::create(
                "INVALID_HEX",
                &format!("Encrypted key is not hex: {reason}"),
            )
        })
    }
}

/// The length only.
impl Debug for EncryptedDataEncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedDataEncryptionKey")
            .field("len", &self.0.len())
            .finish()
    }
}

impl PartialEq for EncryptedDataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for EncryptedDataEncryptionKey {}

/// Hashes the bytes, in variable time: an encrypted DEK opens nothing without the KMS.
impl Hash for EncryptedDataEncryptionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::renderings;

    const ENCRYPTED_DEK: &[u8] = b"zq-key-marker-zq";
    const CIPHER_TEXT: &[u8] = b"zq-cipher-marker-zq";

    #[test]
    fn an_encrypted_key_reads_back_from_hex() -> KmsAeadResult<()> {
        let encrypted_dek = EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec());

        let hex_string = encrypted_dek.to_hex_string();

        assert_eq!(hex_string, hex::encode(ENCRYPTED_DEK));
        assert_eq!(
            EncryptedDataEncryptionKey::try_from_hex_string(&hex_string.to_uppercase())?,
            encrypted_dek
        );
        Ok(())
    }

    #[test]
    fn hex_that_does_not_decode_is_refused_without_echoing_it() {
        let result = EncryptedDataEncryptionKey::try_from_hex_string("0a~0");

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_HEX" && !error.message.contains('~')),
            "{result:?}"
        );
    }

    #[test]
    fn debug_shows_no_encrypted_dek_or_cipher_text_bytes() {
        let debug = format!(
            "{:?} {:?}",
            EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec()),
            CipherText(CIPHER_TEXT.to_vec())
        );

        for stored in [ENCRYPTED_DEK, CIPHER_TEXT] {
            for rendering in renderings(stored) {
                assert!(!debug.contains(&rendering), "{debug}");
            }
        }
    }
}
