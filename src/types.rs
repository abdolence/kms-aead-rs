use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};

use rvstruct::*;
use secret_vault_value::SecretValue;
use subtle::ConstantTimeEq;

use crate::errors::*;
use crate::KmsAeadResult;

/// A value sealed by an [`AeadAlgorithm`](crate::AeadAlgorithm): `[nonce][ciphertext][tag]`.
/// It holds no key, so it is not a storage form for envelope encryption without the wrapped key
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

/// A plaintext data encryption key, zeroized on drop and shown as `***` by `Debug`. Equality
/// compares in constant time.
///
/// The ciphers take the key's own bytes. A provider's
/// [`encrypt_data_encryption_key`](crate::KmsAeadEncryptionProvider::encrypt_data_encryption_key)
/// receives the key as Tink serializes it, which is what the KMS wraps.
#[derive(Debug, Clone)]
pub struct DataEncryptionKey(SecretValue);

impl DataEncryptionKey {
    /// The key bytes.
    pub fn value(&self) -> &SecretValue {
        &self.0
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

/// The version of the KMS key that wrapped a data encryption key: 1 to 255 ASCII alphanumeric
/// characters, such as the version of an Azure Key Vault key.
///
/// The same rule validates every key version read back from the Azure provider's wrapped keys
/// and from the layouts of 0.29, so it may only ever loosen: a stricter rule makes stored data
/// unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsKeyVersion(String);

impl KmsKeyVersion {
    /// The version as the KMS names it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The key version of `bytes`, read from storage. The error reports the length and the class
    /// of the first rejected byte, never the bytes themselves, which end up in logs.
    pub(crate) fn from_ascii(bytes: &[u8]) -> KmsAeadResult<Self> {
        let rejected = if bytes.is_empty() || bytes.len() > usize::from(u8::MAX) {
            Some("is not 1 to 255 bytes long")
        } else {
            bytes
                .iter()
                .find(|byte| !byte.is_ascii_alphanumeric())
                .map(|byte| {
                    if !byte.is_ascii() {
                        "contains a non-ASCII byte"
                    } else if byte.is_ascii_control() {
                        "contains an ASCII control byte"
                    } else {
                        "contains ASCII punctuation or a space"
                    }
                })
        };
        match rejected {
            Some(reason) => Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                &format!("KMS key version of {} bytes {reason}", bytes.len()),
            )),
            None => Ok(Self(bytes.iter().copied().map(char::from).collect())),
        }
    }
}

impl TryFrom<String> for KmsKeyVersion {
    type Error = KmsAeadError;

    fn try_from(value: String) -> KmsAeadResult<Self> {
        Self::from_ascii(value.as_bytes())
    }
}

impl Display for KmsKeyVersion {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A data encryption key wrapped by a KMS: the bytes the provider returned, which are also the
/// bytes to store and the bytes the provider unwraps. They are the KMS ciphertext of the key as
/// Tink serializes it, and they name the KMS key version that wrapped it where the KMS needs one
/// to unwrap; the formats chapter of the book lists each provider's bytes.
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

/// Hashes the bytes, in variable time: a wrapped key opens nothing without the KMS.
impl Hash for EncryptedDataEncryptionKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::renderings;

    const WRAPPED_KEY: &[u8] = b"zq-key-marker-zq";
    const CIPHER_TEXT: &[u8] = b"zq-cipher-marker-zq";

    #[test]
    fn kms_key_version_is_1_to_255_ascii_alphanumeric_characters() {
        assert!(KmsKeyVersion::try_from("a".repeat(255)).is_ok());
        for invalid in [String::new(), "a".repeat(256), "1/2".into(), "v 1".into()] {
            let result = KmsKeyVersion::try_from(invalid.clone());
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_VERSION"),
                "{invalid:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_key_version_error_echoes_no_stored_bytes() {
        let error = KmsKeyVersion::from_ascii(b"marker/18").unwrap_err();

        assert!(
            !format!("{error} {error:?}").contains("marker"),
            "{error:?}"
        );
    }

    #[test]
    fn an_encrypted_key_reads_back_from_hex() -> KmsAeadResult<()> {
        let encrypted_dek = EncryptedDataEncryptionKey::new(WRAPPED_KEY.to_vec());

        let hex_string = encrypted_dek.to_hex_string();

        assert_eq!(hex_string, hex::encode(WRAPPED_KEY));
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
    fn debug_shows_no_wrapped_key_or_cipher_text_bytes() {
        let debug = format!(
            "{:?} {:?}",
            EncryptedDataEncryptionKey::new(WRAPPED_KEY.to_vec()),
            CipherText(CIPHER_TEXT.to_vec())
        );

        for stored in [WRAPPED_KEY, CIPHER_TEXT] {
            for rendering in renderings(stored) {
                assert!(!debug.contains(&rendering), "{debug}");
            }
        }
    }
}
