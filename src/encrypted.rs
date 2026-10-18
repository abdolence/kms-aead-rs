use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use rvstruct::ValueStruct;
use subtle::ConstantTimeEq;

use crate::errors::KmsAeadError;
use crate::formats::{Deterministic, Format};
use crate::KmsAeadResult;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "serde")]
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// A stored value that decrypts to a `T`, a [`Plaintext`](crate::Plaintext), in the format `F`.
///
/// It holds the bytes to store, which `value()` and `into_value()` of [`ValueStruct`] return.
/// Bytes read back become a value through `TryFrom<Vec<u8>>`, which checks them against the
/// layout of `F`, so that a malformed stored value fails when it is read, before any KMS call or
/// decrypt. The check reads the framing only: whether the bytes are authentic is known when they
/// are decrypted.
///
/// [`KmsAeadEnvelope::encrypt_field`](crate::KmsAeadEnvelope::encrypt_field) writes an
/// `Encrypted<T, Envelope>`, and kms-aead-keyring writes `Encrypted<T, Randomized>` and
/// `Encrypted<T, Deterministic>`. `T` is any type that implements `Plaintext`, such as an
/// application newtype, so a field names what it holds: `Encrypted<Email, Envelope>`.
///
/// Only `Encrypted<T, Deterministic>` implements `PartialEq`, `Eq` and `Hash`: values sealed
/// under one deterministic key are equal exactly when their plaintexts and AADs are, which is
/// what a lookup by an encrypted value needs. The other formats seal equal plaintexts into
/// different values, so equal bytes say nothing about the plaintexts; compare `value()` to tell
/// whether two values are the same stored bytes.
///
/// `Debug` shows the length only. The `serde` feature serializes it as bytes, and deserializes it
/// through `TryFrom<Vec<u8>>`. The `postgres` and `sqlx` features store it as `BYTEA` and read it
/// through `TryFrom<Vec<u8>>` too.
pub struct Encrypted<T, F> {
    bytes: Vec<u8>,
    plaintext: PhantomData<fn() -> (T, F)>,
}

/// Reads stored bytes as a value of the format `F`.
///
/// # Errors
///
/// For [`Envelope`](crate::formats::Envelope), the errors of
/// [`CipherTextWithEncryptedKey::separate`](crate::CipherTextWithEncryptedKey::separate), and
/// `INVALID_CIPHER_TEXT_FORMAT` when the cipher text after the wrapped DEK is shorter than a
/// nonce and a tag. For [`Randomized`](crate::formats::Randomized) and [`Deterministic`],
/// `INVALID_CIPHER_TEXT_FORMAT` when the bytes do not start with Tink's output prefix or are
/// shorter than the prefix and an empty value. The messages never quote the bytes.
impl<T, F: Format> TryFrom<Vec<u8>> for Encrypted<T, F> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        F::check(&bytes)?;
        Ok(Self {
            bytes,
            plaintext: PhantomData,
        })
    }
}

/// The bytes to store.
impl<T, F> ValueStruct for Encrypted<T, F> {
    type ValueType = Vec<u8>;

    fn value(&self) -> &Vec<u8> {
        &self.bytes
    }

    fn into_value(self) -> Vec<u8> {
        self.bytes
    }
}

impl<T, F> Clone for Encrypted<T, F> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            plaintext: PhantomData,
        }
    }
}

/// The length only.
impl<T, F> Debug for Encrypted<T, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encrypted")
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// Compares the bytes in constant time.
impl<T> PartialEq for Encrypted<T, Deterministic> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<T> Eq for Encrypted<T, Deterministic> {}

/// Hashes the bytes, in variable time: which deterministic values are equal is not secret.
impl<T> Hash for Encrypted<T, Deterministic> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{Envelope, Randomized};
    use crate::test_provider::renderings;

    /// Tink's output prefix of the key 0x44556677 followed by `body`.
    fn prefixed(body: &[u8]) -> Vec<u8> {
        [&[0x01, 0x44, 0x55, 0x66, 0x77][..], body].concat()
    }

    /// A Tink envelope of a 7-byte wrapped DEK and `cipher_text`.
    fn envelope(cipher_text: &[u8]) -> Vec<u8> {
        [&[0x00, 0x00, 0x00, 0x07][..], b"wrapped", cipher_text].concat()
    }

    #[test]
    fn the_shortest_value_of_each_format_is_read() -> KmsAeadResult<()> {
        Encrypted::<String, Envelope>::try_from(envelope(&[0xAB; 12 + 16]))?;
        Encrypted::<String, Randomized>::try_from(prefixed(&[0xAB; 12 + 16]))?;
        Encrypted::<String, Deterministic>::try_from(prefixed(&[0xAB; 16]))?;
        Ok(())
    }

    #[test]
    fn bytes_outside_the_layout_of_the_format_are_refused() {
        let refused = [
            (
                "envelope, a wrapped DEK past the end",
                Encrypted::<String, Envelope>::try_from(vec![0x00, 0x00, 0x00, 0x07, 0xAB]).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "envelope, a cipher text shorter than a nonce and a tag",
                Encrypted::<String, Envelope>::try_from(envelope(&[0xAB; 12 + 15])).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "randomized, no output prefix",
                Encrypted::<String, Randomized>::try_from(envelope(&[0xAB; 64])).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "randomized, shorter than a nonce and a tag",
                Encrypted::<String, Randomized>::try_from(prefixed(&[0xAB; 12 + 15])).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "deterministic, no output prefix",
                Encrypted::<String, Deterministic>::try_from(vec![0x00; 64]).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "deterministic, shorter than a synthetic IV",
                Encrypted::<String, Deterministic>::try_from(prefixed(&[0xAB; 15])).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
        ];
        for (case, error, code) in refused {
            assert!(
                matches!(&error, Some(KmsAeadError::EncryptionError(error))
                    if error.public.code == code),
                "{case}: {error:?}"
            );
        }
    }

    #[test]
    fn debug_shows_no_stored_bytes() -> KmsAeadResult<()> {
        let body = b"zq-cipher-marker-zq-and-a-tag-of-16";
        let value = Encrypted::<String, Randomized>::try_from(prefixed(body))?;

        let debug = format!("{value:?}");

        for rendering in renderings(body) {
            assert!(!debug.contains(&rendering), "{debug}");
        }
        Ok(())
    }
}
