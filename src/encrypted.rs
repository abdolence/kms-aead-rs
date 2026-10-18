use std::fmt::{Debug, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;

use subtle::ConstantTimeEq;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::formats::{Deterministic, Format, Randomized};
use crate::{KeyId, KmsAeadResult};

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "serde")]
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// A stored value that decrypts to a `T`, a [`Plaintext`](crate::Plaintext), in the layout of the
/// format `F`: [`Envelope`](crate::formats::Envelope), [`Bare`](crate::formats::Bare),
/// [`Randomized`] or [`Deterministic`].
///
/// It holds the bytes to store, which [`value`](Self::value) and [`into_value`](Self::into_value)
/// return, and [`to_hex_string`](Self::to_hex_string) as hex. Bytes read back become a value only
/// through `TryFrom<Vec<u8>>`, or [`try_from_hex_string`](Self::try_from_hex_string) for hex,
/// which check them against the layout of `F`, so that a malformed stored value fails when it is
/// read, before any KMS call or decrypt. The check reads the framing only: whether the bytes are
/// authentic is known when they are decrypted.
///
/// Every call that encrypts returns one: [`KmsAeadEnvelope::encrypt`](crate::KmsAeadEnvelope::encrypt)
/// an `Encrypted<T, Envelope>`, [`AeadCipher::encrypt`](crate::AeadCipher::encrypt) an
/// `Encrypted<T, Randomized>` and [`AeadCipher::encrypt_bare`](crate::AeadCipher::encrypt_bare) an
/// `Encrypted<T, Bare>`, and `DeterministicCipher::encrypt` an `Encrypted<T, Deterministic>`. `T`
/// is any type that implements `Plaintext`, such as an application newtype, so that a field names
/// what it holds: `Encrypted<Email, Envelope>`. A value with no type of its own is a
/// [`SecretValue`](secret_vault_value::SecretValue): `Encrypted<SecretValue, Envelope>`.
///
/// A `Randomized` or `Deterministic` value names the key it was sealed under, which `key_id()`
/// returns. An `Envelope` value carries its encrypted DEK instead, and a `Bare` value names no
/// key.
///
/// Only `Encrypted<T, Deterministic>` implements `PartialEq`, `Eq` and `Hash`: values sealed
/// under one deterministic key are equal exactly when their plaintexts and AADs are, which is
/// what a lookup by an encrypted value needs. The other formats seal equal plaintexts into
/// different values, so equal bytes say nothing about the plaintexts; compare `value()` to tell
/// whether two values are the same stored bytes.
///
/// `Debug` shows the length only. The `serde` feature serialises it as bytes, and deserialises it
/// through `TryFrom<Vec<u8>>`. The `postgres` and `sqlx` features store it as `BYTEA` and read it
/// through `TryFrom<Vec<u8>>` too.
#[derive(Clone)]
pub struct Encrypted<T, F: Format> {
    bytes: Vec<u8>,
    key_id: F::FramedKeyId,
    /// Tags the bytes with the plaintext type and the format; holds no `T`.
    marker: PhantomData<(T, F)>,
}

/// Reads stored bytes as a value of the format `F`.
///
/// # Errors
///
/// - `INVALID_CIPHER_TEXT_FORMAT` when the bytes are shorter than the layout of `F` allows: for
///   [`Bare`](crate::formats::Bare), shorter than a nonce and a tag; for [`Randomized`] and
///   [`Deterministic`], not Tink's output prefix followed by at least an empty value;
/// - for [`Envelope`](crate::formats::Envelope), `UNKNOWN_CIPHER_TEXT_LAYOUT` on an empty value or
///   a first byte that starts no layout, `INVALID_CIPHER_TEXT_FORMAT` on an encrypted DEK length
///   outside 1 to 4,096 bytes or past the end, or a cipher text after it shorter than a nonce and
///   a tag, and [`KmsAeadError::LegacyFormat`] on the layouts written by 0.29 and earlier. With
///   the deprecated `legacy-formats` feature those layouts are read, and a length in their header
///   past the end fails with `INVALID_CIPHER_TEXT_FORMAT`.
///
/// The messages never quote the bytes.
impl<T, F: Format> TryFrom<Vec<u8>> for Encrypted<T, F> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        let key_id = F::check(&bytes)?;
        Ok(Self {
            bytes,
            key_id,
            marker: PhantomData,
        })
    }
}

impl<T, F: Format> Encrypted<T, F> {
    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes to store, taking the value.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The lowercase hex of the bytes to store.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes, and
    /// checks the bytes as `TryFrom<Vec<u8>>` does.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX` when `encoded` is not hex, and the errors of `TryFrom<Vec<u8>>`. The messages
    /// never quote the input.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded)
            .map_err(|error| KmsAeadEncryptionError::invalid_hex("The encrypted value", error))?;
        Self::try_from(bytes)
    }
}

/// The length only.
impl<T, F: Format> Debug for Encrypted<T, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encrypted")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl<T> Encrypted<T, Randomized> {
    /// The id of the key this value was sealed under, which its prefix names: the key to open it
    /// with.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }
}

impl<T> Encrypted<T, Deterministic> {
    /// The id of the key this value was sealed under, which its prefix names: the key to open it
    /// with.
    pub fn key_id(&self) -> KeyId {
        self.key_id
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
    use crate::formats::{Bare, Envelope};
    use crate::test_provider::renderings;

    /// Tink's output prefix of the key 0x44556677 followed by `body`.
    fn prefixed(body: &[u8]) -> Vec<u8> {
        [&[0x01, 0x44, 0x55, 0x66, 0x77][..], body].concat()
    }

    /// A Tink envelope of a 7-byte encrypted DEK and `cipher_text`.
    fn envelope(cipher_text: &[u8]) -> Vec<u8> {
        [&[0x00, 0x00, 0x00, 0x07][..], b"wrapped", cipher_text].concat()
    }

    #[test]
    fn the_shortest_value_of_each_format_is_read() -> KmsAeadResult<()> {
        Encrypted::<String, Envelope>::try_from(envelope(&[0xAB; 12 + 16]))?;
        Encrypted::<String, Bare>::try_from(vec![0xAB; 12 + 16])?;
        Encrypted::<String, Randomized>::try_from(prefixed(&[0xAB; 12 + 16]))?;
        Encrypted::<String, Deterministic>::try_from(prefixed(&[0xAB; 16]))?;
        Ok(())
    }

    #[test]
    fn bytes_outside_the_layout_of_the_format_are_refused() {
        let refused = [
            (
                "envelope, an encrypted DEK past the end",
                Encrypted::<String, Envelope>::try_from(vec![0x00, 0x00, 0x00, 0x07, 0xAB]).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "envelope, a cipher text shorter than a nonce and a tag",
                Encrypted::<String, Envelope>::try_from(envelope(&[0xAB; 12 + 15])).err(),
                "INVALID_CIPHER_TEXT_FORMAT",
            ),
            (
                "bare, shorter than a nonce and a tag",
                Encrypted::<String, Bare>::try_from(vec![0xAB; 12 + 15]).err(),
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
    fn hex_reads_back_through_the_layout_check() -> KmsAeadResult<()> {
        let value = Encrypted::<String, Randomized>::try_from(prefixed(&[0xAB; 12 + 16]))?;

        let read_back = Encrypted::<String, Randomized>::try_from_hex_string(
            &value.to_hex_string().to_uppercase(),
        );
        let too_short = Encrypted::<String, Bare>::try_from_hex_string(&hex::encode([0xAB; 27]));

        assert!(
            matches!(&read_back, Ok(read_back) if read_back.value() == value.value()),
            "{read_back:?}"
        );
        assert!(
            matches!(&too_short, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
            "{too_short:?}"
        );
        Ok(())
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
