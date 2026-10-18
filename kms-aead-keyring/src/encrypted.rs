//! Keyring values: `[0x01][key id: u32 BE][body]`, Tink's TINK-prefixed layout, where the body
//! is what kms-aead's cipher of the version's algorithm writes.

use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use subtle::ConstantTimeEq;

use crate::errors::{KeyPurposeMismatchError, KeyringError, KeyringResult, ValueLayoutError};
use crate::{KeyId, Purpose};

/// A randomized keyring value: `[0x01][key id][nonce: 12][ciphertext][tag: 16]`, the layout of
/// Tink's AEAD and of BigQuery's `AEAD.ENCRYPT` under AES-256-GCM.
#[derive(Debug, Clone, Copy)]
pub struct Randomized;

/// A deterministic keyring value: `[0x01][key id][synthetic IV: 16][ciphertext]`, the layout of
/// Tink's deterministic AEAD and of BigQuery's `DETERMINISTIC_ENCRYPT`. The type exists in every
/// build, so that such values pass through a process without the `deterministic` feature.
#[derive(Debug, Clone, Copy)]
pub struct Deterministic;

mod sealed {
    pub trait Sealed {}
    impl Sealed for super::Randomized {}
    impl Sealed for super::Deterministic {}
}

/// The mode of a keyring value, [`Randomized`] or [`Deterministic`]. Sealed.
pub trait Mode: sealed::Sealed + Send + Sync + 'static {
    /// The purpose of the key versions that seal values of this mode.
    const PURPOSE: Purpose;
}

impl Mode for Randomized {
    const PURPOSE: Purpose = Purpose::Randomized;
}

impl Mode for Deterministic {
    const PURPOSE: Purpose = Purpose::Deterministic;
}

/// A keyring value that decrypts to a `T`, in the mode `M`: `[0x01][key id: u32 BE][body]`, the
/// bytes to store. The prefix is not authenticated: a changed key id selects another version,
/// whose key the body does not open under.
///
/// A value is checked when it is made from stored bytes, so a value of the wrong mode, or bytes
/// that are no keyring value at all, fail there, before any store or KMS call.
///
/// With the `serde` feature it serializes as bytes: a Firestore `bytes` value, and in
/// serde_json an array of numbers.
pub struct Encrypted<T, M = Randomized> {
    bytes: Vec<u8>,
    key_id: KeyId,
    plaintext: PhantomData<fn() -> (T, M)>,
}

impl<T, M: Mode> Encrypted<T, M> {
    /// The version byte of Tink's TINK prefix.
    const PREFIX: u8 = 0x01;
    const HEADER_LEN: usize = 5;

    /// The value `[0x01][key_id][body]`.
    pub(crate) fn new(key_id: KeyId, body: &[u8]) -> Self {
        let mut bytes = Vec::with_capacity(Self::HEADER_LEN + body.len());
        bytes.push(Self::PREFIX);
        bytes.extend_from_slice(&key_id.to_be_bytes());
        bytes.extend_from_slice(body);
        Self {
            bytes,
            key_id,
            plaintext: PhantomData,
        }
    }

    /// The id of the key version that sealed the value.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The bytes to store.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// What the version's cipher wrote: the bytes after the prefix, which every value has.
    pub(crate) fn body(&self) -> &[u8] {
        &self.bytes[Self::HEADER_LEN..]
    }
}

impl<T, M: Mode> TryFrom<Vec<u8>> for Encrypted<T, M> {
    type Error = KeyringError;

    /// Reads stored bytes as a value of mode `M`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ValueLayout`] when the bytes do not start with `0x01`, are shorter than
    /// an empty value of the mode, or carry a key id of 0 or 2^31, and
    /// [`KeyringError::KeyPurposeMismatch`] when the key id belongs to the other purpose.
    fn try_from(bytes: Vec<u8>) -> KeyringResult<Self> {
        let [Self::PREFIX, a, b, c, d, ..] = bytes[..] else {
            return Err(KeyringError::ValueLayout(match bytes.first() {
                Some(&Self::PREFIX) => ValueLayoutError::TooShort(M::PURPOSE),
                _ => ValueLayoutError::NoTinkPrefix,
            }));
        };
        if bytes.len() < M::PURPOSE.min_value_len() {
            return Err(KeyringError::ValueLayout(ValueLayoutError::TooShort(
                M::PURPOSE,
            )));
        }
        let key_id = KeyId::try_from(u32::from_be_bytes([a, b, c, d]))
            .map_err(|_| KeyringError::ValueLayout(ValueLayoutError::ReservedKeyId))?;
        if key_id.purpose() != M::PURPOSE {
            return Err(KeyringError::KeyPurposeMismatch(KeyPurposeMismatchError {
                expected: M::PURPOSE,
                key_id,
            }));
        }
        Ok(Self {
            bytes,
            key_id,
            plaintext: PhantomData,
        })
    }
}

impl<T, M> Clone for Encrypted<T, M> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            key_id: self.key_id,
            plaintext: PhantomData,
        }
    }
}

/// The key id only: neither the bytes nor their length, which is the plaintext's length plus a
/// constant.
impl<T, M> Debug for Encrypted<T, M> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Encrypted")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Compares the bytes in constant time.
impl<T, M> PartialEq for Encrypted<T, M> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<T, M> Eq for Encrypted<T, M> {}

#[cfg(feature = "serde")]
mod encrypted_serde {
    use std::fmt::Formatter;
    use std::marker::PhantomData;

    use serde::de::{Error, SeqAccess, Visitor};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use super::{Encrypted, Mode};

    /// As bytes, through `serialize_bytes`.
    impl<T, M> Serialize for Encrypted<T, M> {
        fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(&self.bytes)
        }
    }

    /// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
    /// `TryFrom<Vec<u8>>` checks them: a malformed stored value fails here, before any decrypt.
    impl<'de, T, M: Mode> Deserialize<'de> for Encrypted<T, M> {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            deserializer.deserialize_bytes(EncryptedVisitor(PhantomData))
        }
    }

    struct EncryptedVisitor<T, M>(PhantomData<fn() -> (T, M)>);

    impl<'de, T, M: Mode> Visitor<'de> for EncryptedVisitor<T, M> {
        type Value = Encrypted<T, M>;

        fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
            formatter.write_str("the bytes of a keyring value")
        }

        fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
            self.visit_byte_buf(bytes.to_vec())
        }

        fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
            Encrypted::try_from(bytes).map_err(E::custom)
        }

        /// Grows the buffer as the bytes arrive: the sequence's length hint comes from the
        /// input, and a hostile one claims any length.
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
            let mut bytes = Vec::new();
            while let Some(byte) = seq.next_element()? {
                bytes.push(byte);
            }
            self.visit_byte_buf(bytes)
        }
    }
}

/// sqlx's PostgreSQL traits, so that a value binds and decodes as a `BYTEA`, and a slice of
/// values as a `BYTEA[]` for `= ANY($1)`. They are a deliberate integration point with sqlx.
#[cfg(feature = "postgres")]
mod encrypted_sqlx {
    use sqlx::encode::IsNull;
    use sqlx::error::BoxDynError;
    use sqlx::postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef};
    use sqlx::{Decode, Encode, Postgres, Type};

    use super::{Encrypted, Mode};

    /// `BYTEA`.
    impl<T, M> Type<Postgres> for Encrypted<T, M> {
        fn type_info() -> PgTypeInfo {
            <Vec<u8> as Type<Postgres>>::type_info()
        }

        fn compatible(ty: &PgTypeInfo) -> bool {
            <Vec<u8> as Type<Postgres>>::compatible(ty)
        }
    }

    /// `BYTEA[]`.
    impl<T, M> PgHasArrayType for Encrypted<T, M> {
        fn array_type_info() -> PgTypeInfo {
            <Vec<u8> as PgHasArrayType>::array_type_info()
        }
    }

    /// The value's bytes.
    impl<T, M> Encode<'_, Postgres> for Encrypted<T, M> {
        fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
            <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
        }
    }

    /// Checked as `TryFrom<Vec<u8>>` checks the bytes: a malformed stored value fails in the
    /// decode, before any decrypt.
    impl<T, M: Mode> Decode<'_, Postgres> for Encrypted<T, M> {
        fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
            Ok(Encrypted::try_from(<Vec<u8> as Decode<Postgres>>::decode(
                value,
            )?)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shortest randomized value: a prefix, a nonce and a tag around an empty plaintext.
    fn randomized_bytes(key_id: u32) -> Vec<u8> {
        let mut bytes = vec![0x01];
        bytes.extend_from_slice(&key_id.to_be_bytes());
        bytes.extend_from_slice(&[0xAB; 12 + 16]);
        bytes
    }

    #[test]
    fn a_value_is_read_back_with_its_key_id() -> KeyringResult<()> {
        let value = Encrypted::<String>::try_from(randomized_bytes(7))?;
        assert_eq!(value.key_id(), KeyId::try_from(7)?);
        assert_eq!(value.as_bytes(), randomized_bytes(7));
        assert_eq!(value.body(), [0xAB; 12 + 16]);
        Ok(())
    }

    #[test]
    fn bytes_without_the_tink_prefix_are_refused() {
        let mut bytes = randomized_bytes(7);
        bytes[0] = 0x00;
        assert!(matches!(
            Encrypted::<String>::try_from(bytes),
            Err(KeyringError::ValueLayout(ValueLayoutError::NoTinkPrefix))
        ));
    }

    #[test]
    fn a_value_shorter_than_an_empty_one_is_refused() {
        let mut randomized = randomized_bytes(7);
        randomized.pop();
        assert!(matches!(
            Encrypted::<String>::try_from(randomized),
            Err(KeyringError::ValueLayout(ValueLayoutError::TooShort(
                Purpose::Randomized
            )))
        ));
        let mut deterministic = vec![0x01, 0x80, 0, 0, 1];
        deterministic.extend_from_slice(&[0xAB; 15]);
        assert!(matches!(
            Encrypted::<String, Deterministic>::try_from(deterministic.clone()),
            Err(KeyringError::ValueLayout(ValueLayoutError::TooShort(
                Purpose::Deterministic
            )))
        ));
        deterministic.push(0xAB);
        assert!(Encrypted::<String, Deterministic>::try_from(deterministic).is_ok());
    }

    #[test]
    fn a_reserved_key_id_is_refused() {
        for key_id in [0, 1 << 31] {
            assert!(matches!(
                Encrypted::<String>::try_from(randomized_bytes(key_id)),
                Err(KeyringError::ValueLayout(ValueLayoutError::ReservedKeyId))
            ));
        }
    }

    #[test]
    fn a_key_id_of_the_other_purpose_is_refused() -> KeyringResult<()> {
        let deterministic_id = 0x8000_0001;
        assert!(matches!(
            Encrypted::<String>::try_from(randomized_bytes(deterministic_id)),
            Err(KeyringError::KeyPurposeMismatch(error))
                if error.expected == Purpose::Randomized && error.key_id == KeyId::try_from(deterministic_id)?
        ));
        assert!(matches!(
            Encrypted::<String, Deterministic>::try_from(randomized_bytes(1)),
            Err(KeyringError::KeyPurposeMismatch(error)) if error.expected == Purpose::Deterministic
        ));
        Ok(())
    }

    #[test]
    fn debug_shows_the_key_id_only() -> KeyringResult<()> {
        let debug = format!("{:?}", Encrypted::<String>::try_from(randomized_bytes(7))?);
        assert!(!debug.contains("171"), "{debug}");
        assert!(!debug.contains("33"), "{debug}");
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_value_round_trips_through_serde_json_as_a_byte_array(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value = Encrypted::<String>::try_from(randomized_bytes(7))?;
        let json = serde_json::to_string(&value)?;
        assert!(json.starts_with("[1,0,0,0,7,171,"), "{json}");
        assert_eq!(serde_json::from_str::<Encrypted<String>>(&json)?, value);
        Ok(())
    }

    /// Bytes whose length hint claims `usize::MAX` elements, as a hostile input can.
    #[cfg(feature = "serde")]
    struct OverstatedLength(std::vec::IntoIter<u8>);

    #[cfg(feature = "serde")]
    impl Iterator for OverstatedLength {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, Some(usize::MAX))
        }
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_sequence_overstating_its_length_deserializes() -> Result<(), Box<dyn std::error::Error>> {
        use serde::de::value::{Error, SeqDeserializer};
        use serde::Deserialize;

        let bytes = OverstatedLength(randomized_bytes(7).into_iter());
        let value = Encrypted::<String>::deserialize(SeqDeserializer::<_, Error>::new(bytes))?;
        assert_eq!(value.as_bytes(), randomized_bytes(7));
        Ok(())
    }

    #[cfg(feature = "serde")]
    #[test]
    fn a_stored_value_of_the_wrong_mode_fails_to_deserialize() -> Result<(), serde_json::Error> {
        let json = serde_json::to_string(&randomized_bytes(1))?;
        assert!(serde_json::from_str::<Encrypted<String, Deterministic>>(&json).is_err());
        Ok(())
    }
}
