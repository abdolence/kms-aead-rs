//! Key ids, the four bytes after the version byte of every keyring value, and the purposes
//! they separate.

use std::fmt::{Display, Formatter};

use kms_aead::formats::{Deterministic, Randomized, TinkOutputPrefix};
use kms_aead::{Encrypted, ValueStruct};
use serde::{Deserialize, Serialize};

use crate::errors::{
    Identifier, IdentifierRule, KeyPurposeMismatchError, KeyringError, KeyringResult,
    ValueLayoutError,
};

/// What a key version is for. A data encryption key of one purpose never serves the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Randomized AEAD: a random nonce per value, so equal plaintexts give different values.
    Randomized,
    /// Deterministic AEAD with AES-SIV: under one version, equal plaintexts and AADs give equal
    /// values, which an equality query can match.
    Deterministic,
}

/// `randomized`, `deterministic`: the values of the `purpose` span field.
impl Display for Purpose {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Purpose::Randomized => "randomized",
            Purpose::Deterministic => "deterministic",
        })
    }
}

/// The key id of a key version, which every keyring value carries big-endian after its version
/// byte. Bit 31 is the purpose, set for deterministic versions; bits 0 to 30 are the ordinal,
/// from 1, counted per purpose. Randomized versions are therefore `1, 2, 3, …` and
/// deterministic ones `2147483649, 2147483650, …`.
///
/// Ids are never reused: a destroyed version keeps its id.
///
/// It serializes as its number, and deserializes through [`TryFrom<u32>`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32")]
pub struct KeyId(u32);

impl KeyId {
    const DETERMINISTIC: u32 = 1 << 31;
    const ORDINAL: u32 = Self::DETERMINISTIC - 1;

    /// The id of the first version of `purpose`.
    pub(crate) fn first(purpose: Purpose) -> Self {
        match purpose {
            Purpose::Randomized => Self(1),
            Purpose::Deterministic => Self(Self::DETERMINISTIC | 1),
        }
    }

    /// The id of the next version of the same purpose, or `None` once the ordinals of the
    /// purpose run out at 2^31 - 1.
    pub(crate) fn next(self) -> Option<Self> {
        (self.0 & Self::ORDINAL != Self::ORDINAL).then(|| Self(self.0 + 1))
    }

    /// The purpose of the version this id names.
    pub fn purpose(self) -> Purpose {
        if self.0 & Self::DETERMINISTIC == 0 {
            Purpose::Randomized
        } else {
            Purpose::Deterministic
        }
    }

    /// The id as a number, as the record's JSON stores it and a query binds it, such as the key
    /// id of a [`SealMarker`](crate::SealMarker) compared against a `BIGINT` column.
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// The bytes of a value under this version: Tink's output prefix of this id, then `body`.
    pub(crate) fn prefixed(self, body: &[u8]) -> Vec<u8> {
        [&TinkOutputPrefix::new(self.0).to_bytes()[..], body].concat()
    }

    /// The key id of `value`, a value of `purpose` in Tink's TINK-prefixed layout, and the
    /// bytes after the prefix.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ValueLayout`] when `value` does not start with the prefix or its key id
    /// is reserved, and [`KeyringError::KeyPurposeMismatch`] when the key id is of another
    /// purpose.
    pub(crate) fn split_value(value: &[u8], purpose: Purpose) -> KeyringResult<(Self, &[u8])> {
        let (prefix, body) = TinkOutputPrefix::split(value)
            .ok_or(KeyringError::ValueLayout(ValueLayoutError::NoTinkPrefix))?;
        let key_id = Self::try_from(prefix.key_id())
            .map_err(|_| KeyringError::ValueLayout(ValueLayoutError::ReservedKeyId))?;
        if key_id.purpose() != purpose {
            return Err(KeyringError::KeyPurposeMismatch(KeyPurposeMismatchError {
                expected: purpose,
                key_id,
            }));
        }
        Ok((key_id, body))
    }
}

/// The version a randomized value names in its prefix, such as for a
/// [`SealMarker`](crate::SealMarker).
///
/// # Errors
///
/// [`KeyringError::ValueLayout`] when the key id is 0 or 2^31, and
/// [`KeyringError::KeyPurposeMismatch`] when it is not a randomized key id.
impl<T> TryFrom<&Encrypted<T, Randomized>> for KeyId {
    type Error = KeyringError;

    fn try_from(value: &Encrypted<T, Randomized>) -> KeyringResult<Self> {
        Self::split_value(value.value(), Purpose::Randomized).map(|(key_id, _)| key_id)
    }
}

/// The version a deterministic value names in its prefix.
///
/// # Errors
///
/// As for a randomized value, with a key id that is not a deterministic one.
impl<T> TryFrom<&Encrypted<T, Deterministic>> for KeyId {
    type Error = KeyringError;

    fn try_from(value: &Encrypted<T, Deterministic>) -> KeyringResult<Self> {
        Self::split_value(value.value(), Purpose::Deterministic).map(|(key_id, _)| key_id)
    }
}

impl TryFrom<u32> for KeyId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] with [`IdentifierRule::Reserved`] for 0 and
    /// 2^31, whose ordinal is zero.
    fn try_from(id: u32) -> KeyringResult<Self> {
        if id & Self::ORDINAL == 0 {
            return Err(KeyringError::invalid_identifier(
                Identifier::KeyId,
                IdentifierRule::Reserved,
            ));
        }
        Ok(Self(id))
    }
}

/// The decimal id, as the record and the spans show it.
impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_zero_is_refused_for_both_purposes() {
        for id in [0, 1 << 31] {
            assert!(matches!(
                KeyId::try_from(id),
                Err(KeyringError::InvalidIdentifier(error))
                    if error.identifier == Identifier::KeyId && error.rule == IdentifierRule::Reserved
            ));
        }
    }

    #[test]
    fn the_last_ordinal_has_no_next() -> KeyringResult<()> {
        assert_eq!(KeyId::try_from(u32::MAX >> 1)?.next(), None);
        assert_eq!(KeyId::try_from(u32::MAX)?.next(), None);
        Ok(())
    }
}
