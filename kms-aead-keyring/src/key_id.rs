//! Key ids, the four bytes after the version byte of every keyring value and beacon, and the
//! purposes they separate.

use std::fmt::{Display, Formatter};

use kms_aead::formats::{Deterministic, Randomized, TinkKeyId};
use kms_aead::{Beacon, Encrypted};
use serde::{Deserialize, Serialize};

use crate::errors::{
    Identifier, IdentifierRule, KeyPurposeMismatchError, KeyringError, KeyringResult,
};

/// What a key version is for. A key of one purpose never serves another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Randomised AEAD: a random nonce per value, so equal plaintexts give different values.
    Randomized,
    /// Deterministic AEAD with AES-SIV: under one version, equal plaintexts and AADs give equal
    /// values, which an equality query can match.
    Deterministic,
    /// Beacons: a 32-byte HMAC key, under which equal plaintexts of one field give equal
    /// [`Beacon`]s.
    Beacon,
}

impl Purpose {
    /// Every purpose, for the record's checks per purpose.
    pub(crate) const ALL: [Purpose; 3] =
        [Purpose::Randomized, Purpose::Deterministic, Purpose::Beacon];
}

/// `randomized`, `deterministic`, `beacon`: the values of the `purpose` span field.
impl Display for Purpose {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Purpose::Randomized => "randomized",
            Purpose::Deterministic => "deterministic",
            Purpose::Beacon => "beacon",
        })
    }
}

/// The key id of a key version, which every keyring value and beacon carries big-endian after
/// its version byte. Bits 31 and 30 are the purpose: bit 31 set for deterministic versions, bit
/// 30 for beacon versions, neither for randomised ones. Bits 0 to 29 are the ordinal, from 1,
/// counted per purpose. Randomised versions are therefore `1, 2, 3, …`, deterministic ones
/// `2147483649, 2147483650, …` and beacon ones `1073741825, 1073741826, …`.
///
/// Ids are never reused: a destroyed version keeps its id.
///
/// It serialises as its number, and deserialises through [`TryFrom<u32>`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "u32")]
pub struct KeyId(u32);

impl KeyId {
    const DETERMINISTIC: u32 = 1 << 31;
    const BEACON: u32 = 1 << 30;
    const ORDINAL: u32 = Self::BEACON - 1;

    /// The id of the first version of `purpose`.
    pub(crate) fn first(purpose: Purpose) -> Self {
        match purpose {
            Purpose::Randomized => Self(1),
            Purpose::Deterministic => Self(Self::DETERMINISTIC | 1),
            Purpose::Beacon => Self(Self::BEACON | 1),
        }
    }

    /// The id of the next version of the same purpose, or `None` once the ordinals of the
    /// purpose run out at 2^30 - 1.
    pub(crate) fn next(self) -> Option<Self> {
        (self.0 & Self::ORDINAL != Self::ORDINAL).then(|| Self(self.0 + 1))
    }

    /// The purpose of the version this id names.
    pub fn purpose(self) -> Purpose {
        if self.0 & Self::DETERMINISTIC != 0 {
            Purpose::Deterministic
        } else if self.0 & Self::BEACON != 0 {
            Purpose::Beacon
        } else {
            Purpose::Randomized
        }
    }

    /// The id as a number, as the record's JSON stores it and a query binds it, such as the key
    /// id of a [`SealMarker`](crate::SealMarker) compared against a `BIGINT` column.
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// The id `key_id` names when it is one of `purpose`: the check of a value's or beacon's
    /// prefix before the keyring reads its version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`] when the id is reserved, and
    /// [`KeyringError::KeyPurposeMismatch`] when it is of another purpose.
    fn of_purpose(key_id: TinkKeyId, purpose: Purpose) -> KeyringResult<Self> {
        let key_id = Self::try_from(key_id)?;
        if key_id.purpose() != purpose {
            return Err(KeyringError::KeyPurposeMismatch(KeyPurposeMismatchError {
                expected: purpose,
                key_id,
            }));
        }
        Ok(key_id)
    }
}

/// The version a randomised value names in its prefix, such as for a
/// [`SealMarker`](crate::SealMarker).
///
/// # Errors
///
/// [`KeyringError::ReservedKeyId`] when the key id is reserved, and
/// [`KeyringError::KeyPurposeMismatch`] when it is not a randomised key id.
impl<T> TryFrom<&Encrypted<T, Randomized>> for KeyId {
    type Error = KeyringError;

    fn try_from(value: &Encrypted<T, Randomized>) -> KeyringResult<Self> {
        Self::of_purpose(value.key_id(), Purpose::Randomized)
    }
}

/// The version a deterministic value names in its prefix.
///
/// # Errors
///
/// As for a randomised value, with a key id that is not a deterministic one.
impl<T> TryFrom<&Encrypted<T, Deterministic>> for KeyId {
    type Error = KeyringError;

    fn try_from(value: &Encrypted<T, Deterministic>) -> KeyringResult<Self> {
        Self::of_purpose(value.key_id(), Purpose::Deterministic)
    }
}

/// The version a beacon names in its prefix.
///
/// # Errors
///
/// As for a randomised value, with a key id that is not a beacon one.
impl<T> TryFrom<&Beacon<T>> for KeyId {
    type Error = KeyringError;

    fn try_from(beacon: &Beacon<T>) -> KeyringResult<Self> {
        Self::of_purpose(beacon.key_id(), Purpose::Beacon)
    }
}

impl TryFrom<u32> for KeyId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] with [`IdentifierRule::Reserved`] for an id whose
    /// ordinal is zero, such as 0, 2^31 and 2^30, and for an id with both purpose bits set.
    fn try_from(id: u32) -> KeyringResult<Self> {
        let both_purposes = Self::DETERMINISTIC | Self::BEACON;
        if id & Self::ORDINAL == 0 || id & both_purposes == both_purposes {
            return Err(KeyringError::invalid_identifier(
                Identifier::KeyId,
                IdentifierRule::Reserved,
            ));
        }
        Ok(Self(id))
    }
}

/// The id in a value's prefix, read by the keyring's rules, as kms-aead's calls return it.
///
/// # Errors
///
/// [`KeyringError::ReservedKeyId`] for an id whose ordinal is zero, or that sets both purpose
/// bits: no version has it.
impl TryFrom<TinkKeyId> for KeyId {
    type Error = KeyringError;

    fn try_from(key_id: TinkKeyId) -> KeyringResult<Self> {
        Self::try_from(key_id.as_u32()).map_err(|_| KeyringError::ReservedKeyId)
    }
}

/// The id kms-aead writes into the prefix of the version's values and beacons, and into a
/// keyset.
impl From<KeyId> for TinkKeyId {
    fn from(key_id: KeyId) -> Self {
        TinkKeyId::new(key_id.0)
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
    fn ordinal_zero_and_two_purpose_bits_are_refused() {
        for id in [0, 1 << 31, 1 << 30, (3 << 30) | 1] {
            assert!(matches!(
                KeyId::try_from(id),
                Err(KeyringError::InvalidIdentifier(error))
                    if error.identifier == Identifier::KeyId && error.rule == IdentifierRule::Reserved
            ));
        }
    }

    #[test]
    fn the_last_ordinal_of_each_purpose_has_no_next() -> KeyringResult<()> {
        for last in [(1 << 30) - 1, (1 << 31) | ((1 << 30) - 1), u32::MAX >> 1] {
            assert_eq!(KeyId::try_from(last)?.next(), None);
        }
        Ok(())
    }

    #[test]
    fn the_purpose_bits_separate_the_purposes() -> KeyringResult<()> {
        for purpose in Purpose::ALL {
            let first = KeyId::first(purpose);
            assert_eq!(first.purpose(), purpose);
            assert_eq!(first.next().map(KeyId::purpose), Some(purpose));
        }
        Ok(())
    }
}
