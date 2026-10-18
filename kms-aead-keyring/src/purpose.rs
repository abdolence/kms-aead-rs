//! The purposes of key versions, and how the keyring numbers the [`KeyId`]s of each.
//!
//! The keyring reads a key id's purpose from its two high bits: bit 31 set for deterministic
//! versions, bit 30 for beacon versions, neither for randomised ones. Bits 0 to 29 are the
//! ordinal, from 1, counted per purpose. Randomised versions are therefore `1, 2, 3, …`,
//! deterministic ones `2147483649, 2147483650, …` and beacon ones `1073741825, 1073741826, …`.
//! An id whose ordinal is zero, or that sets both purpose bits, is reserved: no version has it.
//! Ids are never reused: a destroyed version keeps its id.

use std::fmt::{Display, Formatter};

use kms_aead::KeyId;

use crate::errors::{KeyPurposeMismatchError, KeyringError, KeyringResult};

const DETERMINISTIC_KEY_ID_BIT: u32 = 1 << 31;
const BEACON_KEY_ID_BIT: u32 = 1 << 30;
const KEY_ID_ORDINAL_MASK: u32 = BEACON_KEY_ID_BIT - 1;

/// What a key version is for. A key of one purpose never serves another.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// Randomised AEAD: a random nonce per value, so equal plaintexts give different values.
    Randomized,
    /// Deterministic AEAD with AES-SIV: under one version, equal plaintexts and AADs give equal
    /// values, which an equality query can match.
    Deterministic,
    /// Beacons: a 32-byte HMAC key, under which equal plaintexts of one field give equal
    /// [`Beacon`](kms_aead::Beacon)s.
    Beacon,
}

impl Purpose {
    /// Every purpose, for the record's checks per purpose.
    pub(crate) const ALL: [Purpose; 3] =
        [Purpose::Randomized, Purpose::Deterministic, Purpose::Beacon];

    /// The purpose `key_id`'s bits name. A reserved id with both bits set reads as
    /// deterministic, so callers check [`is_reserved`] first where the id is not a version's.
    pub(crate) fn of(key_id: KeyId) -> Self {
        let id = key_id.as_u32();
        if id & DETERMINISTIC_KEY_ID_BIT != 0 {
            Purpose::Deterministic
        } else if id & BEACON_KEY_ID_BIT != 0 {
            Purpose::Beacon
        } else {
            Purpose::Randomized
        }
    }

    /// The key id of the first version of this purpose.
    pub(crate) fn first_key_id(self) -> KeyId {
        KeyId::new(match self {
            Purpose::Randomized => 1,
            Purpose::Deterministic => DETERMINISTIC_KEY_ID_BIT | 1,
            Purpose::Beacon => BEACON_KEY_ID_BIT | 1,
        })
    }

    /// `key_id` when it can name a version of this purpose: the check of a value's or beacon's
    /// prefix before the keyring reads its record.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`] when the id is reserved, and
    /// [`KeyringError::KeyPurposeMismatch`] when it is of another purpose.
    pub(crate) fn check(self, key_id: KeyId) -> KeyringResult<KeyId> {
        let key_id = unreserved(key_id)?;
        if Purpose::of(key_id) != self {
            return Err(KeyringError::KeyPurposeMismatch(KeyPurposeMismatchError {
                expected: self,
                key_id,
            }));
        }
        Ok(key_id)
    }
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

/// Whether no version can have `key_id`: its ordinal is zero, or it sets both purpose bits.
pub(crate) fn is_reserved(key_id: KeyId) -> bool {
    let id = key_id.as_u32();
    id & KEY_ID_ORDINAL_MASK == 0
        || id & (DETERMINISTIC_KEY_ID_BIT | BEACON_KEY_ID_BIT)
            == DETERMINISTIC_KEY_ID_BIT | BEACON_KEY_ID_BIT
}

/// `key_id` when it is not reserved: the check of an id a caller names before the keyring reads
/// its record.
///
/// # Errors
///
/// [`KeyringError::ReservedKeyId`] when it is.
pub(crate) fn unreserved(key_id: KeyId) -> KeyringResult<KeyId> {
    if is_reserved(key_id) {
        return Err(KeyringError::ReservedKeyId);
    }
    Ok(key_id)
}

/// The key id of the version after `key_id` in its purpose, or `None` once the ordinals of the
/// purpose run out at 2^30 - 1.
pub(crate) fn next_key_id(key_id: KeyId) -> Option<KeyId> {
    let id = key_id.as_u32();
    (id & KEY_ID_ORDINAL_MASK != KEY_ID_ORDINAL_MASK).then(|| KeyId::new(id + 1))
}

/// Serde for an optional key id as a number or `null`, which refuses a reserved id on read.
pub(crate) mod optional_key_id {
    use kms_aead::KeyId;
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::errors::{Identifier, IdentifierRule, KeyringError};

    pub(crate) fn serialize<S: Serializer>(
        key_id: &Option<KeyId>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        key_id.map(KeyId::as_u32).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<KeyId>, D::Error> {
        Option::<u32>::deserialize(deserializer)?
            .map(KeyId::new)
            .map(|key_id| {
                if super::is_reserved(key_id) {
                    return Err(D::Error::custom(KeyringError::invalid_identifier(
                        Identifier::KeyId,
                        IdentifierRule::Reserved,
                    )));
                }
                Ok(key_id)
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinal_zero_and_two_purpose_bits_are_reserved() {
        for id in [0, 1 << 31, 1 << 30, (3 << 30) | 1] {
            assert!(matches!(
                unreserved(KeyId::new(id)),
                Err(KeyringError::ReservedKeyId)
            ));
        }
    }

    #[test]
    fn the_last_ordinal_of_each_purpose_has_no_next() {
        for last in [(1 << 30) - 1, (1 << 31) | ((1 << 30) - 1), u32::MAX >> 1] {
            assert_eq!(next_key_id(KeyId::new(last)), None);
        }
    }

    #[test]
    fn the_purpose_bits_separate_the_purposes() {
        for purpose in Purpose::ALL {
            let first = purpose.first_key_id();
            assert_eq!(Purpose::of(first), purpose);
            assert_eq!(next_key_id(first).map(Purpose::of), Some(purpose));
        }
    }
}
