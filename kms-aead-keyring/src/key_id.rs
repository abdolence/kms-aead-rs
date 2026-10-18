//! Key ids, the four bytes after the version byte of every keyring value, and the purposes
//! they separate.

use std::fmt::{Display, Formatter};

use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult};

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
impl Purpose {
    /// The length of a value of this purpose around an empty plaintext: the prefix, and a nonce
    /// and a tag for a randomized value, a synthetic IV for a deterministic one.
    pub(crate) fn min_value_len(self) -> usize {
        match self {
            Purpose::Randomized => 5 + 12 + 16,
            Purpose::Deterministic => 5 + 16,
        }
    }
}

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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
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

    /// The id as the record's JSON stores it.
    pub(crate) fn as_u32(self) -> u32 {
        self.0
    }

    /// The id as a keyring value carries it.
    pub(crate) fn to_be_bytes(self) -> [u8; 4] {
        self.0.to_be_bytes()
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
    use proptest::prelude::*;

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

    proptest! {
        #[test]
        fn bit_31_is_the_purpose(id in 1u32..u32::MAX) {
            prop_assume!(id != 1 << 31);
            let key_id = KeyId::try_from(id)?;
            let expected = if id >> 31 == 1 { Purpose::Deterministic } else { Purpose::Randomized };
            prop_assert_eq!(key_id.purpose(), expected);
            if let Some(next) = key_id.next() {
                prop_assert_eq!(next.purpose(), expected);
                prop_assert!(next > key_id);
            }
        }
    }

    #[test]
    fn first_ids_start_each_purpose_at_ordinal_one() {
        assert_eq!(KeyId::first(Purpose::Randomized).as_u32(), 1);
        assert_eq!(KeyId::first(Purpose::Deterministic).as_u32(), 0x8000_0001);
        assert_eq!(
            KeyId::first(Purpose::Deterministic).purpose(),
            Purpose::Deterministic
        );
    }
}
