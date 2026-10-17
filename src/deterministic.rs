//! Deterministic encryption with AES-SIV (RFC 5297), beside the randomized path.

use std::fmt::{Display, Formatter};

/// A deterministic AEAD algorithm: equal inputs under one key give equal values. It exists in
/// every build, so that a keyring record names the algorithm of every version even in a process
/// built without the `deterministic` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeterministicAlgorithm {
    /// AES-SIV (RFC 5297) with a 64-byte key, two AES-256 keys. RFC 5297 names it
    /// AEAD_AES_SIV_CMAC_512; Tink's AES256_SIV template uses it.
    Aes256Siv,
}

impl DeterministicAlgorithm {
    pub fn key_len(self) -> usize {
        match self {
            DeterministicAlgorithm::Aes256Siv => 64,
        }
    }
}

/// `aes-256-siv`: the value of the `/kms_aead/algorithm` span field.
impl Display for DeterministicAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DeterministicAlgorithm::Aes256Siv => "aes-256-siv",
        })
    }
}
