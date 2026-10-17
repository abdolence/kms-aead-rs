use std::fmt::{Display, Formatter};

/// A randomized AEAD algorithm. Values are `[nonce][ciphertext][tag]`, with a random nonce from
/// the backend's CSPRNG, and do not depend on which backend sealed them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// RFC 8439. The default of `KmsAeadEnvelope::new`, as in every earlier release.
    ChaCha20Poly1305,
    Aes128Gcm,
    Aes256Gcm,
    /// RFC 8452.
    Aes256GcmSiv,
}

impl AeadAlgorithm {
    /// Every algorithm writes this tag after the cipher text.
    pub(crate) const TAG_LEN: usize = 16;

    /// Every algorithm takes a nonce of this length.
    pub(crate) const NONCE_LEN: usize = 12;

    pub fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => 32,
        }
    }

    pub fn nonce_len(self) -> usize {
        Self::NONCE_LEN
    }
}

/// `chacha20-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `aes-256-gcm-siv`: the values of the
/// `/kms_aead/algorithm` span field.
impl Display for AeadAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AeadAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            AeadAlgorithm::Aes128Gcm => "aes-128-gcm",
            AeadAlgorithm::Aes256Gcm => "aes-256-gcm",
            AeadAlgorithm::Aes256GcmSiv => "aes-256-gcm-siv",
        })
    }
}
