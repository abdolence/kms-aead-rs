use std::fmt::{Display, Formatter};

/// A randomized AEAD algorithm. Values are `[nonce][ciphertext][tag]`, with a 12-byte random
/// nonce from the backend's CSPRNG and a 16-byte tag, and do not depend on which backend sealed
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (RFC 8439). The default of
    /// [`KmsAeadEnvelope::new`](crate::KmsAeadEnvelope::new).
    ChaCha20Poly1305,
    /// AES-GCM with a 16-byte key.
    Aes128Gcm,
    /// AES-GCM with a 32-byte key.
    Aes256Gcm,
    /// AES-GCM-SIV (RFC 8452) with a 32-byte key.
    Aes256GcmSiv,
}

impl AeadAlgorithm {
    /// Every algorithm writes this tag after the cipher text.
    pub(crate) const TAG_LEN: usize = 16;

    /// Every algorithm takes a nonce of this length.
    pub(crate) const NONCE_LEN: usize = 12;

    /// The length of a data encryption key for this algorithm, in bytes.
    pub fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => 32,
        }
    }

    /// The length of the nonce at the start of every value, in bytes.
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
