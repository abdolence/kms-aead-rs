use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};

/// A randomised AEAD algorithm. Values are `[nonce][ciphertext][tag]`, with a 12-byte random
/// nonce from the backend's CSPRNG and a 16-byte tag, and do not depend on which backend encrypted
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadAlgorithm {
    /// ChaCha20-Poly1305 (RFC 8439). The default of
    /// [`KmsAeadEnvelope::new`](crate::KmsAeadEnvelope::new) before 0.30.
    ChaCha20Poly1305,
    /// AES-GCM with a 16-byte key.
    Aes128Gcm,
    /// AES-GCM with a 32-byte key. The default of
    /// [`KmsAeadEnvelope::new`](crate::KmsAeadEnvelope::new).
    Aes256Gcm,
    /// AES-GCM-SIV (RFC 8452) with a 32-byte key.
    Aes256GcmSiv,
}

impl AeadAlgorithm {
    /// Every algorithm, for the tests that cover each.
    #[cfg(test)]
    pub(crate) const ALL: [AeadAlgorithm; 4] = [
        AeadAlgorithm::ChaCha20Poly1305,
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes256Gcm,
        AeadAlgorithm::Aes256GcmSiv,
    ];

    /// Every algorithm writes this tag after the cipher text.
    pub(crate) const TAG_LEN: usize = 16;

    /// Every algorithm takes a nonce of this length.
    pub(crate) const NONCE_LEN: usize = 12;

    /// The name [`Display`] writes, such as `aes-256-gcm`.
    pub fn as_str(self) -> &'static str {
        match self {
            AeadAlgorithm::ChaCha20Poly1305 => "chacha20-poly1305",
            AeadAlgorithm::Aes128Gcm => "aes-128-gcm",
            AeadAlgorithm::Aes256Gcm => "aes-256-gcm",
            AeadAlgorithm::Aes256GcmSiv => "aes-256-gcm-siv",
        }
    }

    /// The length of a data encryption key for this algorithm, in bytes.
    pub fn key_len(self) -> usize {
        match self {
            AeadAlgorithm::Aes128Gcm => 16,
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => 32,
        }
    }
}

/// `chacha20-poly1305`, `aes-128-gcm`, `aes-256-gcm`, `aes-256-gcm-siv`: the values of the
/// `/kms_aead/algorithm` span field.
impl Display for AeadAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for AeadAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "chacha20-poly1305" => Ok(AeadAlgorithm::ChaCha20Poly1305),
            "aes-128-gcm" => Ok(AeadAlgorithm::Aes128Gcm),
            "aes-256-gcm" => Ok(AeadAlgorithm::Aes256Gcm),
            "aes-256-gcm-siv" => Ok(AeadAlgorithm::Aes256GcmSiv),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of an AEAD algorithm: the names are chacha20-poly1305, aes-128-gcm, \
                 aes-256-gcm and aes-256-gcm-siv",
            )),
        }
    }
}

/// A public-key algorithm an asymmetric KEK encrypts data encryption keys with: the public half of
/// a KMS key pair encrypts each DEK in the producer's process, and the KMS decrypts it with the
/// private half, see [`AsymmetricKekPublicKey`](crate::AsymmetricKekPublicKey).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AsymmetricKekAlgorithm {
    /// RSAES-OAEP (RFC 8017), RSA encryption with Optimal Asymmetric Encryption Padding, with
    /// SHA-256 as the OAEP hash and the MGF1 hash and an empty label, under an RSA key of 2048,
    /// 3072 or 4096 bits: the asymmetric decryption of Cloud KMS, AWS KMS, Key Vault and Vault
    /// Transit. 3072 bits is the size for a new key; 2048 bits is deprecated and stays for the
    /// keys that exist.
    RsaOaepSha256,
}

impl AsymmetricKekAlgorithm {
    /// The name [`Display`] writes: `rsa-oaep-sha256`.
    pub fn as_str(self) -> &'static str {
        match self {
            AsymmetricKekAlgorithm::RsaOaepSha256 => "rsa-oaep-sha256",
        }
    }
}

/// `rsa-oaep-sha256`.
impl Display for AsymmetricKekAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for AsymmetricKekAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "rsa-oaep-sha256" => Ok(AsymmetricKekAlgorithm::RsaOaepSha256),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of an asymmetric KEK algorithm: the name is rsa-oaep-sha256",
            )),
        }
    }
}

/// An algorithm a backend implements, or does not: the
/// [`algorithm`](crate::errors::KmsAeadUnsupportedAlgorithmError::algorithm) of
/// [`KmsAeadUnsupportedAlgorithmError`](crate::errors::KmsAeadUnsupportedAlgorithmError).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BackendAlgorithm {
    /// An AEAD algorithm, such as AES-256-GCM-SIV on ring.
    Aead(AeadAlgorithm),
    /// An asymmetric KEK algorithm, such as RSA-OAEP on ring.
    AsymmetricKek(AsymmetricKekAlgorithm),
}

impl From<AeadAlgorithm> for BackendAlgorithm {
    fn from(algorithm: AeadAlgorithm) -> Self {
        BackendAlgorithm::Aead(algorithm)
    }
}

impl From<AsymmetricKekAlgorithm> for BackendAlgorithm {
    fn from(algorithm: AsymmetricKekAlgorithm) -> Self {
        BackendAlgorithm::AsymmetricKek(algorithm)
    }
}

/// The inner algorithm's name, such as `aes-256-gcm-siv` or `rsa-oaep-sha256`.
impl Display for BackendAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BackendAlgorithm::Aead(algorithm) => algorithm.fmt(f),
            BackendAlgorithm::AsymmetricKek(algorithm) => algorithm.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KmsAeadResult;

    #[test]
    fn every_name_parses_back_and_another_name_is_refused() -> KmsAeadResult<()> {
        for algorithm in AeadAlgorithm::ALL {
            assert_eq!(algorithm.to_string().parse::<AeadAlgorithm>()?, algorithm);
        }
        let rsa = AsymmetricKekAlgorithm::RsaOaepSha256;
        assert_eq!(rsa.to_string().parse::<AsymmetricKekAlgorithm>()?, rsa);
        for unknown in [
            "aes-512-gcm".parse::<AeadAlgorithm>().err(),
            "rsa-oaep-sha1".parse::<AsymmetricKekAlgorithm>().err(),
        ] {
            assert!(
                matches!(&unknown, Some(e) if e.code() == "UNKNOWN_ALGORITHM"),
                "{unknown:?}"
            );
        }
        Ok(())
    }
}
