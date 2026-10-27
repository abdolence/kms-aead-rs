//! Signatures with an asymmetric key a KMS or the process holds, verified without a KMS on any
//! backend.
//!
//! A [`Signer`] signs a [`Signable`](crate::Signable) value through a [`KmsSigningProvider`]: one
//! provider call over the pre-image, DSSE's Pre-Authentication Encoding (PAE) of the type's
//! [`SignedPayloadType`](crate::SignedPayloadType) and the SHA-256 of the payload, 46 to 302
//! bytes whatever the payload. A [`Verifier`] checks a [`Signature`] or a [`Signed`] value
//! against a [`VerifyingKeySet`], the public keys it trusts, with no KMS and no secret.
//!
//! ```text
//! detached: [0x01][key id: u32 BE][signature]
//! attached: [0x01][key id: u32 BE][w: u16 BE][signature: w][payload]
//! ```
//!
//! The key id of a signing key is the first four bytes of its RFC 7638 thumbprint, or an id the
//! publisher sets. It is not authenticated: it selects the one key of the set the verifier tries.
//! The providers are in [`providers`](crate::providers): the local KMS in every build, and Google
//! Cloud KMS, AWS KMS, Azure Key Vault and Vault Transit with their features. The book's
//! [Signatures and MACs](https://kms-aead-rust.abdolence.dev/signing.html) chapter walks through
//! them.
//!
//! ```rust
//! # #[cfg(feature = "ring")]
//! # async fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::backends::Ring;
//! use kms_aead::providers::{LocalSigningKeyName, LocalSigningProvider};
//! use kms_aead::signing::{Signer, SigningAlgorithm, Verifier, VerifyingKeySet};
//! use kms_aead::{JsonEncoded, SignableType, SignedPayloadType};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize)]
//! struct Invoice {
//!     number: String,
//!     customer: String,
//!     currency: String,
//!     total_cents: u64,
//! }
//!
//! impl SignableType for Invoice {
//!     const PAYLOAD_TYPE: SignedPayloadType =
//!         SignedPayloadType::from_static("application/vnd.example.invoice+json");
//! }
//!
//! let provider = LocalSigningProvider::<Ring>::ephemeral(
//!     LocalSigningKeyName::try_from("invoices".to_string())?,
//!     SigningAlgorithm::Ed25519,
//! )?;
//! let signer = Signer::<_, Ring>::new(provider).await?;
//! let verifier = Verifier::<Ring>::new(VerifyingKeySet::new([signer.verifying_key().clone()])?)?;
//!
//! let invoice = JsonEncoded::new(Invoice {
//!     number: "INV-1042".into(),
//!     customer: "Northwind Traders".into(),
//!     currency: "EUR".into(),
//!     total_cents: 12_500,
//! });
//! let signature = signer.sign(&invoice).await?;
//!
//! assert_eq!(verifier.verify(&invoice, &signature)?, signer.verifying_key());
//! # Ok(())
//! # }
//! ```

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};

pub(crate) mod private_key;

mod provider;
pub use provider::{KmsSigningProvider, RawSignature, SigningInput, SigningKeyRef};

mod signer;
pub use signer::Signer;

mod verifier;
pub use verifier::Verifier;

mod verifying_key;
pub use verifying_key::{JwkThumbprint, VerifyingKey, VerifyingKeySet};

pub use crate::integrity::{Signature, Signed};

/// A signature algorithm. Every signature is 64 bytes, as `r || s` for ECDSA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    /// Ed25519 (RFC 8032), PureEdDSA over the pre-image.
    Ed25519,
    /// ECDSA on P-256 with SHA-256 over the pre-image.
    EcdsaP256Sha256,
}

impl SigningAlgorithm {
    /// `ed25519` or `ecdsa-p256-sha256`: the name [`Display`] writes and the `algorithm` span
    /// field.
    pub fn as_str(self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        }
    }

    /// 64 for both: Ed25519's signature, and `r || s` of 32 bytes each for P-256.
    pub fn signature_len(self) -> usize {
        match self {
            SigningAlgorithm::Ed25519 | SigningAlgorithm::EcdsaP256Sha256 => 64,
        }
    }

    /// 32 for Ed25519, 65 for P-256: the uncompressed point.
    pub fn public_key_len(self) -> usize {
        match self {
            SigningAlgorithm::Ed25519 => 32,
            SigningAlgorithm::EcdsaP256Sha256 => 65,
        }
    }

    /// `EdDSA` or `ES256`: the JWK `alg`.
    pub fn jwk_alg(self) -> &'static str {
        match self {
            SigningAlgorithm::Ed25519 => "EdDSA",
            SigningAlgorithm::EcdsaP256Sha256 => "ES256",
        }
    }
}

/// `ed25519` or `ecdsa-p256-sha256`.
impl Display for SigningAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for SigningAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "ed25519" => Ok(SigningAlgorithm::Ed25519),
            "ecdsa-p256-sha256" => Ok(SigningAlgorithm::EcdsaP256Sha256),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of a signature algorithm: the names are ed25519 and \
                 ecdsa-p256-sha256",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_parses_back_and_another_name_is_refused() {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            assert_eq!(
                algorithm.as_str().parse::<SigningAlgorithm>().ok(),
                Some(algorithm)
            );
        }
        let unknown = "ecdsa-p384-sha384".parse::<SigningAlgorithm>();
        assert!(
            matches!(&unknown, Err(error) if error.code() == "UNKNOWN_ALGORITHM"),
            "{unknown:?}"
        );
    }
}
