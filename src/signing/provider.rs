use std::fmt::{Debug, Display, Formatter};
use std::future::Future;

use der::asn1::UintRef;
use der::{Decode, Sequence};

use super::{SigningAlgorithm, VerifyingKey};
use crate::errors::{KmsAeadError, KmsAeadSignatureError};
use crate::{KmsAeadResult, KmsProvider};

/// Signs with one asymmetric key version held by a KMS, or by the process. An application
/// implements it for a KMS of its own, with the rules of
/// [`KmsAeadEncryptionProvider`](crate::KmsAeadEncryptionProvider): write each method that
/// returns a future as an `async fn` whose future is `Send`, and put no key material or signature
/// bytes in its errors. Signers are generic over their provider: the trait has no `dyn` form.
///
/// The name carries no `KmsAead` prefix, since the prefix names the crate's AEAD facade and its
/// errors, and a signing provider is not an AEAD.
pub trait KmsSigningProvider: Send + Sync {
    /// The key and version this provider signs with. A provider of a KMS of its own names it with
    /// [`KmsProvider::Other`] and a key name that identifies the version across every KMS
    /// instance it may address.
    fn signing_key(&self) -> &SigningKeyRef;

    /// The algorithm of the key, as configured; [`verifying_key`](Self::verifying_key) confirms
    /// it.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Signs `input`, as [`Signer`](super::Signer) builds it for the algorithm: the pre-image for
    /// Ed25519, and both the pre-image and its SHA-256 for ECDSA P-256, so that a provider takes
    /// whichever form its KMS or library signs. Returns the raw signature, converted from the
    /// KMS's encoding, such as with [`RawSignature::from_ecdsa_p256_der`].
    ///
    /// # Errors
    ///
    /// The KMS's error with its code, `SIGNATURE_ENCODING` for a signature not in the expected
    /// encoding or failing a checksum, `SIGNING_KEY_MISMATCH` for a response that names another
    /// key or version.
    fn sign(
        &self,
        input: SigningInput<'_>,
    ) -> impl Future<Output = KmsAeadResult<RawSignature>> + Send;

    /// The public key of the configured version, from the KMS.
    ///
    /// # Errors
    ///
    /// The KMS's error, `INVALID_PUBLIC_KEY` when the key does not parse,
    /// `SIGNING_ALGORITHM_MISMATCH` when it is not of [`algorithm`](Self::algorithm).
    fn verifying_key(&self) -> impl Future<Output = KmsAeadResult<VerifyingKey>> + Send;
}

/// What a signing provider is asked to sign, per algorithm.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum SigningInput<'a> {
    /// Ed25519 signs the pre-image as it is.
    Ed25519 {
        /// The pre-image, 46 to 302 bytes.
        pre_image: &'a [u8],
    },
    /// ECDSA P-256 with SHA-256: the pre-image and its SHA-256. A KMS takes `digest`. A key pair on
    /// ring or aws-lc-rs takes `pre_image`, since their `sign` hashes its input and would hash a
    /// digest a second time; p256 takes `digest` through `sign_prehash`.
    EcdsaP256Sha256 {
        /// The pre-image, 46 to 302 bytes.
        pre_image: &'a [u8],
        /// The SHA-256 of `pre_image`.
        digest: &'a [u8; 32],
    },
}

impl SigningInput<'_> {
    /// The algorithm the input is for.
    pub(crate) fn algorithm(&self) -> SigningAlgorithm {
        match self {
            SigningInput::Ed25519 { .. } => SigningAlgorithm::Ed25519,
            SigningInput::EcdsaP256Sha256 { .. } => SigningAlgorithm::EcdsaP256Sha256,
        }
    }

    /// Refuses an input that is not for `algorithm`, the algorithm of `signing_key`, before any
    /// request is sent: a KMS would sign the wrong form of the data, or refuse it with an error
    /// that names neither algorithm.
    ///
    /// # Errors
    ///
    /// `SIGNING_ALGORITHM_MISMATCH`.
    pub(crate) fn ensure_algorithm(
        &self,
        signing_key: &SigningKeyRef,
        algorithm: SigningAlgorithm,
    ) -> KmsAeadResult<()> {
        if self.algorithm() == algorithm {
            Ok(())
        } else {
            Err(self.algorithm_mismatch(signing_key, algorithm))
        }
    }

    /// The `SIGNING_ALGORITHM_MISMATCH` of this input for `signing_key`, a key of `algorithm`.
    pub(crate) fn algorithm_mismatch(
        &self,
        signing_key: &SigningKeyRef,
        algorithm: SigningAlgorithm,
    ) -> KmsAeadError {
        KmsAeadSignatureError::create(
            "SIGNING_ALGORITHM_MISMATCH",
            &format!(
                "The signing key {signing_key} is a key of {algorithm}, not of {}",
                self.algorithm()
            ),
        )
    }
}

/// A signature in the raw form of its algorithm, as a provider returns it: the 64 bytes of
/// Ed25519, or `r || s` of P-256, each left-padded to 32 bytes. `Debug` shows the length.
#[derive(Clone)]
pub struct RawSignature(Vec<u8>);

/// `ECDSA-Sig-Value` of RFC 3279: the two integers of an ECDSA signature in DER.
#[derive(Sequence)]
struct EcdsaSigValue<'a> {
    r: UintRef<'a>,
    s: UintRef<'a>,
}

impl RawSignature {
    /// The length of a P-256 scalar, each half of `r || s`.
    const P256_SCALAR_LEN: usize = 32;

    /// `bytes` as a signature of `algorithm`.
    ///
    /// # Errors
    ///
    /// `SIGNATURE_ENCODING` when `bytes` is not `algorithm`'s signature length.
    pub fn new(algorithm: SigningAlgorithm, bytes: Vec<u8>) -> KmsAeadResult<Self> {
        if bytes.len() == algorithm.signature_len() {
            Ok(Self(bytes))
        } else {
            Err(KmsAeadSignatureError::create(
                "SIGNATURE_ENCODING",
                &format!(
                    "A signature of {} bytes is not one of {algorithm}, which is {} bytes",
                    bytes.len(),
                    algorithm.signature_len()
                ),
            ))
        }
    }

    /// A strict DER `ECDSA-Sig-Value` of P-256 as `r || s`, parsed with the `der` crate, for a
    /// KMS that returns DER.
    ///
    /// # Errors
    ///
    /// `SIGNATURE_ENCODING` on a BER length, a negative integer, an integer of more than 32
    /// significant bytes, a leading `0x00` before a byte under `0x80`, or trailing bytes. A
    /// 33-byte integer whose first byte is `0x00` before a byte of `0x80` or more is valid and
    /// converts to its 32 significant bytes; a shorter integer is left-padded with zeros.
    pub fn from_ecdsa_p256_der(der: &[u8]) -> KmsAeadResult<Self> {
        let invalid = |reason: &str| {
            KmsAeadSignatureError::create(
                "SIGNATURE_ENCODING",
                &format!("A DER ECDSA signature of {} bytes {reason}", der.len()),
            )
        };
        let value = EcdsaSigValue::from_der(der)
            .map_err(|error| invalid(&format!("is not strict DER: {}", error.kind())))?;
        let mut bytes = [[0; Self::P256_SCALAR_LEN]; 2];
        for (half, integer) in bytes.iter_mut().zip([value.r, value.s]) {
            let significant = integer.as_bytes();
            let significant = &significant[significant
                .iter()
                .position(|byte| *byte != 0)
                .unwrap_or(significant.len())..];
            let padding = Self::P256_SCALAR_LEN
                .checked_sub(significant.len())
                .ok_or_else(|| invalid("has an integer of more than 32 significant bytes"))?;
            half[padding..].copy_from_slice(significant);
        }
        Ok(Self(bytes.concat()))
    }

    /// The signature bytes.
    pub fn value(&self) -> &[u8] {
        &self.0
    }

    /// The signature bytes, taking the signature.
    pub fn into_value(self) -> Vec<u8> {
        self.0
    }
}

/// The length only.
impl Debug for RawSignature {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawSignature")
            .field("len", &self.0.len())
            .finish()
    }
}

/// A signing key: the KMS that holds it and the key version's name there, the `provider` and
/// `key` fields of the `KMS sign` and `KMS public key` spans. A type apart from
/// [`KekRef`](crate::KekRef): a signing key is never a KEK, so the two are never compared, and a
/// `KekRef` keys the DEK cache while a signing key keys nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SigningKeyRef {
    provider: KmsProvider,
    key: String,
}

impl SigningKeyRef {
    /// The signing key `key` in the KMS `provider`.
    pub fn new(provider: KmsProvider, key: impl Into<String>) -> Self {
        Self {
            provider,
            key: key.into(),
        }
    }

    /// The KMS that holds the key.
    pub fn provider(&self) -> &KmsProvider {
        &self.provider
    }

    /// The key version as the provider names it: the CryptoKeyVersion name for GCP; the key ARN
    /// for AWS; `<vault URL>/keys/<name>/<version>` for Azure;
    /// `<address>/<namespace>/<mount>/keys/<name>/v<N>` for Vault Transit; the
    /// [`LocalSigningKeyName`](crate::providers::LocalSigningKeyName) for the local KMS.
    pub fn key(&self) -> &str {
        &self.key
    }
}

/// `<provider>:<key>`.
impl Display for SigningKeyRef {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.provider, self.key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const P256_SIGNATURE_R: &str =
        "4c3ea9da3b6bddbbd0baec3c94f0cb50e295d017c25b444a97a10dc3119a2e1b";
    const P256_SIGNATURE_S: &str =
        "f1da77f32ca85798256a744107f37ee99015734455067b3d7d3eb841142fbeb8";
    /// The P-256 signature of the book's test vectors, whose `s` takes a leading `0x00`.
    const P256_SIGNATURE_DER: &str =
        "304502204c3ea9da3b6bddbbd0baec3c94f0cb50e295d017c25b444a97a10dc3119a2e1b\
                       022100f1da77f32ca85798256a744107f37ee99015734455067b3d7d3eb841142fbeb8";

    #[test]
    fn a_der_signature_converts_to_r_and_s() -> KmsAeadResult<()> {
        let der = hex::decode(P256_SIGNATURE_DER).expect("hex");

        let raw = RawSignature::from_ecdsa_p256_der(&der)?;

        assert_eq!(
            hex::encode(raw.value()),
            format!("{P256_SIGNATURE_R}{P256_SIGNATURE_S}")
        );
        Ok(())
    }

    #[test]
    fn a_short_integer_is_left_padded() -> KmsAeadResult<()> {
        let der = hex::decode("3006020101020102").expect("hex");

        let raw = RawSignature::from_ecdsa_p256_der(&der)?;

        let mut expected = vec![0; 64];
        expected[31] = 1;
        expected[63] = 2;
        assert_eq!(raw.value(), expected);
        Ok(())
    }

    #[test]
    fn der_that_is_not_strict_is_refused() {
        for refused in [
            // A BER long-form length where the short form fits.
            format!("3081440220{P256_SIGNATURE_R}0220{P256_SIGNATURE_R}"),
            // A negative r: a first byte of 0x80 or more without the 0x00.
            format!("30440220{P256_SIGNATURE_S}0220{P256_SIGNATURE_R}"),
            // A leading 0x00 before a byte under 0x80.
            "300702020001020102".to_string(),
            // Trailing bytes.
            format!("30440220{P256_SIGNATURE_R}0220{P256_SIGNATURE_R}00"),
            // An integer of 33 significant bytes.
            format!("3045022101{P256_SIGNATURE_R}0220{P256_SIGNATURE_R}"),
        ] {
            let result = RawSignature::from_ecdsa_p256_der(&hex::decode(&refused).expect("hex"));
            assert!(
                matches!(&result, Err(error) if error.code() == "SIGNATURE_ENCODING"),
                "{refused}: {result:?}"
            );
        }
    }

    #[test]
    fn an_input_of_another_algorithm_is_refused() {
        let signing_key = SigningKeyRef::new(KmsProvider::Gcp, "key");
        let ed25519 = SigningInput::Ed25519 {
            pre_image: &[0; 46],
        };

        let refused = ed25519.ensure_algorithm(&signing_key, SigningAlgorithm::EcdsaP256Sha256);

        assert!(
            matches!(&refused, Err(error) if error.code() == "SIGNING_ALGORITHM_MISMATCH"),
            "{refused:?}"
        );
        assert!(ed25519
            .ensure_algorithm(&signing_key, SigningAlgorithm::Ed25519)
            .is_ok());
    }

    #[test]
    fn a_raw_signature_of_another_length_is_refused() {
        let result = RawSignature::new(SigningAlgorithm::Ed25519, vec![0; 63]);

        assert!(
            matches!(&result, Err(error) if error.code() == "SIGNATURE_ENCODING"),
            "{result:?}"
        );
    }
}
