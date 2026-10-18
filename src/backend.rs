//! The AEAD backends: the public [`AeadBackend`] a caller chooses at runtime and, behind it, one
//! crate-private [`AeadBackendOps`] implementation per crypto library, so that no type of a
//! crypto library reaches the public API.

use std::fmt::{Display, Formatter};

use crate::AeadAlgorithm;

#[cfg(feature = "ring")]
mod ring;

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;

#[cfg(feature = "rustcrypto")]
mod rust_crypto;

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod contract;

/// The crypto library that runs the [`AeadAlgorithm`]s. The features `ring`, `aws-lc` and
/// `rustcrypto` each add one variant, and a build may enable any number of them.
///
/// There is no default backend: with Cargo's feature unification, a default chosen by features
/// would change for every crate in a build when one crate enables another backend. A value
/// sealed by one backend opens with any other that implements its algorithm.
///
/// Without a backend feature the enum has no variant, so nothing that takes one can be built:
/// [`AeadCipher`](crate::AeadCipher), [`KmsAeadEnvelope`](crate::KmsAeadEnvelope) and
/// [`LocalKmsProvider`](crate::providers::LocalKmsProvider) compile but cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AeadBackend {
    /// The [ring](https://crates.io/crates/ring) library, with the `ring` feature:
    /// ChaCha20-Poly1305, AES-128-GCM and AES-256-GCM. It has no AES-256-GCM-SIV. It does not
    /// zeroize its expanded key schedules, so they stay in freed memory after each call.
    #[cfg(feature = "ring")]
    Ring,
    /// The [aws-lc-rs](https://crates.io/crates/aws-lc-rs) library, with the `aws-lc` or the
    /// `aws-lc-fips` feature: every [`AeadAlgorithm`].
    ///
    /// With `aws-lc-fips` it runs on the AWS-LC FIPS module, and so does every other user of
    /// aws-lc-rs in the build, even when `aws-lc` is enabled too. AES-256-GCM is the algorithm
    /// for FIPS deployments.
    ///
    /// aws-lc-rs copies the key into an AEAD context that AWS-LC allocates with its own
    /// allocator, which overwrites every allocation with zeros before freeing it
    /// (`OPENSSL_free`). The expanded key schedule therefore does not stay in freed memory after
    /// a call, as long as the application leaves AWS-LC's allocator in place: a replacement
    /// installed through `CRYPTO_set_mem_functions` or the `OPENSSL_memory_*` hooks decides on
    /// its own whether freed memory is cleared. The record keys AES-256-GCM-SIV derives from the
    /// key and the nonce for each call live on the stack, and AWS-LC does not clear them.
    #[cfg(feature = "aws-lc-rs")]
    AwsLc,
    /// The pure-Rust [RustCrypto](https://github.com/RustCrypto/AEADs) crates, with the
    /// `rustcrypto` feature: every [`AeadAlgorithm`], with `getrandom` as the CSPRNG. Needs no C
    /// compiler. The feature turns on the crates' `zeroize` features, so their key objects, and
    /// the Poly1305 and POLYVAL keys each call derives, are zeroized when dropped.
    #[cfg(feature = "rustcrypto")]
    RustCrypto,
}

/// `ring`, `aws-lc`, `rustcrypto`: the values of the `/kms_aead/backend` span field.
impl Display for AeadBackend {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let ops: &dyn AeadBackendOps = (*self).into();
        f.write_str(ops.name())
    }
}

/// The one place that maps a backend to its implementation.
impl From<AeadBackend> for &'static dyn AeadBackendOps {
    fn from(backend: AeadBackend) -> Self {
        match backend {
            #[cfg(feature = "ring")]
            AeadBackend::Ring => &ring::RingOps,
            #[cfg(feature = "aws-lc-rs")]
            AeadBackend::AwsLc => &aws_lc::AwsLcOps,
            #[cfg(feature = "rustcrypto")]
            AeadBackend::RustCrypto => &rust_crypto::RustCryptoOps,
        }
    }
}

pub(crate) type Nonce = [u8; AeadAlgorithm::NONCE_LEN];
pub(crate) type Tag = [u8; AeadAlgorithm::TAG_LEN];

/// Crypto libraries report no detail on failure, and none is lost here.
// Only the backends construct it, and a build without a backend feature has none.
#[cfg_attr(
    not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")),
    allow(dead_code)
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The library refused the key.
    Key,
    /// Generating random bytes, sealing or opening failed. An open fails when the value is not
    /// authentic under the key, the nonce and the AAD.
    Operation,
}

/// The operations of one backend. `AeadCipher` checks the key length and the support of the
/// algorithm before it calls a backend, so an implementation may rely on both.
pub(crate) trait AeadBackendOps {
    /// `ring`, `aws-lc` or `rustcrypto`: the value of the `backend` span field.
    fn name(&self) -> &'static str;

    fn supports(&self, algorithm: AeadAlgorithm) -> bool;

    /// Fills `out` from the backend's system CSPRNG.
    fn fill_random(&self, out: &mut [u8]) -> Result<(), Failure>;

    /// Seals `in_out` in place and returns the tag.
    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure>;

    /// Opens `[ciphertext][tag]` in place and returns the length of the plaintext, which starts
    /// at the beginning of `in_out`. `in_out` holds at least a tag.
    fn open_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure>;
}
