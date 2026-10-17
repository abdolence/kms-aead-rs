//! The crypto libraries that implement the [`AeadAlgorithm`](crate::AeadAlgorithm)s.
//!
//! The features `ring`, `aws-lc` and `rustcrypto` each add one backend type, and a build may
//! enable any number of them. A caller names the backend once, as the `B` of
//! [`AeadCipher<B>`](crate::AeadCipher) or [`KmsAeadEnvelope<P, B>`](crate::KmsAeadEnvelope).
//! There is no default backend: with Cargo's feature unification, a default chosen by features
//! would change for every crate in a build when one crate enables another backend.

#[cfg(feature = "ring")]
mod ring;
#[cfg(feature = "ring")]
pub use ring::Ring;

#[cfg(feature = "aws-lc")]
mod aws_lc;
#[cfg(feature = "aws-lc")]
pub use aws_lc::AwsLc;

#[cfg(feature = "rustcrypto")]
mod rust_crypto;
#[cfg(feature = "rustcrypto")]
pub use rust_crypto::RustCrypto;

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod contract;

/// A crypto library that implements the AEAD algorithms. Sealed: only the types in this module
/// implement it, and only this crate can call its methods.
pub trait AeadBackend: sealed::Sealed + Send + Sync + 'static {}

pub(crate) mod sealed {
    use crate::AeadAlgorithm;

    pub type Nonce = [u8; AeadAlgorithm::NONCE_LEN];
    pub type Tag = [u8; AeadAlgorithm::TAG_LEN];

    /// Every method of [`Sealed`] takes one, and only this crate can make one, so no code
    /// outside it can call a backend, even through a `B: AeadBackend` bound.
    #[derive(Clone, Copy)]
    pub struct Token(());

    impl Token {
        pub(crate) const fn new() -> Self {
            Self(())
        }
    }

    /// Crypto libraries report no detail on failure, and none is lost here.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Failure {
        /// The library refused the key.
        Key,
        /// Generating random bytes, sealing or opening failed. An open fails when the value is
        /// not authentic under the key, the nonce and the AAD.
        Operation,
    }

    /// The operations of a backend. `AeadCipher` checks the key length and the support of the
    /// algorithm before it calls a backend, so an implementation may rely on both.
    pub trait Sealed {
        /// `ring`, `aws-lc` or `rustcrypto`: the value of the `backend` span field.
        fn name(token: Token) -> &'static str;

        fn supports(token: Token, algorithm: AeadAlgorithm) -> bool;

        /// Fills `out` from the backend's system CSPRNG.
        fn fill_random(token: Token, out: &mut [u8]) -> Result<(), Failure>;

        /// Seals `in_out` in place and returns the tag.
        fn seal_in_place(
            token: Token,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &Nonce,
            aad: &[u8],
            in_out: &mut [u8],
        ) -> Result<Tag, Failure>;

        /// Opens `[ciphertext][tag]` in place and returns the length of the plaintext, which
        /// starts at the beginning of `in_out`. `in_out` holds at least a tag.
        fn open_in_place(
            token: Token,
            algorithm: AeadAlgorithm,
            key: &[u8],
            nonce: &Nonce,
            aad: &[u8],
            in_out: &mut [u8],
        ) -> Result<usize, Failure>;
    }
}
