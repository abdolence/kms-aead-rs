//! The AEAD backends: one public zero-sized type per crypto library, each implementing the sealed
//! [`AeadBackend`], and the crate-private [`AeadBackendOps`] they run on, so that no type of a
//! crypto library reaches the public API.

use std::fmt::Debug;

use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
use crate::{AeadAlgorithm, KmsAeadResult};

#[cfg(feature = "ring")]
mod ring;
#[cfg(feature = "ring")]
pub use self::ring::Ring;

#[cfg(feature = "aws-lc-rs")]
mod aws_lc;
#[cfg(feature = "aws-lc-rs")]
pub use aws_lc::AwsLc;

#[cfg(feature = "rustcrypto")]
mod rust_crypto;
#[cfg(feature = "rustcrypto")]
pub use rust_crypto::RustCrypto;

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod contract;

/// The crypto library that runs the [`AeadAlgorithm`]s: [`Ring`], [`AwsLc`] or [`RustCrypto`],
/// each added by its feature. A build may enable any number of them, and the backend is the `B`
/// of [`AeadCipher<B>`](crate::AeadCipher), [`DeterministicCipher<B>`](crate::DeterministicCipher),
/// [`KmsAeadEnvelope<P, B>`](crate::KmsAeadEnvelope) and
/// [`LocalKmsProvider<B>`](crate::providers::LocalKmsProvider).
///
/// Sealed: only the backend types of this crate implement it. It has no methods, so code generic
/// over the backend names this trait and nothing else:
///
/// ```rust
/// use kms_aead::providers::{LocalKekId, LocalKmsProvider};
/// use kms_aead::{AeadBackend, KmsAeadEnvelope, KmsAeadResult};
/// use secret_vault_value::SecretValue;
///
/// struct Orders<B> {
///     envelope: KmsAeadEnvelope<LocalKmsProvider<B>, B>,
/// }
///
/// impl<B: AeadBackend> Orders<B> {
///     fn new() -> KmsAeadResult<Self> {
///         let kek = LocalKekId::try_from("orders".to_string())?;
///         let provider = LocalKmsProvider::ephemeral(kek)?;
///         Ok(Self {
///             envelope: KmsAeadEnvelope::new(provider)?,
///         })
///     }
///
///     async fn round_trip(&self, card: &SecretValue) -> KmsAeadResult<SecretValue> {
///         let sealed = self.envelope.encrypt_value(b"orders/1042", card).await?;
///         self.envelope.decrypt_value(b"orders/1042", &sealed).await
///     }
/// }
///
/// # #[cfg(feature = "ring")]
/// # async fn example() -> KmsAeadResult<()> {
/// let orders = Orders::<kms_aead::Ring>::new()?;
/// let card = SecretValue::from("4111 1111 1111 1111");
/// assert_eq!(orders.round_trip(&card).await?, card);
/// # Ok(())
/// # }
/// ```
///
/// There is no default backend: with Cargo's feature unification, a default chosen by features
/// would change for every crate in a build when one crate enables another backend. A value
/// sealed by one backend opens with any other that implements its algorithm.
///
/// A build without a backend feature has no type that implements it, so nothing that seals or
/// wraps can be constructed.
pub trait AeadBackend: private::Sealed + Copy + Debug + Send + Sync + 'static {}

mod private {
    /// Seals [`AeadBackend`](super::AeadBackend). Its supertrait is how the crate reaches a
    /// backend's operations through a `B: AeadBackend` bound, and being crate-private, it keeps
    /// them out of reach of every other crate, which a public supertrait would not.
    #[expect(
        private_bounds,
        reason = "a crate-private supertrait is what keeps the backend operations uncallable \
                  outside the crate"
    )]
    pub trait Sealed: super::AeadBackendOps {}
}

/// `len` random bytes from the CSPRNG backend `B` draws its keys and nonces from: ring's
/// `SystemRandom`, AWS-LC's `RAND_bytes`, which is the FIPS module's DRBG with `aws-lc-fips`, or
/// `getrandom` for RustCrypto.
///
/// # Errors
///
/// `RANDOM_GENERATOR` when the CSPRNG fails.
pub fn generate_random_bytes<B: AeadBackend>(len: usize) -> KmsAeadResult<SecretValue> {
    let mut random = SecretValue::new(vec![0; len]);
    B::fill_random(random.ref_sensitive_value_mut()).map_err(|_| {
        KmsAeadEncryptionError::create("RANDOM_GENERATOR", "Unable to generate random bytes")
    })?;
    Ok(random)
}

pub(crate) type Nonce = [u8; AeadAlgorithm::NONCE_LEN];
pub(crate) type Tag = [u8; AeadAlgorithm::TAG_LEN];

/// Crypto libraries report no detail on failure, and none is lost here.
#[cfg_attr(
    not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")),
    expect(
        dead_code,
        reason = "only the backends construct it, and a build without a backend feature has none"
    )
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
    /// `ring`, `aws-lc` or `rustcrypto`: the value of the `/kms_aead/backend` span field.
    const NAME: &'static str;

    fn supports(algorithm: AeadAlgorithm) -> bool;

    /// Fills `out` from the backend's system CSPRNG.
    fn fill_random(out: &mut [u8]) -> Result<(), Failure>;

    /// Seals `in_out` in place and returns the tag.
    fn seal_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure>;

    /// Opens `[ciphertext][tag]` in place and returns the length of the plaintext, which starts
    /// at the beginning of `in_out`. `in_out` holds at least a tag.
    fn open_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure>;
}
