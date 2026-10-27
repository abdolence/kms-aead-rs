//! The AEAD backends: one zero-sized type per crypto library, `Ring`, `AwsLc` and `RustCrypto`,
//! each added by its feature and implementing the sealed [`AeadBackend`]. The crate root lists
//! the features and the algorithms of each. No type of a crypto library reaches the public API.

use std::fmt::Debug;

use secret_vault_value::SecretValue;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::signing::{SigningAlgorithm, SigningInput};
use crate::{AeadAlgorithm, AsymmetricKekAlgorithm, KmsAeadResult};

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

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod vectors;

/// The crypto library that runs the [`AeadAlgorithm`]s, the beacon HMAC, the signatures and the
/// [`AsymmetricKekAlgorithm`]s: `Ring`, `AwsLc` or `RustCrypto` of
/// [`backends`](crate::backends), each added by its feature. A build may enable any number of
/// them, and the backend is the `B` of [`AeadCipher<B>`](crate::AeadCipher),
/// `DeterministicCipher<B>`, [`KmsAeadEnvelope<P, B>`](crate::KmsAeadEnvelope) and
/// [`LocalKmsProvider<B>`](crate::providers::LocalKmsProvider).
///
/// Sealed: only the backend types of kms-aead implement it. Its items are its
/// [`NAME`](Self::NAME) and [`generate_random_bytes`](Self::generate_random_bytes), so code generic
/// over the backend names this trait and nothing else:
///
/// ```rust
/// use kms_aead::formats::Envelope;
/// use kms_aead::providers::{LocalKekId, LocalKmsProvider};
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::{Encrypted, KmsAeadEnvelope, KmsAeadResult};
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
///         let encrypted: Encrypted<SecretValue, Envelope> =
///             self.envelope.encrypt(b"orders/1042", card).await?;
///         self.envelope.decrypt(b"orders/1042", &encrypted).await
///     }
/// }
///
/// # #[cfg(feature = "ring")]
/// # async fn example() -> KmsAeadResult<()> {
/// let orders = Orders::<kms_aead::backends::Ring>::new()?;
/// let card = SecretValue::from("4111 1111 1111 1111");
/// assert_eq!(orders.round_trip(&card).await?, card);
/// # Ok(())
/// # }
/// ```
///
/// There is no default backend: with Cargo's feature unification, a default chosen by features
/// would change for every crate in a build when one crate enables another backend. A value
/// encrypted by one backend decrypts with any other that implements its algorithm.
///
/// A build without a backend feature has no type that implements it, so nothing that encrypts or
/// decrypts can be constructed.
pub trait AeadBackend: private::Sealed + Copy + Debug + Send + Sync + 'static {
    /// The backend's name in spans and logs, the value of the `/kms_aead/backend` span field:
    /// `ring`, `aws-lc` or `rustcrypto`. `aws-lc-fips` runs the `aws-lc` backend.
    ///
    /// ```rust
    /// use kms_aead::backends::AeadBackend;
    ///
    /// # #[cfg(feature = "ring")]
    /// assert_eq!(kms_aead::backends::Ring::NAME, "ring");
    /// # #[cfg(feature = "aws-lc-rs")]
    /// assert_eq!(kms_aead::backends::AwsLc::NAME, "aws-lc");
    /// # #[cfg(feature = "rustcrypto")]
    /// assert_eq!(kms_aead::backends::RustCrypto::NAME, "rustcrypto");
    /// ```
    const NAME: &'static str;

    /// `len` random bytes from the CSPRNG the backend draws its keys and nonces from: ring's
    /// `SystemRandom`, AWS-LC's `RAND_bytes`, which is the FIPS module's DRBG with `aws-lc-fips`,
    /// or `getrandom` for RustCrypto.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    fn generate_random_bytes(len: usize) -> KmsAeadResult<SecretValue> {
        let mut random = SecretValue::new(vec![0; len]);
        Self::fill_random(random.ref_sensitive_value_mut()).map_err(|_| {
            KmsAeadEncryptionError::create("RANDOM_GENERATOR", "Unable to generate random bytes")
        })?;
        Ok(random)
    }
}

/// The SHA-256 of `message` on the backend `B`.
///
/// # Errors
///
/// `DIGEST` when the backend fails.
pub(crate) fn sha256<B: AeadBackend>(message: &[u8]) -> KmsAeadResult<Sha256Digest> {
    B::sha256(message)
        .map_err(|_| KmsAeadEncryptionError::create("DIGEST", "Unable to calculate a SHA-256"))
}

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

pub(crate) type Nonce = [u8; AeadAlgorithm::NONCE_LEN];
pub(crate) type Tag = [u8; AeadAlgorithm::TAG_LEN];
/// An HMAC-SHA256 output.
pub(crate) type HmacSha256 = [u8; 32];
/// An HMAC-SHA512 output.
pub(crate) type HmacSha512 = [u8; 64];
/// A SHA-256 digest.
pub(crate) type Sha256Digest = [u8; 32];
/// An Ed25519 public key.
#[cfg_attr(
    not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")),
    expect(
        dead_code,
        reason = "only the backends derive a public key, and a build without one has none"
    )
)]
pub(crate) type Ed25519PublicKey = [u8; 32];

/// The backend of a computation that has no `B` of its own and gives the same result on every
/// backend: the public key of an Ed25519 seed, which a local signing key derives as it loads. A
/// build without a backend has none.
#[cfg(feature = "aws-lc-rs")]
pub(crate) type AnyBackend = AwsLc;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "ring"))]
pub(crate) type AnyBackend = Ring;
#[cfg(all(
    not(feature = "aws-lc-rs"),
    not(feature = "ring"),
    feature = "rustcrypto"
))]
pub(crate) type AnyBackend = RustCrypto;

/// Crypto libraries report no detail on failure, and none is lost here.
#[cfg_attr(
    not(any(
        feature = "ring",
        feature = "aws-lc-rs",
        feature = "rustcrypto",
        feature = "stream"
    )),
    expect(
        dead_code,
        reason = "only the backends and the stream module construct it"
    )
)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The library refused the key.
    Key,
    /// Generating random bytes, encrypting or decrypting failed. A decryption fails when the value
    /// is not authentic under the key, the nonce and the AAD.
    Operation,
}

impl Failure {
    /// The error of an encryption that failed: `ENCRYPT_KEY` when the library refused the key, and
    /// `ENCRYPT` otherwise.
    pub(crate) fn encrypting(self) -> KmsAeadError {
        match self {
            Failure::Key => {
                KmsAeadEncryptionError::create("ENCRYPT_KEY", "Unable to create an encrypting key")
            }
            Failure::Operation => {
                KmsAeadEncryptionError::create("ENCRYPT", "Unable to encrypt data")
            }
        }
    }

    /// The error of a decryption that failed: `DECRYPT_KEY` when the library refused the key, and
    /// `DECRYPT` when the value is not authentic.
    pub(crate) fn decrypting(self) -> KmsAeadError {
        match self {
            Failure::Key => {
                KmsAeadEncryptionError::create("DECRYPT_KEY", "Unable to create a decrypting key")
            }
            Failure::Operation => {
                KmsAeadEncryptionError::create("DECRYPT", "Unable to decrypt data")
            }
        }
    }
}

/// The operations of one backend. `AeadCipher` checks the key length and the support of the
/// algorithm before it calls a backend, so an implementation may rely on both, and the
/// asymmetric KEK providers check an RSA key's size and the support of RSA-OAEP before they
/// parse a key on it.
pub(crate) trait AeadBackendOps {
    /// An RSA public key the backend parsed, to encrypt DEKs under.
    type RsaPublicKey: Send + Sync + 'static;

    /// An RSA private key the backend parsed, to decrypt DEKs with. Dropping it clears its memory
    /// as the backend's own key types do.
    type RsaPrivateKey: Send + Sync + 'static;

    fn supports(algorithm: AeadAlgorithm) -> bool;

    /// Fills `out` from the backend's system CSPRNG.
    fn fill_random(out: &mut [u8]) -> Result<(), Failure>;

    /// Encrypts `in_out` in place and returns the tag.
    fn seal_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure>;

    /// Decrypts `[ciphertext][tag]` in place and returns the length of the plaintext, which starts
    /// at the beginning of `in_out`. `in_out` holds at least a tag.
    fn open_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure>;

    /// HMAC-SHA256 of `message` under `key`.
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<HmacSha256, Failure>;

    /// Writes into `out` the HMAC-SHA512 under `key` of the concatenation of `message`'s parts,
    /// which saves the caller from copying an AAD of any length into one buffer. The caller
    /// owns `out`, so it can hold the tag in memory it zeroises.
    fn hmac_sha512(key: &[u8], message: &[&[u8]], out: &mut HmacSha512) -> Result<(), Failure>;

    /// The SHA-256 of `message`.
    fn sha256(message: &[u8]) -> Result<Sha256Digest, Failure>;

    /// Whether the backend takes `public_key`, the raw key of `algorithm`, which has that
    /// algorithm's length: a point on the curve, where the backend checks it before verifying.
    fn check_verifying_key(algorithm: SigningAlgorithm, public_key: &[u8]) -> Result<(), Failure>;

    /// Verifies `signature`, which has the length of `algorithm`'s signatures, over `pre_image`
    /// under `public_key`. ECDSA hashes `pre_image` with SHA-256.
    fn verify(
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        pre_image: &[u8],
        signature: &[u8],
    ) -> Result<(), Failure>;

    /// The public key of the Ed25519 `seed`, 32 bytes.
    #[cfg_attr(
        not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")),
        expect(
            dead_code,
            reason = "a local signing key derives it on a backend, and a build without one has none"
        )
    )]
    fn ed25519_public_key(seed: &[u8]) -> Result<Ed25519PublicKey, Failure>;

    /// Whether `private_key`, an Ed25519 seed or a P-256 scalar, and `public_key` are one key
    /// pair of `algorithm` that the backend signs with.
    fn check_signing_key(
        algorithm: SigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), Failure>;

    /// The raw signature of `input` under the key pair `private_key` and `public_key`, which
    /// [`check_signing_key`](Self::check_signing_key) took for `input`'s algorithm.
    fn sign(
        private_key: &[u8],
        public_key: &[u8],
        input: &SigningInput<'_>,
    ) -> Result<Vec<u8>, Failure>;

    /// A new key pair of `algorithm` from the backend's CSPRNG: the Ed25519 seed or the P-256
    /// scalar, and the raw public key.
    fn generate_signing_key(algorithm: SigningAlgorithm)
        -> Result<(SecretValue, Vec<u8>), Failure>;

    /// Whether the backend encrypts and decrypts DEKs with `algorithm`.
    fn supports_asymmetric_kek(algorithm: AsymmetricKekAlgorithm) -> bool;

    /// The RSA public key of `spki_der`, a SubjectPublicKeyInfo in DER of an `rsaEncryption` key.
    fn rsa_public_key(spki_der: &[u8]) -> Result<Self::RsaPublicKey, Failure>;

    /// The RSAES-OAEP encryption of `message` under `public_key`, with SHA-256 as the OAEP and
    /// the MGF1 hash, an empty label and a seed from the backend's CSPRNG: one block of the
    /// modulus's length.
    fn rsa_oaep_sha256_encrypt(
        public_key: &Self::RsaPublicKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Failure>;

    /// The RSA private key of `pkcs8_der`, a PKCS#8 `PrivateKeyInfo` in DER.
    fn rsa_private_key(pkcs8_der: &[u8]) -> Result<Self::RsaPrivateKey, Failure>;

    /// The length of the modulus of `private_key`, in bits.
    fn rsa_private_key_bits(private_key: &Self::RsaPrivateKey) -> usize;

    /// The SubjectPublicKeyInfo in DER of the public half of `private_key`.
    fn rsa_public_key_der(private_key: &Self::RsaPrivateKey) -> Result<Vec<u8>, Failure>;

    /// The message `block` holds, decrypted with `private_key` as
    /// [`rsa_oaep_sha256_encrypt`](Self::rsa_oaep_sha256_encrypt) encrypts it. A block that is not
    /// one fails with [`Failure::Operation`], however the padding is wrong.
    fn rsa_oaep_sha256_decrypt(
        private_key: &Self::RsaPrivateKey,
        block: &[u8],
    ) -> Result<SecretValue, Failure>;

    /// A new RSA private key of `bits` bits from the backend's CSPRNG, as a PKCS#8
    /// `PrivateKeyInfo` in DER.
    fn generate_rsa_private_key(bits: usize) -> Result<SecretValue, Failure>;
}
