use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, AES_256_GCM_SIV,
    CHACHA20_POLY1305,
};

use super::sealed::{self, Failure, Tag, Token};
use super::AeadBackend;
use crate::AeadAlgorithm;

/// The [aws-lc-rs](https://crates.io/crates/aws-lc-rs) library: ChaCha20-Poly1305, AES-128-GCM,
/// AES-256-GCM and AES-256-GCM-SIV.
///
/// With the `aws-lc-fips` feature it runs on the AWS-LC FIPS module, and so does every other
/// user of aws-lc-rs in the build. AES-256-GCM is the algorithm for FIPS deployments.
///
/// aws-lc-rs copies the key into an AEAD context that AWS-LC allocates with its own allocator,
/// which overwrites every allocation with zeros before freeing it (`OPENSSL_free`). The
/// expanded key schedule therefore does not stay in freed memory after a call, as long as the
/// application leaves AWS-LC's allocator in place: a replacement installed through
/// `CRYPTO_set_mem_functions` or the `OPENSSL_memory_*` hooks decides on its own whether freed
/// memory is cleared. The record keys AES-256-GCM-SIV derives from the key and the nonce for
/// each call live on the stack, and AWS-LC does not clear them.
#[derive(Debug, Clone, Copy)]
pub struct AwsLc;

impl AeadBackend for AwsLc {}

impl AwsLc {
    fn algorithm(algorithm: AeadAlgorithm) -> &'static Algorithm {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
            AeadAlgorithm::Aes128Gcm => &AES_128_GCM,
            AeadAlgorithm::Aes256Gcm => &AES_256_GCM,
            AeadAlgorithm::Aes256GcmSiv => &AES_256_GCM_SIV,
        }
    }

    fn key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<LessSafeKey, Failure> {
        UnboundKey::new(Self::algorithm(algorithm), key)
            .map(LessSafeKey::new)
            .map_err(|_| Failure::Key)
    }
}

impl sealed::Sealed for AwsLc {
    fn name(_: Token) -> &'static str {
        "aws-lc"
    }

    fn supports(_: Token, algorithm: AeadAlgorithm) -> bool {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes128Gcm
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => true,
        }
    }

    fn fill_random(_: Token, out: &mut [u8]) -> Result<(), Failure> {
        aws_lc_rs::rand::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        _: Token,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        let tag = Self::key(algorithm, key)?
            .seal_in_place_separate_tag(
                Nonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                in_out,
            )
            .map_err(|_| Failure::Operation)?;
        Tag::try_from(tag.as_ref()).map_err(|_| Failure::Operation)
    }

    fn open_in_place(
        _: Token,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        Self::key(algorithm, key)?
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), in_out)
            .map(|plain_text| plain_text.len())
            .map_err(|_| Failure::Operation)
    }
}

#[cfg(test)]
mod tests {
    use super::AwsLc;
    use crate::backend::contract;
    use crate::{AeadAlgorithm, AeadCipher};

    /// The contract suite runs only the algorithms a backend supports, so it would still pass
    /// with one of them dropped.
    #[test]
    fn every_aead_algorithm_is_supported() {
        for algorithm in [
            AeadAlgorithm::ChaCha20Poly1305,
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::Aes256GcmSiv,
        ] {
            assert!(AeadCipher::<AwsLc>::new(algorithm).is_ok(), "{algorithm}");
        }
    }

    #[cfg(feature = "aws-lc-fips")]
    #[test]
    fn fips_mode_is_on() {
        assert_eq!(aws_lc_rs::try_fips_mode(), Ok(()));
    }

    #[test]
    fn every_supported_algorithm_round_trips() {
        contract::every_supported_algorithm_round_trips::<AwsLc>();
    }

    #[tokio::test]
    async fn a_64_byte_key_is_refused_by_every_aead_algorithm() {
        contract::a_64_byte_key_is_refused_by_every_aead_algorithm::<AwsLc>().await;
    }

    #[tokio::test]
    async fn a_tampered_value_fails_to_open() {
        contract::a_tampered_value_fails_to_open::<AwsLc>().await;
    }

    #[tokio::test]
    async fn a_value_shorter_than_nonce_and_tag_is_invalid() {
        contract::a_value_shorter_than_nonce_and_tag_is_invalid::<AwsLc>().await;
    }

    #[tokio::test]
    async fn sealing_twice_gives_different_values() {
        contract::sealing_twice_gives_different_values::<AwsLc>().await;
    }

    #[test]
    fn generated_keys_have_the_algorithm_length_and_differ() {
        contract::generated_keys_have_the_algorithm_length_and_differ::<AwsLc>();
    }

    #[tokio::test]
    async fn a_value_sealed_by_0_28_1_opens() {
        contract::a_value_sealed_by_0_28_1_opens::<AwsLc>().await;
    }
}
