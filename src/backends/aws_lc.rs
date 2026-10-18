use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as AeadNonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    AES_256_GCM_SIV, CHACHA20_POLY1305,
};
use aws_lc_rs::hmac;

use super::private::Sealed;
use super::{AeadBackend, AeadBackendOps, Failure, HmacSha256, Nonce, Tag};
use crate::AeadAlgorithm;

/// The [aws-lc-rs](https://crates.io/crates/aws-lc-rs) library, with the `aws-lc` or the
/// `aws-lc-fips` feature: every [`AeadAlgorithm`].
///
/// With `aws-lc-fips` it runs on the AWS-LC FIPS module, and so does every other user of
/// aws-lc-rs in the build, even when `aws-lc` is enabled too. AES-256-GCM is the algorithm for
/// FIPS deployments.
///
/// aws-lc-rs copies the key into an AEAD context that AWS-LC allocates with its own allocator,
/// which overwrites every allocation with zeros before freeing it (`OPENSSL_free`). The expanded
/// key schedule therefore does not stay in freed memory after a call, as long as the application
/// leaves AWS-LC's allocator in place: a replacement installed through
/// `CRYPTO_set_mem_functions` or the `OPENSSL_memory_*` hooks decides on its own whether freed
/// memory is cleared. The record keys AES-256-GCM-SIV derives from the key and the nonce for each
/// call live on the stack, and AWS-LC does not clear them.
#[derive(Debug, Clone, Copy)]
pub struct AwsLc;

impl AeadBackend for AwsLc {
    const NAME: &'static str = "aws-lc";
}

impl Sealed for AwsLc {}

impl AeadBackendOps for AwsLc {
    fn supports(algorithm: AeadAlgorithm) -> bool {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes128Gcm
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => true,
        }
    }

    fn fill_random(out: &mut [u8]) -> Result<(), Failure> {
        aws_lc_rs::rand::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        let tag = less_safe_key(algorithm, key)?
            .seal_in_place_separate_tag(
                AeadNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                in_out,
            )
            .map_err(|_| Failure::Operation)?;
        Tag::try_from(tag.as_ref()).map_err(|_| Failure::Operation)
    }

    fn open_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        less_safe_key(algorithm, key)?
            .open_in_place(
                AeadNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                in_out,
            )
            .map(|plain_text| plain_text.len())
            .map_err(|_| Failure::Operation)
    }
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<HmacSha256, Failure> {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message);
        HmacSha256::try_from(tag.as_ref()).map_err(|_| Failure::Operation)
    }
}

fn less_safe_key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<LessSafeKey, Failure> {
    let algorithm: &'static Algorithm = match algorithm {
        AeadAlgorithm::ChaCha20Poly1305 => &CHACHA20_POLY1305,
        AeadAlgorithm::Aes128Gcm => &AES_128_GCM,
        AeadAlgorithm::Aes256Gcm => &AES_256_GCM,
        AeadAlgorithm::Aes256GcmSiv => &AES_256_GCM_SIV,
    };
    UnboundKey::new(algorithm, key)
        .map(LessSafeKey::new)
        .map_err(|_| Failure::Key)
}

#[cfg(all(test, feature = "aws-lc-fips"))]
mod tests {
    #[test]
    fn fips_mode_is_on() {
        assert_eq!(aws_lc_rs::try_fips_mode(), Ok(()));
    }
}
