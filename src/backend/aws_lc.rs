use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, AES_256_GCM_SIV,
    CHACHA20_POLY1305,
};

use super::{AeadBackendOps, Failure, Tag};
use crate::AeadAlgorithm;

pub(super) struct AwsLcOps;

impl AwsLcOps {
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

impl AeadBackendOps for AwsLcOps {
    fn name(&self) -> &'static str {
        "aws-lc"
    }

    fn supports(&self, algorithm: AeadAlgorithm) -> bool {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes128Gcm
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => true,
        }
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<(), Failure> {
        aws_lc_rs::rand::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &super::Nonce,
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
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &super::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        Self::key(algorithm, key)?
            .open_in_place(Nonce::assume_unique_for_key(*nonce), Aad::from(aad), in_out)
            .map(|plain_text| plain_text.len())
            .map_err(|_| Failure::Operation)
    }
}

#[cfg(all(test, feature = "aws-lc-fips"))]
mod tests {
    #[test]
    fn fips_mode_is_on() {
        assert_eq!(aws_lc_rs::try_fips_mode(), Ok(()));
    }
}
