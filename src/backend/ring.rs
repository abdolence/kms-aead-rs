use ::ring::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as AeadNonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    CHACHA20_POLY1305,
};
use ::ring::rand::{SecureRandom, SystemRandom};

use super::{AeadBackendOps, Failure, Nonce, Tag};
use crate::AeadAlgorithm;

pub(super) struct RingOps;

impl RingOps {
    fn algorithm(algorithm: AeadAlgorithm) -> Option<&'static Algorithm> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => Some(&CHACHA20_POLY1305),
            AeadAlgorithm::Aes128Gcm => Some(&AES_128_GCM),
            AeadAlgorithm::Aes256Gcm => Some(&AES_256_GCM),
            AeadAlgorithm::Aes256GcmSiv => None,
        }
    }

    fn key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<LessSafeKey, Failure> {
        let algorithm = Self::algorithm(algorithm).ok_or(Failure::Key)?;
        UnboundKey::new(algorithm, key)
            .map(LessSafeKey::new)
            .map_err(|_| Failure::Key)
    }
}

impl AeadBackendOps for RingOps {
    fn name(&self) -> &'static str {
        "ring"
    }

    fn supports(&self, algorithm: AeadAlgorithm) -> bool {
        Self::algorithm(algorithm).is_some()
    }

    fn fill_random(&self, out: &mut [u8]) -> Result<(), Failure> {
        SystemRandom::new()
            .fill(out)
            .map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        let tag = Self::key(algorithm, key)?
            .seal_in_place_separate_tag(
                AeadNonce::assume_unique_for_key(*nonce),
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
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        Self::key(algorithm, key)?
            .open_in_place(
                AeadNonce::assume_unique_for_key(*nonce),
                Aad::from(aad),
                in_out,
            )
            .map(|plain_text| plain_text.len())
            .map_err(|_| Failure::Operation)
    }
}
