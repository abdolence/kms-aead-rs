use ::ring::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as AeadNonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    CHACHA20_POLY1305,
};
use ::ring::rand::{SecureRandom, SystemRandom};

use super::private::Sealed;
use super::{AeadBackend, AeadBackendOps, Failure, Nonce, Tag};
use crate::AeadAlgorithm;

/// The [ring](https://crates.io/crates/ring) library, with the `ring` feature: ChaCha20-Poly1305,
/// AES-128-GCM and AES-256-GCM. It has no AES-256-GCM-SIV. It does not zeroize its expanded key
/// schedules, so they stay in freed memory after each call.
#[derive(Debug, Clone, Copy)]
pub struct Ring;

impl AeadBackend for Ring {}

impl Sealed for Ring {}

impl AeadBackendOps for Ring {
    const NAME: &'static str = "ring";

    fn supports(algorithm: AeadAlgorithm) -> bool {
        ring_algorithm(algorithm).is_some()
    }

    fn fill_random(out: &mut [u8]) -> Result<(), Failure> {
        SystemRandom::new()
            .fill(out)
            .map_err(|_| Failure::Operation)
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
}

fn ring_algorithm(algorithm: AeadAlgorithm) -> Option<&'static Algorithm> {
    match algorithm {
        AeadAlgorithm::ChaCha20Poly1305 => Some(&CHACHA20_POLY1305),
        AeadAlgorithm::Aes128Gcm => Some(&AES_128_GCM),
        AeadAlgorithm::Aes256Gcm => Some(&AES_256_GCM),
        AeadAlgorithm::Aes256GcmSiv => None,
    }
}

fn less_safe_key(algorithm: AeadAlgorithm, key: &[u8]) -> Result<LessSafeKey, Failure> {
    let algorithm = ring_algorithm(algorithm).ok_or(Failure::Key)?;
    UnboundKey::new(algorithm, key)
        .map(LessSafeKey::new)
        .map_err(|_| Failure::Key)
}
