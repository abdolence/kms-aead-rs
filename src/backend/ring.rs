use ::ring::aead::{
    Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305,
};
use ::ring::rand::{SecureRandom, SystemRandom};

use super::sealed::{self, Failure, Tag, Token};
use super::AeadBackend;
use crate::AeadAlgorithm;

/// The [ring](https://crates.io/crates/ring) library: ChaCha20-Poly1305, AES-128-GCM and
/// AES-256-GCM. It has no AES-256-GCM-SIV. It does not zeroize its expanded key schedules, so
/// they stay in freed memory after each call.
#[derive(Debug, Clone, Copy)]
pub struct Ring;

impl AeadBackend for Ring {}

impl Ring {
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

impl sealed::Sealed for Ring {
    fn name(_: Token) -> &'static str {
        "ring"
    }

    fn supports(_: Token, algorithm: AeadAlgorithm) -> bool {
        Self::algorithm(algorithm).is_some()
    }

    fn fill_random(_: Token, out: &mut [u8]) -> Result<(), Failure> {
        SystemRandom::new()
            .fill(out)
            .map_err(|_| Failure::Operation)
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
    use super::Ring;
    use crate::backend::contract;
    use crate::errors::KmsAeadError;
    use crate::{AeadAlgorithm, AeadCipher};

    #[test]
    fn aes_256_gcm_siv_is_refused_at_construction() {
        let result = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256GcmSiv);

        assert!(
            matches!(&result, Err(KmsAeadError::UnsupportedAlgorithm(error))
                if error.public.code == "UNSUPPORTED_ALGORITHM"
                    && error.algorithm == AeadAlgorithm::Aes256GcmSiv),
            "{result:?}"
        );
        for algorithm in [
            AeadAlgorithm::ChaCha20Poly1305,
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
        ] {
            assert!(AeadCipher::<Ring>::new(algorithm).is_ok(), "{algorithm}");
        }
    }

    #[test]
    fn every_supported_algorithm_round_trips() {
        contract::every_supported_algorithm_round_trips::<Ring>();
    }

    #[tokio::test]
    async fn a_64_byte_key_is_refused_by_every_aead_algorithm() {
        contract::a_64_byte_key_is_refused_by_every_aead_algorithm::<Ring>().await;
    }

    #[tokio::test]
    async fn a_tampered_value_fails_to_open() {
        contract::a_tampered_value_fails_to_open::<Ring>().await;
    }

    #[tokio::test]
    async fn a_value_shorter_than_nonce_and_tag_is_invalid() {
        contract::a_value_shorter_than_nonce_and_tag_is_invalid::<Ring>().await;
    }

    #[tokio::test]
    async fn sealing_twice_gives_different_values() {
        contract::sealing_twice_gives_different_values::<Ring>().await;
    }

    #[test]
    fn generated_keys_have_the_algorithm_length_and_differ() {
        contract::generated_keys_have_the_algorithm_length_and_differ::<Ring>();
    }

    #[tokio::test]
    async fn a_value_sealed_by_0_28_1_opens() {
        contract::a_value_sealed_by_0_28_1_opens::<Ring>().await;
    }
}
