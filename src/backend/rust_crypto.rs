use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag as AeadTag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::ChaCha20Poly1305;

use super::sealed::{self, Failure, Tag, Token};
use super::AeadBackend;
use crate::AeadAlgorithm;

/// The pure-Rust [RustCrypto](https://github.com/RustCrypto/AEADs) crates: ChaCha20-Poly1305,
/// AES-128-GCM, AES-256-GCM and AES-256-GCM-SIV, with `getrandom` as the CSPRNG. Needs no C
/// compiler. The `rustcrypto` feature turns on the crates' `zeroize` features, so their key
/// objects, and the Poly1305 and POLYVAL keys each call derives, are zeroized when dropped.
#[derive(Debug, Clone, Copy)]
pub struct RustCrypto;

impl AeadBackend for RustCrypto {}

impl RustCrypto {
    fn seal<C: KeyInit + AeadInOut>(
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        let cipher = C::new_from_slice(key).map_err(|_| Failure::Key)?;
        let nonce = <&Nonce<C>>::try_from(nonce.as_slice()).map_err(|_| Failure::Operation)?;
        let tag = cipher
            .encrypt_inout_detached(nonce, aad, in_out.into())
            .map_err(|_| Failure::Operation)?;
        Tag::try_from(tag.as_slice()).map_err(|_| Failure::Operation)
    }

    fn open<C: KeyInit + AeadInOut>(
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        let cipher = C::new_from_slice(key).map_err(|_| Failure::Key)?;
        let nonce = <&Nonce<C>>::try_from(nonce.as_slice()).map_err(|_| Failure::Operation)?;
        let plain_text_len = in_out
            .len()
            .checked_sub(AeadAlgorithm::TAG_LEN)
            .ok_or(Failure::Operation)?;
        let (cipher_text, tag) = in_out.split_at_mut(plain_text_len);
        let tag = <&AeadTag<C>>::try_from(&*tag).map_err(|_| Failure::Operation)?;
        cipher
            .decrypt_inout_detached(nonce, aad, cipher_text.into(), tag)
            .map_err(|_| Failure::Operation)?;
        Ok(plain_text_len)
    }
}

impl sealed::Sealed for RustCrypto {
    fn name(_: Token) -> &'static str {
        "rustcrypto"
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
        getrandom::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        _: Token,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                Self::seal::<ChaCha20Poly1305>(key, nonce, aad, in_out)
            }
            AeadAlgorithm::Aes128Gcm => Self::seal::<Aes128Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256Gcm => Self::seal::<Aes256Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256GcmSiv => Self::seal::<Aes256GcmSiv>(key, nonce, aad, in_out),
        }
    }

    /// Opens into `in_out`, a buffer the caller's `SecretValue` owns; the plaintext is never
    /// copied out of it.
    fn open_in_place(
        _: Token,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &sealed::Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => {
                Self::open::<ChaCha20Poly1305>(key, nonce, aad, in_out)
            }
            AeadAlgorithm::Aes128Gcm => Self::open::<Aes128Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256Gcm => Self::open::<Aes256Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256GcmSiv => Self::open::<Aes256GcmSiv>(key, nonce, aad, in_out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RustCrypto;
    use crate::backend::contract;
    use crate::{AeadAlgorithm, AeadCipher};

    #[test]
    fn every_algorithm_is_supported() {
        for algorithm in [
            AeadAlgorithm::ChaCha20Poly1305,
            AeadAlgorithm::Aes128Gcm,
            AeadAlgorithm::Aes256Gcm,
            AeadAlgorithm::Aes256GcmSiv,
        ] {
            assert!(
                AeadCipher::<RustCrypto>::new(algorithm).is_ok(),
                "{algorithm}"
            );
        }
    }

    #[test]
    fn every_supported_algorithm_round_trips() {
        contract::every_supported_algorithm_round_trips::<RustCrypto>();
    }

    #[tokio::test]
    async fn a_64_byte_key_is_refused_by_every_aead_algorithm() {
        contract::a_64_byte_key_is_refused_by_every_aead_algorithm::<RustCrypto>().await;
    }

    #[tokio::test]
    async fn a_tampered_value_fails_to_open() {
        contract::a_tampered_value_fails_to_open::<RustCrypto>().await;
    }

    #[tokio::test]
    async fn a_value_shorter_than_nonce_and_tag_is_invalid() {
        contract::a_value_shorter_than_nonce_and_tag_is_invalid::<RustCrypto>().await;
    }

    #[tokio::test]
    async fn sealing_twice_gives_different_values() {
        contract::sealing_twice_gives_different_values::<RustCrypto>().await;
    }

    #[test]
    fn generated_keys_have_the_algorithm_length_and_differ() {
        contract::generated_keys_have_the_algorithm_length_and_differ::<RustCrypto>();
    }

    #[tokio::test]
    async fn a_value_sealed_by_0_28_1_opens() {
        contract::a_value_sealed_by_0_28_1_opens::<RustCrypto>().await;
    }
}
