use aes_gcm::aead::{AeadInOut, KeyInit, Nonce, Tag as AeadTag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::ChaCha20Poly1305;

use super::{AeadBackendOps, Failure, Tag};
use crate::AeadAlgorithm;

pub(super) struct RustCryptoOps;

impl RustCryptoOps {
    fn seal<C: KeyInit + AeadInOut>(
        key: &[u8],
        nonce: &super::Nonce,
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
        nonce: &super::Nonce,
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

impl AeadBackendOps for RustCryptoOps {
    fn name(&self) -> &'static str {
        "rustcrypto"
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
        getrandom::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &super::Nonce,
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

    fn open_in_place(
        &self,
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &super::Nonce,
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
