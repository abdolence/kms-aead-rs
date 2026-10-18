use aes_gcm::aead::{AeadInOut, KeyInit, Nonce as AeadNonce, Tag as AeadTag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::private::Sealed;
use super::{AeadBackend, AeadBackendOps, Failure, HmacSha256, Nonce, Tag};
use crate::AeadAlgorithm;

/// The pure-Rust [RustCrypto](https://github.com/RustCrypto/AEADs) crates, with the `rustcrypto`
/// feature: every [`AeadAlgorithm`], with `getrandom` as the CSPRNG. Needs no C compiler. The
/// feature turns on the crates' `zeroize` features, so their key objects, and the Poly1305 and
/// POLYVAL keys each call derives, are zeroised when dropped.
#[derive(Debug, Clone, Copy)]
pub struct RustCrypto;

impl AeadBackend for RustCrypto {
    const NAME: &'static str = "rustcrypto";
}

impl Sealed for RustCrypto {}

impl AeadBackendOps for RustCrypto {
    fn supports(algorithm: AeadAlgorithm) -> bool {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305
            | AeadAlgorithm::Aes128Gcm
            | AeadAlgorithm::Aes256Gcm
            | AeadAlgorithm::Aes256GcmSiv => true,
        }
    }

    fn fill_random(out: &mut [u8]) -> Result<(), Failure> {
        getrandom::fill(out).map_err(|_| Failure::Operation)
    }

    fn seal_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<Tag, Failure> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => seal::<ChaCha20Poly1305>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes128Gcm => seal::<Aes128Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256Gcm => seal::<Aes256Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256GcmSiv => seal::<Aes256GcmSiv>(key, nonce, aad, in_out),
        }
    }

    fn open_in_place(
        algorithm: AeadAlgorithm,
        key: &[u8],
        nonce: &Nonce,
        aad: &[u8],
        in_out: &mut [u8],
    ) -> Result<usize, Failure> {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => open::<ChaCha20Poly1305>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes128Gcm => open::<Aes128Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256Gcm => open::<Aes256Gcm>(key, nonce, aad, in_out),
            AeadAlgorithm::Aes256GcmSiv => open::<Aes256GcmSiv>(key, nonce, aad, in_out),
        }
    }
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<HmacSha256, Failure> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| Failure::Key)?;
        mac.update(message);
        Ok(mac.finalize().into_bytes().into())
    }
}

fn seal<C: KeyInit + AeadInOut>(
    key: &[u8],
    nonce: &Nonce,
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<Tag, Failure> {
    let cipher = C::new_from_slice(key).map_err(|_| Failure::Key)?;
    let nonce = <&AeadNonce<C>>::try_from(nonce.as_slice()).map_err(|_| Failure::Operation)?;
    let tag = cipher
        .encrypt_inout_detached(nonce, aad, in_out.into())
        .map_err(|_| Failure::Operation)?;
    Tag::try_from(tag.as_slice()).map_err(|_| Failure::Operation)
}

fn open<C: KeyInit + AeadInOut>(
    key: &[u8],
    nonce: &Nonce,
    aad: &[u8],
    in_out: &mut [u8],
) -> Result<usize, Failure> {
    let cipher = C::new_from_slice(key).map_err(|_| Failure::Key)?;
    let nonce = <&AeadNonce<C>>::try_from(nonce.as_slice()).map_err(|_| Failure::Operation)?;
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
