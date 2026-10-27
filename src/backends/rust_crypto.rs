use aes_gcm::aead::{AeadInOut, KeyInit, Nonce as AeadNonce, Tag as AeadTag};
use aes_gcm::{Aes128Gcm, Aes256Gcm};
use aes_gcm_siv::Aes256GcmSiv;
use chacha20::rand_core::SeedableRng;
use chacha20::ChaCha20Rng;
use chacha20poly1305::ChaCha20Poly1305;
use ed25519_dalek::Signer as _;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::signature::Verifier as _;
use rsa::oaep::Oaep;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey};
use rsa::traits::{PaddingScheme, PublicKeyParts};
use rsa::{RsaPrivateKey, RsaPublicKey};
use secret_vault_value::SecretValue;
use sha2::{Digest, Sha256, Sha512};

use super::private::Sealed;
use super::{
    AeadBackend, AeadBackendOps, Ed25519PublicKey, Failure, HmacSha256, HmacSha512, Nonce,
    Sha256Digest, Tag,
};
use crate::signing::{SigningAlgorithm, SigningInput};
use crate::{AeadAlgorithm, AsymmetricKekAlgorithm};

/// The pure-Rust [RustCrypto](https://github.com/RustCrypto/AEADs) crates, with the `rustcrypto`
/// feature: every [`AeadAlgorithm`], with `getrandom` as the CSPRNG. Needs no C compiler. The
/// feature turns on the crates' `zeroize` features, so their key objects, and the Poly1305 and
/// POLYVAL keys each call derives, are zeroised when dropped. Signatures run on `ed25519-dalek`
/// and `p256`, whose signing keys are zeroised when dropped too.
///
/// RSA-OAEP runs on the [`rsa`](https://crates.io/crates/rsa) crate, whose private keys are
/// zeroised when dropped. Its private-key operations are not constant time,
/// [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html): a local asymmetric
/// KEK on this backend decrypts with the crate's blinded decryption, and decrypts DEKs from trusted
/// sources only. Encrypting with the public key is a public-key operation, outside the advisory.
#[derive(Debug, Clone, Copy)]
pub struct RustCrypto;

impl AeadBackend for RustCrypto {
    const NAME: &'static str = "rustcrypto";
}

impl Sealed for RustCrypto {}

impl AeadBackendOps for RustCrypto {
    type RsaPublicKey = RsaPublicKey;
    type RsaPrivateKey = RsaPrivateKey;

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

    fn hmac_sha512(key: &[u8], message: &[&[u8]], out: &mut HmacSha512) -> Result<(), Failure> {
        let mut mac = Hmac::<Sha512>::new_from_slice(key).map_err(|_| Failure::Key)?;
        for part in message {
            mac.update(part);
        }
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }

    fn sha256(message: &[u8]) -> Result<Sha256Digest, Failure> {
        Ok(Sha256::digest(message).into())
    }

    fn check_verifying_key(algorithm: SigningAlgorithm, public_key: &[u8]) -> Result<(), Failure> {
        match algorithm {
            SigningAlgorithm::Ed25519 => ed25519_verifying_key(public_key).map(|_| ()),
            SigningAlgorithm::EcdsaP256Sha256 => {
                p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map(|_| ())
                    .map_err(|_| Failure::Key)
            }
        }
    }

    fn verify(
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        pre_image: &[u8],
        signature: &[u8],
    ) -> Result<(), Failure> {
        match algorithm {
            SigningAlgorithm::Ed25519 => {
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| Failure::Operation)?;
                ed25519_verifying_key(public_key)?
                    .verify_strict(pre_image, &signature)
                    .map_err(|_| Failure::Operation)
            }
            SigningAlgorithm::EcdsaP256Sha256 => {
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| Failure::Operation)?;
                p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key)
                    .map_err(|_| Failure::Key)?
                    .verify(pre_image, &signature)
                    .map_err(|_| Failure::Operation)
            }
        }
    }

    fn ed25519_public_key(seed: &[u8]) -> Result<Ed25519PublicKey, Failure> {
        Ok(ed25519_signing_key(seed)?.verifying_key().to_bytes())
    }

    fn check_signing_key(
        algorithm: SigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), Failure> {
        let derived = match algorithm {
            SigningAlgorithm::Ed25519 => Self::ed25519_public_key(private_key)?.to_vec(),
            SigningAlgorithm::EcdsaP256Sha256 => p256_public_key(&p256_signing_key(private_key)?),
        };
        if derived == public_key {
            Ok(())
        } else {
            Err(Failure::Key)
        }
    }

    fn sign(
        private_key: &[u8],
        _public_key: &[u8],
        input: &SigningInput<'_>,
    ) -> Result<Vec<u8>, Failure> {
        match *input {
            SigningInput::Ed25519 { pre_image } => Ok(ed25519_signing_key(private_key)?
                .try_sign(pre_image)
                .map_err(|_| Failure::Operation)?
                .to_bytes()
                .to_vec()),
            // p256 signs the digest, with a nonce derived from the key and the digest as RFC 6979
            // derives it.
            SigningInput::EcdsaP256Sha256 { digest, .. } => {
                let signature: p256::ecdsa::Signature = p256_signing_key(private_key)?
                    .sign_prehash(digest)
                    .map_err(|_| Failure::Operation)?;
                Ok(signature.to_bytes().to_vec())
            }
        }
    }

    fn generate_signing_key(
        algorithm: SigningAlgorithm,
    ) -> Result<(SecretValue, Vec<u8>), Failure> {
        let mut private_key = SecretValue::new(vec![0; 32]);
        match algorithm {
            SigningAlgorithm::Ed25519 => {
                Self::fill_random(private_key.ref_sensitive_value_mut())?;
                let public_key = Self::ed25519_public_key(private_key.ref_sensitive_value())?;
                Ok((private_key, public_key.to_vec()))
            }
            // A random 32 bytes are a P-256 scalar unless they are zero or not below the group
            // order, about once in 2^32 draws, so a few draws always find one.
            SigningAlgorithm::EcdsaP256Sha256 => {
                for _ in 0..P256_SCALAR_DRAWS {
                    Self::fill_random(private_key.ref_sensitive_value_mut())?;
                    if let Ok(key) = p256_signing_key(private_key.ref_sensitive_value()) {
                        return Ok((private_key, p256_public_key(&key)));
                    }
                }
                Err(Failure::Operation)
            }
        }
    }

    fn supports_asymmetric_kek(algorithm: AsymmetricKekAlgorithm) -> bool {
        match algorithm {
            AsymmetricKekAlgorithm::RsaOaepSha256 => true,
        }
    }

    fn rsa_public_key(spki_der: &[u8]) -> Result<Self::RsaPublicKey, Failure> {
        RsaPublicKey::from_public_key_der(spki_der).map_err(|_| Failure::Key)
    }

    fn rsa_oaep_sha256_encrypt(
        public_key: &Self::RsaPublicKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        // Through the padding scheme rather than `RsaPublicKey::encrypt`, which takes a generator
        // that cannot fail: a failure of the system CSPRNG is an error here, not a panic.
        Oaep::<Sha256>::new()
            .encrypt(&mut getrandom::SysRng, public_key, message)
            .map_err(|_| Failure::Operation)
    }

    fn rsa_private_key(pkcs8_der: &[u8]) -> Result<Self::RsaPrivateKey, Failure> {
        RsaPrivateKey::from_pkcs8_der(pkcs8_der).map_err(|_| Failure::Key)
    }

    fn rsa_private_key_bits(private_key: &Self::RsaPrivateKey) -> usize {
        usize::try_from(private_key.n().bits_vartime()).unwrap_or(usize::MAX)
    }

    fn rsa_public_key_der(private_key: &Self::RsaPrivateKey) -> Result<Vec<u8>, Failure> {
        private_key
            .to_public_key()
            .to_public_key_der()
            .map(|der| der.as_bytes().to_vec())
            .map_err(|_| Failure::Key)
    }

    fn rsa_oaep_sha256_decrypt(
        private_key: &Self::RsaPrivateKey,
        block: &[u8],
    ) -> Result<SecretValue, Failure> {
        // Blinded with the system CSPRNG, which masks the timing of the modular exponentiation.
        Oaep::<Sha256>::new()
            .decrypt(Some(&mut getrandom::SysRng), private_key, block)
            .map(SecretValue::new)
            .map_err(|_| Failure::Operation)
    }

    fn generate_rsa_private_key(bits: usize) -> Result<SecretValue, Failure> {
        // `RsaPrivateKey::new` takes a generator that cannot fail, so the fallible system CSPRNG
        // only seeds one: a failure of the CSPRNG is an error of the generation, as on the other
        // backends.
        let mut seed = vec![0; 32];
        getrandom::fill(&mut seed).map_err(|_| Failure::Operation)?;
        let seed = SecretValue::new(seed);
        let seed = <[u8; 32]>::try_from(seed.ref_sensitive_value().as_slice())
            .map_err(|_| Failure::Operation)?;
        let generated = RsaPrivateKey::new(&mut ChaCha20Rng::from_seed(seed), bits)
            .map_err(|_| Failure::Key)?;
        let pkcs8 = generated.to_pkcs8_der().map_err(|_| Failure::Key)?;
        Ok(SecretValue::new(pkcs8.as_bytes().to_vec()))
    }
}

/// The most draws of random bytes for a P-256 scalar before key generation fails.
const P256_SCALAR_DRAWS: usize = 8;

fn ed25519_verifying_key(public_key: &[u8]) -> Result<ed25519_dalek::VerifyingKey, Failure> {
    let bytes = <&[u8; 32]>::try_from(public_key).map_err(|_| Failure::Key)?;
    ed25519_dalek::VerifyingKey::from_bytes(bytes).map_err(|_| Failure::Key)
}

fn ed25519_signing_key(seed: &[u8]) -> Result<ed25519_dalek::SigningKey, Failure> {
    let seed = <&[u8; 32]>::try_from(seed).map_err(|_| Failure::Key)?;
    Ok(ed25519_dalek::SigningKey::from_bytes(seed))
}

fn p256_signing_key(scalar: &[u8]) -> Result<p256::ecdsa::SigningKey, Failure> {
    p256::ecdsa::SigningKey::from_slice(scalar).map_err(|_| Failure::Key)
}

/// The uncompressed point of `key`'s public key.
fn p256_public_key(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    key.verifying_key().to_sec1_point(false).as_bytes().to_vec()
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
