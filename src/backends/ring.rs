use ::ring::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as AeadNonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    CHACHA20_POLY1305,
};
use ::ring::rand::{SecureRandom, SystemRandom};
use ::ring::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED,
    ECDSA_P256_SHA256_FIXED_SIGNING, ED25519,
};
use ::ring::{agreement, digest, hmac};
use secret_vault_value::SecretValue;

use super::private::Sealed;
use super::{
    AeadBackend, AeadBackendOps, Ed25519PublicKey, Failure, HmacSha256, HmacSha512, Nonce,
    Sha256Digest, Tag,
};
use crate::signing::private_key::Pkcs8SigningKey;
use std::convert::Infallible;

use crate::signing::{SigningAlgorithm, SigningInput};
use crate::{AeadAlgorithm, AsymmetricKekAlgorithm};

/// The [ring](https://crates.io/crates/ring) library, with the `ring` feature: ChaCha20-Poly1305,
/// AES-128-GCM and AES-256-GCM. It has no AES-256-GCM-SIV. It does not zeroise its expanded key
/// schedules, so they stay in freed memory after each call.
///
/// ring's RSA signs and verifies only, so it has no [`AsymmetricKekAlgorithm`]: the providers that
/// encrypt with a public key or decrypt with a local private key fail on it at construction, and a
/// reader on ring needs no RSA, since its KMS decrypts.
#[derive(Debug, Clone, Copy)]
pub struct Ring;

impl AeadBackend for Ring {
    const NAME: &'static str = "ring";
}

impl Sealed for Ring {}

impl AeadBackendOps for Ring {
    type RsaPublicKey = Infallible;
    type RsaPrivateKey = Infallible;

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
    fn hmac_sha256(key: &[u8], message: &[u8]) -> Result<HmacSha256, Failure> {
        let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), message);
        HmacSha256::try_from(tag.as_ref()).map_err(|_| Failure::Operation)
    }

    fn hmac_sha512(key: &[u8], message: &[&[u8]], out: &mut HmacSha512) -> Result<(), Failure> {
        let mut context = hmac::Context::with_key(&hmac::Key::new(hmac::HMAC_SHA512, key));
        for part in message {
            context.update(part);
        }
        let tag = context.sign();
        if tag.as_ref().len() != out.len() {
            return Err(Failure::Operation);
        }
        out.copy_from_slice(tag.as_ref());
        Ok(())
    }

    fn sha256(message: &[u8]) -> Result<Sha256Digest, Failure> {
        Sha256Digest::try_from(digest::digest(&digest::SHA256, message).as_ref())
            .map_err(|_| Failure::Operation)
    }

    fn check_verifying_key(algorithm: SigningAlgorithm, public_key: &[u8]) -> Result<(), Failure> {
        match algorithm {
            // ring has no call that decodes an Ed25519 point on its own: it refuses one off the
            // curve at verification.
            SigningAlgorithm::Ed25519 => Ok(()),
            // ring checks a P-256 point only where it uses one, so an ECDH agreement with a
            // throwaway key is the check that the point is on the curve.
            SigningAlgorithm::EcdsaP256Sha256 => {
                let rng = SystemRandom::new();
                let ephemeral =
                    agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &rng)
                        .map_err(|_| Failure::Operation)?;
                agreement::agree_ephemeral(
                    ephemeral,
                    &agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, public_key),
                    |_| (),
                )
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
        let algorithm: &'static dyn ::ring::signature::VerificationAlgorithm = match algorithm {
            SigningAlgorithm::Ed25519 => &ED25519,
            SigningAlgorithm::EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED,
        };
        UnparsedPublicKey::new(algorithm, public_key)
            .verify(pre_image, signature)
            .map_err(|_| Failure::Operation)
    }

    fn ed25519_public_key(seed: &[u8]) -> Result<Ed25519PublicKey, Failure> {
        let key_pair = Ed25519KeyPair::from_seed_unchecked(seed).map_err(|_| Failure::Key)?;
        Ed25519PublicKey::try_from(key_pair.public_key().as_ref()).map_err(|_| Failure::Key)
    }

    fn check_signing_key(
        algorithm: SigningAlgorithm,
        private_key: &[u8],
        public_key: &[u8],
    ) -> Result<(), Failure> {
        match algorithm {
            SigningAlgorithm::Ed25519 => {
                Ed25519KeyPair::from_seed_and_public_key(private_key, public_key)
                    .map(|_| ())
                    .map_err(|_| Failure::Key)
            }
            SigningAlgorithm::EcdsaP256Sha256 => EcdsaKeyPair::from_private_key_and_public_key(
                &ECDSA_P256_SHA256_FIXED_SIGNING,
                private_key,
                public_key,
                &SystemRandom::new(),
            )
            .map(|_| ())
            .map_err(|_| Failure::Key),
        }
    }

    fn sign(
        private_key: &[u8],
        public_key: &[u8],
        input: &SigningInput<'_>,
    ) -> Result<Vec<u8>, Failure> {
        match *input {
            SigningInput::Ed25519 { pre_image } => {
                let key_pair = Ed25519KeyPair::from_seed_and_public_key(private_key, public_key)
                    .map_err(|_| Failure::Key)?;
                Ok(key_pair.sign(pre_image).as_ref().to_vec())
            }
            // ring's ECDSA signing hashes its input, so it takes the pre-image, not the digest.
            SigningInput::EcdsaP256Sha256 { pre_image, .. } => {
                let rng = SystemRandom::new();
                let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    private_key,
                    public_key,
                    &rng,
                )
                .map_err(|_| Failure::Key)?;
                key_pair
                    .sign(&rng, pre_image)
                    .map(|signature| signature.as_ref().to_vec())
                    .map_err(|_| Failure::Operation)
            }
        }
    }

    fn generate_signing_key(
        algorithm: SigningAlgorithm,
    ) -> Result<(SecretValue, Vec<u8>), Failure> {
        match algorithm {
            SigningAlgorithm::Ed25519 => {
                let mut seed = SecretValue::new(vec![0; 32]);
                Self::fill_random(seed.ref_sensitive_value_mut())?;
                let public_key = Self::ed25519_public_key(seed.ref_sensitive_value())?;
                Ok((seed, public_key.to_vec()))
            }
            // ring generates a P-256 key only as a PKCS#8 document.
            SigningAlgorithm::EcdsaP256Sha256 => {
                let document = EcdsaKeyPair::generate_pkcs8(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    &SystemRandom::new(),
                )
                .map_err(|_| Failure::Operation)?;
                let key = Pkcs8SigningKey::from_der(document.as_ref()).map_err(|_| Failure::Key)?;
                Ok((key.private_key, key.public_key.ok_or(Failure::Key)?))
            }
        }
    }

    fn supports_asymmetric_kek(_algorithm: AsymmetricKekAlgorithm) -> bool {
        false
    }

    fn rsa_public_key(_spki_der: &[u8]) -> Result<Self::RsaPublicKey, Failure> {
        Err(Failure::Key)
    }

    fn rsa_oaep_sha256_encrypt(
        public_key: &Self::RsaPublicKey,
        _message: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        match *public_key {}
    }

    fn rsa_private_key(_pkcs8_der: &[u8]) -> Result<Self::RsaPrivateKey, Failure> {
        Err(Failure::Key)
    }

    fn rsa_private_key_bits(private_key: &Self::RsaPrivateKey) -> usize {
        match *private_key {}
    }

    fn rsa_public_key_der(private_key: &Self::RsaPrivateKey) -> Result<Vec<u8>, Failure> {
        match *private_key {}
    }

    fn rsa_oaep_sha256_decrypt(
        private_key: &Self::RsaPrivateKey,
        _block: &[u8],
    ) -> Result<SecretValue, Failure> {
        match *private_key {}
    }

    fn generate_rsa_private_key(_bits: usize) -> Result<SecretValue, Failure> {
        Err(Failure::Key)
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
