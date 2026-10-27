use aws_lc_rs::aead::{
    Aad, Algorithm, LessSafeKey, Nonce as AeadNonce, UnboundKey, AES_128_GCM, AES_256_GCM,
    AES_256_GCM_SIV, CHACHA20_POLY1305,
};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::{
    KeySize, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
    PublicEncryptingKey, OAEP_SHA256_MGF1SHA256,
};
use aws_lc_rs::signature::{
    EcdsaKeyPair, Ed25519KeyPair, KeyPair, ParsedPublicKey, UnparsedPublicKey,
    VerificationAlgorithm, ECDSA_P256_SHA256_FIXED, ECDSA_P256_SHA256_FIXED_SIGNING, ED25519,
};
use aws_lc_rs::{digest, hmac};
use secret_vault_value::SecretValue;

use super::private::Sealed;
use super::{
    AeadBackend, AeadBackendOps, Ed25519PublicKey, Failure, HmacSha256, HmacSha512, Nonce,
    Sha256Digest, Tag,
};
use crate::signing::private_key::Pkcs8SigningKey;
use crate::signing::{SigningAlgorithm, SigningInput};
use crate::{AeadAlgorithm, AsymmetricKekAlgorithm};

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
///
/// RSA-OAEP, the encryption under an asymmetric KEK and the decryption under a local one, runs on
/// AWS-LC's RSA, whose private keys AWS-LC's allocator clears as it frees them.
#[derive(Debug, Clone, Copy)]
pub struct AwsLc;

impl AeadBackend for AwsLc {
    const NAME: &'static str = "aws-lc";
}

impl Sealed for AwsLc {}

impl AeadBackendOps for AwsLc {
    type RsaPublicKey = OaepPublicEncryptingKey;
    type RsaPrivateKey = PrivateDecryptingKey;

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
        // AWS-LC decodes a P-256 point and checks it is on the curve as it parses the key; it
        // takes an Ed25519 key's bytes as they are and refuses a point off the curve at
        // verification.
        ParsedPublicKey::new(verification_algorithm(algorithm), public_key)
            .map(|_| ())
            .map_err(|_| Failure::Key)
    }

    fn verify(
        algorithm: SigningAlgorithm,
        public_key: &[u8],
        pre_image: &[u8],
        signature: &[u8],
    ) -> Result<(), Failure> {
        UnparsedPublicKey::new(verification_algorithm(algorithm), public_key)
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
            // aws-lc-rs's ECDSA signing hashes its input, so it takes the pre-image, not the
            // digest.
            SigningInput::EcdsaP256Sha256 { pre_image, .. } => {
                let key_pair = EcdsaKeyPair::from_private_key_and_public_key(
                    &ECDSA_P256_SHA256_FIXED_SIGNING,
                    private_key,
                    public_key,
                )
                .map_err(|_| Failure::Key)?;
                key_pair
                    .sign(&SystemRandom::new(), pre_image)
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

    fn supports_asymmetric_kek(algorithm: AsymmetricKekAlgorithm) -> bool {
        match algorithm {
            AsymmetricKekAlgorithm::RsaOaepSha256 => true,
        }
    }

    fn rsa_public_key(spki_der: &[u8]) -> Result<Self::RsaPublicKey, Failure> {
        PublicEncryptingKey::from_der(spki_der)
            .map_err(|_| Failure::Key)
            .and_then(|key| OaepPublicEncryptingKey::new(key).map_err(|_| Failure::Key))
    }

    fn rsa_oaep_sha256_encrypt(
        public_key: &Self::RsaPublicKey,
        message: &[u8],
    ) -> Result<Vec<u8>, Failure> {
        let mut block = vec![0; public_key.ciphertext_size()];
        let len = public_key
            .encrypt(&OAEP_SHA256_MGF1SHA256, message, &mut block, None)
            .map_err(|_| Failure::Operation)?
            .len();
        block.truncate(len);
        Ok(block)
    }

    fn rsa_private_key(pkcs8_der: &[u8]) -> Result<Self::RsaPrivateKey, Failure> {
        PrivateDecryptingKey::from_pkcs8(pkcs8_der).map_err(|_| Failure::Key)
    }

    fn rsa_private_key_bits(private_key: &Self::RsaPrivateKey) -> usize {
        private_key.key_size_bits()
    }

    fn rsa_public_key_der(private_key: &Self::RsaPrivateKey) -> Result<Vec<u8>, Failure> {
        private_key
            .public_key()
            .as_der()
            .map(|der| der.as_ref().to_vec())
            .map_err(|_| Failure::Key)
    }

    fn rsa_oaep_sha256_decrypt(
        private_key: &Self::RsaPrivateKey,
        block: &[u8],
    ) -> Result<SecretValue, Failure> {
        let key = OaepPrivateDecryptingKey::new(private_key.clone()).map_err(|_| Failure::Key)?;
        let mut message = SecretValue::new(vec![0; key.min_output_size()]);
        let len = key
            .decrypt(
                &OAEP_SHA256_MGF1SHA256,
                block,
                message.ref_sensitive_value_mut(),
                None,
            )
            .map_err(|_| Failure::Operation)?
            .len();
        message.ref_sensitive_value_mut().truncate(len);
        Ok(message)
    }

    fn generate_rsa_private_key(bits: usize) -> Result<SecretValue, Failure> {
        let size = match bits {
            2048 => KeySize::Rsa2048,
            3072 => KeySize::Rsa3072,
            4096 => KeySize::Rsa4096,
            _ => return Err(Failure::Key),
        };
        let key = PrivateDecryptingKey::generate(size).map_err(|_| Failure::Operation)?;
        let pkcs8 = key.as_der().map_err(|_| Failure::Operation)?;
        Ok(SecretValue::new(pkcs8.as_ref().to_vec()))
    }
}

fn verification_algorithm(algorithm: SigningAlgorithm) -> &'static dyn VerificationAlgorithm {
    match algorithm {
        SigningAlgorithm::Ed25519 => &ED25519,
        SigningAlgorithm::EcdsaP256Sha256 => &ECDSA_P256_SHA256_FIXED,
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
