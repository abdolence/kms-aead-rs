//! What every backend does through `AeadCipher` and `DeterministicCipher`, run for every enabled
//! backend and every algorithm it implements, so that the backends cannot drift apart.

use std::collections::HashSet;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadError;
#[cfg(feature = "aws-lc-rs")]
use crate::AwsLc;
#[cfg(feature = "ring")]
use crate::Ring;
#[cfg(feature = "rustcrypto")]
use crate::RustCrypto;
use crate::{
    generate_random_bytes, AeadAlgorithm, AeadBackend, AeadCipher, BeaconAlgorithm, BeaconBits,
    BeaconMac, CipherText, DataEncryptionKey, KeyId, KmsAeadResult,
};
#[cfg(feature = "deterministic")]
use crate::{DeterministicAlgorithm, DeterministicCipher, DeterministicCipherText};

const AAD: &[u8] = b"orders/1042/card";
const PLAIN_TEXT: &str = "4111 1111 1111 1111";

/// Every cipher of `B`: one per algorithm it implements.
fn ciphers<B: AeadBackend>() -> impl Iterator<Item = AeadCipher<B>> {
    AeadAlgorithm::ALL
        .into_iter()
        .filter_map(|algorithm| AeadCipher::new(algorithm).ok())
}

/// A value one backend sealed, for the others to open.
struct SealedValue<C> {
    backend: &'static str,
    key: DataEncryptionKey,
    cipher_text: C,
}

/// The other tests skip the pairs a backend does not implement, so they would still pass with
/// one of them dropped.
#[test]
fn every_aead_algorithm_is_supported() -> KmsAeadResult<()> {
    #[cfg(feature = "ring")]
    for algorithm in [
        AeadAlgorithm::ChaCha20Poly1305,
        AeadAlgorithm::Aes128Gcm,
        AeadAlgorithm::Aes256Gcm,
    ] {
        AeadCipher::<Ring>::new(algorithm)?;
    }
    #[cfg(feature = "aws-lc-rs")]
    for algorithm in AeadAlgorithm::ALL {
        AeadCipher::<AwsLc>::new(algorithm)?;
    }
    #[cfg(feature = "rustcrypto")]
    for algorithm in AeadAlgorithm::ALL {
        AeadCipher::<RustCrypto>::new(algorithm)?;
    }
    Ok(())
}

#[cfg(feature = "ring")]
#[test]
fn ring_refuses_aes_256_gcm_siv_at_construction() {
    let result = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256GcmSiv);

    assert!(
        matches!(&result, Err(KmsAeadError::UnsupportedAlgorithm(error))
            if error.public.code == "UNSUPPORTED_ALGORITHM"
                && error.algorithm == AeadAlgorithm::Aes256GcmSiv),
        "{result:?}"
    );
}

/// Opening a sealed value gives back the plain text, for any plain text and AAD, and the value
/// is the nonce, the cipher text and the tag.
#[test]
fn every_supported_algorithm_round_trips() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let inputs = (vec(any::<u8>(), 0..4096), vec(any::<u8>(), 0..256));
        for cipher in ciphers::<B>() {
            let key = cipher.generate_key()?;
            TestRunner::default()
                .run(&inputs, |(plain_text, aad)| {
                    let plain_text = SecretValue::new(plain_text);
                    let cipher_text = cipher.encrypt_value(&aad, &plain_text, &key)?;
                    prop_assert_eq!(
                        cipher_text.value().len(),
                        AeadAlgorithm::NONCE_LEN
                            + plain_text.ref_sensitive_value().len()
                            + AeadAlgorithm::TAG_LEN
                    );
                    prop_assert_eq!(cipher.decrypt_value(&aad, &cipher_text, &key)?, plain_text);
                    Ok(())
                })
                .unwrap_or_else(|failure| panic!("{cipher:?}: {failure}"));
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

/// Every backend writes the same layout, so a value sealed by one backend opens with every other
/// that implements its algorithm.
#[test]
fn a_value_sealed_by_one_backend_opens_with_every_other() -> KmsAeadResult<()> {
    fn seal<B: AeadBackend>(
        algorithm: AeadAlgorithm,
        sealed: &mut Vec<SealedValue<CipherText>>,
    ) -> KmsAeadResult<()> {
        if let Ok(cipher) = AeadCipher::<B>::new(algorithm) {
            let key = cipher.generate_key()?;
            let cipher_text = cipher.encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT), &key)?;
            sealed.push(SealedValue {
                backend: B::NAME,
                key,
                cipher_text,
            });
        }
        Ok(())
    }

    fn open<B: AeadBackend>(
        algorithm: AeadAlgorithm,
        sealed: &[SealedValue<CipherText>],
    ) -> KmsAeadResult<()> {
        if let Ok(cipher) = AeadCipher::<B>::new(algorithm) {
            for value in sealed {
                assert_eq!(
                    cipher.decrypt_value(AAD, &value.cipher_text, &value.key)?,
                    SecretValue::from(PLAIN_TEXT),
                    "{algorithm} sealed by {} and opened by {}",
                    value.backend,
                    B::NAME
                );
            }
        }
        Ok(())
    }

    for algorithm in AeadAlgorithm::ALL {
        let mut sealed = Vec::new();
        #[cfg(feature = "ring")]
        seal::<Ring>(algorithm, &mut sealed)?;
        #[cfg(feature = "aws-lc-rs")]
        seal::<AwsLc>(algorithm, &mut sealed)?;
        #[cfg(feature = "rustcrypto")]
        seal::<RustCrypto>(algorithm, &mut sealed)?;

        #[cfg(feature = "ring")]
        open::<Ring>(algorithm, &sealed)?;
        #[cfg(feature = "aws-lc-rs")]
        open::<AwsLc>(algorithm, &sealed)?;
        #[cfg(feature = "rustcrypto")]
        open::<RustCrypto>(algorithm, &sealed)?;
    }
    Ok(())
}

/// Every backend seals AES-SIV with the same implementation today, so a deterministic value
/// sealed under one backend is the value every other seals, and opens there.
#[cfg(feature = "deterministic")]
#[test]
fn a_deterministic_value_sealed_by_one_backend_opens_with_every_other() -> KmsAeadResult<()> {
    fn seal<B: AeadBackend>(
        algorithm: DeterministicAlgorithm,
        sealed: &mut Vec<SealedValue<DeterministicCipherText>>,
    ) -> KmsAeadResult<()> {
        let cipher = DeterministicCipher::<B>::new(algorithm)?;
        let key = cipher.generate_key()?;
        let cipher_text = cipher.encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT), &key)?;
        sealed.push(SealedValue {
            backend: B::NAME,
            key,
            cipher_text,
        });
        Ok(())
    }

    fn open<B: AeadBackend>(
        algorithm: DeterministicAlgorithm,
        sealed: &[SealedValue<DeterministicCipherText>],
    ) -> KmsAeadResult<()> {
        let cipher = DeterministicCipher::<B>::new(algorithm)?;
        let plain_text = SecretValue::from(PLAIN_TEXT);
        for value in sealed {
            assert_eq!(
                cipher.encrypt_value(AAD, &plain_text, &value.key)?,
                value.cipher_text,
                "{algorithm} sealed by {} and by {}",
                value.backend,
                B::NAME
            );
            assert_eq!(
                cipher.decrypt_value(AAD, &value.cipher_text, &value.key)?,
                plain_text,
                "{algorithm} sealed by {} and opened by {}",
                value.backend,
                B::NAME
            );
        }
        Ok(())
    }

    for algorithm in DeterministicAlgorithm::ALL {
        let mut sealed = Vec::new();
        #[cfg(feature = "ring")]
        seal::<Ring>(algorithm, &mut sealed)?;
        #[cfg(feature = "aws-lc-rs")]
        seal::<AwsLc>(algorithm, &mut sealed)?;
        #[cfg(feature = "rustcrypto")]
        seal::<RustCrypto>(algorithm, &mut sealed)?;

        #[cfg(feature = "ring")]
        open::<Ring>(algorithm, &sealed)?;
        #[cfg(feature = "aws-lc-rs")]
        open::<AwsLc>(algorithm, &sealed)?;
        #[cfg(feature = "rustcrypto")]
        open::<RustCrypto>(algorithm, &sealed)?;
    }
    Ok(())
}

#[test]
fn a_64_byte_key_is_refused_by_every_aead_algorithm() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let deterministic_sized_key = DataEncryptionKey::from(SecretValue::new(vec![0x42; 64]));
        let plain_text = SecretValue::from(PLAIN_TEXT);
        for cipher in ciphers::<B>() {
            let sealed = cipher.encrypt_value(AAD, &plain_text, &deterministic_sized_key);
            assert!(
                matches!(&sealed, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_LENGTH"),
                "{cipher:?} seals: {sealed:?}"
            );

            let key = cipher.generate_key()?;
            let cipher_text = cipher.encrypt_value(AAD, &plain_text, &key)?;
            let opened = cipher.decrypt_value(AAD, &cipher_text, &deterministic_sized_key);
            assert!(
                matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_LENGTH"),
                "{cipher:?} opens: {opened:?}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

#[test]
fn a_tampered_value_fails_to_open() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let plain_text = SecretValue::from(PLAIN_TEXT);
        for cipher in ciphers::<B>() {
            let key = cipher.generate_key()?;
            let other_key = cipher.generate_key()?;
            let cipher_text = cipher.encrypt_value(AAD, &plain_text, &key)?;
            let last = cipher_text.value().len() - 1;
            let flipped = |index: usize| {
                let mut bytes = cipher_text.value().clone();
                bytes[index] ^= 0x01;
                CipherText(bytes)
            };
            let cases: [(&str, &[u8], CipherText, &DataEncryptionKey); 5] = [
                (
                    "another AAD",
                    b"orders/1043/card",
                    cipher_text.clone(),
                    &key,
                ),
                ("another key", AAD, cipher_text.clone(), &other_key),
                ("a flipped nonce bit", AAD, flipped(0), &key),
                (
                    "a flipped cipher text bit",
                    AAD,
                    flipped(AeadAlgorithm::NONCE_LEN),
                    &key,
                ),
                ("a flipped tag bit", AAD, flipped(last), &key),
            ];
            for (case, aad, value, key) in cases {
                let opened = cipher.decrypt_value(aad, &value, key);
                assert!(
                    matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                        if error.public.code == "DECRYPT"),
                    "{cipher:?} with {case}: {opened:?}"
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

#[test]
fn a_value_shorter_than_nonce_and_tag_is_invalid() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        for cipher in ciphers::<B>() {
            let key = cipher.generate_key()?;
            for len in [
                0,
                AeadAlgorithm::NONCE_LEN - 1,
                AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN - 1,
            ] {
                let short = CipherText(vec![0xAA; len]);
                let opened = cipher.decrypt_value(AAD, &short, &key);
                assert!(
                    matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                        if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                    "{cipher:?} with {len} bytes: {opened:?}"
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

#[test]
fn sealing_twice_gives_different_values() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let plain_text = SecretValue::from(PLAIN_TEXT);
        for cipher in ciphers::<B>() {
            let key = cipher.generate_key()?;
            let mut nonces = HashSet::new();
            for _ in 0..100 {
                let cipher_text = cipher.encrypt_value(AAD, &plain_text, &key)?;
                nonces.insert(cipher_text.value()[..AeadAlgorithm::NONCE_LEN].to_vec());
            }
            assert_eq!(nonces.len(), 100, "{cipher:?}");
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

#[test]
fn generated_keys_have_the_algorithm_length_and_differ() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        for cipher in ciphers::<B>() {
            let mut keys = HashSet::new();
            for _ in 0..100 {
                let key = cipher.generate_key()?;
                keys.insert(key.value().ref_sensitive_value().clone());
            }
            assert_eq!(keys.len(), 100, "{cipher:?}");
            assert!(
                keys.iter()
                    .all(|key| key.len() == cipher.algorithm().key_len()),
                "{cipher:?}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

#[test]
fn random_bytes_have_the_requested_length_and_differ() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        for len in [0, 33] {
            let random = generate_random_bytes::<B>(len)?;
            assert_eq!(random.ref_sensitive_value().len(), len, "{}", B::NAME);
        }
        assert_ne!(
            generate_random_bytes::<B>(32)?,
            generate_random_bytes::<B>(32)?,
            "{}",
            B::NAME
        );
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

/// The AEAD layer of every envelope layout: kms-aead 0.28.1 output with the default algorithm.
#[test]
fn a_value_sealed_by_0_28_1_opens() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let key = DataEncryptionKey::from(SecretValue::new(
            hex::decode("ee1b4efa8e3b1f550edfe8fe963d575b8cbf4e1f686e8c512ac7e4b3b1b7dd0a")
                .unwrap(),
        ));
        let cipher_text = CipherText(
            hex::decode(
                "f77db8c591c62b724b2554930a6c13f624f90f0c3d20d43ee94104b82c02b1eb4f2ff49dbe7ae9ed0f77",
            )
            .unwrap(),
        );
        let cipher = AeadCipher::<B>::new(AeadAlgorithm::ChaCha20Poly1305)?;

        let opened = cipher.decrypt_value(b"fixture-aad", &cipher_text, &key)?;

        assert_eq!(opened, SecretValue::from("fixture-secret"), "{}", B::NAME);
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}

/// Every backend computes the same beacons, which Python's `hmac` computes too: HMAC-SHA256 under
/// the key 0 to 31 of `[bits: u16 BE][context length: u32 BE]user/email` and the plaintext,
/// behind the beacon prefix of the key id 7, truncated to the bits.
#[test]
fn a_beacon_is_the_prefix_and_the_truncated_hmac_sha256() -> KmsAeadResult<()> {
    fn check<B: AeadBackend>() -> KmsAeadResult<()> {
        let key = DataEncryptionKey::from(SecretValue::new((0u8..32).collect()));
        let mac = BeaconMac::<B>::new(BeaconAlgorithm::HmacSha256);
        for (bits, beacon) in [
            (
                256,
                "010000000762ae3b56ae54b1d98b6ecd05e3da2aac35118110f25483a818cb77aa01bb1eff",
            ),
            (16, "010000000709c9"),
            (12, "01000000073730"),
        ] {
            let bits = BeaconBits::new(bits).unwrap();
            let computed = mac.compute(
                KeyId::new(7),
                b"user/email",
                bits,
                &"alice@example.com".to_string(),
                &key,
            )?;
            assert_eq!(
                hex::encode(computed.value()),
                beacon,
                "{} bits on {}",
                bits.get(),
                B::NAME
            );
            assert_eq!(computed.key_id(), KeyId::new(7));
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}
