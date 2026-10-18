//! What every backend does through `AeadCipher`, run for every enabled backend and every
//! algorithm it implements, so that the backends cannot drift apart.

use std::collections::HashSet;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadError;
use crate::{
    AeadAlgorithm, AeadBackend, AeadCipher, AeadEncryption, Cipher, CipherText, DataEncryptionKey,
    KmsAeadResult,
};

const BACKENDS: &[AeadBackend] = &[
    #[cfg(feature = "ring")]
    AeadBackend::Ring,
    #[cfg(any(feature = "aws-lc", feature = "aws-lc-fips"))]
    AeadBackend::AwsLc,
    #[cfg(feature = "rustcrypto")]
    AeadBackend::RustCrypto,
];

const ALGORITHMS: [AeadAlgorithm; 4] = [
    AeadAlgorithm::ChaCha20Poly1305,
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
];

const AAD: &[u8] = b"orders/1042/card";
const PLAIN_TEXT: &str = "4111 1111 1111 1111";

/// The other tests skip the pairs a backend does not implement, so they would still pass with
/// one of them dropped.
#[test]
fn every_aead_algorithm_is_supported() -> KmsAeadResult<()> {
    for &backend in BACKENDS {
        for algorithm in ALGORITHMS {
            #[cfg(feature = "ring")]
            if backend == AeadBackend::Ring && algorithm == AeadAlgorithm::Aes256GcmSiv {
                continue;
            }
            AeadCipher::new(backend, algorithm)?;
        }
    }
    Ok(())
}

#[cfg(feature = "ring")]
#[test]
fn ring_refuses_aes_256_gcm_siv_at_construction() {
    let result = AeadCipher::new(AeadBackend::Ring, AeadAlgorithm::Aes256GcmSiv);

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
    let inputs = (vec(any::<u8>(), 0..4096), vec(any::<u8>(), 0..256));
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let key = cipher.generate_data_encryption_key()?;
        TestRunner::default()
            .run(&inputs, |(plain_text, aad)| {
                let plain_text = SecretValue::new(plain_text);
                let cipher_text = cipher.seal(&aad, &plain_text, &key)?;
                prop_assert_eq!(
                    cipher_text.value().len(),
                    AeadAlgorithm::NONCE_LEN
                        + plain_text.ref_sensitive_value().len()
                        + AeadAlgorithm::TAG_LEN
                );
                prop_assert_eq!(cipher.open(&aad, &cipher_text, &key)?, plain_text);
                Ok(())
            })
            .unwrap_or_else(|failure| panic!("{cipher:?}: {failure}"));
    }
    Ok(())
}

/// Every backend writes the same layout, so a value sealed by one opens with every other that
/// implements its algorithm.
#[tokio::test]
async fn a_value_sealed_by_one_backend_opens_with_every_other() -> KmsAeadResult<()> {
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for algorithm in ALGORITHMS {
        let ciphers: Vec<AeadCipher> = BACKENDS
            .iter()
            .filter_map(|&backend| AeadCipher::new(backend, algorithm).ok())
            .collect();
        for sealer in &ciphers {
            let key = sealer.generate_data_encryption_key()?;
            let cipher_text = sealer.encrypt_value(&AAD, &plain_text, &key).await?;
            for opener in &ciphers {
                assert_eq!(
                    opener.decrypt_value(&AAD, &cipher_text, &key).await?,
                    plain_text,
                    "{algorithm} sealed by {} and opened by {}",
                    sealer.backend(),
                    opener.backend()
                );
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_64_byte_key_is_refused_by_every_aead_algorithm() -> KmsAeadResult<()> {
    let deterministic_sized_key = DataEncryptionKey::from(SecretValue::new(vec![0x42; 64]));
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let sealed = cipher
            .encrypt_value(&AAD, &plain_text, &deterministic_sized_key)
            .await;
        assert!(
            matches!(&sealed, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_LENGTH"),
            "{cipher:?} seals: {sealed:?}"
        );

        let key = cipher.generate_data_encryption_key()?;
        let cipher_text = cipher.encrypt_value(&AAD, &plain_text, &key).await?;
        let opened = cipher
            .decrypt_value(&AAD, &cipher_text, &deterministic_sized_key)
            .await;
        assert!(
            matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_LENGTH"),
            "{cipher:?} opens: {opened:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_tampered_value_fails_to_open() -> KmsAeadResult<()> {
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let key = cipher.generate_data_encryption_key()?;
        let other_key = cipher.generate_data_encryption_key()?;
        let cipher_text = cipher.encrypt_value(&AAD, &plain_text, &key).await?;
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
            let opened = cipher.decrypt_value(&aad, &value, key).await;
            assert!(
                matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "DECRYPT"),
                "{cipher:?} with {case}: {opened:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_value_shorter_than_nonce_and_tag_is_invalid() -> KmsAeadResult<()> {
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let key = cipher.generate_data_encryption_key()?;
        for len in [
            0,
            AeadAlgorithm::NONCE_LEN - 1,
            AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN - 1,
        ] {
            let short = CipherText(vec![0xAA; len]);
            let opened = cipher.decrypt_value(&AAD, &short, &key).await;
            assert!(
                matches!(&opened, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_CIPHERTEXT"),
                "{cipher:?} with {len} bytes: {opened:?}"
            );
        }
    }
    Ok(())
}

#[tokio::test]
async fn sealing_twice_gives_different_values() -> KmsAeadResult<()> {
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let key = cipher.generate_data_encryption_key()?;
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let cipher_text = cipher.encrypt_value(&AAD, &plain_text, &key).await?;
            nonces.insert(cipher_text.value()[..AeadAlgorithm::NONCE_LEN].to_vec());
        }
        assert_eq!(nonces.len(), 100, "{cipher:?}");
    }
    Ok(())
}

#[test]
fn generated_keys_have_the_algorithm_length_and_differ() -> KmsAeadResult<()> {
    for cipher in BACKENDS.iter().flat_map(|&backend| {
        ALGORITHMS
            .into_iter()
            .filter_map(move |algorithm| AeadCipher::new(backend, algorithm).ok())
    }) {
        let mut keys = HashSet::new();
        for _ in 0..100 {
            let key = cipher.generate_data_encryption_key()?;
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

/// The AEAD layer of every envelope layout: kms-aead 0.28.1 output with the default algorithm.
#[tokio::test]
async fn a_value_sealed_by_0_28_1_opens() -> KmsAeadResult<()> {
    let key = DataEncryptionKey::from(SecretValue::new(
        hex::decode("ee1b4efa8e3b1f550edfe8fe963d575b8cbf4e1f686e8c512ac7e4b3b1b7dd0a").unwrap(),
    ));
    let cipher_text = CipherText(
        hex::decode(
            "f77db8c591c62b724b2554930a6c13f624f90f0c3d20d43ee94104b82c02b1eb4f2ff49dbe7ae9ed0f77",
        )
        .unwrap(),
    );
    for &backend in BACKENDS {
        let cipher = AeadCipher::new(backend, AeadAlgorithm::ChaCha20Poly1305)?;

        let opened = cipher
            .decrypt_value(&"fixture-aad", &cipher_text, &key)
            .await?;

        assert_eq!(opened, SecretValue::from("fixture-secret"), "{backend}");
    }
    Ok(())
}
