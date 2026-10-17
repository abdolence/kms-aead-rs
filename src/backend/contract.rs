//! What every backend does through `AeadCipher`. Each backend's test module runs every function
//! here with its own type, so that the backends cannot drift apart.

use std::collections::HashSet;

use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::TestRunner;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

use super::AeadBackend;
use crate::errors::KmsAeadError;
use crate::{
    AeadAlgorithm, AeadCipher, AeadEncryption, CipherText, DataEncryptionKey, KmsAeadResult,
};

const ALGORITHMS: [AeadAlgorithm; 4] = [
    AeadAlgorithm::ChaCha20Poly1305,
    AeadAlgorithm::Aes128Gcm,
    AeadAlgorithm::Aes256Gcm,
    AeadAlgorithm::Aes256GcmSiv,
];

const AAD: &[u8] = b"orders/1042/card";
const PLAIN_TEXT: &str = "4111 1111 1111 1111";

fn supported_ciphers<B: AeadBackend>() -> Vec<AeadCipher<B>> {
    ALGORITHMS
        .into_iter()
        .filter_map(|algorithm| AeadCipher::<B>::new(algorithm).ok())
        .collect()
}

fn encryption_error_code<T: std::fmt::Debug>(result: KmsAeadResult<T>) -> String {
    match result {
        Err(KmsAeadError::EncryptionError(error)) => error.public.code,
        other => panic!("expected an encryption error, got {other:?}"),
    }
}

async fn seal<B: AeadBackend>(
    cipher: &AeadCipher<B>,
    plain_text: &SecretValue,
    key: &DataEncryptionKey,
) -> CipherText {
    cipher
        .encrypt_value(&AAD, plain_text, key)
        .await
        .unwrap_or_else(|e| panic!("{} seals: {e}", cipher.algorithm()))
}

/// Opening a sealed value gives back the plain text, for any plain text and AAD, and the value
/// is the nonce, the cipher text and the tag.
pub(crate) fn every_supported_algorithm_round_trips<B: AeadBackend>() {
    let inputs = (vec(any::<u8>(), 0..4096), vec(any::<u8>(), 0..256));
    for cipher in supported_ciphers::<B>() {
        let key = cipher.generate_data_encryption_key().unwrap();
        TestRunner::default()
            .run(&inputs, |(plain_text, aad)| {
                let plain_text = SecretValue::new(plain_text);
                let cipher_text = cipher.seal(&aad, &plain_text, &key).unwrap();
                prop_assert_eq!(
                    cipher_text.value().len(),
                    AeadAlgorithm::NONCE_LEN
                        + plain_text.ref_sensitive_value().len()
                        + AeadAlgorithm::TAG_LEN
                );
                prop_assert_eq!(cipher.open(&aad, &cipher_text, &key).unwrap(), plain_text);
                Ok(())
            })
            .unwrap_or_else(|failure| panic!("{}: {failure}", cipher.algorithm()));
    }
}

pub(crate) async fn a_64_byte_key_is_refused_by_every_aead_algorithm<B: AeadBackend>() {
    let deterministic_sized_key = DataEncryptionKey::from(SecretValue::new(vec![0x42; 64]));
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in supported_ciphers::<B>() {
        let sealed = cipher
            .encrypt_value(&AAD, &plain_text, &deterministic_sized_key)
            .await;
        assert_eq!(
            encryption_error_code(sealed),
            "INVALID_KEY_LENGTH",
            "{} seals",
            cipher.algorithm()
        );

        let key = cipher.generate_data_encryption_key().unwrap();
        let cipher_text = seal(&cipher, &plain_text, &key).await;
        let opened = cipher
            .decrypt_value(&AAD, &cipher_text, &deterministic_sized_key)
            .await;
        assert_eq!(
            encryption_error_code(opened),
            "INVALID_KEY_LENGTH",
            "{} opens",
            cipher.algorithm()
        );
    }
}

pub(crate) async fn a_tampered_value_fails_to_open<B: AeadBackend>() {
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in supported_ciphers::<B>() {
        let key = cipher.generate_data_encryption_key().unwrap();
        let other_key = cipher.generate_data_encryption_key().unwrap();
        let cipher_text = seal(&cipher, &plain_text, &key).await;
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
            assert_eq!(
                encryption_error_code(cipher.decrypt_value(&aad, &value, key).await),
                "DECRYPT",
                "{} with {case}",
                cipher.algorithm()
            );
        }
    }
}

pub(crate) async fn a_value_shorter_than_nonce_and_tag_is_invalid<B: AeadBackend>() {
    for cipher in supported_ciphers::<B>() {
        let key = cipher.generate_data_encryption_key().unwrap();
        for len in [
            0,
            AeadAlgorithm::NONCE_LEN - 1,
            AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN - 1,
        ] {
            let short = CipherText(vec![0xAA; len]);
            assert_eq!(
                encryption_error_code(cipher.decrypt_value(&AAD, &short, &key).await),
                "INVALID_CIPHERTEXT",
                "{} with {len} bytes",
                cipher.algorithm()
            );
        }
    }
}

pub(crate) async fn sealing_twice_gives_different_values<B: AeadBackend>() {
    let plain_text = SecretValue::from(PLAIN_TEXT);
    for cipher in supported_ciphers::<B>() {
        let key = cipher.generate_data_encryption_key().unwrap();
        let mut nonces = HashSet::new();
        for _ in 0..100 {
            let cipher_text = seal(&cipher, &plain_text, &key).await;
            nonces.insert(cipher_text.value()[..AeadAlgorithm::NONCE_LEN].to_vec());
        }
        assert_eq!(nonces.len(), 100, "{}", cipher.algorithm());
    }
}

pub(crate) fn generated_keys_have_the_algorithm_length_and_differ<B: AeadBackend>() {
    for cipher in supported_ciphers::<B>() {
        let keys: HashSet<Vec<u8>> = (0..100)
            .map(|_| {
                let key = cipher.generate_data_encryption_key().unwrap();
                key.value().ref_sensitive_value().clone()
            })
            .collect();
        assert_eq!(keys.len(), 100, "{}", cipher.algorithm());
        assert!(
            keys.iter()
                .all(|key| key.len() == cipher.algorithm().key_len()),
            "{}",
            cipher.algorithm()
        );
    }
}

/// The AEAD layer of every envelope layout: kms-aead 0.28.1 output with the default algorithm.
pub(crate) async fn a_value_sealed_by_0_28_1_opens<B: AeadBackend>() {
    let cipher = AeadCipher::<B>::new(AeadAlgorithm::ChaCha20Poly1305).unwrap();
    let key = DataEncryptionKey::from(SecretValue::new(
        hex::decode("ee1b4efa8e3b1f550edfe8fe963d575b8cbf4e1f686e8c512ac7e4b3b1b7dd0a").unwrap(),
    ));
    let cipher_text = CipherText(
        hex::decode(
            "f77db8c591c62b724b2554930a6c13f624f90f0c3d20d43ee94104b82c02b1eb4f2ff49dbe7ae9ed0f77",
        )
        .unwrap(),
    );

    let opened = cipher
        .decrypt_value(&"fixture-aad", &cipher_text, &key)
        .await
        .unwrap();

    assert_eq!(opened, SecretValue::from("fixture-secret"));
}
