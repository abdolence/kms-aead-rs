use crate::errors::*;
use crate::{CipherText, DataEncryptionKey, KmsAeadResult};
use ring::aead::{Algorithm, BoundKey, OpeningKey, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

pub struct OneNonceSequence(Option<ring::aead::Nonce>);

impl OneNonceSequence {
    pub fn new(nonce: ring::aead::Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl ring::aead::NonceSequence for OneNonceSequence {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        self.0.take().ok_or(ring::error::Unspecified)
    }
}

pub fn encrypt_with_sealing_key<A: std::convert::AsRef<[u8]>>(
    algo: &'static Algorithm,
    encryption_key: &DataEncryptionKey,
    nonce_data: &[u8],
    aad: ring::aead::Aad<A>,
    plain_text: &[u8],
) -> KmsAeadResult<CipherText> {
    let mut sealing_key = SealingKey::new(
        UnboundKey::new(algo, encryption_key.value().ref_sensitive_value()).map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT_KEY",
                format!("Unable to create a sealing key: {e:?}").as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data).map_err(|e| {
                KmsAeadEncryptionError::create(
                    "ENCRYPT_KEY",
                    format!("Unable to create a nonce for a sealing key: {e:?}").as_str(),
                )
            })?,
        ),
    );

    let mut encrypted_secret_value = plain_text.to_vec();

    sealing_key
        .seal_in_place_append_tag(aad, &mut encrypted_secret_value)
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT",
                format!("Unable to encrypt data: {e:?}").as_str(),
            )
        })?;
    Ok(CipherText(encrypted_secret_value))
}

pub fn decrypt_with_opening_key<A: std::convert::AsRef<[u8]>>(
    algo: &'static Algorithm,
    encryption_key: &DataEncryptionKey,
    nonce_data: &[u8],
    aad: ring::aead::Aad<A>,
    ciphertext: &[u8],
) -> KmsAeadResult<SecretValue> {
    let mut secret_value: SecretValue = SecretValue::new(ciphertext.to_vec());

    let mut opening_key = OpeningKey::new(
        UnboundKey::new(algo, encryption_key.value().ref_sensitive_value()).map_err(|e| {
            KmsAeadEncryptionError::create(
                "DECRYPT_KEY",
                format!("Unable to create an opening key: {e:?}").as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data).map_err(|e| {
                KmsAeadEncryptionError::create(
                    "DECRYPT_KEY",
                    format!("Unable to create an opening key: {e:?}").as_str(),
                )
            })?,
        ),
    );

    let decrypted = opening_key
        .open_in_place(aad, secret_value.ref_sensitive_value_mut())
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "DECRYPT",
                format!("Unable to decrypt data: {e:?}").as_str(),
            )
        })?;

    Ok(SecretValue::new(decrypted.to_vec()))
}

pub fn generate_secret_key(
    secure_rand: &SystemRandom,
    key_len: usize,
) -> KmsAeadResult<DataEncryptionKey> {
    let mut rand_key_data: Vec<u8> = vec![0; key_len];
    secure_rand.fill(&mut rand_key_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random key: {e:?}").as_str(),
        )
    })?;
    Ok(DataEncryptionKey::from(SecretValue::from(rand_key_data)))
}

pub fn generate_random_nonce(secure_rand: &SystemRandom) -> KmsAeadResult<Vec<u8>> {
    let mut nonce_data: [u8; ring::aead::NONCE_LEN] = [0; ring::aead::NONCE_LEN];
    secure_rand.fill(&mut nonce_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random nonce: {e:?}").as_str(),
        )
    })?;

    Ok(nonce_data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    pub fn generated_random_nonce_test() {
        const NUM_TRIES: usize = 1000;
        let mut all_tries = vec![];

        for _i in 0..NUM_TRIES {
            let nonce_vec = generate_random_nonce(&SystemRandom::new()).unwrap();
            assert_eq!(nonce_vec.len(), ring::aead::NONCE_LEN);
            all_tries.push(hex::encode(nonce_vec));
        }
        // Now at least half should be different in NUM_TRIES
        let tries_set: HashSet<&String> = all_tries.iter().collect();
        assert!((tries_set.len() as f64) > NUM_TRIES as f64 * 0.9);
    }

    #[test]
    pub fn generate_secret_key_correct_length() {
        let secure_rand = SystemRandom::new();

        // Test ChaCha20-Poly1305 key length
        let key1 =
            generate_secret_key(&secure_rand, ring::aead::CHACHA20_POLY1305.key_len()).unwrap();
        assert_eq!(
            key1.value().ref_sensitive_value().len(),
            ring::aead::CHACHA20_POLY1305.key_len()
        );

        // Test AES-256-GCM key length
        let key2 = generate_secret_key(&secure_rand, ring::aead::AES_256_GCM.key_len()).unwrap();
        assert_eq!(
            key2.value().ref_sensitive_value().len(),
            ring::aead::AES_256_GCM.key_len()
        );
    }

    #[test]
    pub fn generate_secret_key_uniqueness() {
        let secure_rand = SystemRandom::new();
        let key_len = ring::aead::CHACHA20_POLY1305.key_len();

        let mut keys = HashSet::new();
        for _ in 0..100 {
            let key = generate_secret_key(&secure_rand, key_len).unwrap();
            let key_hex = hex::encode(key.value().ref_sensitive_value());
            keys.insert(key_hex);
        }

        // All keys should be unique
        assert_eq!(keys.len(), 100);
    }

    #[test]
    pub fn encrypt_decrypt_roundtrip() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"Hello, World!";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        // Ciphertext should be longer (includes auth tag)
        assert!(ciphertext.value().len() > plaintext.len());

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let decrypted =
            decrypt_with_opening_key(algo, &key, &nonce, aad2, ciphertext.value()).unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), plaintext);
    }

    #[test]
    pub fn encrypt_empty_plaintext() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        // Even empty plaintext produces ciphertext (auth tag)
        assert!(ciphertext.value().len() > 0);

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let decrypted =
            decrypt_with_opening_key(algo, &key, &nonce, aad2, ciphertext.value()).unwrap();

        assert_eq!(decrypted.ref_sensitive_value().len(), 0);
    }

    #[test]
    pub fn decrypt_wrong_aad_fails() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad1 = ring::aead::Aad::from(b"correct-aad");
        let plaintext = b"secret";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad1, plaintext).unwrap();

        // Try to decrypt with wrong AAD
        let wrong_aad = ring::aead::Aad::from(b"wrong-aad");
        let result = decrypt_with_opening_key(algo, &key, &nonce, wrong_aad, ciphertext.value());

        assert!(result.is_err(), "Decryption with wrong AAD should fail");
    }

    #[test]
    pub fn decrypt_wrong_nonce_fails() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce1 = generate_random_nonce(&secure_rand).unwrap();
        let nonce2 = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"secret";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce1, aad, plaintext).unwrap();

        // Try to decrypt with wrong nonce
        let aad2 = ring::aead::Aad::from(b"test-aad");
        let result = decrypt_with_opening_key(algo, &key, &nonce2, aad2, ciphertext.value());

        assert!(result.is_err(), "Decryption with wrong nonce should fail");
    }

    #[test]
    pub fn decrypt_modified_ciphertext_fails() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"secret message";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        // Modify the ciphertext
        let mut modified = ciphertext.value().to_vec();
        modified[0] ^= 0x01; // Flip one bit

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let result = decrypt_with_opening_key(algo, &key, &nonce, aad2, &modified);

        assert!(
            result.is_err(),
            "Decryption of modified ciphertext should fail"
        );
    }

    #[test]
    pub fn decrypt_truncated_ciphertext_fails() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"secret message";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        // Truncate the ciphertext
        let mut truncated = ciphertext.value().to_vec();
        truncated.truncate(truncated.len() - 5);

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let result = decrypt_with_opening_key(algo, &key, &nonce, aad2, &truncated);

        assert!(
            result.is_err(),
            "Decryption of truncated ciphertext should fail"
        );
    }

    #[test]
    pub fn test_aes_256_gcm_encryption() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::AES_256_GCM;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = b"Test with AES-256-GCM";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let decrypted =
            decrypt_with_opening_key(algo, &key, &nonce, aad2, ciphertext.value()).unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), plaintext);
    }

    #[test]
    pub fn test_large_plaintext() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();
        let aad = ring::aead::Aad::from(b"test-aad");
        let plaintext = vec![0x42; 100_000]; // 100KB

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, &plaintext).unwrap();

        let aad2 = ring::aead::Aad::from(b"test-aad");
        let decrypted =
            decrypt_with_opening_key(algo, &key, &nonce, aad2, ciphertext.value()).unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), plaintext.as_slice());
    }

    #[test]
    pub fn nonce_has_correct_length() {
        let secure_rand = SystemRandom::new();
        for _ in 0..10 {
            let nonce = generate_random_nonce(&secure_rand).unwrap();
            assert_eq!(nonce.len(), ring::aead::NONCE_LEN);
        }
    }

    #[test]
    pub fn test_binary_aad() {
        let secure_rand = SystemRandom::new();
        let algo = &ring::aead::CHACHA20_POLY1305;
        let key = generate_secret_key(&secure_rand, algo.key_len()).unwrap();
        let nonce = generate_random_nonce(&secure_rand).unwrap();

        // AAD with null bytes and non-ASCII
        let binary_aad_data: Vec<u8> = vec![0x00, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00];
        let aad = ring::aead::Aad::from(binary_aad_data.as_slice());
        let plaintext = b"secret";

        let ciphertext = encrypt_with_sealing_key(algo, &key, &nonce, aad, plaintext).unwrap();

        let aad2 = ring::aead::Aad::from(binary_aad_data.as_slice());
        let decrypted =
            decrypt_with_opening_key(algo, &key, &nonce, aad2, ciphertext.value()).unwrap();

        assert_eq!(decrypted.ref_sensitive_value(), plaintext);
    }
}
