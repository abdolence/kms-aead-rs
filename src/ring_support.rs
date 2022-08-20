use crate::errors::*;
use crate::{CipherText, DataEncryptionKey, KmsAeadResult};
use ring::aead::{Algorithm, BoundKey, OpeningKey, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use std::mem::size_of;

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
    let mut encrypted_secret_value = plain_text.to_vec();

    let mut sealing_key = SealingKey::new(
        UnboundKey::new(algo, encryption_key.value().ref_sensitive_value()).map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT_KEY",
                format!("Unable to create a sealing key: {:?}", e).as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data).map_err(|e| {
                KmsAeadEncryptionError::create(
                    "ENCRYPT_KEY",
                    format!("Unable to create a nonce for a sealing key: {:?}", e).as_str(),
                )
            })?,
        ),
    );

    sealing_key
        .seal_in_place_append_tag(aad, &mut encrypted_secret_value)
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT",
                format!("Unable to encrypt data: {:?}", e).as_str(),
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
                format!("Unable to create an opening key: {:?}", e).as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data).map_err(|e| {
                KmsAeadEncryptionError::create(
                    "DECRYPT_KEY",
                    format!("Unable to create an opening key: {:?}", e).as_str(),
                )
            })?,
        ),
    );

    opening_key
        .open_in_place(aad, secret_value.ref_sensitive_value_mut())
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "DECRYPT",
                format!("Unable to decrypt data: {:?}", e).as_str(),
            )
        })?;

    let len = secret_value.ref_sensitive_value().len();
    secret_value
        .ref_sensitive_value_mut()
        .truncate(len - ring::aead::MAX_TAG_LEN);
    Ok(secret_value)
}

pub fn generate_secret_key(
    secure_rand: &SystemRandom,
    key_len: usize,
) -> KmsAeadResult<DataEncryptionKey> {
    let mut rand_key_data: Vec<u8> = vec![0; key_len];
    secure_rand.fill(&mut rand_key_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random key: {:?}", e).as_str(),
        )
    })?;
    Ok(DataEncryptionKey::from(SecretValue::from(rand_key_data)))
}

pub fn generate_random_nonce(secure_rand: &SystemRandom) -> KmsAeadResult<Vec<u8>> {
    let mut nonce_data: [u8; ring::aead::NONCE_LEN] = [0; ring::aead::NONCE_LEN];
    secure_rand.fill(&mut nonce_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random nonce: {:?}", e).as_str(),
        )
    })?;

    Ok(nonce_data.to_vec())
}

pub fn generate_time_random_nonce(secure_rand: &SystemRandom) -> KmsAeadResult<Vec<u8>> {
    const TIME_LEN: usize = 48 / 8;
    const MILLIS_LEN: usize = size_of::<u128>();
    let mut nonce_data: [u8; ring::aead::NONCE_LEN] = [0; ring::aead::NONCE_LEN];
    let now = std::time::SystemTime::now();

    let since_the_epoch = &now
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Clock may have gone backwards")
        .as_millis()
        .to_be_bytes()[MILLIS_LEN - TIME_LEN..];

    nonce_data[..TIME_LEN]
        .as_mut()
        .clone_from_slice(since_the_epoch);

    secure_rand
        .fill(nonce_data[TIME_LEN..].as_mut())
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPTION",
                format!("Unable to initialise random nonce: {:?}", e).as_str(),
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
        const NUM_TRIES: usize = 10;
        let mut all_tries = vec![];

        for _i in 0..NUM_TRIES {
            let nonce_vec = generate_random_nonce(&SystemRandom::new()).unwrap();
            assert_eq!(nonce_vec.len(), ring::aead::NONCE_LEN);
            all_tries.push(hex::encode(nonce_vec));
        }
        // Now at least half should be different in NUM_TRIES
        let tries_set: HashSet<&String> = all_tries.iter().collect();
        assert!(tries_set.len() > NUM_TRIES / 2);
    }

    #[test]
    pub fn generated_time_random_nonce_test() {
        const NUM_TRIES: usize = 10;
        let mut all_tries = vec![];

        for _i in 0..NUM_TRIES {
            let nonce_vec = generate_time_random_nonce(&SystemRandom::new()).unwrap();
            assert_eq!(nonce_vec.len(), ring::aead::NONCE_LEN);
            std::thread::sleep(std::time::Duration::from_millis(5));
            all_tries.push(hex::encode(nonce_vec));
        }
        let tries_set: HashSet<&String> = all_tries.iter().collect();
        println!("{:?}", tries_set);

        // Now all of them should be unique since we have a sleep
        assert_eq!(tries_set.len(), NUM_TRIES);
    }
}
