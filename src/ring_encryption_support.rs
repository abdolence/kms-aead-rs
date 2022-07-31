use crate::errors::*;
use crate::{EncryptedSecretValue, KmsAeadResult};
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
    session_secret: &SecretValue,
    nonce_data: &SecretValue,
    aad: ring::aead::Aad<A>,
    secret_value: &SecretValue,
) -> KmsAeadResult<EncryptedSecretValue> {
    let mut encrypted_secret_value = secret_value.clone();

    let mut sealing_key = SealingKey::new(
        UnboundKey::new(algo, session_secret.ref_sensitive_value()).map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT_KEY",
                format!("Unable to create a sealing key: {:?}", e).as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data.ref_sensitive_value())
                .map_err(|e| {
                    KmsAeadEncryptionError::create(
                        "ENCRYPT_KEY",
                        format!("Unable to create a nonce for a sealing key: {:?}", e).as_str(),
                    )
                })?,
        ),
    );

    sealing_key
        .seal_in_place_append_tag(aad, encrypted_secret_value.ref_sensitive_value_mut())
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "ENCRYPT",
                format!("Unable to encrypt data: {:?}", e).as_str(),
            )
        })?;
    Ok(encrypted_secret_value.into())
}

pub fn decrypt_with_opening_key<A: std::convert::AsRef<[u8]>>(
    algo: &'static Algorithm,
    session_secret: &SecretValue,
    nonce_data: &SecretValue,
    aad: ring::aead::Aad<A>,
    encrypted_secret_value: &EncryptedSecretValue,
) -> KmsAeadResult<SecretValue> {
    let mut secret_value: SecretValue = encrypted_secret_value.value().clone();

    let mut opening_key = OpeningKey::new(
        UnboundKey::new(algo, session_secret.ref_sensitive_value()).map_err(|e| {
            KmsAeadEncryptionError::create(
                "DECRYPT_KEY",
                format!("Unable to create an opening key: {:?}", e).as_str(),
            )
        })?,
        OneNonceSequence::new(
            ring::aead::Nonce::try_assume_unique_for_key(nonce_data.ref_sensitive_value())
                .map_err(|e| {
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
) -> KmsAeadResult<SecretValue> {
    let mut rand_key_data: Vec<u8> = vec![0; key_len];
    secure_rand.fill(&mut rand_key_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random session key: {:?}", e).as_str(),
        )
    })?;
    Ok(SecretValue::new(rand_key_data))
}

pub fn generate_nonce(secure_rand: &SystemRandom) -> KmsAeadResult<SecretValue> {
    let mut nonce_data: [u8; ring::aead::NONCE_LEN] = [0; ring::aead::NONCE_LEN];
    secure_rand.fill(&mut nonce_data).map_err(|e| {
        KmsAeadEncryptionError::create(
            "ENCRYPTION",
            format!("Unable to initialise random nonce: {:?}", e).as_str(),
        )
    })?;

    Ok(SecretValue::new(nonce_data.to_vec()))
}
