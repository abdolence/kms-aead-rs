//! A provider for unit tests that need no KMS, whose "wrapped" key is the plaintext key itself,
//! and the backend those tests run on.
// Without a backend, only the read-error tests compile; the envelope tests that use the rest of
// this module need a backend.
#![cfg_attr(
    not(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")),
    allow(dead_code)
)]

use async_trait::async_trait;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
#[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
use crate::AeadBackend;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

#[cfg(feature = "ring")]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::RustCrypto;

#[derive(Debug, Clone)]
pub(crate) enum TestKmsProvider {
    Working,
    FailingToWrap,
    FailingToUnwrap,
    /// Returns its key material from `generate_key_material`, as a KMS generator would.
    Generating(SecretValue),
}

#[async_trait]
impl KmsAeadEncryptionProvider for TestKmsProvider {
    fn kek(&self) -> KekRef {
        KekRef::new(KekProvider::Other("test".to_string()), "test-kek")
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match self {
            TestKmsProvider::FailingToWrap => Err(KmsAeadEncryptionError::create(
                "TEST_WRAP",
                "The test provider fails to wrap",
            )),
            _ => Ok(EncryptedDataEncryptionKey::new(
                encryption_key.value().ref_sensitive_value().clone(),
                None,
            )),
        }
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        match self {
            TestKmsProvider::FailingToUnwrap => Err(KmsAeadEncryptionError::create(
                "TEST_UNWRAP",
                "The test provider fails to unwrap",
            )),
            _ => Ok(DataEncryptionKey::from(SecretValue::new(
                encrypted_key.wrapped().to_vec(),
            ))),
        }
    }

    async fn generate_key_material(&self, _len: usize) -> KmsAeadResult<Option<SecretValue>> {
        match self {
            TestKmsProvider::Generating(key_material) => Ok(Some(key_material.clone())),
            _ => Ok(None),
        }
    }
}

/// The forms in which stored or secret bytes could reach a message or a log line: as text,
/// as lowercase and uppercase hex, as standard base64, and as the `Debug` list of a byte slice
/// without its brackets, which also finds the list with them.
pub(crate) fn renderings(bytes: &[u8]) -> Vec<String> {
    vec![
        String::from_utf8_lossy(bytes).into_owned(),
        hex::encode(bytes),
        hex::encode_upper(bytes),
        SecretValue::new(bytes.to_vec())
            .as_sensitive_base64_str()
            .to_string(),
        format!("{bytes:?}").trim_matches(['[', ']']).to_string(),
    ]
}
