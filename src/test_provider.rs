//! A provider for unit tests that need no KMS, whose "wrapped" key is the plaintext key itself,
//! and the backend those tests run on.

use async_trait::async_trait;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

#[cfg(feature = "ring")]
pub(crate) type TestBackend = crate::backend::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
pub(crate) type TestBackend = crate::backend::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
pub(crate) type TestBackend = crate::backend::RustCrypto;

#[derive(Debug, Clone)]
pub(crate) enum TestKmsProvider {
    Working,
    FailingToWrap,
    FailingToUnwrap,
    /// Returns its key material from `generate_key_material`, as a KMS generator would.
    Generating(SecretValue),
}

impl TestKmsProvider {
    pub(crate) fn new() -> Self {
        TestKmsProvider::Working
    }

    pub(crate) fn generating(key_material: SecretValue) -> Self {
        TestKmsProvider::Generating(key_material)
    }
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
