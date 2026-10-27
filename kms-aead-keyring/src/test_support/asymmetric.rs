//! The asymmetric KEK of the tests: a local KMS whose private half the process holds, and a
//! wrapper that gives it another KEK's name.

use std::sync::Arc;

use kms_aead::providers::{LocalAsymmetricKmsProvider, LocalKekId};
use kms_aead::{
    AsymmetricKekAlgorithm, DataEncryptionKey, EncryptedDataEncryptionKey, KekRef,
    KmsAeadDecryptionProvider, KmsAeadEncryptionProvider, KmsAeadResult,
};

/// The backend of the asymmetric tests, which ring cannot serve: it has no RSA.
#[cfg(feature = "aws-lc")]
pub(crate) type RsaBackend = kms_aead::backends::AwsLc;
#[cfg(all(not(feature = "aws-lc"), feature = "rustcrypto"))]
pub(crate) type RsaBackend = kms_aead::backends::RustCrypto;

/// A local asymmetric KMS provider with a fresh RSA key, named `kek`.
pub(crate) fn local_asymmetric(kek: &str) -> KmsAeadResult<LocalAsymmetricKmsProvider<RsaBackend>> {
    LocalAsymmetricKmsProvider::ephemeral(
        LocalKekId::try_from(kek.to_string())?,
        AsymmetricKekAlgorithm::RsaOaepSha256,
    )
}

/// A local asymmetric KMS provider that reports `kek` as its KEK, as the provider of a KMS key
/// the keyring addresses by a Cloud KMS key name would. It encrypts with the public key, and
/// [`encrypts_with_public_key`](KmsAeadEncryptionProvider::encrypts_with_public_key) says so until
/// [`unaware`](Self::unaware) takes that away, which makes it an application's plain KMS
/// provider reading the same keyring.
#[derive(Clone)]
pub(crate) struct ReportedKekProvider {
    kms: Arc<LocalAsymmetricKmsProvider<RsaBackend>>,
    kek: KekRef,
    asymmetric: bool,
}

impl ReportedKekProvider {
    pub(crate) fn new(kms: LocalAsymmetricKmsProvider<RsaBackend>, kek: KekRef) -> Self {
        Self {
            kms: Arc::new(kms),
            kek,
            asymmetric: true,
        }
    }

    /// The same provider, reporting no asymmetric KEK.
    pub(crate) fn unaware(self) -> Self {
        Self {
            asymmetric: false,
            ..self
        }
    }
}

impl KmsAeadEncryptionProvider for ReportedKekProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        self.kms.encrypt_data_encryption_key(dek).await
    }

    fn encrypts_with_public_key(&self) -> bool {
        self.asymmetric
    }
}

impl KmsAeadDecryptionProvider for ReportedKekProvider {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.kms.decrypt_data_encryption_key(encrypted_dek).await
    }
}
