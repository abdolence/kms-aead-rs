//! A provider for unit tests that need no KMS, whose "encrypted" key is the plaintext it is given,
//! the backend those tests run on, and the waits the concurrency tests share.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use async_trait::async_trait;
use secret_vault_value::SecretValue;
use tokio::sync::watch;

use crate::errors::KmsAeadEncryptionError;
use crate::formats::TinkKeyType;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult, ValueStruct,
};

#[cfg(feature = "ring")]
pub(crate) type TestBackend = crate::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
pub(crate) type TestBackend = crate::AwsLc;
#[cfg(all(
    not(feature = "ring"),
    not(feature = "aws-lc-rs"),
    feature = "rustcrypto"
))]
pub(crate) type TestBackend = crate::RustCrypto;

/// How many calls the concurrency tests start at once.
pub(crate) const CONCURRENT_CALLS: usize = 16;

static TEST_KEK: LazyLock<KekRef> =
    LazyLock::new(|| KekRef::new(KekProvider::Other("test".to_string()), "test-kek"));

#[derive(Debug, Clone)]
pub(crate) enum TestKmsProvider {
    Working,
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    FailingToEncrypt,
    FailingToDecrypt,
    /// Returns its key material from `generate_key_material`, as a KMS generator would.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    Generating(SecretValue),
    /// Decrypts a key into its encrypted bytes followed by the nanoseconds from the instant it
    /// holds to the decryption, as a little-endian `u64`, so that a caller can tell how old the key
    /// it is given is.
    Stamping(Instant),
}

#[async_trait]
impl KmsAeadEncryptionProvider for TestKmsProvider {
    fn kek(&self) -> &KekRef {
        &TEST_KEK
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
            TestKmsProvider::FailingToEncrypt => Err(KmsAeadEncryptionError::create(
                "TEST_ENCRYPT",
                "The test provider fails to encrypt",
            )),
            _ => Ok(EncryptedDataEncryptionKey::new(
                dek.value().ref_sensitive_value().clone(),
            )),
        }
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        match self {
            TestKmsProvider::FailingToDecrypt => Err(KmsAeadEncryptionError::create(
                "TEST_DECRYPT",
                "The test provider fails to decrypt",
            )),
            TestKmsProvider::Stamping(since) => {
                let nanos = u64::try_from(since.elapsed().as_nanos())
                    .expect("a test runs for less than 584 years");
                let mut key = encrypted_dek.value().clone();
                key.extend(nanos.to_le_bytes());
                Ok(DataEncryptionKey::from(SecretValue::new(key)))
            }
            _ => Ok(DataEncryptionKey::from(SecretValue::new(
                encrypted_dek.value().clone(),
            ))),
        }
    }

    async fn generate_key_material(&self, _len: usize) -> KmsAeadResult<Option<SecretValue>> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
            TestKmsProvider::Generating(key_material) => Ok(Some(key_material.clone())),
            _ => Ok(None),
        }
    }
}

/// A [`TestKmsProvider`] under a KEK of its own, which counts its encryptions and decryptions and
/// can hold them, once counted, until the test opens its gate.
pub(crate) struct CountingKmsProvider {
    inner: TestKmsProvider,
    kek: KekRef,
    encryptions: AtomicUsize,
    decryptions: AtomicUsize,
    gate: watch::Sender<bool>,
}

impl CountingKmsProvider {
    /// A provider whose calls go through at once.
    pub(crate) fn new(inner: TestKmsProvider, kek: &str) -> Self {
        Self::with_kek(
            inner,
            KekRef::new(KekProvider::Other("test".to_string()), kek),
        )
    }

    /// A provider that names `kek`, such as the KEK of a built-in provider, whose bytes kms-aead
    /// tells apart from the layouts of 0.29.
    pub(crate) fn with_kek(inner: TestKmsProvider, kek: KekRef) -> Self {
        Self {
            inner,
            kek,
            encryptions: AtomicUsize::new(0),
            decryptions: AtomicUsize::new(0),
            gate: watch::Sender::new(true),
        }
    }

    /// A provider whose calls wait until [`open_gate`](Self::open_gate).
    pub(crate) fn gated(inner: TestKmsProvider, kek: &str) -> Self {
        let provider = Self::new(inner, kek);
        provider.gate.send_replace(false);
        provider
    }

    pub(crate) fn open_gate(&self) {
        self.gate.send_replace(true);
    }

    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    pub(crate) fn encryptions(&self) -> usize {
        self.encryptions.load(Ordering::SeqCst)
    }

    pub(crate) fn decryptions(&self) -> usize {
        self.decryptions.load(Ordering::SeqCst)
    }

    async fn pass_gate(&self) {
        self.gate.subscribe().wait_for(|open| *open).await.unwrap();
    }
}

#[async_trait]
impl KmsAeadEncryptionProvider for CountingKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        self.encryptions.fetch_add(1, Ordering::SeqCst);
        self.pass_gate().await;
        self.inner.encrypt_data_encryption_key(dek).await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.decryptions.fetch_add(1, Ordering::SeqCst);
        self.pass_gate().await;
        self.inner.decrypt_data_encryption_key(encrypted_dek).await
    }
}

/// What [`TestKmsProvider`] returns when kms-aead encrypts `key` as a key of `key_type`: the key as
/// Tink serialises it.
pub(crate) fn encrypted_by_test_provider(
    key_type: impl Into<TinkKeyType>,
    key: &[u8],
) -> EncryptedDataEncryptionKey {
    let dek = DataEncryptionKey::from(SecretValue::new(key.to_vec()));
    let serialized = crate::formats::serialize_tink_key(key_type.into(), &dek);
    EncryptedDataEncryptionKey::new(serialized.ref_sensitive_value().clone())
}

/// Lets every spawned task of a current-thread runtime run until it waits on something.
pub(crate) async fn let_spawned_tasks_wait() {
    for _ in 0..CONCURRENT_CALLS * 4 {
        tokio::task::yield_now().await;
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

/// A value Tink's `KmsEnvelopeAead` wrote on a live KMS key.
#[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
pub(crate) struct TinkEnvelope {
    pub(crate) algorithm: crate::AeadAlgorithm,
    pub(crate) aad: &'static str,
    pub(crate) plain_text: &'static str,
    pub(crate) value: &'static str,
}
