//! A provider for unit tests that need no KMS, whose "wrapped" key is the plaintext key itself,
//! the backend those tests run on, and the waits the concurrency tests share.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};
use std::time::Instant;

use async_trait::async_trait;
use secret_vault_value::SecretValue;
use tokio::sync::watch;

use crate::errors::KmsAeadEncryptionError;
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
use crate::AeadBackend;
use crate::{
    DataEncryptionKey, DekBinding, EncryptedDataEncryptionKey, KekProvider, KekRef,
    KmsAeadEncryptionProvider, KmsAeadResult,
};

#[cfg(feature = "ring")]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::AwsLc;
#[cfg(all(
    not(feature = "ring"),
    not(feature = "aws-lc-rs"),
    feature = "rustcrypto"
))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::RustCrypto;

/// How many calls the concurrency tests start at once.
pub(crate) const CONCURRENT_CALLS: usize = 16;

static TEST_KEK: LazyLock<KekRef> =
    LazyLock::new(|| KekRef::new(KekProvider::Other("test".to_string()), "test-kek"));

/// Ignores the binding: a wrapped key opens under any binding.
#[derive(Debug, Clone)]
pub(crate) enum TestKmsProvider {
    Working,
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    FailingToWrap,
    FailingToUnwrap,
    /// Returns its key material from `generate_key_material`, as a KMS generator would.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    Generating(SecretValue),
    /// Unwraps a key into its wrapped bytes followed by the nanoseconds from the instant it
    /// holds to the unwrap, as a little-endian `u64`, so that a caller can tell how old the key
    /// it is given is.
    Stamping(Instant),
    /// Unwraps every key into the key it holds, whatever the wrapped bytes.
    #[cfg(feature = "deterministic")]
    Unwrapping(SecretValue),
}

#[async_trait]
impl KmsAeadEncryptionProvider for TestKmsProvider {
    fn kek(&self) -> &KekRef {
        &TEST_KEK
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
        _binding: Option<&DekBinding>,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
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
        _binding: Option<&DekBinding>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        match self {
            TestKmsProvider::FailingToUnwrap => Err(KmsAeadEncryptionError::create(
                "TEST_UNWRAP",
                "The test provider fails to unwrap",
            )),
            TestKmsProvider::Stamping(since) => {
                let nanos = u64::try_from(since.elapsed().as_nanos())
                    .expect("a test runs for less than 584 years");
                let mut key = encrypted_key.wrapped().to_vec();
                key.extend(nanos.to_le_bytes());
                Ok(DataEncryptionKey::from(SecretValue::new(key)))
            }
            #[cfg(feature = "deterministic")]
            TestKmsProvider::Unwrapping(key) => Ok(DataEncryptionKey::from(key.clone())),
            _ => Ok(DataEncryptionKey::from(SecretValue::new(
                encrypted_key.wrapped().to_vec(),
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

/// A [`TestKmsProvider`] under a KEK of its own, which counts its wraps and unwraps and can hold
/// them, once counted, until the test opens its gate.
pub(crate) struct CountingKmsProvider {
    inner: TestKmsProvider,
    kek: KekRef,
    wraps: AtomicUsize,
    unwraps: AtomicUsize,
    unwrap_bindings: Mutex<Vec<Option<DekBinding>>>,
    gate: watch::Sender<bool>,
}

impl CountingKmsProvider {
    /// A provider whose calls go through at once.
    pub(crate) fn new(inner: TestKmsProvider, kek: &str) -> Self {
        Self {
            inner,
            kek: KekRef::new(KekProvider::Other("test".to_string()), kek),
            wraps: AtomicUsize::new(0),
            unwraps: AtomicUsize::new(0),
            unwrap_bindings: Mutex::new(Vec::new()),
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
    pub(crate) fn wraps(&self) -> usize {
        self.wraps.load(Ordering::SeqCst)
    }

    /// The binding of every unwrap, in order.
    pub(crate) fn unwrap_bindings(&self) -> Vec<Option<DekBinding>> {
        self.unwrap_bindings.lock().unwrap().clone()
    }

    pub(crate) fn unwraps(&self) -> usize {
        self.unwraps.load(Ordering::SeqCst)
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
        encryption_key: &DataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        self.wraps.fetch_add(1, Ordering::SeqCst);
        self.pass_gate().await;
        self.inner
            .encrypt_data_encryption_key(encryption_key, binding)
            .await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.unwraps.fetch_add(1, Ordering::SeqCst);
        self.unwrap_bindings.lock().unwrap().push(binding.cloned());
        self.pass_gate().await;
        self.inner
            .decrypt_data_encryption_key(encrypted_key, binding)
            .await
    }
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
