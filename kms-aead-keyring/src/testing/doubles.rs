//! The test doubles that need an AEAD backend: a local KMS provider and a memory store that
//! count their calls and fail on demand.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kms_aead::errors::KmsAeadNetworkError;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{
    AeadBackend, DataEncryptionKey, EncryptedDataEncryptionKey, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

use crate::errors::KeyringResult;
use crate::store::{
    KeyringStore, KeyringWatch, MemoryKeyringStore, MemoryRevision, Revalidation, StoreKind,
    Stored, Swap,
};
use crate::{EntityId, EntityKind, FieldAad, FieldName, FieldSpec, KeyringId, KeyringRecord};

/// The backend of the build: the gate runs each backend feature on its own.
#[cfg(feature = "ring")]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
pub(crate) const TEST_BACKEND: AeadBackend = AeadBackend::RustCrypto;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

/// The AAD of `user/<id>/email`.
pub(crate) fn email_of(user: &str) -> KeyringResult<FieldAad> {
    Ok(EMAIL.aad(&EntityId::try_from(user)?))
}

/// A local KMS provider whose clones share counters of its calls, and whose wraps fail while
/// [`fail_wraps`](ProviderCalls::fail_wraps) is set.
#[derive(Clone)]
pub(crate) struct TestProvider {
    kms: Arc<LocalKmsProvider>,
    pub(crate) calls: Arc<ProviderCalls>,
}

#[derive(Default)]
pub(crate) struct ProviderCalls {
    pub(crate) unwraps: AtomicUsize,
    pub(crate) wraps: AtomicUsize,
    pub(crate) fail_wraps: AtomicBool,
}

impl TestProvider {
    /// A provider for a random local KEK named `kek`.
    pub(crate) fn new(kek: &str) -> KmsAeadResult<Self> {
        Ok(Self {
            kms: Arc::new(LocalKmsProvider::ephemeral(
                LocalKekId::try_from(kek.to_string())?,
                TEST_BACKEND,
            )?),
            calls: Arc::default(),
        })
    }

    pub(crate) fn unwraps(&self) -> usize {
        self.calls.unwraps.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl KmsAeadEncryptionProvider for TestProvider {
    fn kek(&self) -> KekRef {
        self.kms.kek()
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        if self.calls.fail_wraps.load(Ordering::SeqCst) {
            return Err(KmsAeadNetworkError::create(
                "UNAVAILABLE",
                "The test KMS is down",
            ));
        }
        self.calls.wraps.fetch_add(1, Ordering::SeqCst);
        self.kms.encrypt_data_encryption_key(encryption_key).await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.calls.unwraps.fetch_add(1, Ordering::SeqCst);
        self.kms.decrypt_data_encryption_key(encrypted_key).await
    }
}

/// A memory store whose clones share its records and counters of its calls, and which answers
/// as scripted by [`StoreCalls`].
#[derive(Clone)]
pub(crate) struct TestStore {
    pub(crate) memory: MemoryKeyringStore,
    pub(crate) calls: Arc<StoreCalls>,
    /// How long each revalidation takes, so that concurrent calls overlap it.
    delay: Duration,
}

#[derive(Default)]
pub(crate) struct StoreCalls {
    pub(crate) loads: AtomicUsize,
    pub(crate) revalidations: AtomicUsize,
    /// The writes still to refuse with a conflict.
    pub(crate) conflicts: AtomicU32,
    /// Whether the record reads as missing.
    pub(crate) missing: AtomicBool,
    /// A record that `watch` writes before it subscribes, as a write by another process
    /// between a keyring's first load and its subscription would.
    pub(crate) written_before_watch: Mutex<Option<KeyringRecord>>,
}

impl TestStore {
    pub(crate) fn new(memory: &MemoryKeyringStore) -> Self {
        Self::with_delay(memory, Duration::ZERO)
    }

    pub(crate) fn with_delay(memory: &MemoryKeyringStore, delay: Duration) -> Self {
        Self {
            memory: memory.clone(),
            calls: Arc::default(),
            delay,
        }
    }

    pub(crate) fn loads(&self) -> usize {
        self.calls.loads.load(Ordering::SeqCst)
    }

    pub(crate) fn revalidations(&self) -> usize {
        self.calls.revalidations.load(Ordering::SeqCst)
    }

    fn missing(&self) -> bool {
        self.calls.missing.load(Ordering::SeqCst)
    }
}

impl KeyringStore for TestStore {
    type Revision = MemoryRevision;

    const KIND: StoreKind = StoreKind::Memory;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<MemoryRevision>>> {
        self.calls.loads.fetch_add(1, Ordering::SeqCst);
        match self.missing() {
            true => Ok(None),
            false => self.memory.load(id).await,
        }
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &MemoryRevision,
    ) -> KeyringResult<Revalidation<MemoryRevision>> {
        self.calls.revalidations.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        match self.missing() {
            true => Ok(Revalidation::Missing),
            false => self.memory.revalidate(id, known).await,
        }
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&MemoryRevision>,
    ) -> KeyringResult<Swap<MemoryRevision>> {
        let conflict = self
            .calls
            .conflicts
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        match conflict {
            true => Ok(Swap::Conflict),
            false => self.memory.compare_and_swap(record, expected).await,
        }
    }

    async fn watch(&self, id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        let written = self
            .calls
            .written_before_watch
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        if let Some(record) = written {
            let stored = self.memory.load(id).await?.map(|stored| stored.revision);
            self.memory
                .compare_and_swap(&record, stored.as_ref())
                .await?;
        }
        self.memory.watch(id).await
    }
}
