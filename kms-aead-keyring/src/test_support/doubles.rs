//! The test doubles that need an AEAD backend: a local KMS provider and a memory store that
//! count their calls and fail on demand.

use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kms_aead::errors::KmsAeadNetworkError;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KekRef, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

use crate::errors::KeyringResult;
use crate::store::{KeyringStore, KeyringWatch, Revalidation, StoreKind, Stored, Swap};
use crate::testing::{MemoryKeyringStore, MemoryRevision};
use crate::{
    EntityId, EntityKind, FieldAad, FieldName, FieldSpec, Keyring, KeyringId, KeyringRecord,
};

/// The backend of the build: the gate runs each backend feature on its own.
#[cfg(feature = "ring")]
pub(crate) type TestBackend = kms_aead::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
pub(crate) type TestBackend = kms_aead::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
pub(crate) type TestBackend = kms_aead::RustCrypto;

/// A keyring on the store `S`, the test provider and the backend of the build.
pub(crate) type TestKeyring<S> = Keyring<S, TestProvider, TestBackend>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

/// The AAD of `user/<id>/email`.
pub(crate) fn email_of(user: &str) -> KeyringResult<FieldAad> {
    Ok(EMAIL.aad(&EntityId::try_from(user)?))
}

/// A local KMS provider whose clones share counters of its calls, and whose encryptions fail while
/// [`fail_encryptions`](ProviderCalls::fail_encryptions) is set.
#[derive(Clone)]
pub(crate) struct TestProvider {
    kms: Arc<LocalKmsProvider<TestBackend>>,
    kek: KekRef,
    pub(crate) calls: Arc<ProviderCalls>,
}

#[derive(Default)]
pub(crate) struct ProviderCalls {
    pub(crate) decryptions: AtomicUsize,
    pub(crate) encryptions: AtomicUsize,
    pub(crate) fail_encryptions: AtomicBool,
}

impl TestProvider {
    /// A provider for a random local KEK named `kek`.
    pub(crate) fn new(kek: &str) -> KmsAeadResult<Self> {
        let kms = LocalKmsProvider::ephemeral(LocalKekId::try_from(kek.to_string())?)?;
        Ok(Self {
            kek: kms.kek().clone(),
            kms: Arc::new(kms),
            calls: Arc::default(),
        })
    }

    /// A local KMS reporting a Cloud KMS key as its KEK.
    pub(crate) fn cloud_kms() -> KmsAeadResult<Self> {
        Ok(Self {
            kek: KekRef::new(
                KekProvider::Gcp,
                "projects/p/locations/europe-north1/keyRings/r/cryptoKeys/tenant-42",
            ),
            ..Self::new("tenant-42-kek")?
        })
    }
}

#[async_trait]
impl KmsAeadEncryptionProvider for TestProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        if self.calls.fail_encryptions.load(Ordering::SeqCst) {
            return Err(KmsAeadNetworkError::create(
                "UNAVAILABLE",
                "The test KMS is down",
            ));
        }
        self.calls.encryptions.fetch_add(1, Ordering::SeqCst);
        self.kms.encrypt_data_encryption_key(dek).await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.calls.decryptions.fetch_add(1, Ordering::SeqCst);
        self.kms.decrypt_data_encryption_key(encrypted_dek).await
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
    pub(crate) fn new(memory: &MemoryKeyringStore, delay: Duration) -> Self {
        Self {
            memory: memory.clone(),
            calls: Arc::default(),
            delay,
        }
    }
}

impl KeyringStore for TestStore {
    type Revision = MemoryRevision;

    const KIND: StoreKind = StoreKind::Memory;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<MemoryRevision>>> {
        self.calls.loads.fetch_add(1, Ordering::SeqCst);
        if self.calls.missing.load(Ordering::SeqCst) {
            Ok(None)
        } else {
            self.memory.load(id).await
        }
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &MemoryRevision,
    ) -> KeyringResult<Revalidation<MemoryRevision>> {
        self.calls.revalidations.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        if self.calls.missing.load(Ordering::SeqCst) {
            Ok(Revalidation::Missing)
        } else {
            self.memory.revalidate(id, known).await
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
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                left.checked_sub(1)
            })
            .is_ok();
        if conflict {
            Ok(Swap::Conflict)
        } else {
            self.memory.compare_and_swap(record, expected).await
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
