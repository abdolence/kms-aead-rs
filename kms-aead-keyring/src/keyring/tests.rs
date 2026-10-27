use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use kms_aead::cache::{DekCache, DekCacheOutcome};
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::{Bare, Randomized};
use kms_aead::providers::KmsKeyVersion;
use kms_aead::{
    AeadAlgorithm, AeadCipher, BeaconAlgorithm, DeterministicAlgorithm, KmsAeadEncryptionProvider,
    KmsAeadResult, KmsProvider, Plaintext,
};
use secret_vault_value::SecretValue;
use serde_json::Value;

use super::*;
use crate::errors::{
    PromotionTooEarlyError, RecordConflictError, RecordRegressedError, RegressionRule,
};
use crate::store::KeyringStore;
use crate::sweep::EncryptionMarker;
use crate::test_support::{
    email_of, TestAdmin, TestBackend, TestKeyring, TestProvider, TestRegistry, TestResult,
    TestStore, EMAIL, TENANT,
};
use crate::testing::MemoryKeyringStore;
use crate::{
    EntityId, EntityKind, FieldName, FieldSpec, KeyringAlgorithms, KeyringRegistryOptions,
    Transition,
};

/// A keyring created on a counting store, beside the memory store it writes to, with the
/// administrative handle that created it and an application's handle on it.
struct Fixture {
    memory: MemoryKeyringStore,
    store: TestStore,
    provider: TestProvider,
    registry: TestRegistry<TestStore>,
    admin: TestAdmin<TestStore>,
    keyring: TestKeyring<TestStore>,
}

impl Fixture {
    async fn new(options: KeyringRegistryOptions) -> KeyringResult<Self> {
        let memory = MemoryKeyringStore::new();
        let store = TestStore::new(&memory, Duration::ZERO);
        let provider = TestProvider::new("tenant-42-kek")?;
        let registry = TestRegistry::new(store.clone(), options)?;
        let admin = registry
            .create(provider.clone(), TENANT, KeyringAlgorithms::new())
            .await?;
        let keyring = registry.open(provider.clone(), TENANT).await?;
        Ok(Self {
            memory,
            store,
            provider,
            registry,
            admin,
            keyring,
        })
    }

    /// The same keyring in the administrative job's process.
    async fn other_process(&self) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
        TestRegistry::new(
            self.memory.clone(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .admin(self.provider.clone(), TENANT)
        .await
    }
}

const ALICE: &str = "alice@example.com";

/// `value` with its key id changed to `key_id`.
fn relabelled<T>(
    value: &Encrypted<T, Randomized>,
    key_id: u32,
) -> KeyringResult<Encrypted<T, Randomized>> {
    let mut bytes = value.value().to_vec();
    bytes[1..5].copy_from_slice(&key_id.to_be_bytes());
    Ok(Encrypted::try_from(bytes)?)
}

#[tokio::test]
async fn a_value_is_the_key_id_prefix_and_the_aead_cipher_output() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let bytes = value.value();
    assert_eq!(bytes[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);

    let record = fixture.keyring.record();
    let encrypted_dek = record
        .version(KeyId::new(1))
        .and_then(KeyVersion::encrypted_dek)
        .ok_or("version 1 holds no key")?;
    let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
    let bare = Encrypted::<String, Bare>::try_from(bytes[5..].to_vec())?;
    let (decrypted, _) = DekCache::disabled()
        .with_dek(&fixture.provider, encrypted_dek, |dek| {
            cipher.decrypt_bare(&aad.bytes, &bare, dek)
        })
        .await?;
    assert_eq!(decrypted?, ALICE);
    Ok(())
}

#[tokio::test]
async fn values_round_trip_through_their_plaintext_types() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;

    let text = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(keyring.decrypt(&aad, &text).await?, ALICE);

    let bytes = vec![0u8, 0xFF, 0x07];
    let encrypted = keyring.encryptor().await.encrypt(&aad, &bytes).await?;
    assert_eq!(keyring.decrypt(&aad, &encrypted).await?, bytes);

    let json = crate::JsonEncoded::new(vec![("plan".to_string(), 3u32)]);
    let encrypted = keyring.encryptor().await.encrypt(&aad, &json).await?;
    assert_eq!(keyring.decrypt(&aad, &encrypted).await?, json);
    Ok(())
}

/// An application's email type, encrypted as the UTF-8 of the address.
#[derive(Debug, PartialEq)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

/// A newtype field is encrypted as the plaintext of the type it maps to, so a reader of that type,
/// such as BigQuery's `AEAD.DECRYPT_STRING` for a `String`, decrypts it.
#[tokio::test]
async fn a_newtype_field_is_encrypted_as_its_string() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let alice = Email(ALICE.to_string());

    let encrypted: Encrypted<Email, Randomized> = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &alice)
        .await?;
    let as_string = Encrypted::<String, Randomized>::try_from(encrypted.value().to_vec())?;

    assert_eq!(fixture.keyring.decrypt(&aad, &encrypted).await?, alice);
    assert_eq!(fixture.keyring.decrypt(&aad, &as_string).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_value_decrypts_only_with_its_aad() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let value = keyring
        .encryptor()
        .await
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;

    for aad in [
        email_of("43")?,
        email_of("42")?.with_context(b"eu"),
        EMAIL.custom_aad(b"user/42/email/")?,
    ] {
        assert!(matches!(
            keyring.decrypt(&aad, &value).await,
            Err(KeyringError::KmsAead(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
        ));
    }
    let same_bytes = EMAIL.custom_aad(b"user/42/email")?;
    assert_eq!(keyring.decrypt(&same_bytes, &value).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_relabelled_prefix_fails_under_the_other_version() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let first = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let second = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(
        (first.key_id(), second.key_id()),
        (KeyId::new(1), KeyId::new(2))
    );

    assert!(matches!(
        keyring.decrypt(&aad, &relabelled(&first, 2)?).await,
        Err(KeyringError::KmsAead(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
    ));
    assert!(matches!(
        keyring.decrypt(&aad, &relabelled(&second, 1)?).await,
        Err(KeyringError::KmsAead(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
    ));
    assert_eq!(keyring.decrypt(&aad, &first).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_reserved_or_deterministic_key_id_fails_before_any_store_or_kms_call() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let store_calls = || {
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst),
        )
    };
    let before = store_calls();
    let decryptions = fixture.provider.calls.decryptions.load(Ordering::SeqCst);

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &relabelled(&value, 0)?).await,
        Err(KeyringError::ReservedKeyId(_))
    ));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &relabelled(&value, 0x8000_0001)?).await,
        Err(KeyringError::KeyPurposeMismatch(error)) if error.expected == Purpose::Randomized
    ));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &relabelled(&value, 0xC000_0001)?).await,
        Err(KeyringError::KeyPurposeMismatch(error)) if error.expected == Purpose::Randomized
    ));
    assert_eq!(store_calls(), before);
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        decryptions
    );
    Ok(())
}

#[tokio::test]
async fn an_operation_on_a_reserved_key_id_fails_before_any_store_call() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = &fixture.admin;
    let store_calls = || {
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst),
        )
    };
    let before = store_calls();

    for reserved in [0, 1 << 31, 1 << 30, 3 << 30].map(KeyId::new) {
        for refused in [
            admin.promote_now(reserved).await.map(|_| ()),
            admin.mark_compromised(reserved, None).await.map(|_| ()),
            admin.retire(reserved).await,
            admin.reinstate(reserved).await,
            admin.destroy(reserved).await,
            admin
                .export_tink_keyset(KeysetSelection::Single(reserved))
                .await
                .map(|_| ()),
        ] {
            assert!(matches!(refused, Err(KeyringError::ReservedKeyId(_))));
        }
    }
    assert_eq!(store_calls(), before);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_id_reloads_once_under_concurrency() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let admin = TestRegistry::new(
        memory.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(provider.clone(), TENANT, KeyringAlgorithms::new())
    .await?;
    let store = TestStore::new(&memory, Duration::from_millis(50));
    let reader = Arc::new(
        TestRegistry::new(
            store.clone(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .open(provider, TENANT)
        .await?,
    );
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let aad = Arc::new(email_of("42")?);
    let value = admin
        .keyring()
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;

    let mut reads = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let (reader, aad, value) = (Arc::clone(&reader), Arc::clone(&aad), value.clone());
        reads.spawn(async move { reader.decrypt(&aad, &value).await });
    }
    while let Some(read) = reads.join_next().await {
        assert_eq!(read??, ALICE);
    }
    assert_eq!(store.calls.revalidations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reload_is_rate_limited() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let unknown = relabelled(
        &fixture
            .keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?,
        9,
    )?;

    for _ in 0..3 {
        assert!(matches!(
            fixture.keyring.decrypt(&aad, &unknown).await,
            Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == KeyId::new(9)
        ));
        assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(fixture.keyring.decrypt(&aad, &unknown).await.is_err());
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn reencrypt_of_a_key_id_the_record_lacks_reloads_and_fails() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let unknown = relabelled(
        &fixture
            .keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?,
        9,
    )?;

    assert!(matches!(
        fixture.keyring.encryptor().await.reencrypt(&aad, &unknown).await,
        Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == KeyId::new(9)
    ));
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn record_ttl_revalidates_with_a_conditional_read() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let admin = fixture.other_process().await?;
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    let cached = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(cached.key_id(), KeyId::new(1));
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 0)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let refreshed = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(refreshed.key_id(), KeyId::new(2));
    fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 1)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let unchanged = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(unchanged.key_id(), KeyId::new(2));
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 2)
    );
    Ok(())
}

/// A record gone from the store is a shredded keyring: the process destroys every version of its
/// cached record at the next revalidation, and its registry opens the keyring anew, refusing the
/// record as it was, which would revive what the process destroyed.
#[tokio::test(start_paused = true)]
async fn a_missing_record_destroys_every_version_in_the_process() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    fixture.store.calls.missing.store(true, Ordering::SeqCst);

    tokio::time::advance(KeyringRegistryOptions::DEFAULT_RECORD_TTL).await;
    let encrypted = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await;

    assert!(matches!(encrypted, Err(KeyringError::NoActiveVersion(_))));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await,
        Err(KeyringError::RecordMissing(_))
    ));

    fixture.store.calls.missing.store(false, Ordering::SeqCst);
    let restored = fixture
        .registry
        .open(fixture.provider.clone(), TENANT)
        .await;
    assert!(matches!(restored, Err(KeyringError::RecordRegressed(_))));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    Ok(())
}

#[tokio::test]
async fn a_record_ttl_of_duration_max_opens() -> TestResult {
    let options = KeyringRegistryOptions::new()
        .with_watch(false)
        .with_record_ttl(Duration::MAX)
        .with_reload_min_interval(Duration::MAX);
    let fixture = Fixture::new(options).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let unknown = relabelled(&value, 9)?;
    for _ in 0..2 {
        assert!(matches!(
            fixture.keyring.decrypt(&aad, &unknown).await,
            Err(KeyringError::KeyVersionUnknown(_))
        ));
    }
    fixture.keyring.reload().await?;
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn open_with_the_wrong_kek_fails() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let other = TestProvider::new("another-kek")?;
    let opened = TestRegistry::new(
        fixture.memory.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .open(other.clone(), TENANT)
    .await;
    assert!(matches!(
        opened,
        Err(KeyringError::KekMismatch(error))
            if &error.recorded == fixture.provider.kek() && &error.provider == other.kek()
    ));
    Ok(())
}

#[tokio::test]
async fn cas_conflicts_are_retried_then_refused() -> TestResult {
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_keyring(KeyringOptions::new().with_cas_retries(2)),
    )
    .await?;
    fixture.store.calls.conflicts.store(2, Ordering::SeqCst);
    let encryptions = fixture.provider.calls.encryptions.load(Ordering::SeqCst);
    let staged = fixture.admin.rotate(Purpose::Randomized).await?;
    assert_eq!(staged, KeyId::new(2));
    assert_eq!(fixture.store.calls.loads.load(Ordering::SeqCst), 3);
    assert_eq!(
        fixture.provider.calls.encryptions.load(Ordering::SeqCst),
        encryptions + 1
    );

    fixture.store.calls.conflicts.store(3, Ordering::SeqCst);
    assert!(matches!(
        fixture.admin.promote_now(staged).await,
        Err(KeyringError::RecordConflict(RecordConflictError {
            attempts: 3,
            ..
        }))
    ));
    let stored = fixture.other_process().await?.keyring().record();
    assert_eq!(
        stored.version(staged).map(KeyVersion::state),
        Some(KeyVersionState::Pending)
    );
    Ok(())
}

#[tokio::test]
async fn mark_compromised_evicts_the_dek() -> TestResult {
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_keyring(
                KeyringOptions::new().with_compromised_reads(CompromisedReadPolicy::Allow),
            ),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(fixture.provider.calls.decryptions.load(Ordering::SeqCst), 1);

    let rotation = fixture
        .admin
        .mark_compromised(KeyId::new(1), Some("laptop lost".to_string()))
        .await?;
    assert_eq!(
        rotation.map(|rotation| rotation.current),
        Some(KeyId::new(2))
    );
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        2,
        "the key was evicted, so the read missed"
    );
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        2,
        "Allow reads through the cache"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_decrypted_under_a_superseded_record_is_evicted() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let held = fixture.keyring.record();
    let encrypted_dek = held
        .version(KeyId::new(1))
        .and_then(KeyVersion::encrypted_dek)
        .ok_or("version 1 holds no key")?;
    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::new(1), None)
        .await?;
    fixture.keyring.reload().await?;

    fixture
        .keyring
        .with_cached_dek(&held, KeyId::new(1), encrypted_dek, |_| ())
        .await?;
    let ((), outcome) = fixture
        .keyring
        .dek_cache()
        .with_dek(&fixture.provider, encrypted_dek, |_| ())
        .await?;
    assert_eq!(outcome, DekCacheOutcome::Miss);
    Ok(())
}

#[tokio::test]
async fn block_refuses_before_decrypting() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    fixture.admin.mark_compromised(KeyId::new(1), None).await?;
    let decryptions = fixture.provider.calls.decryptions.load(Ordering::SeqCst);

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == KeyId::new(1)
    ));
    let other = fixture.other_process().await?;
    assert!(matches!(
        other.keyring().decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        decryptions
    );
    Ok(())
}

#[tokio::test]
async fn a_forgery_under_a_known_dek_is_refused_under_block() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let record = fixture.keyring.record();
    let encrypted_dek = record
        .version(KeyId::new(1))
        .and_then(KeyVersion::encrypted_dek)
        .ok_or("version 1 holds no key")?;
    let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
    let first = KeyId::new(1);
    let (forged, _) = DekCache::disabled()
        .with_dek(&fixture.provider, encrypted_dek, |leaked_dek| {
            cipher.encrypt(
                first,
                &aad.bytes,
                &"mallory@example.com".to_string(),
                leaked_dek,
            )
        })
        .await?;
    let forged: Encrypted<String, Randomized> = forged?;
    fixture
        .admin
        .mark_compromised(KeyId::new(1), Some("dek leaked".to_string()))
        .await?;

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &forged).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    let status = fixture.keyring.decrypt_with_trust(&aad, &forged).await?;
    assert_eq!(status.value, "mallory@example.com");
    assert_eq!(status.key_id, KeyId::new(1));
    assert!(matches!(
        status.trust,
        KeyTrust::Compromised(compromise) if compromise.note() == Some("dek leaked")
    ));
    Ok(())
}

#[tokio::test]
async fn decrypt_with_trust_decrypts_a_compromised_version_past_the_cache() -> TestResult {
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_keyring(
                KeyringOptions::new().with_compromised_reads(CompromisedReadPolicy::Allow),
            ),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    fixture.admin.mark_compromised(KeyId::new(1), None).await?;
    let decryptions = fixture.provider.calls.decryptions.load(Ordering::SeqCst);

    for read in 1..=2 {
        let status = fixture.keyring.decrypt_with_trust(&aad, &value).await?;
        assert!(matches!(status.trust, KeyTrust::Compromised(_)));
        assert_eq!(
            fixture.provider.calls.decryptions.load(Ordering::SeqCst),
            decryptions + read
        );
    }
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        decryptions + 3,
        "the reads above cached nothing"
    );

    let trusted = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let status = fixture.keyring.decrypt_with_trust(&aad, &trusted).await?;
    assert_eq!(
        (status.key_id, status.trust),
        (KeyId::new(2), KeyTrust::Trusted)
    );
    Ok(())
}

#[tokio::test]
async fn a_reload_runs_while_a_write_waits_for_the_kms() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let calls = &fixture.provider.calls;
    let held = calls.encryption_gate.write().await;
    let encryptions = calls.encryptions.load(Ordering::SeqCst);

    let (staged, reloaded) = tokio::join!(fixture.admin.rotate(Purpose::Randomized), async {
        while calls.encryptions.load(Ordering::SeqCst) == encryptions {
            tokio::task::yield_now().await;
        }
        let reloaded = tokio::time::timeout(Duration::from_secs(1), fixture.keyring.reload()).await;
        drop(held);
        reloaded
    });

    assert!(matches!(reloaded, Ok(Ok(_))));
    assert_eq!(staged?, KeyId::new(2));
    Ok(())
}

#[tokio::test]
async fn mark_compromised_writes_the_flag_when_the_encryption_fails() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    fixture
        .provider
        .calls
        .fail_encryptions
        .store(true, Ordering::SeqCst);

    assert_eq!(
        fixture.admin.mark_compromised(KeyId::new(1), None).await?,
        None
    );
    for record in [
        fixture.keyring.record(),
        fixture.other_process().await?.keyring().record(),
    ] {
        let version = record.version(KeyId::new(1)).ok_or("version 1 is gone")?;
        assert_eq!(version.state(), KeyVersionState::DecryptOnly);
        assert!(version.compromised().is_some());
        assert!(record.active(Purpose::Randomized).is_none());
    }
    assert!(matches!(
        fixture.keyring.encryptor().await.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::NoActiveVersion(error)) if error.purpose == Purpose::Randomized
    ));
    assert!(matches!(
        fixture.admin.rotate(Purpose::Randomized).await,
        Err(KeyringError::KmsAead(_))
    ));

    fixture
        .provider
        .calls
        .fail_encryptions
        .store(false, Ordering::SeqCst);
    let staged = fixture.admin.rotate(Purpose::Randomized).await?;
    assert!(matches!(
        fixture
            .keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await,
        Err(KeyringError::NoActiveVersion(_))
    ));
    let rotation = fixture.admin.promote_now(staged).await?;
    assert_eq!((rotation.previous, rotation.current), (None, KeyId::new(2)));
    assert_eq!(
        (fixture
            .keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?)
            .key_id(),
        KeyId::new(2)
    );
    Ok(())
}

#[tokio::test]
async fn retired_and_destroyed_versions_refuse_reads() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let old = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    admin.retire(KeyId::new(1)).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    assert!(matches!(
        keyring.decrypt_with_trust(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    admin.reinstate(KeyId::new(1)).await?;
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);

    admin.retire(KeyId::new(1)).await?;
    admin.destroy(KeyId::new(1)).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    assert!(matches!(
        admin.retire(KeyId::new(2)).await,
        Err(KeyringError::InvalidTransition(error))
            if error.from == KeyVersionState::Active && error.transition == Transition::Retire
    ));
    let stored = fixture.other_process().await?.keyring().record();
    let destroyed = stored.version(KeyId::new(1)).ok_or("version 1 is gone")?;
    assert_eq!(destroyed.state(), KeyVersionState::Destroyed);
    assert!(destroyed.encrypted_dek().is_none());
    Ok(())
}

#[tokio::test]
async fn dangerously_destroy_all_versions_leaves_nothing_to_encrypt_or_decrypt_with() -> TestResult
{
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let encrypted = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let promoted = admin.rotate(Purpose::Randomized).await?;
    admin.promote_now(promoted).await?;
    admin.rotate(Purpose::Randomized).await?;

    admin.dangerously_destroy_all_versions().await?;

    for record in [
        keyring.record(),
        fixture.other_process().await?.keyring().record(),
    ] {
        assert!(record
            .versions()
            .iter()
            .all(|version| version.state() == KeyVersionState::Destroyed));
    }
    assert!(matches!(
        keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await,
        Err(KeyringError::NoActiveVersion(_))
    ));
    assert!(matches!(
        keyring.decrypt(&aad, &encrypted).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    Ok(())
}

#[tokio::test]
async fn dangerously_shred_leaves_open_failing_with_record_missing() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;

    fixture.admin.dangerously_shred().await?;

    let elsewhere = TestRegistry::new(
        fixture.memory.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?;
    assert!(matches!(
        fixture
            .registry
            .open(fixture.provider.clone(), TENANT)
            .await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert!(matches!(
        elsewhere.open(fixture.provider.clone(), TENANT).await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert!(fixture.memory.load(&TENANT).await?.is_none());
    Ok(())
}

/// A process that watches the keyring takes the shred from the store's change signal, within the
/// reload interval, and evicts the keyring's key from its DEK cache.
#[tokio::test(start_paused = true)]
async fn a_watching_process_drops_a_shredded_keyring_within_the_reload_interval() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new()).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let encrypted_dek = fixture
        .keyring
        .record()
        .version(KeyId::new(1))
        .and_then(KeyVersion::encrypted_dek)
        .cloned()
        .ok_or("version 1 holds no key")?;
    // The follow task's first revalidation, which no signal causes.
    tokio::time::sleep(Duration::from_millis(1)).await;

    fixture.other_process().await?.dangerously_shred().await?;
    tokio::time::sleep(KeyringRegistryOptions::DEFAULT_RELOAD_MIN_INTERVAL).await;

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    let (_, outcome) = fixture
        .keyring
        .dek_cache()
        .with_dek(&fixture.provider, &encrypted_dek, |_| ())
        .await?;
    assert_eq!(outcome, DekCacheOutcome::Miss);
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    fixture.registry.shutdown(None).await;
    Ok(())
}

/// A shred whose delete fails leaves a record of destroyed versions, which a second shred deletes;
/// a third finds nothing to do.
#[tokio::test]
async fn an_interrupted_shred_is_completed_by_running_it_again() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    fixture
        .store
        .calls
        .fail_deletions
        .store(true, Ordering::SeqCst);

    let interrupted = fixture.admin.dangerously_shred().await;

    assert!(matches!(interrupted, Err(KeyringError::Store(_))));
    let left = fixture
        .memory
        .load(&TENANT)
        .await?
        .ok_or("the record is gone")?;
    assert!(left
        .record
        .versions()
        .iter()
        .all(|version| version.state() == KeyVersionState::Destroyed));
    fixture
        .store
        .calls
        .fail_deletions
        .store(false, Ordering::SeqCst);
    fixture.admin.dangerously_shred().await?;
    assert!(fixture.memory.load(&TENANT).await?.is_none());
    fixture.admin.dangerously_shred().await?;
    Ok(())
}

/// The id of a shredded keyring is free for a new keyring, which the registry opens anew, while
/// the handles on the shredded one keep every version destroyed and read the store no more.
#[tokio::test]
async fn a_keyring_created_again_after_a_shred_is_a_new_keyring() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    fixture.admin.dangerously_shred().await?;

    let created = fixture
        .registry
        .create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
        .await?;
    let value = created
        .keyring()
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;

    let opened = fixture
        .registry
        .open(fixture.provider.clone(), TENANT)
        .await?;
    assert_eq!(opened.decrypt(&aad, &value).await?, ALICE);
    assert_eq!(value.key_id(), KeyId::new(1));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    assert!(matches!(
        fixture.admin.rotate(Purpose::Randomized).await,
        Err(KeyringError::RecordMissing(_))
    ));
    Ok(())
}

/// A shred repeated on the handle that completed it, as after a lost reply, is complete without
/// reading the store, so it leaves a keyring created under the id meanwhile alone.
#[tokio::test]
async fn a_shred_repeated_after_the_id_was_created_again_leaves_the_new_keyring() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    fixture.admin.dangerously_shred().await?;
    fixture
        .registry
        .create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
        .await?;

    fixture.admin.dangerously_shred().await?;

    assert!(fixture.memory.load(&TENANT).await?.is_some());
    Ok(())
}

#[tokio::test]
async fn create_refuses_an_existing_record_and_open_or_create_opens_it() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let created = TestRegistry::new(
        fixture.memory.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
    .await;
    assert!(matches!(created, Err(KeyringError::RecordExists(_))));

    let opened = TestRegistry::new(
        fixture.memory.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .open_or_create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
    .await?;
    assert_eq!(
        opened.keyring().record().to_json()?,
        fixture.keyring.record().to_json()?
    );

    let empty = MemoryKeyringStore::new();
    let opened = TestRegistry::new(
        empty.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .open(fixture.provider.clone(), TENANT)
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
    let fresh = TestRegistry::new(empty, KeyringRegistryOptions::new().with_watch(false))?
        .open_or_create(fixture.provider.clone(), TENANT, KeyringAlgorithms::new())
        .await?;
    let record = fresh.keyring().record();
    let active = record
        .active(Purpose::Randomized)
        .ok_or("no active version")?;
    assert_eq!(
        (active.id(), active.algorithm()),
        (
            KeyId::new(1),
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm)
        )
    );
    Ok(())
}

#[tokio::test]
async fn reencrypt_deks_encrypts_every_version_again_and_values_still_decrypt() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let old = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let staged = admin.rotate(Purpose::Randomized).await?;
    let previous_encrypted_deks = keyring.record().encrypted_deks();
    let first_kek_version = KmsKeyVersion::try_from("1".to_string())?;
    let rotated_kek_version = KmsKeyVersion::try_from("2".to_string())?;
    assert_eq!(
        keyring.record().kek_versions_in_use(),
        [Some(&first_kek_version)]
    );
    fixture
        .provider
        .calls
        .kek_rotated
        .store(true, Ordering::SeqCst);
    let decryptions = fixture.provider.calls.decryptions.load(Ordering::SeqCst);

    let reencryptions = admin.reencrypt_deks().await?;

    assert_eq!(
        reencryptions,
        [KeyId::new(1), staged].map(|key_id| DekReencryption {
            key_id,
            previous_kek_version: Some(first_kek_version.clone()),
            kek_version: Some(rotated_kek_version.clone()),
        })
    );
    assert_eq!(
        keyring.record().kek_versions_in_use(),
        [Some(&rotated_kek_version)]
    );
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        decryptions + 2
    );
    let current_encrypted_deks = keyring.record().encrypted_deks();
    for ((key_id, previous_encrypted_dek), (reencrypted_id, current_encrypted_dek)) in
        previous_encrypted_deks.iter().zip(&current_encrypted_deks)
    {
        assert_eq!(key_id, reencrypted_id);
        assert_ne!(previous_encrypted_dek, current_encrypted_dek);
    }
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn reencrypt_deks_records_the_kek_version_of_a_version_another_writer_added() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let staged = fixture
        .other_process()
        .await?
        .rotate(Purpose::Randomized)
        .await?;
    fixture
        .provider
        .calls
        .kek_rotated
        .store(true, Ordering::SeqCst);
    fixture.store.calls.conflicts.store(1, Ordering::SeqCst);

    let reencryptions = fixture.admin.reencrypt_deks().await?;

    let first_kek_version = KmsKeyVersion::try_from("1".to_string())?;
    let rotated_kek_version = KmsKeyVersion::try_from("2".to_string())?;
    assert_eq!(
        reencryptions,
        [KeyId::new(1), staged].map(|key_id| DekReencryption {
            key_id,
            previous_kek_version: Some(first_kek_version.clone()),
            kek_version: Some(rotated_kek_version.clone()),
        })
    );
    let stored = fixture.other_process().await?.keyring().record();
    assert_eq!(stored.kek_versions_in_use(), [Some(&rotated_kek_version)]);
    Ok(())
}

#[tokio::test]
async fn every_write_that_encrypts_a_dek_records_the_kek_version_it_stores() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = &fixture.admin;
    fixture
        .provider
        .calls
        .kek_rotated
        .store(true, Ordering::SeqCst);
    fixture.store.calls.conflicts.store(1, Ordering::SeqCst);

    let staged = admin.rotate(Purpose::Randomized).await?;
    let replacement = admin
        .mark_compromised(KeyId::new(1), None)
        .await?
        .ok_or("the compromised active version is replaced")?;

    let stored = fixture.other_process().await?.keyring().record();
    let kek_versions: Vec<(KeyId, Option<&KmsKeyVersion>)> = stored
        .versions()
        .iter()
        .map(|version| (version.id(), version.kek_version()))
        .collect();
    let first_kek_version = KmsKeyVersion::try_from("1".to_string())?;
    let rotated_kek_version = KmsKeyVersion::try_from("2".to_string())?;
    assert_eq!(
        kek_versions,
        [
            (KeyId::new(1), Some(&first_kek_version)),
            (staged, Some(&rotated_kek_version)),
            (replacement.current, Some(&rotated_kek_version)),
        ]
    );
    Ok(())
}

#[tokio::test]
async fn the_reencryption_epoch_moves_on_once_per_write_that_activates_a_version() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let (admin, keyring) = (&fixture.admin, &fixture.keyring);
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(1)
    );

    let second = admin.rotate(Purpose::Randomized).await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(1)
    );
    admin.promote_now(second).await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(2)
    );
    let third = admin
        .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
        .await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(2)
    );
    admin.promote_now(third).await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(3)
    );

    admin.mark_compromised(KeyId::new(1), None).await?;
    admin.retire(second).await?;
    admin.reinstate(second).await?;
    admin.retire(second).await?;
    admin.destroy(second).await?;
    admin.reencrypt_deks().await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(3)
    );

    let replacement = admin
        .mark_compromised(third, None)
        .await?
        .ok_or("the compromised active version is replaced")?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(4)
    );
    fixture
        .provider
        .calls
        .fail_encryptions
        .store(true, Ordering::SeqCst);
    assert_eq!(
        admin.mark_compromised(replacement.current, None).await?,
        None
    );
    fixture
        .provider
        .calls
        .fail_encryptions
        .store(false, Ordering::SeqCst);
    admin
        .destroy(admin.rotate(Purpose::Randomized).await?)
        .await?;
    admin.dangerously_destroy_all_versions().await?;
    assert_eq!(
        keyring.record().encryption_marker(),
        EncryptionMarker::of_epoch(4)
    );
    assert_eq!(
        fixture
            .other_process()
            .await?
            .keyring()
            .record()
            .encryption_marker(),
        EncryptionMarker::of_epoch(4)
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_promotions_move_the_reencryption_epoch_on_once_each() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let options = KeyringRegistryOptions::new().with_watch(false);
    let creator = TestRegistry::new(memory.clone(), options.clone())?
        .create(
            provider.clone(),
            TENANT,
            KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
        )
        .await?;
    let randomized = creator.rotate(Purpose::Randomized).await?;
    let beacon = creator.rotate(Purpose::Beacon).await?;
    // Two processes whose loads take long enough that both writes read the same record, so that
    // one of them loses its compare-and-swap and applies its promotion again on the other's.
    let stores = [
        TestStore::new(&memory, Duration::from_millis(50)),
        TestStore::new(&memory, Duration::from_millis(50)),
    ];
    let first = TestRegistry::new(stores[0].clone(), options.clone())?
        .admin(provider.clone(), TENANT)
        .await?;
    let second = TestRegistry::new(stores[1].clone(), options)?
        .admin(provider, TENANT)
        .await?;

    let (first_rotation, second_rotation) =
        tokio::join!(first.promote_now(randomized), second.promote_now(beacon));

    first_rotation?;
    second_rotation?;
    let loads: usize = stores
        .iter()
        .map(|store| store.calls.loads.load(Ordering::SeqCst))
        .sum();
    assert_eq!(loads, 5, "two opens, two writes and one retry");
    let record = memory
        .load(&TENANT)
        .await?
        .ok_or("the record is gone")?
        .record;
    assert_eq!(record.encryption_marker(), EncryptionMarker::of_epoch(3));
    let mut starts = Vec::new();
    for (replaced, promoted) in [
        (Purpose::Randomized.first_key_id(), randomized),
        (Purpose::Beacon.first_key_id(), beacon),
    ] {
        let range = record
            .version(promoted)
            .and_then(KeyVersion::reencrypt_range)
            .ok_or("a promoted version has a range")?;
        assert_eq!(
            record
                .version(replaced)
                .and_then(KeyVersion::reencrypt_range)
                .and_then(|replaced| replaced.end()),
            Some(range.start()),
            "the replaced version's range ends where the promoted one's starts"
        );
        starts.push(range.start());
    }
    starts.sort();
    assert_eq!(
        starts,
        [EncryptionMarker::of_epoch(2), EncryptionMarker::of_epoch(3)]
    );
    Ok(())
}

/// A write that reads a value before it encrypts: the read revalidates the cache, whose TTL is
/// zero, after another process promoted a version of every purpose.
#[tokio::test]
async fn an_encryptor_encrypts_every_field_under_the_record_its_marker_names() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let options = KeyringRegistryOptions::new().with_watch(false);
    let algorithms = KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256);
    #[cfg(feature = "deterministic")]
    let algorithms = algorithms.with_deterministic(DeterministicAlgorithm::Aes256Siv);
    let admin = TestRegistry::new(memory.clone(), options.clone())?
        .create(provider.clone(), TENANT, algorithms)
        .await?;
    let store = TestStore::new(&memory, Duration::ZERO);
    let keyring = TestRegistry::new(store.clone(), options.with_record_ttl(Duration::ZERO))?
        .open(provider, TENANT)
        .await?;
    let aad = email_of("42")?;
    let alice = ALICE.to_string();
    let stored = keyring.encryptor().await.encrypt(&aad, &alice).await?;
    let mut staged = Vec::new();
    for purpose in Purpose::ALL {
        if admin.keyring().record().active(purpose).is_some() {
            staged.push(admin.rotate(purpose).await?);
        }
    }

    let encryptor = keyring.encryptor().await;
    for key_id in staged {
        admin.promote_now(key_id).await?;
    }
    let revalidations = store.calls.revalidations.load(Ordering::SeqCst);
    assert_eq!(keyring.decrypt(&aad, &stored).await?, ALICE);
    assert!(store.calls.revalidations.load(Ordering::SeqCst) > revalidations);
    let encrypted = [
        (
            Purpose::Randomized,
            encryptor.encrypt(&aad, &alice).await?.key_id(),
        ),
        (
            Purpose::Beacon,
            encryptor.beacon(&EMAIL, &alice).await?.key_id(),
        ),
        #[cfg(feature = "deterministic")]
        (
            Purpose::Deterministic,
            encryptor
                .encrypt_deterministic(&EMAIL.deterministic_aad(), &alice)
                .await?
                .key_id(),
        ),
    ];

    let marker = encryptor.record().encryption_marker();
    let current = keyring.record();
    assert!(
        current.encryption_marker() > marker,
        "the cache moved on mid-write"
    );
    for (purpose, key_id) in encrypted {
        assert_eq!(
            encryptor.record().active(purpose).map(KeyVersion::id),
            Some(key_id),
            "the {purpose} field is under the encryptor's record"
        );
        let range = current
            .version(key_id)
            .and_then(KeyVersion::reencrypt_range)
            .ok_or("a version encrypted under has a range")?;
        assert!(range.contains(marker), "the range of the {purpose} version");
    }
    Ok(())
}

#[tokio::test]
async fn an_encryptor_older_than_a_value_refuses_to_reencrypt_it_under_its_own_versions(
) -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = fixture.other_process().await?;
    let aad = email_of("42")?;
    let alice = ALICE.to_string();
    let stale = fixture.keyring.encryptor().await;
    let compromised = stale
        .record()
        .active(Purpose::Randomized)
        .map(KeyVersion::id)
        .ok_or("a new keyring has an active randomised version")?;
    let old = stale.encrypt(&aad, &alice).await?;
    let replacement = admin
        .mark_compromised(compromised, None)
        .await?
        .ok_or("the compromised active version is replaced")?
        .current;
    let newer = admin
        .keyring()
        .encryptor()
        .await
        .encrypt(&aad, &alice)
        .await?;

    let refused = stale.reencrypt(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::EncryptorOutdated(error)) if error.key_id == replacement
        ),
        "a re-encryption back under the compromised version: {:?}",
        refused.map(|reencrypted| reencrypted.map(|reencrypted| reencrypted.value.key_id()))
    );
    let encryptor = fixture.keyring.encryptor().await;
    assert!(encryptor.reencrypt(&aad, &newer).await?.is_none());
    let reencrypted = encryptor
        .reencrypt(&aad, &old)
        .await?
        .ok_or("a value under the compromised version is re-encrypted")?;
    assert_eq!(reencrypted.value.key_id(), replacement);
    assert!(matches!(reencrypted.trust, KeyTrust::Compromised(_)));
    Ok(())
}

#[tokio::test]
async fn reencrypt_under_a_version_the_cache_holds_as_pending_reloads_the_cache() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let alice = ALICE.to_string();
    let old = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &alice)
        .await?;
    let pending = fixture.admin.rotate(Purpose::Randomized).await?;
    let stale = fixture.keyring.encryptor().await;
    let admin = fixture.other_process().await?;
    admin.promote_now(pending).await?;
    let newer = admin
        .keyring()
        .encryptor()
        .await
        .encrypt(&aad, &alice)
        .await?;
    let revalidations = fixture.store.calls.revalidations.load(Ordering::SeqCst);

    let refused = stale.reencrypt(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::EncryptorOutdated(error)) if error.key_id == pending
        ),
        "a re-encryption back under the previous version: {:?}",
        refused.map(|reencrypted| reencrypted.map(|reencrypted| reencrypted.value.key_id()))
    );
    let encryptor = fixture.keyring.encryptor().await;
    assert!(encryptor.reencrypt(&aad, &newer).await?.is_none());
    let reencrypted = encryptor
        .reencrypt(&aad, &old)
        .await?
        .ok_or("a value under the previous version is re-encrypted")?;
    assert_eq!(reencrypted.value.key_id(), pending);
    assert!(matches!(
        stale.reencrypt(&aad, &newer).await,
        Err(KeyringError::EncryptorOutdated(_))
    ));
    assert_eq!(
        fixture.store.calls.revalidations.load(Ordering::SeqCst),
        revalidations + 1
    );
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn an_encryptor_that_holds_a_values_version_as_pending_refuses_to_reencrypt_it() -> TestResult
{
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let options = KeyringRegistryOptions::new().with_watch(false);
    let admin = TestRegistry::new(memory.clone(), options.clone())?
        .create(
            provider.clone(),
            TENANT,
            KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
        )
        .await?;
    let aad = EMAIL.deterministic_aad();
    let alice = ALICE.to_string();
    let old = admin
        .keyring()
        .encryptor()
        .await
        .encrypt_deterministic(&aad, &alice)
        .await?;
    let pending = admin.rotate(Purpose::Deterministic).await?;
    let keyring = TestRegistry::new(memory, options)?
        .open(provider, TENANT)
        .await?;
    let stale = keyring.encryptor().await;
    admin.promote_now(pending).await?;
    let newer = admin
        .keyring()
        .encryptor()
        .await
        .encrypt_deterministic(&aad, &alice)
        .await?;

    let refused = stale.reencrypt_deterministic(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::EncryptorOutdated(error)) if error.key_id == pending
        ),
        "a re-encryption back under the previous version: {:?}",
        refused.map(|reencrypted| reencrypted.map(|reencrypted| reencrypted.value.key_id()))
    );
    let encryptor = keyring.encryptor().await;
    assert!(encryptor
        .reencrypt_deterministic(&aad, &newer)
        .await?
        .is_none());
    let reencrypted = encryptor
        .reencrypt_deterministic(&aad, &old)
        .await?
        .ok_or("a value under the previous version is re-encrypted")?;
    assert_eq!(reencrypted.value, newer);
    assert_eq!(reencrypted.trust, KeyTrust::Trusted);
    Ok(())
}

#[tokio::test]
async fn change_algorithm_rotates_to_the_new_algorithm() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let old = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);

    let staged = admin.change_algorithm(chacha).await?;
    let record = keyring.record();
    assert_eq!(
        record.algorithms().randomized,
        AeadAlgorithm::ChaCha20Poly1305
    );
    let version = record.version(staged).ok_or("the staged version is gone")?;
    assert_eq!(
        (version.algorithm(), version.state()),
        (chacha, KeyVersionState::Pending)
    );
    admin.promote_now(staged).await?;
    let new = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(new.key_id(), staged);
    assert_eq!(keyring.decrypt(&aad, &new).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    Ok(())
}

#[cfg(feature = "ring")]
#[tokio::test]
async fn an_algorithm_the_backend_lacks_is_refused_before_any_write() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let before = fixture.keyring.record().to_json()?;
    assert!(matches!(
        fixture
            .admin
            .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256GcmSiv))
            .await,
        Err(KeyringError::KmsAead(KmsAeadError::UnsupportedAlgorithm(_)))
    ));
    assert_eq!(
        fixture
            .other_process()
            .await?
            .keyring()
            .record()
            .to_json()?,
        before
    );
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn a_deterministic_policy_creates_deterministic_versions() -> TestResult {
    let provider = TestProvider::new("tenant-42-kek")?;
    let algorithms = KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv);
    let admin = TestRegistry::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(provider.clone(), TENANT, algorithms)
    .await?;
    let record = admin.keyring().record();
    assert_eq!(
        record.active(Purpose::Deterministic).map(KeyVersion::id),
        Some(KeyId::new(0x8000_0001))
    );
    assert_eq!(
        admin.rotate(Purpose::Deterministic).await?,
        KeyId::new(0x8000_0002)
    );
    Ok(())
}

#[cfg(not(feature = "deterministic"))]
#[tokio::test]
async fn a_deterministic_policy_needs_the_feature() -> TestResult {
    let algorithms = KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv);
    let created = TestRegistry::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(TestProvider::new("tenant-42-kek")?, TENANT, algorithms)
    .await;
    assert!(matches!(created, Err(KeyringError::DeterministicDisabled)));
    Ok(())
}

/// One rule of the record's regression checks, refused on each path that reads the store; the
/// other rules are the record's own tests.
#[tokio::test(start_paused = true)]
async fn a_regressed_record_is_refused() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::new(1), None)
        .await?;
    fixture.keyring.reload().await?;
    let held = fixture.keyring.record().to_json()?;
    let stored = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
    let mut document: Value = serde_json::from_slice(&stored.record.to_json()?)?;
    document["versions"][0]["compromised"] = Value::Null;
    let regressed = KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())?;
    fixture
        .memory
        .compare_and_swap(&regressed, Some(&stored.revision))
        .await?;
    let rule = RegressionRule::CompromiseCleared(KeyId::new(1));

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;
    assert_eq!(value.key_id(), KeyId::new(2));
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
    ));
    assert!(matches!(
        fixture.admin.rotate(Purpose::Randomized).await,
        Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
    ));
    assert_eq!(fixture.keyring.record().to_json()?, held);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_refreshed_record_evicts_the_keys_it_withdraws() -> TestResult {
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_keyring(
                KeyringOptions::new().with_compromised_reads(CompromisedReadPolicy::Allow),
            ),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(fixture.provider.calls.decryptions.load(Ordering::SeqCst), 1);

    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::new(1), None)
        .await?;
    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        (fixture
            .keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?)
            .key_id(),
        KeyId::new(2)
    );
    assert_eq!(fixture.provider.calls.decryptions.load(Ordering::SeqCst), 2);
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.decryptions.load(Ordering::SeqCst),
        3,
        "the refresh evicted version 1's key"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_write_before_the_watch_subscribes_is_seen() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let late = MemoryKeyringStore::new();
    let loaded = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
    late.compare_and_swap(&loaded.record, None).await?;
    let admin = fixture.other_process().await?;
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let rotated = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
    let store = TestStore::new(&late, Duration::ZERO);
    *store
        .calls
        .written_before_watch
        .lock()
        .map_err(|_| "poisoned")? = Some(rotated.record);

    let registry = TestRegistry::new(store, KeyringRegistryOptions::new())?;
    let keyring = registry.open(fixture.provider.clone(), TENANT).await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        keyring
            .record()
            .active(Purpose::Randomized)
            .map(KeyVersion::id),
        Some(KeyId::new(2))
    );
    registry.shutdown(None).await;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_signals_coalesce_to_one_revalidation_per_interval() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new()).await?;
    let admin = fixture.other_process().await?;

    admin.rotate(Purpose::Randomized).await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    admin.promote_now(KeyId::new(2)).await?;
    for _ in 0..4 {
        admin
            .promote_now(admin.rotate(Purpose::Randomized).await?)
            .await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    assert_eq!(
        fixture
            .keyring
            .record()
            .active(Purpose::Randomized)
            .map(KeyVersion::id),
        Some(KeyId::new(6))
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    fixture.registry.shutdown(None).await;
    Ok(())
}

#[tokio::test]
async fn a_staged_version_decrypts_and_never_encrypts() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let first = KeyId::new(1);

    let staged = admin.rotate(Purpose::Randomized).await?;
    let record = keyring.record();
    let version = record.version(staged).ok_or("the staged version is gone")?;
    assert_eq!(version.state(), KeyVersionState::Pending);
    assert_eq!(version.staged_at(), Some(version.created_at()));
    let value = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(value.key_id(), first);

    let rotation = admin.promote_now(staged).await?;
    assert_eq!((rotation.previous, rotation.current), (Some(first), staged));
    let promoted = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(promoted.key_id(), staged);
    assert_eq!(keyring.decrypt(&aad, &promoted).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    Ok(())
}

/// An instance that refreshed while a version was pending decrypts the values written under it
/// once it is promoted, before the instance sees the promotion and without a reload.
#[tokio::test(start_paused = true)]
async fn a_promoted_version_decrypts_on_an_instance_that_saw_it_staged() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = fixture.other_process().await?;
    let aad = email_of("42")?;

    let staged = admin.rotate(Purpose::Randomized).await?;
    tokio::time::advance(KeyringRegistryOptions::DEFAULT_RECORD_TTL).await;
    let encrypted_before = fixture
        .keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(encrypted_before.key_id(), KeyId::new(1));
    assert_eq!(
        fixture
            .keyring
            .record()
            .version(staged)
            .map(KeyVersion::state),
        Some(KeyVersionState::Pending)
    );
    let store_calls = (
        fixture.store.calls.loads.load(Ordering::SeqCst),
        fixture.store.calls.revalidations.load(Ordering::SeqCst),
    );

    admin.promote_now(staged).await?;
    let promoted = admin
        .keyring()
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(promoted.key_id(), staged);

    assert_eq!(fixture.keyring.decrypt(&aad, &promoted).await?, ALICE);
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst),
        ),
        store_calls
    );
    Ok(())
}

#[tokio::test]
async fn a_pending_version_is_destroyed_or_promoted_and_blocks_another_rotation() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = &fixture.admin;
    let staged = admin.rotate(Purpose::Randomized).await?;

    let refused = [
        (
            admin.rotate(Purpose::Randomized).await.map(|_| ()),
            Transition::Rotate,
        ),
        (admin.retire(staged).await, Transition::Retire),
        (
            admin.mark_compromised(staged, None).await.map(|_| ()),
            Transition::MarkCompromised,
        ),
    ];
    for (result, transition) in refused {
        assert!(
            matches!(
                &result,
                Err(KeyringError::InvalidTransition(error))
                    if error.key_id == staged
                        && error.from == KeyVersionState::Pending
                        && error.transition == transition
            ),
            "{transition}: {result:?}"
        );
    }

    admin.destroy(staged).await?;
    assert!(matches!(
        admin.promote_now(staged).await,
        Err(KeyringError::InvalidTransition(error))
            if error.from == KeyVersionState::Destroyed && error.transition == Transition::Promote
    ));
    let restaged = admin.rotate(Purpose::Randomized).await?;
    assert_eq!(restaged, KeyId::new(3));
    Ok(())
}

const BIGQUERY_EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);

/// A keyring on `provider` with the algorithms BigQuery reads, and a deterministic version too
/// where the build can create one.
async fn bigquery_keyring(provider: TestProvider) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
    let algorithms = KeyringAlgorithms::new();
    #[cfg(feature = "deterministic")]
    let algorithms = algorithms.with_deterministic(DeterministicAlgorithm::Aes256Siv);
    TestRegistry::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(provider, TENANT, algorithms)
    .await
}

#[tokio::test]
async fn interop_bigquery_encrypts_under_its_algorithms_and_a_cloud_kms_kek() -> TestResult {
    let admin = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let keyring = admin.keyring();
    let aad = BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?);
    let value = keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    #[cfg(feature = "deterministic")]
    {
        let aad = BIGQUERY_EMAIL.deterministic_aad();
        let value = keyring
            .encryptor()
            .await
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(keyring.decrypt_deterministic(&aad, &value).await?, ALICE);
    }
    Ok(())
}

#[tokio::test]
async fn interop_bigquery_refuses_a_non_gcm_version() -> TestResult {
    let admin = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let keyring = admin.keyring();
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);
    admin
        .promote_now(admin.change_algorithm(chacha).await?)
        .await?;

    assert!(matches!(
        keyring
            .encryptor()
            .await
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Algorithm(chacha)
    ));
    keyring
        .encryptor()
        .await
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;
    Ok(())
}

#[tokio::test]
async fn interop_tink_encrypts_under_the_algorithms_and_keks_every_tink_reads() -> TestResult {
    let tink_email = BIGQUERY_EMAIL.with_interop(Interop::Tink);
    let aad = tink_email.aad(&EntityId::try_from("42")?);
    let local = bigquery_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let cloud_kms = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let (local, cloud_kms_keyring) = (local.keyring(), cloud_kms.keyring());
    let aes_128_gcm = KeyAlgorithm::Randomized(AeadAlgorithm::Aes128Gcm);
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);

    assert!(matches!(
        local.encryptor().await.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KmsProvider::Local)
    ));
    cloud_kms
        .promote_now(cloud_kms.change_algorithm(aes_128_gcm).await?)
        .await?;
    cloud_kms_keyring
        .encryptor()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    cloud_kms
        .promote_now(cloud_kms.change_algorithm(chacha).await?)
        .await?;
    assert!(matches!(
        cloud_kms_keyring.encryptor().await.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Algorithm(chacha)
    ));
    Ok(())
}

#[tokio::test]
async fn interop_tink_checks_a_custom_aad_too() -> TestResult {
    let aad = BIGQUERY_EMAIL
        .with_interop(Interop::Tink)
        .custom_aad(b"tenant-7/42")?;
    let admin = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let keyring = admin.keyring();
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);
    admin
        .promote_now(admin.change_algorithm(chacha).await?)
        .await?;

    assert!(matches!(
        keyring.encryptor().await.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Algorithm(chacha)
    ));
    Ok(())
}

#[tokio::test]
async fn interop_bigquery_refuses_a_non_gcp_kek() -> TestResult {
    let admin = bigquery_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let keyring = admin.keyring();

    assert!(matches!(
        keyring
            .encryptor()
            .await
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KmsProvider::Local)
    ));
    #[cfg(feature = "deterministic")]
    assert!(matches!(
        keyring
            .encryptor()
            .await
            .encrypt_deterministic(&BIGQUERY_EMAIL.deterministic_aad(), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KmsProvider::Local)
    ));
    Ok(())
}

#[tokio::test]
async fn promote_refuses_until_the_record_ttl_has_passed_since_staging() -> TestResult {
    let record_ttl = Duration::from_secs(60);
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_record_ttl(record_ttl),
    )
    .await?;
    let staged = fixture.admin.rotate(Purpose::Randomized).await?;

    let result = fixture.admin.promote(staged).await;
    assert!(
        matches!(
            &result,
            Err(KeyringError::PromotionTooEarly(PromotionTooEarlyError { key_id, remaining, .. }))
                if *key_id == staged
                    && !remaining.is_zero()
                    && *remaining <= record_ttl
        ),
        "{result:?}"
    );
    let stored = fixture.other_process().await?.keyring().record();
    assert_eq!(
        stored.version(staged).map(KeyVersion::state),
        Some(KeyVersionState::Pending)
    );
    Ok(())
}

#[tokio::test]
async fn promote_succeeds_once_the_record_ttl_has_passed() -> TestResult {
    let record_ttl = Duration::from_millis(200);
    let fixture = Fixture::new(
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_record_ttl(record_ttl),
    )
    .await?;
    let staged = fixture.admin.rotate(Purpose::Randomized).await?;

    tokio::time::sleep(record_ttl).await;
    let rotation = fixture.admin.promote(staged).await?;
    assert_eq!(rotation.current, staged);
    Ok(())
}

/// Keyrings under an asymmetric KEK, which need RSA and so run on aws-lc or RustCrypto.
#[cfg(any(feature = "aws-lc", feature = "rustcrypto"))]
mod asymmetric_kek {
    use kms_aead::providers::{LocalSigningKeyName, LocalSigningProvider};
    use kms_aead::signing::{Signer, SigningAlgorithm, VerifyingKeySet};
    use kms_aead::KekRef;
    use tracing::Level;

    use super::*;
    use crate::test_support::{local_asymmetric, EventCapture, ReportedKekProvider, RsaBackend};
    use crate::{KeyringRegistry, RecordSignaturePolicy};

    type RsaRegistry = KeyringRegistry<MemoryKeyringStore, RsaBackend>;

    /// The `keyring` field of the keyring events.
    const KEYRING_FIELD: &str = "/kms_aead_keyring/keyring";

    const TINK_EMAIL: FieldSpec = BIGQUERY_EMAIL.with_interop(Interop::Tink);

    fn registry(store: &MemoryKeyringStore, verification: RecordSignaturePolicy) -> RsaRegistry {
        KeyringRegistry::new(
            store.clone(),
            KeyringRegistryOptions::new()
                .with_watch(false)
                .with_record_signatures(verification),
        )
        .expect("a registry")
    }

    fn cloud_kms_key() -> KekRef {
        KekRef::new(
            KmsProvider::Gcp,
            "projects/p/locations/europe-north1/keyRings/r/cryptoKeys/tenant-42",
        )
    }

    /// The providers of one asymmetric KEK that the administration and an application hold:
    /// the first reports the KEK as asymmetric, the second is a plain KMS provider.
    fn administration_and_application(
        kek: KekRef,
    ) -> KmsAeadResult<(ReportedKekProvider, ReportedKekProvider)> {
        let administration = ReportedKekProvider::new(local_asymmetric("tenant-42-kek")?, kek);
        let application = administration.clone().unaware();
        Ok((administration, application))
    }

    fn only_warning(capture: &EventCapture) -> Result<(), Box<dyn std::error::Error>> {
        let events = capture.events();
        let [event] = events.as_slice() else {
            return Err(format!("expected one event, captured {events:?}").into());
        };
        assert_eq!(event.level, Level::WARN);
        assert_eq!(
            event.fields.get(KEYRING_FIELD).map(String::as_str),
            Some(TENANT.as_str())
        );
        Ok(())
    }

    #[tokio::test]
    async fn every_version_is_encrypted_with_the_public_key_and_still_decrypts() -> TestResult {
        let store = MemoryKeyringStore::new();
        let admin = registry(&store, RecordSignaturePolicy::default())
            .create(
                local_asymmetric("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        let keyring = admin.keyring();
        let aad = email_of("42")?;
        let first = keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?;
        admin
            .promote_now(admin.rotate(Purpose::Randomized).await?)
            .await?;
        let second = keyring
            .encryptor()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?;
        let encrypted_before = keyring.record().encrypted_deks();

        admin.reencrypt_deks().await?;
        let encrypted_after = keyring.record().encrypted_deks();

        assert_eq!(encrypted_before.len(), 2);
        assert_eq!(encrypted_after.len(), 2);
        for ((key_id, before), (_, after)) in encrypted_before.iter().zip(&encrypted_after) {
            assert!(before.is_encrypted_with_public_key(), "{key_id:?}");
            assert!(after.is_encrypted_with_public_key(), "{key_id:?}");
            assert_ne!(before.value(), after.value(), "{key_id:?}");
        }
        assert_eq!(keyring.decrypt(&aad, &first).await?, ALICE);
        assert_eq!(keyring.decrypt(&aad, &second).await?, ALICE);
        Ok(())
    }

    #[tokio::test]
    async fn a_keyring_under_an_asymmetric_kek_exports_no_tink_keyset() -> TestResult {
        let (administration, application) = administration_and_application(cloud_kms_key())?;
        let store = MemoryKeyringStore::new();
        let creator = registry(&store, RecordSignaturePolicy::default())
            .create(administration.clone(), TENANT, KeyringAlgorithms::new())
            .await?;
        let reader = registry(&store, RecordSignaturePolicy::default())
            .admin(application, TENANT)
            .await?;

        for (source, result) in [
            (
                "the provider",
                creator
                    .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
                    .await,
            ),
            (
                "the record",
                reader
                    .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
                    .await,
            ),
        ] {
            assert!(
                matches!(
                    &result,
                    Err(KeyringError::Interop(error))
                        if error.interop == Interop::Tink
                            && error.requirement == InteropRequirement::Kek(KmsProvider::Gcp)
                ),
                "{source}: {:?}",
                result.map(|_| ())
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_keyring_under_an_asymmetric_kek_encrypts_no_interop_field() -> TestResult {
        let (administration, application) = administration_and_application(cloud_kms_key())?;
        let store = MemoryKeyringStore::new();
        let creator = registry(&store, RecordSignaturePolicy::default())
            .create(administration, TENANT, KeyringAlgorithms::new())
            .await?;
        let reader = registry(&store, RecordSignaturePolicy::default())
            .open(application, TENANT)
            .await?;
        let id = EntityId::try_from("42")?;

        for field in [BIGQUERY_EMAIL, TINK_EMAIL] {
            for (source, keyring) in [("the provider", creator.keyring()), ("the record", &reader)]
            {
                let encrypted = keyring
                    .encryptor()
                    .await
                    .encrypt(&field.aad(&id), &ALICE.to_string())
                    .await;
                assert!(
                    matches!(
                        &encrypted,
                        Err(KeyringError::Interop(error))
                            if error.requirement == InteropRequirement::Kek(KmsProvider::Gcp)
                    ),
                    "{source}: {:?}",
                    encrypted.map(|_| ())
                );
            }
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_unsigned_admin_over_an_asymmetric_provider_warns_when_built() -> TestResult {
        let signer = record_signer().await?;
        let verification = RecordSignaturePolicy::VerifyIfSigned(trusting(&signer));
        let capture = EventCapture::install();

        registry(&MemoryKeyringStore::new(), RecordSignaturePolicy::default())
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        registry(&MemoryKeyringStore::new(), verification)
            .create_signed(
                local_asymmetric("tenant-42-kek")?,
                signer,
                TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        assert!(capture.events().is_empty(), "{:?}", capture.events());

        registry(&MemoryKeyringStore::new(), RecordSignaturePolicy::default())
            .create(
                local_asymmetric("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new(),
            )
            .await?;
        only_warning(&capture)
    }

    #[tokio::test]
    async fn a_public_key_encrypted_record_warns_each_time_it_is_loaded_under_verify_if_signed(
    ) -> TestResult {
        let (administration, application) = administration_and_application(cloud_kms_key())?;
        let store = MemoryKeyringStore::new();
        let admin = registry(&store, RecordSignaturePolicy::default())
            .create(administration, TENANT, KeyringAlgorithms::new())
            .await?;
        let capture = EventCapture::install();

        let reader = registry(&store, RecordSignaturePolicy::default())
            .open(application, TENANT)
            .await?;
        only_warning(&capture)?;

        admin.rotate(Purpose::Randomized).await?;
        reader.reload().await?;
        assert_eq!(capture.events().len(), 2, "{:?}", capture.events());
        Ok(())
    }

    #[tokio::test]
    async fn a_public_key_encrypted_record_does_not_warn_under_required() -> TestResult {
        let (administration, application) = administration_and_application(cloud_kms_key())?;
        let signer = record_signer().await?;
        let keys = trusting(&signer);
        let store = MemoryKeyringStore::new();
        registry(&store, RecordSignaturePolicy::VerifyIfSigned(keys.clone()))
            .create_signed(administration, signer, TENANT, KeyringAlgorithms::new())
            .await?;
        let capture = EventCapture::install();

        registry(&store, RecordSignaturePolicy::Required(keys))
            .open(application, TENANT)
            .await?;

        assert!(capture.events().is_empty(), "{:?}", capture.events());
        Ok(())
    }

    #[tokio::test]
    async fn a_record_of_an_application_own_kek_does_not_warn() -> TestResult {
        let application_kek = KekRef::new(KmsProvider::Other("tenant-vault".to_string()), "key-1");
        let (administration, application) = administration_and_application(application_kek)?;
        let store = MemoryKeyringStore::new();
        registry(&store, RecordSignaturePolicy::default())
            .create(administration, TENANT, KeyringAlgorithms::new())
            .await?;
        let capture = EventCapture::install();

        registry(&store, RecordSignaturePolicy::default())
            .open(application, TENANT)
            .await?;

        assert!(capture.events().is_empty(), "{:?}", capture.events());
        Ok(())
    }

    async fn record_signer() -> KmsAeadResult<Signer<LocalSigningProvider<RsaBackend>, RsaBackend>>
    {
        Signer::new(LocalSigningProvider::ephemeral(
            LocalSigningKeyName::try_from("records".to_string())?,
            SigningAlgorithm::Ed25519,
        )?)
        .await
    }

    fn trusting(signer: &Signer<LocalSigningProvider<RsaBackend>, RsaBackend>) -> VerifyingKeySet {
        VerifyingKeySet::new([signer.verifying_key().clone()]).expect("one key")
    }
}
