use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use kms_aead::cache::{DekCache, DekCacheOutcome};
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::{Bare, Randomized};
use kms_aead::providers::KekVersion;
use kms_aead::{
    AeadAlgorithm, AeadCipher, BeaconAlgorithm, DeterministicAlgorithm, KekProvider, KmsAeadResult,
    Plaintext,
};
use secret_vault_value::SecretValue;
use serde_json::Value;

use super::*;
use crate::errors::{RecordConflictError, RecordRegressedError, RegressionRule};
use crate::store::KeyringStore;
use crate::sweep::SealMarker;
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
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let bytes = value.value();
    assert_eq!(bytes[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);

    let record = fixture.keyring.record();
    let encrypted_dek = &record
        .version(KeyId::new(1))
        .and_then(KeyVersion::dek_encryption)
        .ok_or("version 1 holds no key")?
        .encrypted_dek;
    let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
    let bare = Encrypted::<String, Bare>::try_from(bytes[5..].to_vec())?;
    let (opened, _) = DekCache::disabled()
        .with_dek(&fixture.provider, encrypted_dek, |dek| {
            cipher.decrypt_bare(&aad.bytes, &bare, dek)
        })
        .await?;
    assert_eq!(opened?, ALICE);
    Ok(())
}

#[tokio::test]
async fn values_round_trip_through_their_plaintext_types() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;

    let text = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(keyring.decrypt(&aad, &text).await?, ALICE);

    let bytes = vec![0u8, 0xFF, 0x07];
    let sealed = keyring.sealer().await.encrypt(&aad, &bytes).await?;
    assert_eq!(keyring.decrypt(&aad, &sealed).await?, bytes);

    #[cfg(feature = "serde-json")]
    {
        let json = crate::Json(vec![("plan".to_string(), 3u32)]);
        let sealed = keyring.sealer().await.encrypt(&aad, &json).await?;
        assert_eq!(keyring.decrypt(&aad, &sealed).await?, json);
    }
    Ok(())
}

/// An application's email type, sealed as the UTF-8 of the address.
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

/// A newtype field is sealed as the plaintext of the type it maps to, so a reader of that type,
/// such as BigQuery's `AEAD.DECRYPT_STRING` for a `String`, opens it.
#[tokio::test]
async fn a_newtype_field_is_sealed_as_its_string() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let alice = Email(ALICE.to_string());

    let sealed: Encrypted<Email, Randomized> =
        fixture.keyring.sealer().await.encrypt(&aad, &alice).await?;
    let as_string = Encrypted::<String, Randomized>::try_from(sealed.value().to_vec())?;

    assert_eq!(fixture.keyring.decrypt(&aad, &sealed).await?, alice);
    assert_eq!(fixture.keyring.decrypt(&aad, &as_string).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_value_opens_only_with_its_aad() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let value = keyring
        .sealer()
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
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    admin
        .promote(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let second = keyring
        .sealer()
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
        .sealer()
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
        Err(KeyringError::ReservedKeyId)
    ));
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &relabelled(&value, 0x8000_0001)?).await,
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

    for reserved in [0, 1 << 31, 1 << 30, (3 << 30) | 1].map(KeyId::new) {
        for refused in [
            admin.promote(reserved).await.map(|_| ()),
            admin.mark_compromised(reserved, None).await.map(|_| ()),
            admin.retire(reserved).await,
            admin.reinstate(reserved).await,
            admin.destroy(reserved).await,
            admin
                .export_tink_keyset(KeysetSelection::Single(reserved))
                .await
                .map(|_| ()),
        ] {
            assert!(matches!(refused, Err(KeyringError::ReservedKeyId)));
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
        .promote(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let aad = Arc::new(email_of("42")?);
    let value = admin
        .keyring()
        .sealer()
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
            .sealer()
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
async fn reseal_of_a_key_id_the_record_lacks_reloads_and_fails() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let unknown = relabelled(
        &fixture
            .keyring
            .sealer()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?,
        9,
    )?;

    assert!(matches!(
        fixture.keyring.sealer().await.reseal(&aad, &unknown).await,
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
        .promote(admin.rotate(Purpose::Randomized).await?)
        .await?;

    let cached = fixture
        .keyring
        .sealer()
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
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(refreshed.key_id(), KeyId::new(2));
    fixture
        .keyring
        .sealer()
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
        .sealer()
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

#[tokio::test(start_paused = true)]
async fn a_missing_record_keeps_the_cached_one() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture
        .keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    fixture.store.calls.missing.store(true, Ordering::SeqCst);

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        (fixture
            .keyring
            .sealer()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await?)
            .key_id(),
        KeyId::new(1)
    );
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);

    let opened = TestRegistry::new(
        fixture.store.clone(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .open(fixture.provider.clone(), TENANT)
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
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
        .sealer()
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
        fixture.admin.promote(staged).await,
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
        .sealer()
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
    let encrypted_dek = &held
        .version(KeyId::new(1))
        .and_then(KeyVersion::dek_encryption)
        .ok_or("version 1 holds no key")?
        .encrypted_dek;
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
        .sealer()
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
    let encrypted_dek = &record
        .version(KeyId::new(1))
        .and_then(KeyVersion::dek_encryption)
        .ok_or("version 1 holds no key")?
        .encrypted_dek;
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
        .sealer()
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
        .sealer()
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
        fixture.keyring.sealer().await.encrypt(&aad, &ALICE.to_string()).await,
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
            .sealer()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await,
        Err(KeyringError::NoActiveVersion(_))
    ));
    let rotation = fixture.admin.promote(staged).await?;
    assert_eq!((rotation.previous, rotation.current), (None, KeyId::new(2)));
    assert_eq!(
        (fixture
            .keyring
            .sealer()
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
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    admin
        .promote(admin.rotate(Purpose::Randomized).await?)
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
    assert!(destroyed.dek_encryption().is_none());
    Ok(())
}

#[tokio::test]
async fn dangerously_destroy_all_versions_leaves_nothing_to_encrypt_or_decrypt_with() -> TestResult
{
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let sealed = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let promoted = admin.rotate(Purpose::Randomized).await?;
    admin.promote(promoted).await?;
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
            .sealer()
            .await
            .encrypt(&aad, &ALICE.to_string())
            .await,
        Err(KeyringError::NoActiveVersion(_))
    ));
    assert!(matches!(
        keyring.decrypt(&aad, &sealed).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
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
async fn reencrypt_deks_encrypts_every_version_again_and_values_still_open() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let old = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let staged = admin.rotate(Purpose::Randomized).await?;
    let previous_encrypted_deks = keyring.record().dek_encryptions();
    let first_kek_version = KekVersion::try_from("1".to_string())?;
    let rotated_kek_version = KekVersion::try_from("2".to_string())?;
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
    let current_encrypted_deks = keyring.record().dek_encryptions();
    for ((key_id, previous), (reencrypted_id, current)) in
        previous_encrypted_deks.iter().zip(&current_encrypted_deks)
    {
        assert_eq!(key_id, reencrypted_id);
        assert_ne!(previous.encrypted_dek, current.encrypted_dek);
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

    let first_kek_version = KekVersion::try_from("1".to_string())?;
    let rotated_kek_version = KekVersion::try_from("2".to_string())?;
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
    let kek_versions: Vec<(KeyId, Option<&KekVersion>)> = stored
        .versions()
        .iter()
        .map(|version| (version.id(), version.kek_version()))
        .collect();
    let first_kek_version = KekVersion::try_from("1".to_string())?;
    let rotated_kek_version = KekVersion::try_from("2".to_string())?;
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
async fn the_seal_epoch_moves_on_once_per_write_that_activates_a_version() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let (admin, keyring) = (&fixture.admin, &fixture.keyring);
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(1));

    let second = admin.rotate(Purpose::Randomized).await?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(1));
    admin.promote(second).await?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(2));
    let third = admin
        .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
        .await?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(2));
    admin.promote(third).await?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(3));

    admin.mark_compromised(KeyId::new(1), None).await?;
    admin.retire(second).await?;
    admin.reinstate(second).await?;
    admin.retire(second).await?;
    admin.destroy(second).await?;
    admin.reencrypt_deks().await?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(3));

    let replacement = admin
        .mark_compromised(third, None)
        .await?
        .ok_or("the compromised active version is replaced")?;
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(4));
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
    assert_eq!(keyring.record().seal_marker(), SealMarker::of_epoch(4));
    assert_eq!(
        fixture
            .other_process()
            .await?
            .keyring()
            .record()
            .seal_marker(),
        SealMarker::of_epoch(4)
    );
    Ok(())
}

#[tokio::test]
async fn concurrent_promotions_move_the_seal_epoch_on_once_each() -> TestResult {
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
        tokio::join!(first.promote(randomized), second.promote(beacon));

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
    assert_eq!(record.seal_marker(), SealMarker::of_epoch(3));
    let mut starts = Vec::new();
    for (replaced, promoted) in [
        (Purpose::Randomized.first_key_id(), randomized),
        (Purpose::Beacon.first_key_id(), beacon),
    ] {
        let range = record
            .version(promoted)
            .and_then(KeyVersion::seal_range)
            .ok_or("a promoted version has a range")?;
        assert_eq!(
            record
                .version(replaced)
                .and_then(KeyVersion::seal_range)
                .and_then(|replaced| replaced.end()),
            Some(range.start()),
            "the replaced version's range ends where the promoted one's starts"
        );
        starts.push(range.start());
    }
    starts.sort();
    assert_eq!(starts, [SealMarker::of_epoch(2), SealMarker::of_epoch(3)]);
    Ok(())
}

/// A write that reads a value before it seals: the read revalidates the cache, whose TTL is zero,
/// after another process promoted a version of every purpose.
#[tokio::test]
async fn a_sealer_seals_every_field_under_the_record_its_marker_names() -> TestResult {
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
    let stored = keyring.sealer().await.encrypt(&aad, &alice).await?;
    let mut staged = Vec::new();
    for purpose in Purpose::ALL {
        if admin.keyring().record().active(purpose).is_some() {
            staged.push(admin.rotate(purpose).await?);
        }
    }

    let sealer = keyring.sealer().await;
    for key_id in staged {
        admin.promote(key_id).await?;
    }
    let revalidations = store.calls.revalidations.load(Ordering::SeqCst);
    assert_eq!(keyring.decrypt(&aad, &stored).await?, ALICE);
    assert!(store.calls.revalidations.load(Ordering::SeqCst) > revalidations);
    let sealed = [
        (
            Purpose::Randomized,
            sealer.encrypt(&aad, &alice).await?.key_id(),
        ),
        (
            Purpose::Beacon,
            sealer.beacon(&EMAIL, &alice).await?.key_id(),
        ),
        #[cfg(feature = "deterministic")]
        (
            Purpose::Deterministic,
            sealer
                .encrypt_deterministic(&EMAIL.deterministic_aad(), &alice)
                .await?
                .key_id(),
        ),
    ];

    let marker = sealer.record().seal_marker();
    let current = keyring.record();
    assert!(
        current.seal_marker() > marker,
        "the cache moved on mid-write"
    );
    for (purpose, key_id) in sealed {
        assert_eq!(
            sealer.record().active(purpose).map(KeyVersion::id),
            Some(key_id),
            "the {purpose} field is under the sealer's record"
        );
        let range = current
            .version(key_id)
            .and_then(KeyVersion::seal_range)
            .ok_or("a version sealed under has a range")?;
        assert!(range.contains(marker), "the range of the {purpose} version");
    }
    Ok(())
}

#[tokio::test]
async fn a_sealer_older_than_a_value_refuses_to_reseal_it_under_its_own_versions() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = fixture.other_process().await?;
    let aad = email_of("42")?;
    let alice = ALICE.to_string();
    let stale = fixture.keyring.sealer().await;
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
    let newer = admin.keyring().sealer().await.encrypt(&aad, &alice).await?;

    let refused = stale.reseal(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::SealerOutdated(error)) if error.key_id == replacement
        ),
        "a re-seal back under the compromised version: {:?}",
        refused.map(|resealed| resealed.map(|resealed| resealed.value.key_id()))
    );
    let sealer = fixture.keyring.sealer().await;
    assert!(sealer.reseal(&aad, &newer).await?.is_none());
    let resealed = sealer
        .reseal(&aad, &old)
        .await?
        .ok_or("a value under the compromised version is re-sealed")?;
    assert_eq!(resealed.value.key_id(), replacement);
    assert!(matches!(resealed.trust, KeyTrust::Compromised(_)));
    Ok(())
}

#[tokio::test]
async fn reseal_under_a_version_the_cache_holds_as_pending_reloads_the_cache() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let alice = ALICE.to_string();
    let old = fixture.keyring.sealer().await.encrypt(&aad, &alice).await?;
    let pending = fixture.admin.rotate(Purpose::Randomized).await?;
    let stale = fixture.keyring.sealer().await;
    let admin = fixture.other_process().await?;
    admin.promote(pending).await?;
    let newer = admin.keyring().sealer().await.encrypt(&aad, &alice).await?;
    let revalidations = fixture.store.calls.revalidations.load(Ordering::SeqCst);

    let refused = stale.reseal(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::SealerOutdated(error)) if error.key_id == pending
        ),
        "a re-seal back under the previous version: {:?}",
        refused.map(|resealed| resealed.map(|resealed| resealed.value.key_id()))
    );
    let sealer = fixture.keyring.sealer().await;
    assert!(sealer.reseal(&aad, &newer).await?.is_none());
    let resealed = sealer
        .reseal(&aad, &old)
        .await?
        .ok_or("a value under the previous version is re-sealed")?;
    assert_eq!(resealed.value.key_id(), pending);
    assert!(matches!(
        stale.reseal(&aad, &newer).await,
        Err(KeyringError::SealerOutdated(_))
    ));
    assert_eq!(
        fixture.store.calls.revalidations.load(Ordering::SeqCst),
        revalidations + 1
    );
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn a_sealer_that_holds_a_values_version_as_pending_refuses_to_reseal_it() -> TestResult {
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
        .sealer()
        .await
        .encrypt_deterministic(&aad, &alice)
        .await?;
    let pending = admin.rotate(Purpose::Deterministic).await?;
    let keyring = TestRegistry::new(memory, options)?
        .open(provider, TENANT)
        .await?;
    let stale = keyring.sealer().await;
    admin.promote(pending).await?;
    let newer = admin
        .keyring()
        .sealer()
        .await
        .encrypt_deterministic(&aad, &alice)
        .await?;

    let refused = stale.reseal_deterministic(&aad, &newer).await;

    assert!(
        matches!(
            &refused,
            Err(KeyringError::SealerOutdated(error)) if error.key_id == pending
        ),
        "a re-seal back under the previous version: {:?}",
        refused.map(|resealed| resealed.map(|resealed| resealed.value.key_id()))
    );
    let sealer = keyring.sealer().await;
    assert!(sealer.reseal_deterministic(&aad, &newer).await?.is_none());
    let resealed = sealer
        .reseal_deterministic(&aad, &old)
        .await?
        .ok_or("a value under the previous version is re-sealed")?;
    assert_eq!(resealed.value, newer);
    assert_eq!(resealed.trust, KeyTrust::Trusted);
    Ok(())
}

#[tokio::test]
async fn change_algorithm_rotates_to_the_new_algorithm() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let admin = &fixture.admin;
    let aad = email_of("42")?;
    let old = keyring
        .sealer()
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
    admin.promote(staged).await?;
    let new = keyring
        .sealer()
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
        .sealer()
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
        .sealer()
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
            .sealer()
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
    let opened = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
    late.compare_and_swap(&opened.record, None).await?;
    let admin = fixture.other_process().await?;
    admin
        .promote(admin.rotate(Purpose::Randomized).await?)
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
    registry.shutdown().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_signals_coalesce_to_one_revalidation_per_interval() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new()).await?;
    let admin = fixture.other_process().await?;

    admin.rotate(Purpose::Randomized).await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    admin.promote(KeyId::new(2)).await?;
    for _ in 0..4 {
        admin
            .promote(admin.rotate(Purpose::Randomized).await?)
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
    fixture.registry.shutdown().await?;
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
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(value.key_id(), first);

    let rotation = admin.promote(staged).await?;
    assert_eq!((rotation.previous, rotation.current), (Some(first), staged));
    let promoted = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(promoted.key_id(), staged);
    assert_eq!(keyring.decrypt(&aad, &promoted).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    Ok(())
}

/// An instance that refreshed while a version was pending opens the values written under it
/// once it is promoted, before the instance sees the promotion and without a reload.
#[tokio::test(start_paused = true)]
async fn a_promoted_version_opens_on_an_instance_that_saw_it_staged() -> TestResult {
    let fixture = Fixture::new(KeyringRegistryOptions::new().with_watch(false)).await?;
    let admin = fixture.other_process().await?;
    let aad = email_of("42")?;

    let staged = admin.rotate(Purpose::Randomized).await?;
    tokio::time::advance(KeyringRegistryOptions::DEFAULT_RECORD_TTL).await;
    let sealed_before = fixture
        .keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(sealed_before.key_id(), KeyId::new(1));
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

    admin.promote(staged).await?;
    let promoted = admin
        .keyring()
        .sealer()
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
        admin.promote(staged).await,
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
async fn interop_bigquery_seals_under_its_algorithms_and_a_cloud_kms_kek() -> TestResult {
    let admin = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let keyring = admin.keyring();
    let aad = BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?);
    let value = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    #[cfg(feature = "deterministic")]
    {
        let aad = BIGQUERY_EMAIL.deterministic_aad();
        let value = keyring
            .sealer()
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
    admin.promote(admin.change_algorithm(chacha).await?).await?;

    assert!(matches!(
        keyring
            .sealer()
            .await
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Algorithm(chacha)
    ));
    keyring
        .sealer()
        .await
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;
    Ok(())
}

#[tokio::test]
async fn interop_tink_seals_under_the_algorithms_and_keks_every_tink_reads() -> TestResult {
    let tink_email = BIGQUERY_EMAIL.with_interop(Interop::Tink);
    let aad = tink_email.aad(&EntityId::try_from("42")?);
    let local = bigquery_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let cloud_kms = bigquery_keyring(TestProvider::cloud_kms()?).await?;
    let (local, cloud_kms_keyring) = (local.keyring(), cloud_kms.keyring());
    let aes_128_gcm = KeyAlgorithm::Randomized(AeadAlgorithm::Aes128Gcm);
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);

    assert!(matches!(
        local.sealer().await.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KekProvider::Local)
    ));
    cloud_kms
        .promote(cloud_kms.change_algorithm(aes_128_gcm).await?)
        .await?;
    cloud_kms_keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    cloud_kms
        .promote(cloud_kms.change_algorithm(chacha).await?)
        .await?;
    assert!(matches!(
        cloud_kms_keyring.sealer().await.encrypt(&aad, &ALICE.to_string()).await,
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
    admin.promote(admin.change_algorithm(chacha).await?).await?;

    assert!(matches!(
        keyring.sealer().await.encrypt(&aad, &ALICE.to_string()).await,
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
            .sealer()
            .await
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KekProvider::Local)
    ));
    #[cfg(feature = "deterministic")]
    assert!(matches!(
        keyring
            .sealer()
            .await
            .encrypt_deterministic(&BIGQUERY_EMAIL.deterministic_aad(), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KekProvider::Local)
    ));
    Ok(())
}
