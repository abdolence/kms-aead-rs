use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use kms_aead::cache::{DekCache, DekCacheOutcome};
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::Randomized;
use kms_aead::{
    AeadAlgorithm, AeadCipher, CipherText, KekRef, KmsAeadResult, Plaintext, ValueStruct,
};
use secret_vault_value::SecretValue;
use serde_json::Value;

use super::*;
use crate::errors::{RecordConflictError, RecordRegressedError, RegressionRule};
use crate::store::KeyringStore;
use crate::test_support::{
    email_of, TestBackend, TestKeyring, TestProvider, TestResult, TestStore, TENANT,
};
use crate::testing::MemoryKeyringStore;
use crate::{EntityId, EntityKind, FieldName, FieldSpec, Transition};

/// A keyring created on a counting store, beside the memory store it writes to.
struct Fixture {
    memory: MemoryKeyringStore,
    store: TestStore,
    provider: TestProvider,
    keyring: TestKeyring<TestStore>,
}

impl Fixture {
    async fn new(options: KeyringOptions) -> KeyringResult<Self> {
        let memory = MemoryKeyringStore::new();
        let store = TestStore::new(&memory, Duration::ZERO);
        let provider = TestProvider::new("tenant-42-kek")?;
        let keyring = TestKeyring::create(
            store.clone(),
            provider.clone(),
            TENANT,
            KeyringPolicy::new(),
            options,
        )
        .await?;
        Ok(Self {
            memory,
            store,
            provider,
            keyring,
        })
    }

    /// The same keyring in another process, such as the administrative job.
    async fn other_process(&self) -> KeyringResult<TestKeyring<MemoryKeyringStore>> {
        TestKeyring::open(
            self.memory.clone(),
            self.provider.clone(),
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let bytes = value.value();
    assert_eq!(bytes[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);

    let record = fixture.keyring.record();
    let dek = record
        .version(KeyId::try_from(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
    let (opened, _) = DekCache::disabled()
        .with_key(&fixture.provider, dek, |key| {
            cipher.decrypt_value(&aad.bytes, &CipherText(bytes[5..].to_vec()), key)
        })
        .await?;
    assert_eq!(opened?.as_sensitive_str(), ALICE);
    Ok(())
}

#[tokio::test]
async fn values_round_trip_through_their_plaintext_types() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;

    let text = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(keyring.decrypt(&aad, &text).await?, ALICE);

    let bytes = vec![0u8, 0xFF, 0x07];
    let sealed = keyring.encrypt(&aad, &bytes).await?;
    assert_eq!(keyring.decrypt(&aad, &sealed).await?, bytes);

    #[cfg(feature = "serde-json")]
    {
        let json = crate::Json(vec![("plan".to_string(), 3u32)]);
        let sealed = keyring.encrypt(&aad, &json).await?;
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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let alice = Email(ALICE.to_string());

    let sealed: Encrypted<Email, Randomized> = fixture.keyring.encrypt(&aad, &alice).await?;
    let as_string = Encrypted::<String, Randomized>::try_from(sealed.value().clone())?;

    assert_eq!(fixture.keyring.decrypt(&aad, &sealed).await?, alice);
    assert_eq!(fixture.keyring.decrypt(&aad, &as_string).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_value_opens_only_with_its_aad() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let value = keyring
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;

    for aad in [
        email_of("43")?,
        email_of("42")?.with_context(b"eu"),
        FieldAad::custom(b"user/42/email/".to_vec()),
    ] {
        assert!(matches!(
            keyring.decrypt(&aad, &value).await,
            Err(KeyringError::Kms(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
        ));
    }
    let same_bytes = FieldAad::custom(b"user/42/email".to_vec());
    assert_eq!(keyring.decrypt(&same_bytes, &value).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_relabelled_prefix_fails_under_the_other_version() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let first = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    keyring
        .promote(keyring.rotate(Purpose::Randomized).await?)
        .await?;
    let second = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        (KeyId::try_from(&first)?, KeyId::try_from(&second)?),
        (KeyId::try_from(1)?, KeyId::try_from(2)?)
    );

    assert!(matches!(
        keyring.decrypt(&aad, &relabelled(&first, 2)?).await,
        Err(KeyringError::Kms(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
    ));
    assert!(matches!(
        keyring.decrypt(&aad, &relabelled(&second, 1)?).await,
        Err(KeyringError::Kms(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
    ));
    assert_eq!(keyring.decrypt(&aad, &first).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_reserved_or_deterministic_key_id_fails_before_any_store_or_kms_call() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let store_calls = || {
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst),
        )
    };
    let before = store_calls();
    let unwraps = fixture.provider.calls.unwraps.load(Ordering::SeqCst);

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
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_id_reloads_once_under_concurrency() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let admin = TestKeyring::create(
        memory.clone(),
        provider.clone(),
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let store = TestStore::new(&memory, Duration::from_millis(50));
    let reader = Arc::new(
        TestKeyring::open(
            store.clone(),
            provider,
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
        .await?,
    );
    admin
        .promote(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let aad = Arc::new(email_of("42")?);
    let value = admin.encrypt(&aad, &ALICE.to_string()).await?;

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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let unknown = relabelled(&fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?, 9)?;

    for _ in 0..3 {
        assert!(matches!(
            fixture.keyring.decrypt(&aad, &unknown).await,
            Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == KeyId::try_from(9)?
        ));
        assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(fixture.keyring.decrypt(&aad, &unknown).await.is_err());
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn record_ttl_revalidates_with_a_conditional_read() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let admin = fixture.other_process().await?;
    admin
        .promote(admin.rotate(Purpose::Randomized).await?)
        .await?;

    let cached = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&cached)?, KeyId::try_from(1)?);
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 0)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let refreshed = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&refreshed)?, KeyId::try_from(2)?);
    fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 1)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let unchanged = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&unchanged)?, KeyId::try_from(2)?);
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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    fixture.store.calls.missing.store(true, Ordering::SeqCst);

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        KeyId::try_from(&fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?)?,
        KeyId::try_from(1)?
    );
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);

    let opened = TestKeyring::open(
        fixture.store.clone(),
        fixture.provider.clone(),
        TENANT,
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
    Ok(())
}

#[tokio::test]
async fn a_record_ttl_of_duration_max_opens() -> TestResult {
    let options = KeyringOptions::new()
        .with_watch(false)
        .with_record_ttl(Duration::MAX)
        .with_reload_min_interval(Duration::MAX);
    let fixture = Fixture::new(options).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let other = TestProvider::new("another-kek")?;
    let opened = TestKeyring::open(
        fixture.memory.clone(),
        other.clone(),
        TENANT,
        KeyringOptions::new().with_watch(false),
    )
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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false).with_cas_retries(2)).await?;
    fixture.store.calls.conflicts.store(2, Ordering::SeqCst);
    let staged = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(staged, KeyId::try_from(2)?);
    assert_eq!(fixture.store.calls.loads.load(Ordering::SeqCst), 3);

    fixture.store.calls.conflicts.store(3, Ordering::SeqCst);
    assert!(matches!(
        fixture.keyring.promote(staged).await,
        Err(KeyringError::RecordConflict(RecordConflictError {
            attempts: 3,
            ..
        }))
    ));
    let stored = fixture.other_process().await?.record();
    assert_eq!(
        stored.version(staged).map(KeyVersion::state),
        Some(KeyVersionState::Pending)
    );
    Ok(())
}

#[tokio::test]
async fn mark_compromised_evicts_the_dek() -> TestResult {
    let fixture = Fixture::new(
        KeyringOptions::new()
            .with_watch(false)
            .with_compromised_reads(CompromisedReadPolicy::Allow),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(fixture.provider.calls.unwraps.load(Ordering::SeqCst), 1);

    let rotation = fixture
        .keyring
        .mark_compromised(KeyId::try_from(1)?, Some("laptop lost".to_string()))
        .await?;
    assert_eq!(
        rotation.map(|rotation| rotation.current),
        Some(KeyId::try_from(2)?)
    );
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        2,
        "the key was evicted, so the read missed"
    );
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        2,
        "Allow reads through the cache"
    );
    Ok(())
}

#[tokio::test]
async fn a_key_unwrapped_under_a_superseded_record_is_evicted() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let held = fixture.keyring.record();
    let dek = held
        .version(KeyId::try_from(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::try_from(1)?, None)
        .await?;
    fixture.keyring.reload().await?;

    fixture
        .keyring
        .with_cached_key(&held, KeyId::try_from(1)?, dek, |_| ())
        .await?;
    let ((), outcome) = fixture
        .keyring
        .dek_cache()
        .with_key(&fixture.provider, dek, |_| ())
        .await?;
    assert_eq!(outcome, DekCacheOutcome::Miss);
    Ok(())
}

#[tokio::test]
async fn block_refuses_before_unwrapping() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    fixture
        .keyring
        .mark_compromised(KeyId::try_from(1)?, None)
        .await?;
    let unwraps = fixture.provider.calls.unwraps.load(Ordering::SeqCst);

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == KeyId::try_from(1)?
    ));
    let other = fixture.other_process().await?;
    assert!(matches!(
        other.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps
    );
    Ok(())
}

#[tokio::test]
async fn a_forgery_under_a_known_dek_is_refused_under_block() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let record = fixture.keyring.record();
    let dek = record
        .version(KeyId::try_from(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    let cipher = AeadCipher::<TestBackend>::new(AeadAlgorithm::Aes256Gcm)?;
    let first = KeyId::try_from(1)?;
    let (forged, _) = DekCache::disabled()
        .with_key(&fixture.provider, dek, |leaked| {
            cipher.encrypt_field(
                first.into(),
                &aad.bytes,
                &"mallory@example.com".to_string(),
                leaked,
            )
        })
        .await?;
    let forged: Encrypted<String, Randomized> = forged?;
    fixture
        .keyring
        .mark_compromised(KeyId::try_from(1)?, Some("dek leaked".to_string()))
        .await?;

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &forged).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    let status = fixture.keyring.decrypt_with_status(&aad, &forged).await?;
    assert_eq!(status.value, "mallory@example.com");
    assert_eq!(status.key_id, KeyId::try_from(1)?);
    assert!(matches!(
        status.trust,
        KeyTrust::Compromised(compromise) if compromise.note() == Some("dek leaked")
    ));
    Ok(())
}

#[tokio::test]
async fn decrypt_with_status_unwraps_a_compromised_version_past_the_cache() -> TestResult {
    let fixture = Fixture::new(
        KeyringOptions::new()
            .with_watch(false)
            .with_compromised_reads(CompromisedReadPolicy::Allow),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    fixture
        .keyring
        .mark_compromised(KeyId::try_from(1)?, None)
        .await?;
    let unwraps = fixture.provider.calls.unwraps.load(Ordering::SeqCst);

    for read in 1..=2 {
        let status = fixture.keyring.decrypt_with_status(&aad, &value).await?;
        assert!(matches!(status.trust, KeyTrust::Compromised(_)));
        assert_eq!(
            fixture.provider.calls.unwraps.load(Ordering::SeqCst),
            unwraps + read
        );
    }
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps + 3,
        "the reads above cached nothing"
    );

    let trusted = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let status = fixture.keyring.decrypt_with_status(&aad, &trusted).await?;
    assert_eq!(
        (status.key_id, status.trust),
        (KeyId::try_from(2)?, KeyTrust::Trusted)
    );
    Ok(())
}

#[tokio::test]
async fn mark_compromised_writes_the_flag_when_the_wrap_fails() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    fixture
        .provider
        .calls
        .fail_wraps
        .store(true, Ordering::SeqCst);

    assert_eq!(
        fixture
            .keyring
            .mark_compromised(KeyId::try_from(1)?, None)
            .await?,
        None
    );
    for record in [
        fixture.keyring.record(),
        fixture.other_process().await?.record(),
    ] {
        let version = record
            .version(KeyId::try_from(1)?)
            .ok_or("version 1 is gone")?;
        assert_eq!(version.state(), KeyVersionState::DecryptOnly);
        assert!(version.compromised().is_some());
        assert!(record.active(Purpose::Randomized).is_none());
    }
    assert!(matches!(
        fixture.keyring.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::NoActiveVersion(error)) if error.purpose == Purpose::Randomized
    ));
    assert!(matches!(
        fixture.keyring.rotate(Purpose::Randomized).await,
        Err(KeyringError::Kms(_))
    ));

    fixture
        .provider
        .calls
        .fail_wraps
        .store(false, Ordering::SeqCst);
    let staged = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert!(matches!(
        fixture.keyring.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::NoActiveVersion(_))
    ));
    let rotation = fixture.keyring.promote(staged).await?;
    assert_eq!(
        (rotation.previous, rotation.current),
        (None, KeyId::try_from(2)?)
    );
    assert_eq!(
        KeyId::try_from(&fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?)?,
        KeyId::try_from(2)?
    );
    Ok(())
}

#[tokio::test]
async fn retired_and_destroyed_versions_refuse_reads() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    keyring
        .promote(keyring.rotate(Purpose::Randomized).await?)
        .await?;

    keyring.retire(KeyId::try_from(1)?).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    assert!(matches!(
        keyring.decrypt_with_status(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    keyring.reinstate(KeyId::try_from(1)?).await?;
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);

    keyring.retire(KeyId::try_from(1)?).await?;
    keyring.destroy(KeyId::try_from(1)?).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    assert!(matches!(
        keyring.retire(KeyId::try_from(2)?).await,
        Err(KeyringError::InvalidTransition(error))
            if error.from == KeyVersionState::Active && error.transition == Transition::Retire
    ));
    let stored = fixture.other_process().await?.record();
    let destroyed = stored
        .version(KeyId::try_from(1)?)
        .ok_or("version 1 is gone")?;
    assert_eq!(destroyed.state(), KeyVersionState::Destroyed);
    assert!(destroyed.wrapped_dek().is_none());
    Ok(())
}

#[tokio::test]
async fn create_refuses_an_existing_record_and_open_or_create_opens_it() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let created = TestKeyring::create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(created, Err(KeyringError::RecordExists(_))));

    let opened = TestKeyring::open_or_create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    assert_eq!(
        opened.record().to_json()?,
        fixture.keyring.record().to_json()?
    );

    let empty = MemoryKeyringStore::new();
    let opened = TestKeyring::open(
        empty.clone(),
        fixture.provider.clone(),
        TENANT,
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
    let fresh = TestKeyring::open_or_create(
        empty,
        fixture.provider.clone(),
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let record = fresh.record();
    let active = record
        .active(Purpose::Randomized)
        .ok_or("no active version")?;
    assert_eq!(
        (active.key_id(), active.algorithm()),
        (
            KeyId::try_from(1)?,
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm)
        )
    );
    Ok(())
}

#[tokio::test]
async fn rewrap_wraps_every_version_again_and_values_still_open() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    keyring.rotate(Purpose::Randomized).await?;
    let before = keyring.record().wrapped_deks();
    let unwraps = fixture.provider.calls.unwraps.load(Ordering::SeqCst);

    assert_eq!(keyring.rewrap().await?, 2);
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps + 2
    );
    let after = keyring.record().wrapped_deks();
    for ((key_id, wrapped), (rewrapped_id, rewrapped)) in before.iter().zip(&after) {
        assert_eq!(key_id, rewrapped_id);
        assert_ne!(wrapped, rewrapped);
    }
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn change_algorithm_rotates_to_the_new_algorithm() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);

    let staged = keyring.change_algorithm(chacha).await?;
    let record = keyring.record();
    assert_eq!(
        record.algorithms().randomized(),
        AeadAlgorithm::ChaCha20Poly1305
    );
    let version = record.version(staged).ok_or("the staged version is gone")?;
    assert_eq!(
        (version.algorithm(), version.state()),
        (chacha, KeyVersionState::Pending)
    );
    keyring.promote(staged).await?;
    let new = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&new)?, staged);
    assert_eq!(keyring.decrypt(&aad, &new).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    Ok(())
}

#[cfg(feature = "ring")]
#[tokio::test]
async fn an_algorithm_the_backend_lacks_is_refused_before_any_write() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let before = fixture.keyring.record().to_json()?;
    assert!(matches!(
        fixture
            .keyring
            .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::Aes256GcmSiv))
            .await,
        Err(KeyringError::Kms(KmsAeadError::UnsupportedAlgorithm(_)))
    ));
    assert_eq!(fixture.other_process().await?.record().to_json()?, before);
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn a_deterministic_policy_creates_deterministic_versions() -> TestResult {
    let provider = TestProvider::new("tenant-42-kek")?;
    let policy = KeyringPolicy::new()
        .with_deterministic_algorithm(kms_aead::DeterministicAlgorithm::Aes256Siv);
    let keyring = TestKeyring::create(
        MemoryKeyringStore::new(),
        provider.clone(),
        TENANT,
        policy,
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let record = keyring.record();
    assert_eq!(
        record
            .active(Purpose::Deterministic)
            .map(KeyVersion::key_id),
        Some(KeyId::try_from(0x8000_0001)?)
    );
    assert_eq!(
        keyring.rotate(Purpose::Deterministic).await?,
        KeyId::try_from(0x8000_0002)?
    );
    Ok(())
}

#[cfg(not(feature = "deterministic"))]
#[tokio::test]
async fn a_deterministic_policy_needs_the_feature() -> TestResult {
    let policy = KeyringPolicy::new()
        .with_deterministic_algorithm(kms_aead::DeterministicAlgorithm::Aes256Siv);
    let created = TestKeyring::create(
        MemoryKeyringStore::new(),
        TestProvider::new("tenant-42-kek")?,
        TENANT,
        policy,
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(created, Err(KeyringError::DeterministicDisabled)));
    Ok(())
}

/// One rule of the record's regression checks, refused on each path that reads the store; the
/// other rules are the record's own tests.
#[tokio::test(start_paused = true)]
async fn a_regressed_record_is_refused() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::try_from(1)?, None)
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
    let rule = RegressionRule::CompromiseCleared(KeyId::try_from(1)?);

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let value = fixture
        .keyring
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;
    assert_eq!(KeyId::try_from(&value)?, KeyId::try_from(2)?);
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
    ));
    assert!(matches!(
        fixture.keyring.rotate(Purpose::Randomized).await,
        Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
    ));
    assert_eq!(fixture.keyring.record().to_json()?, held);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_refreshed_record_evicts_the_keys_it_withdraws() -> TestResult {
    let fixture = Fixture::new(
        KeyringOptions::new()
            .with_watch(false)
            .with_compromised_reads(CompromisedReadPolicy::Allow),
    )
    .await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(fixture.provider.calls.unwraps.load(Ordering::SeqCst), 1);

    fixture
        .other_process()
        .await?
        .mark_compromised(KeyId::try_from(1)?, None)
        .await?;
    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        KeyId::try_from(&fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?)?,
        KeyId::try_from(2)?
    );
    assert_eq!(fixture.provider.calls.unwraps.load(Ordering::SeqCst), 2);
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        3,
        "the refresh evicted version 1's key"
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_write_before_the_watch_subscribes_is_seen() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
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

    let keyring = TestKeyring::open(
        store,
        fixture.provider.clone(),
        TENANT,
        KeyringOptions::new(),
    )
    .await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(
        keyring
            .record()
            .active(Purpose::Randomized)
            .map(KeyVersion::key_id),
        Some(KeyId::try_from(2)?)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_signals_coalesce_to_one_revalidation_per_interval() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new()).await?;
    let admin = fixture.other_process().await?;

    admin.rotate(Purpose::Randomized).await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    admin.promote(KeyId::try_from(2)?).await?;
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
            .map(KeyVersion::key_id),
        Some(KeyId::try_from(6)?)
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 2);
    Ok(())
}

#[tokio::test]
async fn a_staged_version_decrypts_and_never_encrypts() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let first = KeyId::try_from(1)?;

    let staged = keyring.rotate(Purpose::Randomized).await?;
    let record = keyring.record();
    let version = record.version(staged).ok_or("the staged version is gone")?;
    assert_eq!(version.state(), KeyVersionState::Pending);
    assert_eq!(version.staged_at(), Some(version.created_at()));
    let value = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&value)?, first);

    let rotation = keyring.promote(staged).await?;
    assert_eq!((rotation.previous, rotation.current), (Some(first), staged));
    let promoted = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&promoted)?, staged);
    assert_eq!(keyring.decrypt(&aad, &promoted).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    Ok(())
}

/// An instance that refreshed while a version was pending opens the values written under it
/// once it is promoted, before the instance sees the promotion and without a reload.
#[tokio::test(start_paused = true)]
async fn a_promoted_version_opens_on_an_instance_that_saw_it_staged() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let admin = fixture.other_process().await?;
    let aad = email_of("42")?;

    let staged = admin.rotate(Purpose::Randomized).await?;
    tokio::time::advance(KeyringOptions::DEFAULT_RECORD_TTL).await;
    let sealed_before = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&sealed_before)?, KeyId::try_from(1)?);
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
    let promoted = admin.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(KeyId::try_from(&promoted)?, staged);

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
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let keyring = &fixture.keyring;
    let staged = keyring.rotate(Purpose::Randomized).await?;

    let refused = [
        (
            keyring.rotate(Purpose::Randomized).await.map(|_| ()),
            Transition::Rotate,
        ),
        (keyring.retire(staged).await, Transition::Retire),
        (
            keyring.mark_compromised(staged, None).await.map(|_| ()),
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

    keyring.destroy(staged).await?;
    assert!(matches!(
        keyring.promote(staged).await,
        Err(KeyringError::InvalidTransition(error))
            if error.from == KeyVersionState::Destroyed && error.transition == Transition::Promote
    ));
    let restaged = keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(restaged, KeyId::try_from(3)?);
    Ok(())
}

const BIGQUERY_EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);

/// A keyring on `provider` with the algorithms BigQuery reads, and a deterministic version too
/// where the build can create one.
async fn bigquery_keyring(
    provider: TestProvider,
) -> KeyringResult<TestKeyring<MemoryKeyringStore>> {
    let policy = KeyringPolicy::new();
    #[cfg(feature = "deterministic")]
    let policy = policy.with_deterministic_algorithm(DeterministicAlgorithm::Aes256Siv);
    TestKeyring::create(
        MemoryKeyringStore::new(),
        provider,
        TENANT,
        policy,
        KeyringOptions::new().with_watch(false),
    )
    .await
}

/// The test KMS, reporting a Cloud KMS key as its KEK.
fn cloud_kms_provider() -> KeyringResult<TestProvider> {
    Ok(TestProvider::new("tenant-42-kek")?.reporting(KekRef::new(
        KekProvider::Gcp,
        "projects/p/locations/europe-north1/keyRings/r/cryptoKeys/tenant-42",
    )))
}

#[tokio::test]
async fn interop_bigquery_seals_under_its_algorithms_and_a_cloud_kms_kek() -> TestResult {
    let keyring = bigquery_keyring(cloud_kms_provider()?).await?;
    let aad = BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?);
    let value = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    #[cfg(feature = "deterministic")]
    {
        let aad = BIGQUERY_EMAIL.deterministic_aad();
        let value = keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?;
        assert_eq!(keyring.decrypt_deterministic(&aad, &value).await?, ALICE);
    }
    Ok(())
}

#[tokio::test]
async fn interop_bigquery_refuses_a_non_gcm_version() -> TestResult {
    let keyring = bigquery_keyring(cloud_kms_provider()?).await?;
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);
    keyring
        .promote(keyring.change_algorithm(chacha).await?)
        .await?;

    assert!(matches!(
        keyring
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Algorithm(chacha)
    ));
    keyring
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;
    Ok(())
}

#[tokio::test]
async fn interop_bigquery_refuses_a_non_gcp_kek() -> TestResult {
    let keyring = bigquery_keyring(TestProvider::new("tenant-42-kek")?).await?;

    assert!(matches!(
        keyring
            .encrypt(&BIGQUERY_EMAIL.aad(&EntityId::try_from("42")?), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KekProvider::Local)
    ));
    #[cfg(feature = "deterministic")]
    assert!(matches!(
        keyring
            .encrypt_deterministic(&BIGQUERY_EMAIL.deterministic_aad(), &ALICE.to_string())
            .await,
        Err(KeyringError::Interop(error))
            if error.requirement == InteropRequirement::Kek(KekProvider::Local)
    ));
    Ok(())
}
