use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kms_aead::cache::DekCacheOutcome;
use kms_aead::errors::KmsAeadError;
use kms_aead::{AeadAlgorithm, AeadCipher, AeadEncryption, CipherText, DataEncryptionKey};
use secret_vault_value::SecretValue;
use serde_json::{json, Value};

use super::*;
use crate::errors::{RecordConflictError, RecordRegressedError, RegressionRule};
use crate::store::{KeyringStore, MemoryKeyringStore};
use crate::testing::{backend, email_of, TestProvider, TestResult, TestStore, TENANT};
use crate::Transition;

/// A keyring created on a counting store, beside the memory store it writes to.
struct Fixture {
    memory: MemoryKeyringStore,
    store: TestStore,
    provider: TestProvider,
    keyring: Keyring<TestStore, TestProvider>,
}

impl Fixture {
    async fn new(options: KeyringOptions) -> KeyringResult<Self> {
        let memory = MemoryKeyringStore::new();
        let store = TestStore::new(&memory);
        let provider = TestProvider::new("tenant-42-kek")?;
        let keyring = Keyring::create(
            store.clone(),
            provider.clone(),
            backend(),
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
    async fn other_process(&self) -> KeyringResult<Keyring<MemoryKeyringStore, TestProvider>> {
        Keyring::open(
            self.memory.clone(),
            self.provider.clone(),
            backend(),
            TENANT,
            no_watch(),
        )
        .await
    }

    fn unwraps(&self) -> usize {
        self.provider.unwraps()
    }
}

/// The default options without push, so that only the calls a test makes read the store.
fn no_watch() -> KeyringOptions {
    KeyringOptions::new().with_watch(false)
}

fn key_id(id: u32) -> KeyringResult<KeyId> {
    KeyId::try_from(id)
}

const ALICE: &str = "alice@example.com";

fn alice() -> String {
    ALICE.to_string()
}

/// `value` with its key id changed to `key_id`.
fn relabelled<T>(value: &Encrypted<T>, key_id: u32) -> KeyringResult<Encrypted<T>> {
    let mut bytes = value.as_bytes().to_vec();
    bytes[1..5].copy_from_slice(&key_id.to_be_bytes());
    Encrypted::try_from(bytes)
}

fn is_decrypt_failure<T>(result: &KeyringResult<T>) -> bool {
    matches!(
        result,
        Err(KeyringError::Kms(KmsAeadError::EncryptionError(error))) if error.public.code == "DECRYPT"
    )
}

#[tokio::test]
async fn a_value_is_the_key_id_prefix_and_the_aead_cipher_output() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    let bytes = value.as_bytes();
    assert_eq!(bytes[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);

    let record = fixture.keyring.record();
    let dek = record
        .version(key_id(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    let key = fixture.provider.decrypt_data_encryption_key(dek).await?;
    let opened = AeadCipher::new(backend(), AeadAlgorithm::Aes256Gcm)?
        .decrypt_value(&aad.bytes, &CipherText(bytes[5..].to_vec()), &key)
        .await?;
    assert_eq!(opened.as_sensitive_str(), ALICE);
    Ok(())
}

/// `alice@example.com` sealed by Tink 1.16.1 for Python with a keyset of one AES-256-GCM key
/// with the TINK prefix: key id 7, the bytes 0 to 31 as the key, `user/42/email` as the
/// associated data.
const TINK_VALUE: [u8; 50] = [
    0x01, 0x00, 0x00, 0x00, 0x07, 0x11, 0x0a, 0xc1, 0x1b, 0x7b, 0x32, 0x08, 0x0d, 0xe3, 0x83, 0xa3,
    0xb8, 0xbc, 0x9e, 0x0d, 0xac, 0xcf, 0x01, 0x2a, 0xc0, 0x0b, 0xb3, 0x76, 0xb1, 0x4c, 0xcd, 0xb7,
    0xeb, 0x05, 0x00, 0xc7, 0x7a, 0xea, 0x67, 0xeb, 0x9b, 0x37, 0x35, 0xaa, 0xd6, 0x0e, 0x53, 0x4b,
    0x10, 0xbe,
];

#[tokio::test]
async fn a_value_sealed_by_tink_decrypts() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tink-kek")?;
    let tink_key = DataEncryptionKey::from(SecretValue::from((0u8..32).collect::<Vec<_>>()));
    let wrapped = provider.encrypt_data_encryption_key(&tink_key).await?;
    let document = json!({
        "schema": 1,
        "id": "tenant-42",
        "kek": { "provider": "local", "key": "tink-kek" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": null },
        "versions": [{
            "key_id": 7,
            "algorithm": "aes-256-gcm",
            "state": "active",
            "compromised": null,
            "created_at": "2026-01-10T09:00:00Z",
            "state_changed_at": "2026-01-10T09:00:00Z",
            "wrapped_dek": STANDARD.encode(wrapped.to_bytes()?),
        }],
        "created_at": "2026-01-10T09:00:00Z",
        "updated_at": "2026-01-10T09:00:00Z",
    });
    let record = KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())?;
    memory.compare_and_swap(&record, None).await?;
    let keyring = Keyring::open(memory, provider, backend(), TENANT, no_watch()).await?;

    let value = Encrypted::<String>::try_from(TINK_VALUE.to_vec())?;
    assert_eq!(keyring.decrypt(&email_of("42")?, &value).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn values_round_trip_through_their_plaintext_types() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;

    let text = keyring.encrypt(&aad, &alice()).await?;
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

#[tokio::test]
async fn a_value_opens_only_with_its_aad() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let value = keyring.encrypt(&email_of("42")?, &alice()).await?;

    for aad in [
        email_of("43")?,
        email_of("42")?.with_context(b"eu"),
        FieldAad::custom(b"user/42/email/".to_vec()),
    ] {
        assert!(is_decrypt_failure(&keyring.decrypt(&aad, &value).await));
    }
    let same_bytes = FieldAad::custom(b"user/42/email".to_vec());
    assert_eq!(keyring.decrypt(&same_bytes, &value).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn a_relabelled_prefix_fails_under_the_other_version() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let first = keyring.encrypt(&aad, &alice()).await?;
    keyring.rotate(Purpose::Randomized).await?;
    let second = keyring.encrypt(&aad, &alice()).await?;
    assert_eq!((first.key_id(), second.key_id()), (key_id(1)?, key_id(2)?));

    assert!(is_decrypt_failure(
        &keyring.decrypt(&aad, &relabelled(&first, 2)?).await
    ));
    assert!(is_decrypt_failure(
        &keyring.decrypt(&aad, &relabelled(&second, 1)?).await
    ));
    assert_eq!(keyring.decrypt(&aad, &first).await?, ALICE);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_id_reloads_once_under_concurrency() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let admin = Keyring::create(
        memory.clone(),
        provider.clone(),
        backend(),
        TENANT,
        KeyringPolicy::new(),
        no_watch(),
    )
    .await?;
    let store = TestStore::with_delay(&memory, Duration::from_millis(50));
    let reader =
        Arc::new(Keyring::open(store.clone(), provider, backend(), TENANT, no_watch()).await?);
    admin.rotate(Purpose::Randomized).await?;
    let aad = Arc::new(email_of("42")?);
    let value = admin.encrypt(&aad, &alice()).await?;

    let mut reads = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let (reader, aad, value) = (Arc::clone(&reader), Arc::clone(&aad), value.clone());
        reads.spawn(async move { reader.decrypt(&aad, &value).await });
    }
    while let Some(read) = reads.join_next().await {
        assert_eq!(read??, ALICE);
    }
    assert_eq!(store.revalidations(), 1);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn reload_is_rate_limited() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    let unknown = relabelled(&fixture.keyring.encrypt(&aad, &alice()).await?, 9)?;

    for _ in 0..3 {
        assert!(matches!(
            fixture.keyring.decrypt(&aad, &unknown).await,
            Err(KeyringError::KeyVersionUnknown(error)) if error.key_id == key_id(9)?
        ));
        assert_eq!(fixture.store.revalidations(), 1);
    }
    tokio::time::advance(Duration::from_secs(5)).await;
    assert!(fixture.keyring.decrypt(&aad, &unknown).await.is_err());
    assert_eq!(fixture.store.revalidations(), 2);
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn record_ttl_revalidates_with_a_conditional_read() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    fixture
        .other_process()
        .await?
        .rotate(Purpose::Randomized)
        .await?;

    let cached = fixture.keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(cached.key_id(), key_id(1)?);
    assert_eq!(
        (fixture.store.loads(), fixture.store.revalidations()),
        (0, 0)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let refreshed = fixture.keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(refreshed.key_id(), key_id(2)?);
    fixture.keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(
        (fixture.store.loads(), fixture.store.revalidations()),
        (0, 1)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let unchanged = fixture.keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(unchanged.key_id(), key_id(2)?);
    assert_eq!(
        (fixture.store.loads(), fixture.store.revalidations()),
        (0, 2)
    );
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_missing_record_keeps_the_cached_one() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    fixture.store.calls.missing.store(true, Ordering::SeqCst);

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        fixture.keyring.encrypt(&aad, &alice()).await?.key_id(),
        key_id(1)?
    );
    assert_eq!(fixture.store.revalidations(), 1);
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);

    let opened = Keyring::open(
        fixture.store.clone(),
        fixture.provider.clone(),
        backend(),
        TENANT,
        no_watch(),
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
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
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
    let fixture = Fixture::new(no_watch()).await?;
    let other = TestProvider::new("another-kek")?;
    let opened = Keyring::open(
        fixture.memory.clone(),
        other.clone(),
        backend(),
        TENANT,
        no_watch(),
    )
    .await;
    assert!(matches!(
        opened,
        Err(KeyringError::KekMismatch(error))
            if error.recorded == fixture.provider.kek() && error.provider == other.kek()
    ));
    Ok(())
}

#[tokio::test]
async fn cas_conflicts_are_retried_then_refused() -> TestResult {
    let fixture = Fixture::new(no_watch().with_cas_retries(2)).await?;
    fixture.store.calls.conflicts.store(2, Ordering::SeqCst);
    let rotation = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(rotation.current, key_id(2)?);
    assert_eq!(fixture.store.loads(), 3);

    fixture.store.calls.conflicts.store(3, Ordering::SeqCst);
    assert!(matches!(
        fixture.keyring.rotate(Purpose::Randomized).await,
        Err(KeyringError::RecordConflict(RecordConflictError {
            attempts: 3,
            ..
        }))
    ));
    let stored = fixture.other_process().await?.record();
    assert_eq!(
        stored.active(Purpose::Randomized).map(KeyVersion::key_id),
        Some(key_id(2)?)
    );
    Ok(())
}

#[tokio::test]
async fn mark_compromised_evicts_the_dek() -> TestResult {
    let fixture =
        Fixture::new(no_watch().with_compromised_reads(CompromisedReadPolicy::Allow)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(fixture.unwraps(), 1);

    let rotation = fixture
        .keyring
        .mark_compromised(key_id(1)?, Some("laptop lost".to_string()))
        .await?;
    assert_eq!(rotation.map(|rotation| rotation.current), Some(key_id(2)?));
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert_eq!(
        fixture.unwraps(),
        2,
        "the key was evicted, so the read missed"
    );
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(fixture.unwraps(), 2, "Allow reads through the cache");
    Ok(())
}

#[tokio::test]
async fn a_key_unwrapped_under_a_superseded_record_is_evicted() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let held = fixture.keyring.record();
    let dek = held
        .version(key_id(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    fixture
        .other_process()
        .await?
        .mark_compromised(key_id(1)?, None)
        .await?;
    fixture.keyring.reload().await?;

    fixture.keyring.with_cached_key(&held, dek, |_| ()).await?;
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
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    fixture.keyring.mark_compromised(key_id(1)?, None).await?;
    let unwraps = fixture.unwraps();

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == key_id(1)?
    ));
    let other = fixture.other_process().await?;
    assert!(matches!(
        other.decrypt(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    assert_eq!(fixture.unwraps(), unwraps);
    Ok(())
}

#[tokio::test]
async fn a_forgery_under_a_known_dek_is_refused_under_block() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    let record = fixture.keyring.record();
    let dek = record
        .version(key_id(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    let leaked = fixture.provider.decrypt_data_encryption_key(dek).await?;
    let body = AeadCipher::new(backend(), AeadAlgorithm::Aes256Gcm)?
        .encrypt_value(
            &aad.bytes,
            &SecretValue::from("mallory@example.com"),
            &leaked,
        )
        .await?;
    let forged = Encrypted::<String>::new(key_id(1)?, &body.0);
    fixture
        .keyring
        .mark_compromised(key_id(1)?, Some("dek leaked".to_string()))
        .await?;

    assert!(matches!(
        fixture.keyring.decrypt(&aad, &forged).await,
        Err(KeyringError::KeyVersionCompromised(_))
    ));
    let status = fixture.keyring.decrypt_with_status(&aad, &forged).await?;
    assert_eq!(status.value, "mallory@example.com");
    assert_eq!(status.key_id, key_id(1)?);
    assert!(matches!(
        status.trust,
        KeyTrust::Compromised(compromise) if compromise.note() == Some("dek leaked")
    ));
    Ok(())
}

#[tokio::test]
async fn decrypt_with_status_unwraps_a_compromised_version_past_the_cache() -> TestResult {
    let fixture =
        Fixture::new(no_watch().with_compromised_reads(CompromisedReadPolicy::Allow)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    fixture.keyring.mark_compromised(key_id(1)?, None).await?;
    let unwraps = fixture.unwraps();

    for read in 1..=2 {
        let status = fixture.keyring.decrypt_with_status(&aad, &value).await?;
        assert!(matches!(status.trust, KeyTrust::Compromised(_)));
        assert_eq!(fixture.unwraps(), unwraps + read);
    }
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(
        fixture.unwraps(),
        unwraps + 3,
        "the reads above cached nothing"
    );

    let trusted = fixture.keyring.encrypt(&aad, &alice()).await?;
    let status = fixture.keyring.decrypt_with_status(&aad, &trusted).await?;
    assert_eq!(
        (status.key_id, status.trust),
        (key_id(2)?, KeyTrust::Trusted)
    );
    Ok(())
}

#[tokio::test]
async fn mark_compromised_writes_the_flag_when_the_wrap_fails() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let aad = email_of("42")?;
    fixture
        .provider
        .calls
        .fail_wraps
        .store(true, Ordering::SeqCst);

    assert_eq!(
        fixture.keyring.mark_compromised(key_id(1)?, None).await?,
        None
    );
    for record in [
        fixture.keyring.record(),
        fixture.other_process().await?.record(),
    ] {
        let version = record.version(key_id(1)?).ok_or("version 1 is gone")?;
        assert_eq!(version.state(), KeyVersionState::DecryptOnly);
        assert!(version.compromised().is_some());
        assert!(record.active(Purpose::Randomized).is_none());
    }
    assert!(matches!(
        fixture.keyring.encrypt(&aad, &alice()).await,
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
    let rotation = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert_eq!((rotation.previous, rotation.current), (None, key_id(2)?));
    assert_eq!(
        fixture.keyring.encrypt(&aad, &alice()).await?.key_id(),
        key_id(2)?
    );
    Ok(())
}

#[tokio::test]
async fn retired_and_destroyed_versions_refuse_reads() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &alice()).await?;
    keyring.rotate(Purpose::Randomized).await?;

    keyring.retire(key_id(1)?).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    assert!(matches!(
        keyring.decrypt_with_status(&aad, &old).await,
        Err(KeyringError::KeyVersionRetired(_))
    ));
    keyring.reinstate(key_id(1)?).await?;
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);

    keyring.retire(key_id(1)?).await?;
    keyring.destroy(key_id(1)?).await?;
    assert!(matches!(
        keyring.decrypt(&aad, &old).await,
        Err(KeyringError::KeyVersionDestroyed(_))
    ));
    assert!(matches!(
        keyring.retire(key_id(2)?).await,
        Err(KeyringError::InvalidTransition(error))
            if error.from == KeyVersionState::Active && error.transition == Transition::Retire
    ));
    let stored = fixture.other_process().await?.record();
    let destroyed = stored.version(key_id(1)?).ok_or("version 1 is gone")?;
    assert_eq!(destroyed.state(), KeyVersionState::Destroyed);
    assert!(destroyed.wrapped_dek().is_none());
    Ok(())
}

#[tokio::test]
async fn create_refuses_an_existing_record_and_open_or_create_opens_it() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let created = Keyring::create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        backend(),
        TENANT,
        KeyringPolicy::new(),
        no_watch(),
    )
    .await;
    assert!(matches!(created, Err(KeyringError::RecordExists(_))));

    let opened = Keyring::open_or_create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        backend(),
        TENANT,
        KeyringPolicy::new(),
        no_watch(),
    )
    .await?;
    assert_eq!(
        opened.record().to_json()?,
        fixture.keyring.record().to_json()?
    );

    let empty = MemoryKeyringStore::new();
    let opened = Keyring::open(
        empty.clone(),
        fixture.provider.clone(),
        backend(),
        TENANT,
        no_watch(),
    )
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
    let fresh = Keyring::open_or_create(
        empty,
        fixture.provider.clone(),
        backend(),
        TENANT,
        KeyringPolicy::new(),
        no_watch(),
    )
    .await?;
    let record = fresh.record();
    let active = record
        .active(Purpose::Randomized)
        .ok_or("no active version")?;
    assert_eq!(
        (active.key_id(), active.algorithm()),
        (
            key_id(1)?,
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm)
        )
    );
    Ok(())
}

#[tokio::test]
async fn rewrap_wraps_every_version_again_and_values_still_open() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &alice()).await?;
    keyring.rotate(Purpose::Randomized).await?;
    let before = keyring.record().wrapped_deks();
    let unwraps = fixture.unwraps();

    assert_eq!(keyring.rewrap().await?, 2);
    assert_eq!(fixture.unwraps(), unwraps + 2);
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
    let fixture = Fixture::new(no_watch()).await?;
    let keyring = &fixture.keyring;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &alice()).await?;
    let chacha = KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305);

    let rotation = keyring.change_algorithm(chacha).await?;
    let record = keyring.record();
    assert_eq!(
        record.algorithms().randomized(),
        AeadAlgorithm::ChaCha20Poly1305
    );
    assert_eq!(
        record.version(rotation.current).map(KeyVersion::algorithm),
        Some(chacha)
    );
    let new = keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(new.key_id(), rotation.current);
    assert_eq!(keyring.decrypt(&aad, &new).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    Ok(())
}

#[cfg(feature = "ring")]
#[tokio::test]
async fn an_algorithm_the_backend_lacks_is_refused_before_any_write() -> TestResult {
    let fixture = Fixture::new(no_watch()).await?;
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
    let keyring = Keyring::create(
        MemoryKeyringStore::new(),
        provider,
        backend(),
        TENANT,
        policy,
        no_watch(),
    )
    .await?;
    let record = keyring.record();
    assert_eq!(
        record
            .active(Purpose::Deterministic)
            .map(KeyVersion::key_id),
        Some(key_id(0x8000_0001)?)
    );
    assert_eq!(
        keyring.rotate(Purpose::Deterministic).await?.current,
        key_id(0x8000_0002)?
    );
    Ok(())
}

#[cfg(not(feature = "deterministic"))]
#[tokio::test]
async fn a_deterministic_policy_needs_the_feature() -> TestResult {
    let policy = KeyringPolicy::new()
        .with_deterministic_algorithm(kms_aead::DeterministicAlgorithm::Aes256Siv);
    let created = Keyring::create(
        MemoryKeyringStore::new(),
        TestProvider::new("tenant-42-kek")?,
        backend(),
        TENANT,
        policy,
        no_watch(),
    )
    .await;
    assert!(matches!(created, Err(KeyringError::DeterministicDisabled)));
    Ok(())
}

/// The held record of the regression cases: 1 compromised, 2 retired, 3 destroyed, 4 active.
async fn regression_fixture() -> KeyringResult<Fixture> {
    let fixture = Fixture::new(no_watch()).await?;
    let admin = fixture.other_process().await?;
    for _ in 0..3 {
        admin.rotate(Purpose::Randomized).await?;
    }
    admin.mark_compromised(key_id(1)?, None).await?;
    for retired in [2, 3] {
        admin.retire(key_id(retired)?).await?;
    }
    admin.destroy(key_id(3)?).await?;
    fixture.keyring.reload().await?;
    Ok(fixture)
}

#[tokio::test(start_paused = true)]
async fn a_regressed_record_is_refused() -> TestResult {
    type Change = fn(&mut Value);
    let cases: [(Change, RegressionRule); 6] = [
        (
            |record| {
                if let Some(versions) = record["versions"].as_array_mut() {
                    versions.remove(0);
                }
            },
            RegressionRule::VersionMissing(key_id(1)?),
        ),
        (
            |record| record["versions"][1]["algorithm"] = json!("chacha20-poly1305"),
            RegressionRule::VersionAltered(key_id(2)?),
        ),
        (
            |record| record["versions"][0]["compromised"] = Value::Null,
            RegressionRule::CompromiseCleared(key_id(1)?),
        ),
        (
            |record| record["versions"][0]["compromised"]["at"] = json!("2026-01-01T00:00:00Z"),
            RegressionRule::CompromiseAltered(key_id(1)?),
        ),
        (
            |record| {
                record["versions"][1]["state"] = json!("active");
                record["versions"][3]["state"] = json!("decrypt_only");
            },
            RegressionRule::StateReverted(key_id(2)?),
        ),
        (
            |record| {
                record["versions"][2]["state"] = json!("retired");
                record["versions"][2]["wrapped_dek"] = record["versions"][1]["wrapped_dek"].clone();
            },
            RegressionRule::StateReverted(key_id(3)?),
        ),
    ];
    for (change, rule) in cases {
        let fixture = regression_fixture().await?;
        let held = fixture.keyring.record().to_json()?;
        let stored = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
        let mut document: Value = serde_json::from_slice(&stored.record.to_json()?)?;
        change(&mut document);
        let regressed = KeyringRecord::from_json(&TENANT, document.to_string().as_bytes())?;
        fixture
            .memory
            .compare_and_swap(&regressed, Some(&stored.revision))
            .await?;

        tokio::time::advance(Duration::from_secs(5 * 60)).await;
        let value = fixture.keyring.encrypt(&email_of("42")?, &alice()).await?;
        assert_eq!(value.key_id(), key_id(4)?, "{rule}");
        assert_eq!(fixture.keyring.record().to_json()?, held, "{rule}");
        assert_eq!(fixture.store.revalidations(), 1, "{rule}");

        assert!(
            matches!(
                fixture.keyring.reload().await,
                Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
            ),
            "{rule}"
        );
        assert!(
            matches!(
                fixture.keyring.rotate(Purpose::Randomized).await,
                Err(KeyringError::RecordRegressed(RecordRegressedError { rule: refused, .. })) if refused == rule
            ),
            "{rule}"
        );
        assert_eq!(fixture.keyring.record().to_json()?, held, "{rule}");
    }
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn a_refreshed_record_evicts_the_keys_it_withdraws() -> TestResult {
    let fixture =
        Fixture::new(no_watch().with_compromised_reads(CompromisedReadPolicy::Allow)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &alice()).await?;
    assert_eq!(fixture.unwraps(), 1);

    fixture
        .other_process()
        .await?
        .mark_compromised(key_id(1)?, None)
        .await?;
    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    assert_eq!(
        fixture.keyring.encrypt(&aad, &alice()).await?.key_id(),
        key_id(2)?
    );
    assert_eq!(fixture.unwraps(), 2);
    fixture.keyring.decrypt(&aad, &value).await?;
    assert_eq!(fixture.unwraps(), 3, "the refresh evicted version 1's key");
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn watch_signals_coalesce_to_one_revalidation_per_interval() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new()).await?;
    let admin = fixture.other_process().await?;

    admin.rotate(Purpose::Randomized).await?;
    tokio::time::sleep(Duration::from_millis(1)).await;
    assert_eq!(fixture.store.revalidations(), 1);
    for _ in 0..4 {
        admin.rotate(Purpose::Randomized).await?;
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(fixture.store.revalidations(), 1);

    tokio::time::sleep(Duration::from_secs(5)).await;
    assert_eq!(fixture.store.revalidations(), 2);
    assert_eq!(
        fixture
            .keyring
            .record()
            .active(Purpose::Randomized)
            .map(KeyVersion::key_id),
        Some(key_id(6)?)
    );
    tokio::time::sleep(Duration::from_secs(60)).await;
    assert_eq!(fixture.store.revalidations(), 2);
    Ok(())
}
