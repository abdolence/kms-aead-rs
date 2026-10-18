use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kms_aead::cache::DekCacheOutcome;
use kms_aead::errors::KmsAeadError;
use kms_aead::{AeadAlgorithm, AeadCipher, CipherText, DataEncryptionKey, DekBinding, KekRef};
use secret_vault_value::SecretValue;
use serde_json::{json, Value};

use super::*;
use crate::errors::{RecordConflictError, RecordRegressedError, RegressionRule};
use crate::store::{KeyringStore, MemoryKeyringStore};
use crate::testing::{email_of, TestProvider, TestResult, TestStore, TENANT, TEST_BACKEND};
use crate::{EntityId, EntityKind, FieldName, FieldSpec, Transition};

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
        let store = TestStore::new(&memory, Duration::ZERO);
        let provider = TestProvider::new("tenant-42-kek")?;
        let keyring = Keyring::create(
            store.clone(),
            provider.clone(),
            TEST_BACKEND,
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
            TEST_BACKEND,
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
        .await
    }
}

const ALICE: &str = "alice@example.com";

/// `value` with its key id changed to `key_id`.
fn relabelled<T>(value: &Encrypted<T>, key_id: u32) -> KeyringResult<Encrypted<T>> {
    let mut bytes = value.as_bytes().to_vec();
    bytes[1..5].copy_from_slice(&key_id.to_be_bytes());
    Encrypted::try_from(bytes)
}

#[tokio::test]
async fn a_value_is_the_key_id_prefix_and_the_aead_cipher_output() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let value = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let bytes = value.as_bytes();
    assert_eq!(bytes[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(bytes.len(), 5 + 12 + ALICE.len() + 16);

    let record = fixture.keyring.record();
    let dek = record
        .version(KeyId::try_from(1)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 1 holds no key")?;
    let key = fixture
        .provider
        .decrypt_data_encryption_key(dek, Some(&TENANT.dek_binding(KeyId::try_from(1)?)?))
        .await?;
    let opened = AeadCipher::new(TEST_BACKEND, AeadAlgorithm::Aes256Gcm)?.decrypt_value(
        &aad.bytes,
        &CipherText(bytes[5..].to_vec()),
        &key,
    )?;
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
    let wrapped = provider
        .encrypt_data_encryption_key(&tink_key, Some(&TENANT.dek_binding(KeyId::try_from(7)?)?))
        .await?;
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
    let keyring = Keyring::open(
        memory,
        provider,
        TEST_BACKEND,
        TENANT,
        KeyringOptions::new().with_watch(false),
    )
    .await?;

    let value = Encrypted::<String>::try_from(TINK_VALUE.to_vec())?;
    assert_eq!(keyring.decrypt(&email_of("42")?, &value).await?, ALICE);
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
    keyring.rotate(Purpose::Randomized).await?;
    let second = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        (first.key_id(), second.key_id()),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_key_id_reloads_once_under_concurrency() -> TestResult {
    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tenant-42-kek")?;
    let admin = Keyring::create(
        memory.clone(),
        provider.clone(),
        TEST_BACKEND,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let store = TestStore::new(&memory, Duration::from_millis(50));
    let reader = Arc::new(
        Keyring::open(
            store.clone(),
            provider,
            TEST_BACKEND,
            TENANT,
            KeyringOptions::new().with_watch(false),
        )
        .await?,
    );
    admin.rotate(Purpose::Randomized).await?;
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
    fixture
        .other_process()
        .await?
        .rotate(Purpose::Randomized)
        .await?;

    let cached = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(cached.key_id(), KeyId::try_from(1)?);
    assert_eq!(
        (
            fixture.store.calls.loads.load(Ordering::SeqCst),
            fixture.store.calls.revalidations.load(Ordering::SeqCst)
        ),
        (0, 0)
    );

    tokio::time::advance(Duration::from_secs(5 * 60)).await;
    let refreshed = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(refreshed.key_id(), KeyId::try_from(2)?);
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
    assert_eq!(unchanged.key_id(), KeyId::try_from(2)?);
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
        fixture
            .keyring
            .encrypt(&aad, &ALICE.to_string())
            .await?
            .key_id(),
        KeyId::try_from(1)?
    );
    assert_eq!(fixture.store.calls.revalidations.load(Ordering::SeqCst), 1);
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);
    assert!(matches!(
        fixture.keyring.reload().await,
        Err(KeyringError::RecordMissing(_))
    ));
    assert_eq!(fixture.keyring.decrypt(&aad, &value).await?, ALICE);

    let opened = Keyring::open(
        fixture.store.clone(),
        fixture.provider.clone(),
        TEST_BACKEND,
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
    let opened = Keyring::open(
        fixture.memory.clone(),
        other.clone(),
        TEST_BACKEND,
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
    let rotation = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(rotation.current, KeyId::try_from(2)?);
    assert_eq!(fixture.store.calls.loads.load(Ordering::SeqCst), 3);

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
        Some(KeyId::try_from(2)?)
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

    let key_id = KeyId::try_from(1)?;
    fixture
        .keyring
        .with_cached_key(&held, key_id, dek, async |cache, binding| {
            cache
                .with_key(&fixture.provider, dek, binding, |_| ())
                .await
        })
        .await?;
    let binding = TENANT.dek_binding(key_id)?;
    let ((), outcome) = fixture
        .keyring
        .dek_cache()
        .with_key(&fixture.provider, dek, Some(&binding), |_| ())
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
    let leaked = fixture
        .provider
        .decrypt_data_encryption_key(dek, Some(&TENANT.dek_binding(KeyId::try_from(1)?)?))
        .await?;
    let body = AeadCipher::new(TEST_BACKEND, AeadAlgorithm::Aes256Gcm)?.encrypt_value(
        &aad.bytes,
        &SecretValue::from("mallory@example.com"),
        &leaked,
    )?;
    let forged = Encrypted::<String>::new(KeyId::try_from(1)?, &body.0);
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
    let rotation = fixture.keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(
        (rotation.previous, rotation.current),
        (None, KeyId::try_from(2)?)
    );
    assert_eq!(
        fixture
            .keyring
            .encrypt(&aad, &ALICE.to_string())
            .await?
            .key_id(),
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
    keyring.rotate(Purpose::Randomized).await?;

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
    let created = Keyring::create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        TEST_BACKEND,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(created, Err(KeyringError::RecordExists(_))));

    let opened = Keyring::open_or_create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        TEST_BACKEND,
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
    let opened = Keyring::open(
        empty.clone(),
        fixture.provider.clone(),
        TEST_BACKEND,
        TENANT,
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(opened, Err(KeyringError::RecordMissing(_))));
    let fresh = Keyring::open_or_create(
        empty,
        fixture.provider.clone(),
        TEST_BACKEND,
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
        let binding = DekBinding::try_from(format!("tenant-42/{key_id}"))?;
        fixture
            .provider
            .decrypt_data_encryption_key(rewrapped, Some(&binding))
            .await?;
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
    let new = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(new.key_id(), rotation.current);
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
    let keyring = Keyring::create(
        MemoryKeyringStore::new(),
        provider.clone(),
        TEST_BACKEND,
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
        keyring.rotate(Purpose::Deterministic).await?.current,
        KeyId::try_from(0x8000_0002)?
    );
    let dek = record
        .version(KeyId::try_from(0x8000_0001)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("version 2147483649 holds no key")?;
    let binding = DekBinding::try_from("tenant-42/2147483649".to_string())?;
    provider
        .decrypt_data_encryption_key(dek, Some(&binding))
        .await?;
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
        TEST_BACKEND,
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
    assert_eq!(value.key_id(), KeyId::try_from(2)?);
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
        fixture
            .keyring
            .encrypt(&aad, &ALICE.to_string())
            .await?
            .key_id(),
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
    fixture
        .other_process()
        .await?
        .rotate(Purpose::Randomized)
        .await?;
    let rotated = fixture.memory.load(&TENANT).await?.ok_or("no record")?;
    let store = TestStore::new(&late, Duration::ZERO);
    *store
        .calls
        .written_before_watch
        .lock()
        .map_err(|_| "poisoned")? = Some(rotated.record);

    let keyring = Keyring::open(
        store,
        fixture.provider.clone(),
        TEST_BACKEND,
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
    for _ in 0..4 {
        admin.rotate(Purpose::Randomized).await?;
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

/// Writes the record of `id` with the active randomized version moved to decrypt-only and a new
/// active version `key_id` that holds `dek`: what a writer of the store without KMS rights can do.
async fn write_copied_version(
    memory: &MemoryKeyringStore,
    id: &KeyringId,
    key_id: u32,
    dek: &EncryptedDataEncryptionKey,
) -> TestResult {
    let stored = memory.load(id).await?.ok_or("no record")?;
    let mut document: Value = serde_json::from_slice(&stored.record.to_json()?)?;
    let versions = document["versions"]
        .as_array_mut()
        .ok_or("the record has no versions")?;
    let active = versions
        .iter_mut()
        .find(|version| version["state"] == "active")
        .ok_or("the record has no active version")?;
    active["state"] = json!("decrypt_only");
    let mut copy = active.clone();
    copy["key_id"] = json!(key_id);
    copy["state"] = json!("active");
    copy["compromised"] = Value::Null;
    copy["wrapped_dek"] = json!(STANDARD.encode(dek.to_bytes()?));
    versions.push(copy);
    let record = KeyringRecord::from_json(id, document.to_string().as_bytes())?;
    assert!(matches!(
        memory
            .compare_and_swap(&record, Some(&stored.revision))
            .await?,
        Swap::Written(_)
    ));
    Ok(())
}

/// The wrapped key of version `key_id` of `keyring`'s cached record.
fn wrapped_dek_of<S: KeyringStore>(
    keyring: &Keyring<S, TestProvider>,
    key_id: u32,
) -> Result<EncryptedDataEncryptionKey, Box<dyn std::error::Error>> {
    Ok(keyring
        .record()
        .version(KeyId::try_from(key_id)?)
        .and_then(KeyVersion::wrapped_dek)
        .ok_or("the version holds no key")?
        .clone())
}

#[tokio::test]
async fn a_wrapped_key_copied_to_a_new_version_is_refused() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    let sealed_under_v1 = fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let leaked = wrapped_dek_of(&fixture.keyring, 1)?;
    fixture
        .keyring
        .mark_compromised(KeyId::try_from(1)?, None)
        .await?;
    write_copied_version(&fixture.memory, &TENANT, 3, &leaked).await?;

    fixture.keyring.reload().await?;
    assert_eq!(
        fixture
            .keyring
            .record()
            .active(Purpose::Randomized)
            .map(KeyVersion::key_id),
        Some(KeyId::try_from(3)?)
    );
    assert!(matches!(
        fixture.keyring.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    let forged = relabelled(&sealed_under_v1, 3)?;
    assert!(matches!(
        fixture.keyring.decrypt(&aad, &forged).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    assert!(matches!(
        fixture.keyring.decrypt_with_status(&aad, &forged).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    Ok(())
}

#[tokio::test]
async fn a_cached_key_does_not_serve_another_version() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let aad = email_of("42")?;
    fixture.keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let warm = wrapped_dek_of(&fixture.keyring, 1)?;
    write_copied_version(&fixture.memory, &TENANT, 2, &warm).await?;
    fixture.keyring.reload().await?;
    let unwraps = fixture.provider.calls.unwraps.load(Ordering::SeqCst);

    assert!(matches!(
        fixture.keyring.encrypt(&aad, &ALICE.to_string()).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    assert_eq!(
        fixture.provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps + 1
    );
    Ok(())
}

#[tokio::test]
async fn a_wrapped_key_of_another_keyring_is_refused() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let neighbour = Keyring::create(
        fixture.memory.clone(),
        fixture.provider.clone(),
        TEST_BACKEND,
        KeyringId::from_static("tenant-43"),
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let foreign = wrapped_dek_of(&neighbour, 1)?;
    write_copied_version(&fixture.memory, &TENANT, 2, &foreign).await?;
    fixture.keyring.reload().await?;

    assert!(matches!(
        fixture.keyring.encrypt(&email_of("42")?, &ALICE.to_string()).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    Ok(())
}

#[tokio::test]
async fn bindings_are_keyring_id_slash_key_id() -> TestResult {
    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    let dek = wrapped_dek_of(&fixture.keyring, 1)?;
    let provider = &fixture.provider;

    let bound = DekBinding::try_from("tenant-42/1".to_string())?;
    provider
        .decrypt_data_encryption_key(&dek, Some(&bound))
        .await?;
    for binding in [Some(DekBinding::try_from("tenant-42/2".to_string())?), None] {
        assert!(matches!(
            provider.decrypt_data_encryption_key(&dek, binding.as_ref()).await,
            Err(error) if error.code() == "DECRYPT"
        ));
    }
    Ok(())
}

#[tokio::test]
async fn a_bound_keyring_fails_on_a_provider_without_bindings() -> TestResult {
    let provider = TestProvider::new("tenant-42-kek")?;
    provider.calls.refuse_bindings.store(true, Ordering::SeqCst);
    let created = Keyring::create(
        MemoryKeyringStore::new(),
        provider,
        TEST_BACKEND,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await;
    assert!(matches!(
        created,
        Err(KeyringError::Kms(error)) if error.code() == "BINDING_UNSUPPORTED"
    ));

    let fixture = Fixture::new(KeyringOptions::new().with_watch(false)).await?;
    fixture
        .provider
        .calls
        .refuse_bindings
        .store(true, Ordering::SeqCst);
    assert!(matches!(
        fixture.keyring.encrypt(&email_of("42")?, &ALICE.to_string()).await,
        Err(KeyringError::Kms(error)) if error.code() == "BINDING_UNSUPPORTED"
    ));
    Ok(())
}

#[tokio::test]
async fn an_unbound_keyring_runs_on_a_provider_without_bindings() -> TestResult {
    let provider = TestProvider::new("tenant-42-kek")?;
    provider.calls.refuse_bindings.store(true, Ordering::SeqCst);
    let keyring = Keyring::create(
        MemoryKeyringStore::new(),
        provider,
        TEST_BACKEND,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new()
            .with_watch(false)
            .with_bind_keys(false),
    )
    .await?;
    let aad = email_of("42")?;
    let old = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    keyring.rotate(Purpose::Randomized).await?;
    assert_eq!(keyring.rewrap().await?, 2);
    let new = keyring.encrypt(&aad, &ALICE.to_string()).await?;

    assert_eq!(keyring.decrypt(&aad, &old).await?, ALICE);
    assert_eq!(keyring.decrypt(&aad, &new).await?, ALICE);
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
) -> KeyringResult<Keyring<MemoryKeyringStore, TestProvider>> {
    let policy = KeyringPolicy::new();
    #[cfg(feature = "deterministic")]
    let policy = policy.with_deterministic_algorithm(DeterministicAlgorithm::Aes256Siv);
    Keyring::create(
        MemoryKeyringStore::new(),
        provider,
        TEST_BACKEND,
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
    keyring.change_algorithm(chacha).await?;

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
