use std::sync::atomic::Ordering;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kms_aead::{DataEncryptionKey, DeterministicAlgorithm, KmsAeadEncryptionProvider};
use secret_vault_value::SecretValue;
use serde_json::json;

use crate::store::{KeyringStore, MemoryKeyringStore};
use crate::testing::{email_of, TestProvider, TestResult, TENANT, TEST_BACKEND};
use crate::{
    Deterministic, DeterministicAad, Encrypted, EntityKind, FieldName, FieldSpec, Interop, KeyId,
    KeyTrust, Keyring, KeyringError, KeyringOptions, KeyringPolicy, KeyringRecord, KeyringResult,
    Purpose,
};

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

const ALICE: &str = "alice@example.com";

/// A keyring with an AES-SIV version beside the randomized one.
async fn deterministic_keyring(
    provider: TestProvider,
) -> KeyringResult<Keyring<MemoryKeyringStore, TestProvider>> {
    Keyring::create(
        MemoryKeyringStore::new(),
        provider,
        TEST_BACKEND,
        TENANT,
        KeyringPolicy::new().with_deterministic_algorithm(DeterministicAlgorithm::Aes256Siv),
        KeyringOptions::new().with_watch(false),
    )
    .await
}

#[tokio::test]
async fn equal_plaintexts_give_equal_values_under_one_version() -> TestResult {
    let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let aad = EMAIL.deterministic_aad();
    let alice = keyring
        .encrypt_deterministic(&aad, &ALICE.to_string())
        .await?;

    assert_eq!(
        keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?,
        alice
    );
    assert_ne!(
        keyring
            .encrypt_deterministic(&aad, &"bob@example.com".to_string())
            .await?,
        alice
    );
    assert_eq!(alice.key_id(), KeyId::try_from(0x8000_0001)?);
    assert_eq!(alice.as_bytes().len(), 5 + 16 + ALICE.len());
    assert_eq!(keyring.decrypt_deterministic(&aad, &alice).await?, ALICE);
    Ok(())
}

#[tokio::test]
async fn probes_cover_every_decrypting_version_newest_first() -> TestResult {
    let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let aad = EMAIL.deterministic_aad();
    let first = keyring
        .encrypt_deterministic(&aad, &ALICE.to_string())
        .await?;
    keyring.rotate(Purpose::Deterministic).await?;
    keyring.rotate(Purpose::Deterministic).await?;

    let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
        [
            KeyId::try_from(0x8000_0003)?,
            KeyId::try_from(0x8000_0002)?,
            KeyId::try_from(0x8000_0001)?,
        ]
    );
    assert_eq!(
        probes[0],
        keyring
            .encrypt_deterministic(&aad, &ALICE.to_string())
            .await?
    );
    assert_eq!(probes[2], first);
    Ok(())
}

#[tokio::test]
async fn retired_versions_give_no_probe() -> TestResult {
    let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let aad = EMAIL.deterministic_aad();
    keyring.rotate(Purpose::Deterministic).await?;
    let first = KeyId::try_from(0x8000_0001)?;
    let current = [KeyId::try_from(0x8000_0002)?];

    keyring.retire(first).await?;
    let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
        current
    );

    keyring.destroy(first).await?;
    let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
        current
    );
    Ok(())
}

#[tokio::test]
async fn a_probe_under_a_compromised_version_is_listed() -> TestResult {
    let provider = TestProvider::new("tenant-42-kek")?;
    let keyring = deterministic_keyring(provider.clone()).await?;
    let aad = EMAIL.deterministic_aad();
    let first = keyring
        .encrypt_deterministic(&aad, &ALICE.to_string())
        .await?;
    keyring.mark_compromised(first.key_id(), None).await?;

    let probes = keyring.equality_probes(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        probes.iter().map(Encrypted::key_id).collect::<Vec<_>>(),
        [KeyId::try_from(0x8000_0002)?, first.key_id()]
    );
    assert_eq!(probes[1], first);

    let unwraps = provider.calls.unwraps.load(Ordering::SeqCst);
    keyring.equality_probes(&aad, &ALICE.to_string()).await?;
    assert_eq!(
        provider.calls.unwraps.load(Ordering::SeqCst),
        unwraps + 1,
        "the compromised key is unwrapped for each call, and never cached"
    );
    Ok(())
}

#[tokio::test]
async fn a_deterministic_read_under_a_compromised_version_follows_the_read_policy() -> TestResult {
    let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let aad = EMAIL.deterministic_aad();
    let value = keyring
        .encrypt_deterministic(&aad, &ALICE.to_string())
        .await?;
    keyring.mark_compromised(value.key_id(), None).await?;

    assert!(matches!(
        keyring.decrypt_deterministic(&aad, &value).await,
        Err(KeyringError::KeyVersionCompromised(error)) if error.key_id == value.key_id()
    ));
    let decrypted = keyring
        .decrypt_deterministic_with_status(&aad, &value)
        .await?;
    assert_eq!(decrypted.value, ALICE);
    assert_eq!(decrypted.key_id, value.key_id());
    assert!(matches!(decrypted.trust, KeyTrust::Compromised(_)));
    Ok(())
}

/// The deterministic AAD holds no entity id, so a value copied from user 42's row into user 7's
/// opens there, where the randomized twin, bound to its row, does not.
#[tokio::test]
async fn a_deterministic_value_opens_in_another_row() -> TestResult {
    let keyring = deterministic_keyring(TestProvider::new("tenant-42-kek")?).await?;
    let deterministic = keyring
        .encrypt_deterministic(&EMAIL.deterministic_aad(), &ALICE.to_string())
        .await?;
    let randomized = keyring
        .encrypt(&email_of("42")?, &ALICE.to_string())
        .await?;

    assert_eq!(
        keyring
            .decrypt_deterministic(&EMAIL.deterministic_aad(), &deterministic)
            .await?,
        ALICE
    );
    assert!(matches!(
        keyring.decrypt(&email_of("7")?, &randomized).await,
        Err(KeyringError::Kms(error)) if error.code() == "DECRYPT"
    ));
    Ok(())
}

/// The empty plaintext sealed by tink-java's AES-SIV with the TINK prefix: key id 0x44556677,
/// the bytes 0 to 63 as the 64-byte key, and one associated-data item, the byte 0xFF. From
/// `testCreateForEncryptConstructorForDecrypt_tinkPrefix` in
/// <https://github.com/tink-crypto/tink-java/blob/eadd2736490b50d80b3117a5586ffe0985c9207e/src/test/java/com/google/crypto/tink/subtle/AesSivTest.java#L396-L424>.
const TINK_DETERMINISTIC_VALUE: [u8; 21] = [
    0x01, 0x44, 0x55, 0x66, 0x77, 0x1b, 0xc4, 0x9c, 0x6a, 0x89, 0x4e, 0xf5, 0x74, 0x4a, 0x0a, 0x01,
    0xd4, 0x66, 0x08, 0xcb, 0xcc,
];

/// Tink's key id has bit 31 clear, which is a randomized id here, so the value is read under
/// the deterministic version 2^31 + 1 holding Tink's key: the rest of the bytes are Tink's.
#[tokio::test]
async fn a_deterministic_value_sealed_by_tink_decrypts() -> TestResult {
    assert!(matches!(
        Encrypted::<Vec<u8>, Deterministic>::try_from(TINK_DETERMINISTIC_VALUE.to_vec()),
        Err(KeyringError::KeyPurposeMismatch(_))
    ));
    let key_id = KeyId::try_from(0x8000_0001)?;
    let mut bytes = TINK_DETERMINISTIC_VALUE.to_vec();
    bytes[1..5].copy_from_slice(&0x8000_0001u32.to_be_bytes());
    let value = Encrypted::<Vec<u8>, Deterministic>::try_from(bytes)?;

    let memory = MemoryKeyringStore::new();
    let provider = TestProvider::new("tink-kek")?;
    let tink_key = DataEncryptionKey::from(SecretValue::from((0u8..64).collect::<Vec<_>>()));
    let wrapped = provider
        .encrypt_data_encryption_key(&tink_key, Some(&TENANT.dek_binding(key_id)?))
        .await?;
    let document = json!({
        "schema": 1,
        "id": "tenant-42",
        "kek": { "provider": "local", "key": "tink-kek" },
        "algorithms": { "randomized": "aes-256-gcm", "deterministic": "aes-256-siv" },
        "versions": [{
            "key_id": 0x8000_0001u32,
            "algorithm": "aes-256-siv",
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
    let aad = DeterministicAad {
        bytes: vec![0xFF],
        interop: Interop::None,
    };

    assert_eq!(
        keyring.decrypt_deterministic(&aad, &value).await?,
        Vec::<u8>::new()
    );
    assert_eq!(
        keyring
            .encrypt_deterministic(&aad, &Vec::<u8>::new())
            .await?,
        value
    );
    Ok(())
}
