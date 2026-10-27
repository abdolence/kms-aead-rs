use std::num::NonZeroU32;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use kms_aead::formats::PrivateKeyFormat;
use kms_aead::providers::{
    LocalSigningKey, LocalSigningKeyName, LocalSigningKeyVersion, LocalSigningProvider,
};
use kms_aead::signing::SigningAlgorithm;
use kms_aead::KmsAeadResult;
use secret_vault_value::SecretValue;
use serde_json::Value;

use super::*;
use crate::store::{KeyringStore, Swap};
use crate::test_support::{error_code_of, TestBackend, TestProvider, TestResult, TENANT};
use crate::testing::MemoryKeyringStore;
use crate::{
    KeyVersionState, KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, Purpose,
};

/// The PKCS#8 of the RFC 8032 section 7.1 test 1 key, the Ed25519 key of the book's test vectors,
/// as `openssl genpkey` writes it.
const ED25519_PKCS8_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----
";

/// The SHA-256 of [`CANONICAL_DOCUMENT`], from the book.
const CANONICAL_DIGEST: [u8; 32] = [
    0x19, 0x5a, 0xd5, 0x29, 0xd5, 0xec, 0x1b, 0xee, 0xc7, 0xf6, 0xd8, 0x06, 0x16, 0x9d, 0x59, 0x87,
    0x23, 0xbf, 0x06, 0x7c, 0x6a, 0xbd, 0x6b, 0x52, 0x2a, 0xb3, 0x30, 0x31, 0x0f, 0x2d, 0x79, 0xd2,
];

/// The book's keyring record with a member this release does not define, in another member
/// order and with whitespace, as a store may hold it.
const STORED_DOCUMENT: &str = r#"{
  "versions": [{
    "state_changed_at": "2026-10-25T09:00:00Z", "state": "decrypt_only", "key_id": 1,
    "seal_epochs": {"start": 1, "end": null}, "kek_version": "1", "encrypted_dek": "AQ==",
    "created_at": "2026-10-25T09:00:00Z",
    "compromised": {"note": "clé \u0007", "at": "2026-10-25T09:00:00Z"},
    "algorithm": "aes-256-gcm"
  }],
  "updated_at": "2026-10-25T09:00:00Z", "seal_epoch": 1, "schema": 1,
  "kek": {"provider": "local", "key": "tenant-kek"}, "id": "tenant-42",
  "future": {"b": 1, "a": [true, null]},
  "created_at": "2026-10-25T09:00:00Z",
  "algorithms": {"randomized": "aes-256-gcm", "mac": null, "deterministic": null, "beacon": null}
}"#;

/// The canonical document of [`STORED_DOCUMENT`], 579 bytes, from the book.
const CANONICAL_DOCUMENT: &str = concat!(
    r#"{"algorithms":{"beacon":null,"deterministic":null,"mac":null,"randomized":"aes-256-gcm"},"#,
    r#""created_at":"2026-10-25T09:00:00Z","future":{"a":[true,null],"b":1},"id":"tenant-42","#,
    r#""kek":{"key":"tenant-kek","provider":"local"},"schema":1,"seal_epoch":1,"#,
    r#""updated_at":"2026-10-25T09:00:00Z","versions":[{"algorithm":"aes-256-gcm","#,
    r#""compromised":{"at":"2026-10-25T09:00:00Z","note":"clé \u0007"},"#,
    r#""created_at":"2026-10-25T09:00:00Z","encrypted_dek":"AQ==","kek_version":"1","key_id":1,"#,
    r#""seal_epochs":{"end":null,"start":1},"state":"decrypt_only","#,
    r#""state_changed_at":"2026-10-25T09:00:00Z"}]}"#
);

type TestSigner = Signer<LocalSigningProvider<TestBackend>, TestBackend>;
type SigningAdmin = KeyringAdmin<MemoryKeyringStore, TestProvider, TestBackend, TestSigner>;
type TestRegistry = KeyringRegistry<MemoryKeyringStore, TestBackend>;

/// A signer on the Ed25519 key of the book's test vectors.
async fn test_vector_signer() -> KmsAeadResult<TestSigner> {
    Signer::new(LocalSigningProvider::new(
        LocalSigningKeyName::try_from("records".to_string())?,
        vec![LocalSigningKey::from_secret(
            LocalSigningKeyVersion::from(NonZeroU32::MIN),
            SecretValue::from(ED25519_PKCS8_PEM),
            PrivateKeyFormat::Pkcs8Pem,
        )?],
    )?)
    .await
}

/// A signer on a key of its own.
async fn new_signer() -> KmsAeadResult<TestSigner> {
    Signer::new(LocalSigningProvider::ephemeral(
        LocalSigningKeyName::try_from("records".to_string())?,
        SigningAlgorithm::Ed25519,
    )?)
    .await
}

fn registry_with_policy(
    store: &MemoryKeyringStore,
    verification: RecordSignaturePolicy,
) -> TestRegistry {
    KeyringRegistry::new(
        store.clone(),
        KeyringRegistryOptions::new()
            .with_watch(false)
            .with_record_signatures(verification),
    )
    .expect("a registry")
}

fn verifying_key_set_of(signer: &TestSigner) -> VerifyingKeySet {
    VerifyingKeySet::new([signer.verifying_key().clone()]).expect("one key")
}

/// A keyring created by a signing admin on `store`, and that admin.
async fn signed_keyring(
    store: &MemoryKeyringStore,
    signer: TestSigner,
) -> KeyringResult<SigningAdmin> {
    let verification = RecordSignaturePolicy::VerifyIfSigned(verifying_key_set_of(&signer));
    registry_with_policy(store, verification)
        .create_signed(
            TestProvider::new("tenant-42-kek")?,
            signer,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await
}

#[tokio::test]
async fn the_canonical_document_and_its_signature_are_the_books() -> TestResult {
    let record = KeyringRecord::from_json(&TENANT, STORED_DOCUMENT.as_bytes())?;
    let parsed: Value = serde_json::from_str(STORED_DOCUMENT)?;

    let canonical = crate::record::canonical::canonical_json(&parsed).expect("integers only");
    let signature = test_vector_signer().await?.sign_record(&record).await?;

    assert_eq!(canonical.len(), 579);
    assert_eq!(String::from_utf8(canonical)?, CANONICAL_DOCUMENT);
    assert_eq!(*record.canonical_digest(), CANONICAL_DIGEST);
    assert_eq!(
        STANDARD.encode(signature.value()),
        "AZD6yv6RAlxJsp1uzsdIQxlvyawlD282Dfrtg3QthYeSPnQ02B6jbpOBFA65Y2Zq5lILiXyyTCxj9bv36JGSWC2H2UAG"
    );
    Ok(())
}

#[tokio::test]
async fn a_signed_record_verifies_and_one_changed_after_signing_does_not() -> TestResult {
    let store = MemoryKeyringStore::new();
    let signer = new_signer().await?;
    let verification = RecordSignaturePolicy::VerifyIfSigned(verifying_key_set_of(&signer));
    signed_keyring(&store, signer).await?;
    let stored = store.load(&TENANT).await?.expect("a record");
    let mut document: Value = serde_json::from_slice(&stored.record.to_json()?)?;
    document["updated_at"] = Value::from("2026-10-26T09:00:00Z");
    let changed = KeyringRecord::from_json(&TENANT, &serde_json::to_vec(&document)?)?;
    store
        .compare_and_swap(&changed, Some(&stored.revision))
        .await?;

    let opened = registry_with_policy(&store, verification)
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;

    assert!(stored.record.signature().is_some());
    assert!(
        matches!(&opened, Err(KeyringError::RecordSignatureInvalid(error))
            if error.cause.code() == "SIGNATURE_INVALID"),
        "{:?}",
        opened.map(|_| ())
    );
    Ok(())
}

#[tokio::test]
async fn a_registry_with_no_key_refuses_a_signed_record() -> TestResult {
    let store = MemoryKeyringStore::new();
    signed_keyring(&store, new_signer().await?).await?;

    let opened = registry_with_policy(&store, RecordSignaturePolicy::default())
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;

    assert!(
        matches!(&opened, Err(KeyringError::RecordSignatureInvalid(error))
            if error.cause.code() == "SIGNING_KEY_UNKNOWN"),
        "{:?}",
        opened.map(|_| ())
    );
    Ok(())
}

#[tokio::test]
async fn a_signing_admin_signs_an_unsigned_record_only_through_sign_record() -> TestResult {
    let store = MemoryKeyringStore::new();
    let signer = new_signer().await?;
    let verification = RecordSignaturePolicy::VerifyIfSigned(verifying_key_set_of(&signer));
    let admin = registry_with_policy(&store, verification.clone())
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?
        .with_record_signer(signer)?;
    let before = store.load(&TENANT).await?.expect("a record").revision;

    let rotated = admin.rotate(Purpose::Randomized).await;
    let unchanged = store.load(&TENANT).await?.expect("a record").revision;
    admin.sign_record().await?;

    assert_eq!(error_code_of(rotated), "RECORD_UNSIGNED");
    assert_eq!(unchanged, before);
    let signed = registry_with_policy(
        &store,
        RecordSignaturePolicy::Required(verification_keys(&verification)),
    )
    .open(TestProvider::new("tenant-42-kek")?, TENANT)
    .await?;
    assert!(signed.record().signature().is_some());
    admin.rotate(Purpose::Randomized).await?;
    Ok(())
}

fn verification_keys(verification: &RecordSignaturePolicy) -> VerifyingKeySet {
    match verification {
        RecordSignaturePolicy::VerifyIfSigned(keys) | RecordSignaturePolicy::Required(keys) => {
            keys.clone()
        }
    }
}

/// A signer whose signatures are another key's than the one it names.
struct MismatchedSigner {
    signer: TestSigner,
    named: TestSigner,
}

impl RecordSigner for MismatchedSigner {
    async fn sign_record(&self, record: &KeyringRecord) -> KmsAeadResult<Signature<KeyringRecord>> {
        self.signer.sign_record(record).await
    }

    fn verifying_key(&self) -> &VerifyingKey {
        self.named.verifying_key()
    }
}

#[tokio::test]
async fn a_signature_the_signer_s_own_key_refuses_is_never_written() -> TestResult {
    let store = MemoryKeyringStore::new();
    let named = new_signer().await?;
    let trusting_named = RecordSignaturePolicy::VerifyIfSigned(verifying_key_set_of(&named));
    let admin = registry_with_policy(&store, trusting_named)
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?
        .with_record_signer(MismatchedSigner {
            signer: new_signer().await?,
            named,
        })?;
    let before = store.load(&TENANT).await?.expect("a record").revision;

    let signed = admin.sign_record().await;

    assert_eq!(error_code_of(signed), "RECORD_SIGNATURE_INVALID");
    assert_eq!(
        store.load(&TENANT).await?.expect("a record").revision,
        before
    );
    Ok(())
}

#[tokio::test]
async fn a_running_process_refuses_a_record_whose_signature_was_removed() -> TestResult {
    let store = MemoryKeyringStore::new();
    let signer = test_vector_signer().await?;
    let signed_keys = verifying_key_set_of(&signer);
    let signing_admin = signed_keyring(&store, signer).await?;
    let reader = registry_with_policy(
        &store,
        RecordSignaturePolicy::VerifyIfSigned(signed_keys.clone()),
    )
    .open(TestProvider::new("tenant-42-kek")?, TENANT)
    .await?;
    let unsigned_admin = registry_with_policy(
        &store,
        RecordSignaturePolicy::VerifyIfSigned(signed_keys.clone()),
    )
    .admin(TestProvider::new("tenant-42-kek")?, TENANT)
    .await?;

    let refused_rotation = unsigned_admin.rotate(Purpose::Randomized).await;
    unsigned_admin.dangerously_unsign_record().await?;
    let reloaded = reader.reload().await;

    assert_eq!(error_code_of(refused_rotation), "RECORD_SIGNER_MISSING");
    assert_eq!(error_code_of(reloaded), "RECORD_SIGNATURE_REMOVED");
    assert!(reader.record().signature().is_some());
    assert_eq!(
        error_code_of(signing_admin.rotate(Purpose::Randomized).await),
        "RECORD_SIGNATURE_REMOVED"
    );
    assert_eq!(
        error_code_of(signing_admin.sign_record().await),
        "RECORD_SIGNATURE_REMOVED"
    );

    let restarted = registry_with_policy(
        &store,
        RecordSignaturePolicy::VerifyIfSigned(signed_keys.clone()),
    )
    .open(TestProvider::new("tenant-42-kek")?, TENANT)
    .await?;
    let strict = registry_with_policy(&store, RecordSignaturePolicy::Required(signed_keys.clone()))
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;
    assert!(restarted.record().signature().is_none());
    assert_eq!(error_code_of(strict), "RECORD_UNSIGNED");

    // The transition: a signed revision replacing an unsigned record is taken.
    registry_with_policy(&store, RecordSignaturePolicy::VerifyIfSigned(signed_keys))
        .admin(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?
        .with_record_signer(test_vector_signer().await?)?
        .sign_record()
        .await?;
    assert!(restarted.reload().await?.signature().is_some());
    Ok(())
}

/// A process that took the deletion of a signed record keeps refusing an unsigned record under
/// the id, as it refused one over the signed record.
#[tokio::test]
async fn an_unsigned_record_under_the_id_of_a_deleted_signed_one_is_refused() -> TestResult {
    let store = MemoryKeyringStore::new();
    let signer = test_vector_signer().await?;
    let signed_keys = verifying_key_set_of(&signer);
    let signing_admin = signed_keyring(&store, signer).await?;
    let verification = RecordSignaturePolicy::VerifyIfSigned(signed_keys.clone());
    let readers = registry_with_policy(&store, verification.clone());
    let reader = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;
    let unsigned_admin = registry_with_policy(&store, verification)
        .admin(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;

    assert_eq!(
        error_code_of(unsigned_admin.dangerously_shred().await),
        "RECORD_SIGNER_MISSING"
    );
    assert!(store.load(&TENANT).await?.is_some());
    signing_admin.dangerously_shred().await?;
    assert_eq!(error_code_of(reader.reload().await), "RECORD_MISSING");
    registry_with_policy(&store, RecordSignaturePolicy::default())
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;

    let reopened = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;
    let restarted = registry_with_policy(&store, RecordSignaturePolicy::default())
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;
    let strict = registry_with_policy(&store, RecordSignaturePolicy::Required(signed_keys))
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;
    assert_eq!(error_code_of(reopened), "RECORD_SIGNATURE_REMOVED");
    assert!(restarted.record().signature().is_none());
    assert_eq!(error_code_of(strict), "RECORD_UNSIGNED");
    Ok(())
}

/// A signed revision from before a shred, restored to the store, is a regression to a process
/// that took the deletion, whose signature check passes under `Required` too.
#[tokio::test]
async fn a_restored_signed_revision_of_a_shredded_keyring_is_refused_as_a_regression() -> TestResult
{
    let store = MemoryKeyringStore::new();
    let signer = test_vector_signer().await?;
    let signed_keys = verifying_key_set_of(&signer);
    let signing_admin = signed_keyring(&store, signer).await?;
    let before = store.load(&TENANT).await?.ok_or("no record")?;
    let readers = registry_with_policy(&store, RecordSignaturePolicy::Required(signed_keys));
    let reader = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;

    signing_admin.dangerously_shred().await?;
    assert_eq!(error_code_of(reader.reload().await), "RECORD_MISSING");
    assert!(matches!(
        store.compare_and_swap(&before.record, None).await?,
        Swap::Written(_)
    ));

    let reopened = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await;
    assert_eq!(error_code_of(reopened), "RECORD_REGRESSED");
    Ok(())
}

/// A new keyring under the id of a shredded one has other versions, so a process that took the
/// deletion opens it.
#[tokio::test]
async fn a_new_signed_keyring_under_the_id_of_a_shredded_one_opens() -> TestResult {
    let store = MemoryKeyringStore::new();
    let signer = test_vector_signer().await?;
    let signed_keys = verifying_key_set_of(&signer);
    let signing_admin = signed_keyring(&store, signer).await?;
    let readers = registry_with_policy(&store, RecordSignaturePolicy::Required(signed_keys));
    let reader = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;

    signing_admin.dangerously_shred().await?;
    assert_eq!(error_code_of(reader.reload().await), "RECORD_MISSING");
    signed_keyring(&store, test_vector_signer().await?).await?;

    let reopened = readers
        .open(TestProvider::new("tenant-42-kek")?, TENANT)
        .await?;
    assert!(reopened.record().signature().is_some());
    assert!(reopened
        .record()
        .versions()
        .iter()
        .any(|version| version.state() != KeyVersionState::Destroyed));
    Ok(())
}

#[test]
fn a_required_registry_without_a_key_is_refused_when_it_is_created() {
    let created = KeyringRegistry::<_, TestBackend>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new()
            .with_record_signatures(RecordSignaturePolicy::Required(VerifyingKeySet::default())),
    );

    assert_eq!(error_code_of(created), "EMPTY_KEY_SET");
}

#[tokio::test]
async fn a_signer_the_registry_does_not_trust_is_refused_before_any_write() -> TestResult {
    let store = MemoryKeyringStore::new();
    let trusted = new_signer().await?;
    let registry = registry_with_policy(
        &store,
        RecordSignaturePolicy::VerifyIfSigned(verifying_key_set_of(&trusted)),
    );
    let admin = registry
        .create(
            TestProvider::new("tenant-42-kek")?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let other = KeyringId::from_static("tenant-43");

    let with_record_signer = admin.with_record_signer(new_signer().await?);
    let created = registry
        .create_signed(
            TestProvider::new("tenant-43-kek")?,
            new_signer().await?,
            other.clone(),
            KeyringAlgorithms::new(),
        )
        .await;
    let opened_or_created = registry
        .open_or_create_signed(
            TestProvider::new("tenant-43-kek")?,
            new_signer().await?,
            other.clone(),
            KeyringAlgorithms::new(),
        )
        .await;

    assert_eq!(error_code_of(with_record_signer), "SIGNING_KEY_UNKNOWN");
    assert_eq!(error_code_of(created), "SIGNING_KEY_UNKNOWN");
    assert_eq!(error_code_of(opened_or_created), "SIGNING_KEY_UNKNOWN");
    assert!(store.load(&other).await?.is_none());
    Ok(())
}
