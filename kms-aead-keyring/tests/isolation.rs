//! The randomised API is the same with and without the `deterministic` feature: its types,
//! defaults and AAD rules. The gate runs this file in both builds, so a difference between them
//! fails one of the two runs.

#![cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]

use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadAlgorithm;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldAad, FieldName, FieldSpec, KeyAlgorithm, KeyId,
    KeyVersion, Keyring, KeyringId, KeyringOptions, KeyringPolicy, Purpose,
};

#[cfg(feature = "ring")]
type Backend = kms_aead::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
type Backend = kms_aead::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
type Backend = kms_aead::RustCrypto;

type LocalKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Backend>, Backend>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

const ALICE: &str = "alice@example.com";

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A keyring under the default policy and options, on a local KEK.
async fn default_keyring() -> Result<LocalKeyring, Box<dyn std::error::Error>> {
    let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
    Ok(LocalKeyring::create(
        MemoryKeyringStore::new(),
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringPolicy::new(),
        KeyringOptions::new().with_watch(false),
    )
    .await?)
}

#[tokio::test]
async fn a_default_keyring_has_randomized_versions_only() -> TestResult {
    let keyring = default_keyring().await?;
    let record = keyring.record();
    assert_eq!(record.algorithms().randomized(), AeadAlgorithm::Aes256Gcm);
    assert_eq!(record.algorithms().deterministic(), None);
    assert_eq!(
        record.active(Purpose::Deterministic).map(KeyVersion::id),
        None
    );
    assert_eq!(
        record
            .versions()
            .iter()
            .map(KeyVersion::id)
            .collect::<Vec<_>>(),
        [KeyId::new(1)]
    );
    Ok(())
}

/// A randomised value's bytes are Tink's AES-GCM layout.
#[tokio::test]
async fn a_randomized_value_is_the_tink_aes_gcm_layout() -> TestResult {
    let keyring = default_keyring().await?;
    let aad = EMAIL.aad(&EntityId::try_from("42")?);
    let value: Encrypted<String, Randomized> = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    assert_eq!(value.value()[..5], [0x01, 0, 0, 0, 1]);
    assert_eq!(value.value().len(), 5 + 12 + ALICE.len() + 16);
    assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    Ok(())
}

/// A field without an interop requirement takes any algorithm, any AAD and any KEK.
#[tokio::test]
async fn a_default_field_seals_under_any_algorithm_aad_and_kek() -> TestResult {
    let keyring = default_keyring().await?;
    let staged = keyring
        .change_algorithm(KeyAlgorithm::Randomized(AeadAlgorithm::ChaCha20Poly1305))
        .await?;
    keyring.promote(staged).await?;
    for aad in [
        EMAIL.aad(&EntityId::try_from("42")?),
        FieldAad::custom(&[0xFF; 3]),
    ] {
        let value = keyring.encrypt(&aad, &ALICE.to_string()).await?;
        assert_eq!(keyring.decrypt(&aad, &value).await?, ALICE);
    }
    Ok(())
}
