//! A full rotation on the memory store and the local KMS, with no cloud credentials: the
//! administrative job stages a key version, waits out the promotion guard and promotes it, a sweep
//! re-seals the values under the new version, and the old version is retired and destroyed. Then
//! the KEK rotates to a second version, `reencrypt_deks` moves every DEK under it, and the record
//! is checked to need that version alone.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example rotate --features ring,admin
//! ```

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::providers::{KekVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    DekReencryption, Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust,
    KeyVersion, Keyring, KeyringAdmin, KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, KeyringResult, Plaintext, Purpose, Resealed, Rotation,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

/// The record TTL of the registry, short so that the promotion guard passes in a second. A fleet
/// keeps the default of 5 minutes or longer.
const RECORD_TTL: Duration = Duration::from_secs(1);

/// The application's email type, sealed as the UTF-8 of the address.
#[derive(Debug, Clone)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

#[derive(Clone)]
struct UserRow {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// The users table, by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

/// Re-seals the row of `user` under the active version, with the marker of the sealer's record.
async fn reseal(keyring: &UsersKeyring, table: &Table, user: &str) -> KeyringResult<ResealOutcome> {
    let row = table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(user)
        .cloned();
    let Some(row) = row else {
        return Ok(ResealOutcome::Skipped);
    };
    let sealer = keyring.sealer().await;
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &row.email).await?;
    let (email, outcome) = match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        None => (row.email, ResealOutcome::Skipped),
    };
    let seal: SealMarker = sealer.record().seal_marker();
    table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(user.to_string(), UserRow { email, seal });
    Ok(outcome)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kek_id = LocalKekId::try_from("users-kek".to_string())?;
    let kek_v1 = LocalKekVersion::from(NonZeroU32::MIN);
    let kek_v2 = LocalKekVersion::from(NonZeroU32::new(2).ok_or("2 is not zero")?);

    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_record_ttl(RECORD_TTL),
    )?;
    let provider = LocalKmsProvider::<Ring>::new(
        kek_id.clone(),
        vec![LocalKek::from_secret(
            kek_v1,
            SecretValue::new(vec![0x01; 32]),
        )?],
    )?;
    let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(provider, TENANT, KeyringAlgorithms::new())
        .await?;
    let keyring: &UsersKeyring = admin.keyring();

    let mut rows = BTreeMap::new();
    for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
        let sealer = keyring.sealer().await;
        let email = sealer
            .encrypt(
                &EMAIL.aad(&EntityId::try_from(user)?),
                &Email(email.to_string()),
            )
            .await?;
        let seal = sealer.record().seal_marker();
        rows.insert(user.to_string(), UserRow { email, seal });
    }
    println!(
        "wrote {} users at seal marker {}",
        rows.len(),
        keyring.record().seal_marker()
    );

    let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
    println!("staged key version {}", staged.as_u32());
    let rotation: Rotation = match admin.promote(staged).await {
        Err(KeyringError::PromotionTooEarly(error)) => {
            println!(
                "promotion refused for another {} ms, until every process whose record \
                 revalidates has seen the version",
                error.remaining.as_millis()
            );
            tokio::time::sleep(error.remaining).await;
            admin.promote(staged).await?
        }
        promoted => promoted?,
    };
    let previous: KeyId = rotation
        .previous
        .ok_or("the keyring had an active version")?;
    println!(
        "promoted key version {} over {}",
        rotation.current.as_u32(),
        previous.as_u32()
    );

    let current: SealMarker = keyring.record().seal_marker();
    let candidates: Vec<String> = rows
        .iter()
        .filter(|(_, row)| row.seal < current)
        .map(|(user, _)| user.clone())
        .collect();
    let table = Table::new(rows);
    let report: SweepReport = sweep::run(
        keyring.id(),
        stream::iter(candidates.into_iter().map(Ok)),
        NonZeroUsize::MIN,
        |candidate| {
            let table = &table;
            async move { reseal(keyring, table, &candidate).await }
        },
    )
    .await;
    println!(
        "re-sealed {} values at seal marker {}",
        report.resealed,
        keyring.record().seal_marker()
    );
    let table = table.into_inner().unwrap_or_else(PoisonError::into_inner);

    let range = keyring
        .record()
        .version(previous)
        .and_then(KeyVersion::seal_range)
        .ok_or("a replaced version has a seal range")?;
    if table.values().any(|row| range.contains(row.seal)) {
        return Err("values are left under the previous version".into());
    }
    admin.retire(previous).await?;
    admin.destroy(previous).await?;
    println!("retired and destroyed key version {}", previous.as_u32());

    // The KEK rotated in the KMS, and the highest listed version, 2, encrypts. A fleet gets there
    // in its second deploy, after one that lists version 2 and still encrypts under version 1.
    let kek_rotated = LocalKmsProvider::<Ring>::new(
        kek_id.clone(),
        vec![
            LocalKek::from_secret(kek_v1, SecretValue::new(vec![0x01; 32]))?,
            LocalKek::from_secret(kek_v2, SecretValue::new(vec![0x02; 32]))?,
        ],
    )?;
    let admin = registry.admin(kek_rotated, TENANT).await?;
    let moved: Vec<DekReencryption> = admin.reencrypt_deks().await?;
    for reencryption in &moved {
        if let (Some(from), Some(to)) = (
            &reencryption.previous_kek_version,
            &reencryption.kek_version,
        ) {
            println!(
                "DEK of key version {} moved from KEK version {from} to {to}",
                reencryption.key_id.as_u32()
            );
        }
    }

    // The check before KEK version 1 is disabled reads the stored record and needs no KMS call.
    let record = admin.keyring().reload().await?;
    let new_kek_version = KekVersion::from(kek_v2);
    if record.kek_versions_in_use() != [Some(&new_kek_version)] {
        return Err("a DEK is still under KEK version 1".into());
    }
    println!("every DEK is under KEK version {new_kek_version}");

    // Once version 1 is disabled, every DEK still decrypts through the KMS.
    let kek_v1_disabled = LocalKmsProvider::<Ring>::new(
        kek_id,
        vec![LocalKek::from_secret(
            kek_v2,
            SecretValue::new(vec![0x02; 32]),
        )?],
    )?;
    registry
        .admin(kek_v1_disabled, TENANT)
        .await?
        .reencrypt_deks()
        .await?;
    println!("every DEK decrypts with KEK version {new_kek_version} alone");

    for (user, row) in &table {
        let aad = EMAIL.aad(&EntityId::try_from(user.as_str())?);
        let Email(email) = admin.keyring().decrypt(&aad, &row.email).await?;
        println!(
            "user {user} under key version {}: {email}",
            row.email.key_id().as_u32()
        );
    }
    registry.shutdown(None).await;
    Ok(())
}
