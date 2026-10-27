//! A full rotation on the memory store and the local KMS, with no cloud credentials: the
//! administrative job stages a key version, waits out the promotion guard and promotes it, a sweep
//! re-encrypts the values under the new version, and the old version is retired and destroyed. Then
//! the KEK rotates to a second version, `reencrypt_deks` moves every DEK under it, and the record
//! is checked to need that version alone. The sweep is `reencrypt` and `sweep_table`.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example rotate --features ring,admin
//! ```

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::time::Duration;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{KmsKeyVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, EncryptionMarker, ReencryptOutcome, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    DekReencryption, Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyVersion,
    Keyring, KeyringAdmin, KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, KeyringResult, Plaintext, Purpose, Rotation,
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

#[derive(Clone)]
struct UserRow {
    email: Encrypted<Email, Randomized>,
    /// Stored in the row so that the sweep finds the rows still under older versions by a range
    /// query on it.
    encryption_marker: EncryptionMarker,
}

/// Re-encrypts the row of `user` under the active version, with the marker of the encryptor's
/// record.
async fn reencrypt(
    keyring: &UsersKeyring,
    table: &Table,
    user: &str,
) -> KeyringResult<ReencryptOutcome> {
    let Some(row) = table.borrow().get(user).cloned() else {
        return Ok(ReencryptOutcome::Skipped);
    };
    let encryptor = keyring.encryptor().await;
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let reencrypted = encryptor.reencrypt(&aad, &row.email).await?;
    let outcome = ReencryptOutcome::from(&reencrypted);
    let email = reencrypted.map_or(row.email, |reencrypted| reencrypted.value);
    let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
    table.borrow_mut().insert(
        user.to_string(),
        UserRow {
            email,
            encryption_marker,
        },
    );
    Ok(outcome)
}

/// Re-encrypts every row whose encryption marker is below the keyring's.
async fn sweep_table(keyring: &UsersKeyring, table: &Table) -> SweepReport {
    let current: EncryptionMarker = keyring.record().encryption_marker();
    let candidates: Vec<String> = table
        .borrow()
        .iter()
        .filter(|(_, row)| row.encryption_marker < current)
        .map(|(user, _)| user.clone())
        .collect();
    sweep::reencrypt_records(
        keyring.id(),
        stream::iter(candidates.into_iter().map(Ok)),
        NonZeroUsize::MIN,
        |candidate| async move { reencrypt(keyring, table, &candidate).await },
    )
    .await
}

/// The application's email type, encrypted as the UTF-8 of the address.
#[derive(Clone)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

// Running the example: the rotation around the sweep, and the KEK rotation after it.

/// The users table by user id, in memory in place of the database.
type Table = RefCell<BTreeMap<String, UserRow>>;

/// A local KEK of `version` whose key material is `fill` repeated.
fn kek(version: LocalKekVersion, fill: u8) -> Result<LocalKek, Box<dyn std::error::Error>> {
    Ok(LocalKek::from_secret(
        version,
        SecretValue::new(vec![fill; 32]),
        SymmetricKeyFormat::Raw,
    )?)
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
    let provider = LocalKmsProvider::<Ring>::new(kek_id.clone(), vec![kek(kek_v1, 0x01)?])?;
    let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(provider, TENANT, KeyringAlgorithms::new())
        .await?;
    let keyring: &UsersKeyring = admin.keyring();

    let table = Table::default();
    for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
        let encryptor = keyring.encryptor().await;
        let email = encryptor
            .encrypt(
                &EMAIL.aad(&EntityId::try_from(user)?),
                &Email(email.to_string()),
            )
            .await?;
        let encryption_marker = encryptor.record().encryption_marker();
        table.borrow_mut().insert(
            user.to_string(),
            UserRow {
                email,
                encryption_marker,
            },
        );
    }
    println!(
        "wrote {} users at encryption marker {}",
        table.borrow().len(),
        keyring.record().encryption_marker()
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

    let report: SweepReport = sweep_table(keyring, &table).await;
    println!(
        "re-encrypted {} values at encryption marker {}",
        report.reencrypted,
        keyring.record().encryption_marker()
    );

    let range = keyring
        .record()
        .version(previous)
        .and_then(KeyVersion::reencrypt_range)
        .ok_or("a replaced version has a re-encryption range")?;
    if table
        .borrow()
        .values()
        .any(|row| range.contains(row.encryption_marker))
    {
        return Err("values are left under the previous version".into());
    }
    admin.retire(previous).await?;
    admin.destroy(previous).await?;
    println!("retired and destroyed key version {}", previous.as_u32());

    // The KEK rotated in the KMS, and the highest listed version, 2, encrypts. A fleet gets there
    // in its second deploy, after one that lists version 2 and still encrypts under version 1.
    let kek_rotated = LocalKmsProvider::<Ring>::new(
        kek_id.clone(),
        vec![kek(kek_v1, 0x01)?, kek(kek_v2, 0x02)?],
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
    let new_kek_version = KmsKeyVersion::from(kek_v2);
    if record.kek_versions_in_use() != [Some(&new_kek_version)] {
        return Err("a DEK is still under KEK version 1".into());
    }
    println!("every DEK is under KEK version {new_kek_version}");

    // Once version 1 is disabled, every DEK still decrypts through the KMS.
    let kek_v1_disabled = LocalKmsProvider::<Ring>::new(kek_id, vec![kek(kek_v2, 0x02)?])?;
    registry
        .admin(kek_v1_disabled, TENANT)
        .await?
        .reencrypt_deks()
        .await?;
    println!("every DEK decrypts with KEK version {new_kek_version} alone");

    for (user, row) in &table.into_inner() {
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
