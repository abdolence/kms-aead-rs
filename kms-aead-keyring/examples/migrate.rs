//! Migrates a table of store-less envelope values to keyring values: rows written before the
//! table had a seal marker read as envelope values, a sweep re-seals each under the keyring and
//! marks it, and every row then reads through the keyring. After a rotation, the same sweep moves
//! the rows to the new version. The administrative job creates and rotates the keyring, and the
//! application reads and sweeps the rows. Runs on the memory store with a local KEK, and needs no
//! cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example migrate --features ring,admin
//! ```

use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Mutex, PoisonError};

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::errors::KmsAeadError;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKmsProvider};
use kms_aead::{
    AeadAlgorithm, AeadCipher, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
    KmsAeadResult,
};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::sweep::{
    self, ResealOutcome, SealFormat, SealMarker, SealThresholds, SweepReport,
};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
    Purpose, Resealed,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

/// The keyring of this example: the memory store, a local KEK and the ring backend.
type UsersKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
/// The algorithm the store-less envelope was configured with: the envelope layout does not
/// record it.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::ChaCha20Poly1305;

/// A row of the users table. Rows written before the migration have no `seal`, and read as
/// envelope values.
#[derive(Clone, Serialize, Deserialize)]
struct UserRow {
    email: Vec<u8>,
    #[serde(default)]
    seal: SealMarker,
}

/// The rows by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

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

/// The AAD the application gave its envelope values.
fn envelope_aad(user: &str) -> Vec<u8> {
    format!("users:{user}:email").into_bytes()
}

/// A local KMS provider for the KEK `tenant-kek` with `material`, as each process loads it.
fn provider(material: &SecretValue) -> Result<LocalKmsProvider<Ring>, Box<dyn std::error::Error>> {
    let kek = LocalKek::from_secret(NonZeroU32::MIN.into(), material.clone())?;
    Ok(LocalKmsProvider::new(
        LocalKekId::try_from("tenant-kek".to_string())?,
        vec![kek],
    )?)
}

/// The email of `user`, read through the row's seal marker.
async fn read_email(
    keyring: &UsersKeyring,
    user: &str,
    row: UserRow,
) -> Result<Email, Box<dyn std::error::Error>> {
    match row.seal.format {
        SealFormat::Envelope => {
            let value = Encrypted::<Email, Envelope>::try_from(row.email)?;
            Ok(keyring
                .decrypt_envelope(&envelope_aad(user), &value, ENVELOPE_ALGORITHM)
                .await?)
        }
        SealFormat::Keyring => {
            let value = Encrypted::<Email, Randomized>::try_from(row.email)?;
            Ok(keyring
                .decrypt(&EMAIL.aad(&EntityId::try_from(user)?), &value)
                .await?)
        }
        other => Err(format!("unknown seal format {other:?}").into()),
    }
}

/// Prints every row of `table` with its email, read through its marker.
async fn print_rows(
    keyring: &UsersKeyring,
    table: &Table,
) -> Result<(), Box<dyn std::error::Error>> {
    let rows = table.lock().unwrap_or_else(PoisonError::into_inner).clone();
    for (user, row) in rows {
        let marker = row.seal;
        let Email(email) = read_email(keyring, &user, row).await?;
        match marker.randomized {
            Some(key_id) => {
                println!(
                    "  user {user}: {email}, a keyring value under key id {}",
                    key_id.as_u32()
                )
            }
            None => println!("  user {user}: {email}, an envelope value"),
        }
    }
    Ok(())
}

/// Why the re-seal of a row failed.
enum MigrateError {
    Keyring(KeyringError),
    /// A stored value that does not parse as the layout its marker names.
    Value(KmsAeadError),
    /// A row in a layout this application does not write, which stays behind for a person to
    /// look at.
    UnknownLayout(SealFormat),
}

impl From<KeyringError> for MigrateError {
    fn from(error: KeyringError) -> Self {
        MigrateError::Keyring(error)
    }
}

impl From<KmsAeadError> for MigrateError {
    fn from(error: KmsAeadError) -> Self {
        MigrateError::Value(error)
    }
}

/// The text the sweep logs, which names the failure and no value of the row.
impl Display for MigrateError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            MigrateError::Keyring(error) => write!(f, "the keyring failed with {}", error.code()),
            MigrateError::Value(error) => write!(f, "a stored value failed with {}", error.code()),
            MigrateError::UnknownLayout(format) => write!(f, "an unknown seal format {format:?}"),
        }
    }
}

/// Re-seals the row of `user` under the active version, from an envelope value or a keyring value
/// under an older version, unless a writer did since the sweep's query.
async fn reseal(
    keyring: &UsersKeyring,
    table: &Table,
    user: &str,
) -> Result<ResealOutcome, MigrateError> {
    let row = table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(user)
        .cloned();
    let Some(row) = row else {
        return Ok(ResealOutcome::Skipped);
    };
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let (email, from_compromised) = match row.seal.format {
        SealFormat::Envelope => {
            let email: Email = keyring
                .decrypt_envelope(
                    &envelope_aad(user),
                    &Encrypted::<Email, Envelope>::try_from(row.email)?,
                    ENVELOPE_ALGORITHM,
                )
                .await?;
            // Envelope values name no key version, so the record carries no trust to decide on.
            (keyring.encrypt(&aad, &email).await?, false)
        }
        SealFormat::Keyring => {
            let email = Encrypted::<Email, Randomized>::try_from(row.email)?;
            let Some(resealed): Option<Resealed<Email, Randomized>> =
                keyring.reseal(&aad, &email).await?
            else {
                return Ok(ResealOutcome::Skipped);
            };
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, from_compromised)
        }
        other => return Err(MigrateError::UnknownLayout(other)),
    };
    let row = UserRow {
        seal: SealMarker::keyring([email.key_id()])?,
        email: email.into_value(),
    };
    table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(user.to_string(), row);
    Ok(ResealOutcome::Resealed { from_compromised })
}

/// Sweeps every row behind the keyring's active versions, and prints the report.
async fn sweep_table(keyring: &UsersKeyring, table: &Table) {
    let thresholds: SealThresholds = keyring.seal_thresholds();
    let candidates: Vec<String> = table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, row)| row.seal.is_behind(&thresholds))
        .map(|(user, _)| user.clone())
        .collect();
    let report: SweepReport = sweep::run(
        keyring.id(),
        stream::iter(candidates),
        NonZeroUsize::MIN.saturating_add(1),
        |candidate| async move { reseal(keyring, table, &candidate).await },
    )
    .await;
    println!(
        "sweep: scanned {}, resealed {}, skipped {}, failed {}",
        report.scanned, report.resealed, report.skipped, report.failed
    );
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let material = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?
        .generate_dek()?
        .value()
        .clone();

    // Before the migration: a store-less envelope writes rows without a seal marker.
    let table = Table::default();
    let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
        provider(&material)?,
        KmsAeadEnvelopeOptions::new()
            .with_algorithm(ENVELOPE_ALGORITHM)
            .with_dek_reuse(DekReusePolicy::new()),
    )?;
    for (user, email) in [
        ("41", "ada@example.com"),
        ("42", "alice@example.com"),
        ("43", "bob@example.com"),
    ] {
        let value: Encrypted<Email, Envelope> = envelope
            .encrypt(&envelope_aad(user), &Email(email.to_string()))
            .await?;
        let row = serde_json::from_value(serde_json::json!({ "email": value.into_value() }))?;
        table
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(user.to_string(), row);
    }
    println!("wrote 3 rows with a store-less envelope");

    // The administrative job creates the keyring under the same KEK, and the application opens
    // it to read the rows through their markers.
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
        .create(provider(&material)?, TENANT, KeyringAlgorithms::new())
        .await?;
    let keyring: UsersKeyring = registry.open(provider(&material)?, TENANT).await?;
    print_rows(&keyring, &table).await?;

    // The migration: every envelope row is behind any thresholds.
    sweep_table(&keyring, &table).await;
    print_rows(&keyring, &table).await?;

    // A rotation later, by the administrative job: the same sweep moves the rows to the new
    // version.
    let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
    admin.promote(staged).await?;
    sweep_table(&keyring, &table).await;
    print_rows(&keyring, &table).await?;
    registry.shutdown().await?;
    Ok(())
}
