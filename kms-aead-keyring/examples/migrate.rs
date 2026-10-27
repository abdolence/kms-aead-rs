//! Migrates a table of store-less envelope values to keyring values. Rows written before the table
//! had an encryption marker read as `EncryptionMarker::ENVELOPE`, the lowest marker, so one sweep
//! re-encrypts them under the keyring and marks them, and after a rotation the same sweep moves
//! every row to the new version. The sweep is `reencrypt` and `sweep_table`, and [Move envelope
//! values to a keyring](https://kms-aead-rust.abdolence.dev/use-cases/envelope-to-keyring.html)
//! in the book explains it. The rest of the file writes the envelope rows, runs the migration and
//! the rotation, and prints the rows.
//!
//! It runs on the memory store with a local KEK, and needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example migrate --features ring,admin
//! ```

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKmsProvider};
use kms_aead::{
    AeadAlgorithm, AeadCipher, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
    KmsAeadResult,
};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::sweep::{self, EncryptionMarker, ReencryptOutcome, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeyringResult, Plaintext, Purpose,
};
use secret_vault_value::SecretValue;
use serde::Deserialize;

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

/// A row of the users table as the database stores it. Rows written before the migration have no
/// `encryption_marker`, and read as envelope values.
#[derive(Clone, Deserialize)]
struct UserRow {
    email: Vec<u8>,
    /// Stored in the row so that the sweep finds the rows still under older versions by a range
    /// query on it, and so that a read knows the layout of `email`.
    #[serde(default)]
    encryption_marker: EncryptionMarker,
}

/// The email of a row, parsed once from its bytes and marker. The column holds both layouts until
/// the sweep has migrated every row, so a row is one of the two.
enum StoredEmail {
    Envelope(Encrypted<Email, Envelope>),
    Keyring {
        value: Encrypted<Email, Randomized>,
        marker: EncryptionMarker,
    },
}

impl TryFrom<UserRow> for StoredEmail {
    type Error = KeyringError;

    fn try_from(row: UserRow) -> Result<Self, Self::Error> {
        if row.encryption_marker == EncryptionMarker::ENVELOPE {
            Ok(StoredEmail::Envelope(row.email.try_into()?))
        } else {
            Ok(StoredEmail::Keyring {
                value: row.email.try_into()?,
                marker: row.encryption_marker,
            })
        }
    }
}

/// Re-encrypts the row of `user` under the active version, from an envelope value or a keyring
/// value under an older version, and writes the encryption marker of the encryptor's record
/// beside it. A keyring value that is current already gets the marker alone.
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
    let (email, outcome) = match StoredEmail::try_from(row)? {
        StoredEmail::Envelope(value) => {
            let email: Email = keyring
                .decrypt_envelope_for_migration(&envelope_aad(user), &value, ENVELOPE_ALGORITHM)
                .await?;
            // Envelope values name no key version, so the record carries no trust to decide on.
            let reencrypted = ReencryptOutcome::Reencrypted {
                from_compromised: false,
            };
            (encryptor.encrypt(&aad, &email).await?, reencrypted)
        }
        StoredEmail::Keyring { value, .. } => {
            let reencrypted = encryptor.reencrypt(&aad, &value).await?;
            let outcome = ReencryptOutcome::from(&reencrypted);
            (
                reencrypted.map_or(value, |reencrypted| reencrypted.value),
                outcome,
            )
        }
    };
    let row = UserRow {
        email: email.into_value(),
        encryption_marker: encryptor.record().encryption_marker(),
    };
    table.borrow_mut().insert(user.to_string(), row);
    Ok(outcome)
}

/// Sweeps every row whose encryption marker is below the keyring's, and prints the report.
async fn sweep_table(keyring: &UsersKeyring, table: &Table) {
    let current: EncryptionMarker = keyring.record().encryption_marker();
    let candidates: Vec<String> = table
        .borrow()
        .iter()
        .filter(|(_, row)| row.encryption_marker < current)
        .map(|(user, _)| user.clone())
        .collect();
    let report: SweepReport = sweep::reencrypt_records(
        keyring.id(),
        stream::iter(candidates.into_iter().map(Ok)),
        NonZeroUsize::MIN,
        |candidate| async move { reencrypt(keyring, table, &candidate).await },
    )
    .await;
    println!("sweep: {report:?}");
}

/// The application's email type, encrypted as the UTF-8 of the address.
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

// Running the example: the rows, the keyring and a rotation, and a print of the rows after each
// step.

/// The rows by user id, in memory in place of the database.
type Table = RefCell<BTreeMap<String, UserRow>>;

/// The AAD the application gave its envelope values.
fn envelope_aad(user: &str) -> Vec<u8> {
    format!("users:{user}:email").into_bytes()
}

/// A local KMS provider for the KEK `tenant-kek` with `material`, as each process loads it.
fn provider(material: &SecretValue) -> Result<LocalKmsProvider<Ring>, Box<dyn std::error::Error>> {
    let kek = LocalKek::from_secret(
        NonZeroU32::MIN.into(),
        material.clone(),
        SymmetricKeyFormat::Raw,
    )?;
    Ok(LocalKmsProvider::new(
        LocalKekId::try_from("tenant-kek".to_string())?,
        vec![kek],
    )?)
}

/// Prints every row of `table` with its email, read through its stored layout.
async fn print_rows(
    keyring: &UsersKeyring,
    table: &Table,
) -> Result<(), Box<dyn std::error::Error>> {
    let rows = table.borrow().clone();
    for (user, row) in rows {
        match StoredEmail::try_from(row)? {
            StoredEmail::Envelope(value) => {
                let Email(email) = keyring
                    .decrypt_envelope_for_migration(
                        &envelope_aad(&user),
                        &value,
                        ENVELOPE_ALGORITHM,
                    )
                    .await?;
                println!("  user {user}: {email}, an envelope value");
            }
            StoredEmail::Keyring { value, marker } => {
                let aad = EMAIL.aad(&EntityId::try_from(user.as_str())?);
                let Email(email) = keyring.decrypt(&aad, &value).await?;
                println!(
                    "  user {user}: {email}, a keyring value encrypted at re-encryption epoch {marker}"
                );
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let material = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?
        .generate_dek()?
        .value()
        .clone();

    // Before the migration: a store-less envelope writes rows without an encryption marker.
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
        table.borrow_mut().insert(user.to_string(), row);
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

    // The migration: an envelope row's marker, epoch 0, is below every keyring's.
    sweep_table(&keyring, &table).await;
    print_rows(&keyring, &table).await?;

    // A rotation later, by the administrative job: the same sweep moves the rows to the new
    // version. One process, so it promotes without waiting out the record TTL.
    let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
    admin.promote_now(staged).await?;
    sweep_table(&keyring, &table).await;
    print_rows(&keyring, &table).await?;
    registry.shutdown(None).await;
    Ok(())
}
