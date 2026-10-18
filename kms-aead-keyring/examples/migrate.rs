//! Migrates a table of store-less envelope values to keyring values: rows written before the
//! table had a seal marker read as envelope values, a sweep re-seals each under the keyring and
//! marks it, and every row then reads through the keyring. Runs on the memory store with a local
//! KEK, and needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example migrate --features ring
//! ```

use std::collections::BTreeMap;
use std::num::{NonZeroU32, NonZeroUsize};
use std::sync::{Mutex, PoisonError};

use futures_util::stream;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKmsProvider};
use kms_aead::{
    AeadAlgorithm, AeadCipher, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
    KmsAeadResult, Ring,
};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::sweep::{self, Outcome};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, KeyringResult, Plaintext, SealFormat, SealMarker,
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

/// Re-seals the row of `user` as a keyring value, unless a writer did since the sweep's query.
async fn reseal(keyring: &UsersKeyring, table: &Table, user: &str) -> KeyringResult<Outcome> {
    let row = table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(user)
        .cloned();
    let Some(row) = row.filter(|row| row.seal.format == SealFormat::Envelope) else {
        return Ok(Outcome::Skipped);
    };
    let email: Email = keyring
        .decrypt_envelope(
            &envelope_aad(user),
            &Encrypted::<Email, Envelope>::try_from(row.email)?,
            ENVELOPE_ALGORITHM,
        )
        .await?;
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let resealed = keyring.encrypt(&aad, &email).await?;
    let row = UserRow {
        seal: SealMarker::keyring([resealed.key_id()])?,
        email: resealed.into_value(),
    };
    table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(user.to_string(), row);
    // Envelope values name no key version, so the record carries no trust to decide on.
    Ok(Outcome::Resealed([].iter().collect()))
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

    // The keyring under the same KEK, which reads the rows through their markers.
    let keyring = UsersKeyring::open_or_create(
        MemoryKeyringStore::new(),
        provider(&material)?,
        TENANT,
        KeyringPolicy::new(),
        KeyringOptions::new(),
    )
    .await?;
    print_rows(&keyring, &table).await?;

    // The sweep over `seal.format = 'envelope'`.
    let candidates = table
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .filter(|(_, row)| row.seal.format == SealFormat::Envelope)
        .map(|(user, _)| user.clone())
        .collect::<Vec<_>>();
    let report = sweep::run(
        &TENANT,
        stream::iter(candidates),
        NonZeroUsize::MIN.saturating_add(1),
        |candidate| {
            let (keyring, table) = (&keyring, &table);
            async move { reseal(keyring, table, &candidate).await }
        },
    )
    .await;
    println!(
        "sweep: scanned {}, resealed {}, skipped {}, failed {}",
        report.scanned, report.resealed, report.skipped, report.failed
    );

    print_rows(&keyring, &table).await?;
    Ok(())
}
