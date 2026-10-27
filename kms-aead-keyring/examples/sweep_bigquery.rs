//! A keyring sweep on BigQuery: one SQL `UPDATE` through a keyset exported from the keyring
//! re-encrypts every row whose encryption marker is below the current one. BigQuery re-encrypts the
//! field itself, with no Rust loop and no value leaving it, so the sweep is `sweep_users` and not
//! `sweep::reencrypt_records`. [Sweeps on
//! BigQuery](https://kms-aead-rust.abdolence.dev/operations/sweeps-bigquery.html) in the book
//! explains it. The rest of the file runs it: it seeds users, rotates, sweeps, checks that
//! BigQuery reads every user, and drops the dataset.
//!
//! The example runs against the Cloud KMS key that `PROJECT_ID`, `PROJECT_LOCATION`,
//! `KMS_KEY_RING` and `KMS_KEY` name, under the application default credentials, which need the
//! key's encrypt and decrypt rights and `bigquery.datasets.create` and `bigquery.jobs.create` in
//! the project. It creates a dataset of its own, and its keyring record stays in memory.
//!
//! ```sh
//! PROJECT_ID=my-project PROJECT_LOCATION=europe-north1 KMS_KEY_RING=my-key-ring KMS_KEY=my-key \
//!   cargo run -p kms-aead-keyring --example sweep_bigquery --features ring,ci-bigquery -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::error::Error;
use std::time::Instant;

use bigquery::{
    BigQueryDatasetId, BigQueryDb, BigQueryFieldType, BigQueryLocation, BigQueryQueryOutcome,
    BigQueryResult, BigQueryTableId, BigQueryWriteSummary,
};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::encodings::BigQuery;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::EncryptionMarker;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EncryptedKeyset, EntityId, EntityKind, FieldName, FieldSpec, Interop, Keyring,
    KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeysetSelection, Plaintext, Purpose,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

type UsersKeyring = Keyring<MemoryKeyringStore, GcpKmsProvider, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
/// The email field, with the AAD layout BigQuery's `AEAD` functions take.
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);
/// The users table, which the statements name as `users` in the example's default dataset: a
/// table name cannot be a query parameter.
const USERS_TABLE: BigQueryTableId = BigQueryTableId::from_static("users");
/// The type of the `@keyset` parameter, the serialised keyset.
const KEYSET_PARAMETER_TYPE: BigQueryFieldType = BigQueryFieldType::Bytes { max_length: None };
/// The rows one encryptor encrypts, which share its marker.
const ROWS_PER_ENCRYPTOR: usize = 1000;
const DEFAULT_USER_COUNT: u32 = 100;

/// Re-encrypts, in one `UPDATE` through `keyset`, every user whose marker is below the keyset's.
/// The statement is atomic and its `WHERE` is the checkpoint: a failed run changed nothing, and the
/// next one finds every row this one did not write.
async fn sweep_users(
    db: &BigQueryDb,
    dataset: &BigQueryDatasetId,
    keyset: &EncryptedKeyset<BigQuery>,
) -> BigQueryResult<BigQueryQueryOutcome> {
    db.fluent()
        .query(
            "UPDATE users
             SET email = AEAD.ENCRYPT(
                   KEYS.KEYSET_CHAIN(@kms_key, @keyset),
                   AEAD.DECRYPT_BYTES(
                     KEYS.KEYSET_CHAIN(@kms_key, @keyset),
                     email,
                     CAST(CONCAT('user/', id, '/email') AS BYTES)
                   ),
                   CAST(CONCAT('user/', id, '/email') AS BYTES)
                 ),
                 encryption_marker = @encryption_marker
             WHERE encryption_marker < @encryption_marker",
        )
        .default_dataset(dataset.clone())
        .param("kms_key", keyset.key_uri())
        .param_as("keyset", KEYSET_PARAMETER_TYPE, keyset.value())
        .param("encryption_marker", keyset.encryption_marker())
        .execute()
        .await
}

/// The application's email type, encrypted as the UTF-8 of the address, which BigQuery reads as a
/// `STRING`.
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

// Running the example: creates the dataset, seeds the users, rotates, sweeps, checks, and drops the
// dataset.

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: u32 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USER_COUNT,
    };
    let project = std::env::var("PROJECT_ID")?;
    let location = std::env::var("PROJECT_LOCATION")?;
    let db = BigQueryDb::new(&project).await?;
    let key_ref = GcpKmsKeyRef::new(
        project,
        location.clone(),
        std::env::var("KMS_KEY_RING")?,
        std::env::var("KMS_KEY")?,
    );
    let dataset =
        BigQueryDatasetId::new(format!("sweep_example_{}", uuid::Uuid::now_v7().simple()))?;
    db.fluent()
        .schema()
        .dataset(dataset.clone())
        .create()
        .location(BigQueryLocation::new(location)?)
        .execute()
        .await?;

    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;

    let outcome = run(&registry, &db, &dataset, &key_ref, count).await;
    registry.shutdown(None).await;
    let cleanup = delete_test_data(&db, &dataset).await;
    outcome?;
    cleanup?;
    Ok(())
}

/// Seeds `count` users, rotates, sweeps, prints the number of rows the sweep re-encrypted, and
/// checks that BigQuery reads every user.
async fn run(
    registry: &KeyringRegistry<MemoryKeyringStore, Ring>,
    db: &BigQueryDb,
    dataset: &BigQueryDatasetId,
    key_ref: &GcpKmsKeyRef,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let admin: KeyringAdmin<MemoryKeyringStore, GcpKmsProvider, Ring> = registry
        .create(
            GcpKmsProvider::new(key_ref).await?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring: &UsersKeyring = admin.keyring();
    seed_test_data(db, dataset, keyring, count).await?;

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    // Exported after the promotion: the keyset's primary is the active version, and its marker
    // is the one the statement stores beside the values it encrypts.
    let started = Instant::now();
    let keyset: EncryptedKeyset<BigQuery> = admin
        .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    let swept: BigQueryQueryOutcome = sweep_users(db, dataset, &keyset).await?;
    println!(
        "swept to encryption marker {} in {:.2?}: reencrypted {:?} rows",
        keyset.encryption_marker(),
        started.elapsed(),
        swept.num_dml_affected_rows
    );

    let readable: u64 = count_readable_users(db, dataset, &keyset).await?;
    if readable != u64::from(count) {
        return Err(format!("{readable} of {count} users read back in BigQuery").into());
    }
    println!("BigQuery reads all {readable} users");
    Ok(())
}

// The example's own data: a users table written before the sweep, read back after it, and dropped
// with the dataset.

/// A row of the users table.
#[derive(Serialize)]
struct User {
    id: String,
    email: Encrypted<Email, Randomized>,
    encryption_marker: EncryptionMarker,
}

/// Creates the users table and writes users `1..=count` to it through the Storage Write API,
/// [`ROWS_PER_ENCRYPTOR`] at a time through one encryptor.
async fn seed_test_data(
    db: &BigQueryDb,
    dataset: &BigQueryDatasetId,
    keyring: &UsersKeyring,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    db.fluent()
        .schema()
        .table(dataset.table(USERS_TABLE))
        .columns(|columns| {
            columns.fields([
                columns.field("id").string().required(),
                columns.field("email").bytes().required(),
                columns.field("encryption_marker").bytes().required(),
            ])
        })
        .sync()
        .await?;

    let started = Instant::now();
    // The table's default stream, whose rows an `UPDATE` can modify as soon as they are
    // acknowledged.
    let (mut writer, _) = db
        .create_streaming_writer::<User>(dataset.table(USERS_TABLE))
        .await?;
    let ids: Vec<u32> = (1..=count).collect();
    for ids in ids.chunks(ROWS_PER_ENCRYPTOR) {
        let encryptor = keyring.encryptor().await;
        let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
        for id in ids {
            let id = id.to_string();
            let email: Encrypted<Email, Randomized> = encryptor
                .encrypt(
                    &EMAIL.aad(&EntityId::try_from(id.as_str())?),
                    &Email(format!("user-{id}@example.com")),
                )
                .await?;
            writer
                .write(&User {
                    id,
                    email,
                    encryption_marker,
                })
                .await?;
        }
    }
    let written: BigQueryWriteSummary = writer.finish().await?;
    if written.rows_failed > 0 {
        return Err(format!("{} of {count} users failed to write", written.rows_failed).into());
    }
    println!(
        "wrote {count} users at encryption marker {} in {:.2?}",
        keyring.record().encryption_marker(),
        started.elapsed()
    );
    Ok(())
}

/// The one cell of a `SELECT … AS count`.
#[derive(Deserialize)]
struct Count {
    count: u64,
}

/// The users whose email BigQuery decrypts through `keyset` to the address the seeding wrote.
async fn count_readable_users(
    db: &BigQueryDb,
    dataset: &BigQueryDatasetId,
    keyset: &EncryptedKeyset<BigQuery>,
) -> Result<u64, Box<dyn Error>> {
    let readable: Count = db
        .fluent()
        .query(
            "SELECT COUNTIF(
               AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(@kms_key, @keyset), email, CONCAT('user/', id, '/email'))
                 = CONCAT('user-', id, '@example.com')
             ) AS count FROM users",
        )
        .default_dataset(dataset.clone())
        .param("kms_key", keyset.key_uri())
        .param_as("keyset", KEYSET_PARAMETER_TYPE, keyset.value())
        .obj::<Count>()
        .query()
        .await?
        .pop()
        .ok_or("the count returned no row")?;
    Ok(readable.count)
}

/// Drops the example's dataset with the users table in it.
async fn delete_test_data(db: &BigQueryDb, dataset: &BigQueryDatasetId) -> BigQueryResult<()> {
    db.fluent()
        .schema()
        .dataset(dataset.clone())
        .dangerously_delete_with_contents()
        .await?;
    println!("dropped the example's dataset {dataset}");
    Ok(())
}
