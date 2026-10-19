//! A sweep on BigQuery: writes users through a `Sealer`, each with its seal marker, rotates and
//! promotes the randomised version, re-seals every row whose marker is below the current one with
//! one `UPDATE` in SQL through an exported keyset, and prints the rows it re-sealed. The statement
//! is the one of
//! [Sweeps by store](https://kms-aead-rust.abdolence.dev/operations.html#bigquery) in the book: a
//! field BigQuery reads is re-sealed without a Rust loop and without a value leaving BigQuery, so
//! the sweep is that statement rather than `sweep::run`.
//!
//! A sweep is a job that runs on a schedule, and again until it re-seals no row. Retiring the
//! previous version is a separate administrative step, see
//! [Rotation cadence](https://kms-aead-rust.abdolence.dev/operations.html#rotation-cadence).
//!
//! The example runs against the Cloud KMS key that `PROJECT_ID`, `PROJECT_LOCATION`,
//! `KMS_KEY_RING` and `KMS_KEY` name, under the application default credentials, which need the
//! key's encrypt and decrypt rights and BigQuery's `bigquery.datasets.create` and
//! `bigquery.jobs.create` in the project. BigQuery opens the keyset through the same key. The
//! example creates a dataset of its own in `PROJECT_LOCATION`, and drops it at the end. The
//! keyring record stays in memory.
//!
//! ```sh
//! PROJECT_ID=my-project PROJECT_LOCATION=europe-north1 KMS_KEY_RING=my-key-ring KMS_KEY=my-key \
//!   cargo run -p kms-aead-keyring --example sweep_bigquery --features ring,serde,ci-bigquery -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::error::Error;
use std::time::Instant;

use bigquery::{
    BigQueryDatasetId, BigQueryDb, BigQueryFieldType, BigQueryLocation, BigQueryQueryOutcome,
    BigQueryTableId,
};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::encodings::BigQuery;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::SealMarker;
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
const USERS: BigQueryTableId = BigQueryTableId::from_static("users");
/// The rows of one `INSERT`, each statement sealed by one sealer.
const INSERT_ROWS: usize = 1000;
const DEFAULT_USERS: u32 = 100;

/// The application's email type, sealed as the UTF-8 of the address, which BigQuery reads as a
/// `STRING`.
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

/// A row of the users table, sent as one `STRUCT` of an `ARRAY` parameter.
#[derive(Serialize)]
struct User {
    id: String,
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// The one cell of a `SELECT … AS count`.
#[derive(Deserialize)]
struct Count {
    count: u64,
}

/// Writes `count` users, rotates, and sweeps.
async fn run(
    db: &BigQueryDb,
    dataset: &BigQueryDatasetId,
    key_ref: &GcpKmsKeyRef,
    count: u32,
) -> Result<(), Box<dyn Error>> {
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let admin: KeyringAdmin<MemoryKeyringStore, GcpKmsProvider, Ring> = registry
        .create(
            GcpKmsProvider::new(key_ref).await?,
            TENANT,
            KeyringAlgorithms::new(),
        )
        .await?;
    let keyring: &UsersKeyring = admin.keyring();

    let started = Instant::now();
    let ids: Vec<u32> = (1..=count).collect();
    for page in ids.chunks(INSERT_ROWS) {
        // One sealer per statement, so that every row of it stores the marker of the record its
        // values were sealed under.
        let sealer = keyring.sealer().await;
        let seal: SealMarker = sealer.record().seal_marker();
        let mut rows: Vec<User> = Vec::with_capacity(page.len());
        for id in page {
            let id = id.to_string();
            let email: Encrypted<Email, Randomized> = sealer
                .encrypt(
                    &EMAIL.aad(&EntityId::try_from(id.as_str())?),
                    &Email(format!("user-{id}@example.com")),
                )
                .await?;
            rows.push(User { id, email, seal });
        }
        db.fluent()
            .query("INSERT INTO users (id, email, seal) SELECT id, email, seal FROM UNNEST(@rows)")
            .default_dataset(dataset.clone())
            .param("rows", rows)
            .execute()
            .await?;
    }
    println!(
        "wrote {count} users at seal marker {} in {:.2?}",
        keyring.record().seal_marker(),
        started.elapsed()
    );

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;

    // Exported after the promotion: the keyset's primary is the active version, and its marker
    // is the one the statement stores beside the values it seals.
    let started = Instant::now();
    let keyset: EncryptedKeyset<BigQuery> = admin
        .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    let keyset_bytes = BigQueryFieldType::Bytes { max_length: None };
    let swept: BigQueryQueryOutcome = db
        .fluent()
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
                 seal = @seal
             WHERE seal < @seal AND seal > @envelope",
        )
        .default_dataset(dataset.clone())
        .param("kms_key", keyset.key_uri())
        .param_as("keyset", keyset_bytes.clone(), keyset.value())
        .param("seal", keyset.seal_marker())
        .param("envelope", SealMarker::ENVELOPE)
        .execute()
        .await?;
    println!(
        "swept to seal marker {} in {:.2?}: resealed {}",
        keyset.seal_marker(),
        started.elapsed(),
        swept
            .num_dml_affected_rows
            .map_or_else(|| "unknown".to_string(), |rows| rows.to_string())
    );

    let readable: u64 = db
        .fluent()
        .query(
            "SELECT COUNTIF(
               AEAD.DECRYPT_STRING(KEYS.KEYSET_CHAIN(@kms_key, @keyset), email, CONCAT('user/', id, '/email'))
                 = CONCAT('user-', id, '@example.com')
             ) AS count FROM users",
        )
        .default_dataset(dataset.clone())
        .param("kms_key", keyset.key_uri())
        .param_as("keyset", keyset_bytes, keyset.value())
        .obj::<Count>()
        .query()
        .await?
        .pop()
        .ok_or("the count returned no row")?
        .count;
    if readable != u64::from(count) {
        return Err(format!("{readable} of {count} users read back in BigQuery").into());
    }
    println!("BigQuery reads all {readable} users");
    registry.shutdown().await?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let count: u32 = match std::env::args().nth(1) {
        Some(count) => count.parse()?,
        None => DEFAULT_USERS,
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
    let outcome = async {
        db.fluent()
            .schema()
            .table(dataset.table(USERS))
            .columns(|columns| {
                columns.fields([
                    columns.field("id").string().required(),
                    columns.field("email").bytes().required(),
                    columns.field("seal").bytes().required(),
                ])
            })
            .sync()
            .await?;
        run(&db, &dataset, &key_ref, count).await
    }
    .await;
    db.fluent()
        .schema()
        .dataset(dataset.clone())
        .dangerously_delete_with_contents()
        .await?;
    println!("dropped the example's dataset {dataset}");
    outcome
}
