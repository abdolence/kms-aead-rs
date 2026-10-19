//! A sweep on BigQuery: writes users through a `Sealer`, each with its seal marker, rotates and
//! promotes the randomised version, re-seals every row whose marker is below the current one with
//! one `UPDATE` in SQL through an exported keyset, and retires the previous version once the query
//! of its seal range finds no row. The statement is the one of
//! [Sweeps by store](https://kms-aead-rust.abdolence.dev/operations.html#bigquery) in the book: a
//! field BigQuery reads is re-sealed without a Rust loop and without a value leaving BigQuery, so
//! the sweep is that statement rather than `sweep::run`.
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
//!   cargo run -p kms-aead-keyring --example sweep_bigquery --features ring,ci-bigquery -- 1000
//! ```
//!
//! The argument is the number of users, 100 by default.

use std::error::Error;
use std::time::Instant;

use gcloud_sdk::google::cloud::bigquery::v2::job_service_client::JobServiceClient;
use gcloud_sdk::google::cloud::bigquery::v2::{PostQueryRequest, QueryRequest, QueryResponse};
use gcloud_sdk::prost_types::value::Kind;
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::encodings::BigQuery;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{SealMarker, SealRange};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EncryptedKeyset, EntityId, EntityKind, FieldName, FieldSpec, Interop, KeyId,
    KeyVersion, Keyring, KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry,
    KeyringRegistryOptions, KeysetSelection, Plaintext, Purpose, Rotation,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<MemoryKeyringStore, GcpKmsProvider, Ring>;
type BigQueryClient = GoogleApi<JobServiceClient<GoogleAuthMiddleware>>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
/// The email field, with the AAD layout BigQuery's `AEAD` functions take.
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);
/// The rows of one `INSERT`, which keeps each statement under BigQuery's query length limit.
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

/// Where the example's queries run: a project and its location.
struct BigQueryJobs {
    client: BigQueryClient,
    project: String,
    location: String,
}

impl BigQueryJobs {
    /// Runs `sql` to completion.
    async fn query(&self, sql: String) -> Result<QueryResponse, Box<dyn Error>> {
        let response = self
            .client
            .get()
            .query(PostQueryRequest {
                project_id: self.project.clone(),
                query_request: Some(QueryRequest {
                    query: sql,
                    use_legacy_sql: Some(false),
                    location: self.location.clone(),
                    timeout_ms: Some(120_000),
                    ..Default::default()
                }),
            })
            .await?
            .into_inner();
        if !response.errors.is_empty() || response.job_complete != Some(true) {
            return Err(format!("the query failed: {:?}", response.errors).into());
        }
        Ok(response)
    }

    /// The `INT64` of the one cell `sql` returns, such as a `COUNT(*)`.
    async fn count(&self, sql: String) -> Result<u64, Box<dyn Error>> {
        let response = self.query(sql).await?;
        let cell = response
            .rows
            .first()
            .and_then(|row| row.fields.get("f"))
            .and_then(|cells| match &cells.kind {
                Some(Kind::ListValue(cells)) => cells.values.first(),
                _ => None,
            })
            .and_then(|cell| match &cell.kind {
                Some(Kind::StructValue(cell)) => cell.fields.get("v"),
                _ => None,
            });
        match cell.and_then(|value| value.kind.as_ref()) {
            // BigQuery's JSON rows hold an `INT64` as its decimal text.
            Some(Kind::StringValue(count)) => Ok(count.parse()?),
            _ => Err("the query returned no count".into()),
        }
    }
}

/// `bytes` as a GoogleSQL expression.
fn from_hex(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("FROM_HEX('{hex}')")
}

/// Writes `count` users, rotates, sweeps, and retires the previous version.
async fn run(
    jobs: &BigQueryJobs,
    users: &str,
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
        let mut rows = Vec::with_capacity(page.len());
        for id in page {
            let email: Encrypted<Email, Randomized> = sealer
                .encrypt(
                    &EMAIL.aad(&EntityId::try_from(id.to_string())?),
                    &Email(format!("user-{id}@example.com")),
                )
                .await?;
            rows.push(format!(
                "('{id}', {}, {})",
                from_hex(email.value()),
                from_hex(seal.value())
            ));
        }
        jobs.query(format!(
            "INSERT INTO {users} (id, email, seal) VALUES {}",
            rows.join(", ")
        ))
        .await?;
    }
    println!(
        "wrote {count} users at seal marker {} in {:.2?}",
        keyring.record().seal_marker(),
        started.elapsed()
    );

    // One process rotates and sweeps, so the promotion need not wait for other processes'
    // records to revalidate.
    let rotation: Rotation = admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let previous: KeyId = rotation
        .previous
        .ok_or("the keyring had an active version")?;

    // Exported after the promotion: the keyset's primary is the active version, and its marker
    // is the one the statement stores beside the values it seals.
    let started = Instant::now();
    let keyset: EncryptedKeyset<BigQuery> = admin
        .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    let chain = format!(
        "KEYS.KEYSET_CHAIN('{}', {})",
        keyset.key_uri(),
        keyset.to_sql_literal()
    );
    let seal = from_hex(keyset.seal_marker().value());
    let aad = "CAST(CONCAT('user/', id, '/email') AS BYTES)";
    let swept = jobs
        .query(format!(
            "UPDATE {users}
             SET email = AEAD.ENCRYPT({chain}, AEAD.DECRYPT_BYTES({chain}, email, {aad}), {aad}),
                 seal = {seal}
             WHERE seal < {seal} AND seal > {envelope}",
            envelope = from_hex(SealMarker::ENVELOPE.value()),
        ))
        .await?;
    println!(
        "swept to seal marker {} in {:.2?}: resealed {}",
        keyset.seal_marker(),
        started.elapsed(),
        swept
            .num_dml_affected_rows
            .map_or_else(|| "unknown".to_string(), |rows| rows.to_string())
    );

    let started = Instant::now();
    let range: SealRange = keyring
        .record()
        .version(previous)
        .and_then(KeyVersion::seal_range)
        .ok_or("a replaced version has a seal range")?;
    let end = match range.end() {
        Some(end) => from_hex(end.value()),
        None => "CAST(NULL AS BYTES)".to_string(),
    };
    let under_previous = jobs
        .count(format!(
            "SELECT COUNT(*) FROM {users} WHERE seal >= {start} AND ({end} IS NULL OR seal < {end})",
            start = from_hex(range.start().value()),
        ))
        .await?;
    if under_previous > 0 {
        return Err(format!(
            "{under_previous} users are left under key version {}",
            previous.as_u32()
        )
        .into());
    }
    admin.retire(previous).await?;
    println!(
        "no user under key version {}, retired it in {:.2?}",
        previous.as_u32(),
        started.elapsed()
    );

    let readable = jobs
        .count(format!(
            "SELECT COUNTIF(AEAD.DECRYPT_STRING({chain}, email, CONCAT('user/', id, '/email'))
               = CONCAT('user-', id, '@example.com')) FROM {users}"
        ))
        .await?;
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
    let jobs = BigQueryJobs {
        client: GoogleApi::from_function(
            JobServiceClient::new,
            "https://bigquery.googleapis.com",
            None,
        )
        .await?,
        project: std::env::var("PROJECT_ID")?,
        location: std::env::var("PROJECT_LOCATION")?,
    };
    let key_ref = GcpKmsKeyRef::new(
        jobs.project.clone(),
        jobs.location.clone(),
        std::env::var("KMS_KEY_RING")?,
        std::env::var("KMS_KEY")?,
    );
    let dataset = format!(
        "{}.sweep_example_{}",
        jobs.project,
        uuid::Uuid::now_v7().simple()
    );
    jobs.query(format!(
        "CREATE SCHEMA `{dataset}` OPTIONS (location = '{}');
         CREATE TABLE `{dataset}.users` (id STRING NOT NULL, email BYTES NOT NULL, seal BYTES NOT NULL)",
        jobs.location
    ))
    .await?;

    let users = format!("`{dataset}.users`");
    let outcome = run(&jobs, &users, &key_ref, count).await;
    jobs.query(format!("DROP SCHEMA `{dataset}` CASCADE"))
        .await?;
    println!("dropped the example's dataset {dataset}");
    outcome
}
