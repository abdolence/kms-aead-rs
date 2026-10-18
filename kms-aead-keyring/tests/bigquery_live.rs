//! Values written by the keyring read in BigQuery through an exported keyset, against the Cloud
//! KMS key that `PROJECT_ID`, `PROJECT_LOCATION`, `KMS_KEY_RING` and `KMS_KEY` name, with
//! BigQuery queries run in that project and location under the application default
//! credentials. The principal needs the KMS key's encrypt and decrypt rights and
//! `bigquery.jobs.create` in the project.

use gcloud_sdk::google::cloud::bigquery::v2::job_service_client::JobServiceClient;
use gcloud_sdk::google::cloud::bigquery::v2::{PostQueryRequest, QueryRequest};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{DeterministicAlgorithm, Ring, ValueStruct};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Interop, KeyId, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, KeysetSelection, Purpose,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

const ALICE: &str = "alice@example.com";

/// A key id no version of the keyring has.
const ABSENT_KEY_ID: u32 = 7;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn env(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|error| format!("{name}: {error}").into())
}

/// The cells of the one row `query` returns, as BigQuery's JSON rows give them: a `NULL` cell is
/// `None`, and every other cell is its value as text.
async fn single_row(
    project: &str,
    location: &str,
    query: String,
) -> Result<Vec<Option<String>>, Box<dyn std::error::Error>> {
    let client: GoogleApi<JobServiceClient<GoogleAuthMiddleware>> = GoogleApi::from_function(
        JobServiceClient::new,
        "https://bigquery.googleapis.com",
        None,
    )
    .await?;
    let response = client
        .get()
        .query(PostQueryRequest {
            project_id: project.to_string(),
            query_request: Some(QueryRequest {
                query,
                use_legacy_sql: Some(false),
                location: location.to_string(),
                timeout_ms: Some(60_000),
                ..Default::default()
            }),
        })
        .await?
        .into_inner();
    assert_eq!(response.job_complete, Some(true));
    assert!(response.errors.is_empty(), "{:?}", response.errors);
    let [row] = response.rows.as_slice() else {
        return Err(format!("{} rows", response.rows.len()).into());
    };
    let cells = match row.fields.get("f").and_then(|cells| cells.kind.as_ref()) {
        Some(gcloud_sdk::prost_types::value::Kind::ListValue(cells)) => &cells.values,
        other => return Err(format!("no cells in {other:?}").into()),
    };
    Ok(cells
        .iter()
        .map(|cell| match cell.kind.as_ref() {
            Some(gcloud_sdk::prost_types::value::Kind::StructValue(cell)) => {
                match cell.fields.get("v").and_then(|value| value.kind.as_ref()) {
                    Some(gcloud_sdk::prost_types::value::Kind::StringValue(value)) => {
                        Some(value.clone())
                    }
                    _ => None,
                }
            }
            _ => None,
        })
        .collect())
}

#[tokio::test]
#[ignore = "needs the Cloud KMS key PROJECT_ID, PROJECT_LOCATION, KMS_KEY_RING and KMS_KEY name, and BigQuery in that project"]
async fn bigquery_reads_values_through_exported_keysets() -> TestResult {
    let (project, location) = (env("PROJECT_ID")?, env("PROJECT_LOCATION")?);
    let key_ref = GcpKmsKeyRef::new(
        project.clone(),
        location.clone(),
        env("KMS_KEY_RING")?,
        env("KMS_KEY")?,
    );
    let keyring = Keyring::<MemoryKeyringStore, GcpKmsProvider, Ring>::create(
        MemoryKeyringStore::new(),
        GcpKmsProvider::new(&key_ref).await?,
        KeyringId::try_from(format!("bigquery-live-{}", uuid::Uuid::now_v7()))?,
        KeyringPolicy::new().with_deterministic_algorithm(DeterministicAlgorithm::Aes256Siv),
        KeyringOptions::new().with_watch(false),
    )
    .await?;
    let field = EMAIL.with_interop(Interop::BigQuery);
    let aad = field.aad(&EntityId::try_from("42")?);
    let deterministic_aad = field.deterministic_aad();

    let first = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    keyring
        .promote(keyring.rotate(Purpose::Randomized).await?)
        .await?;
    let second = keyring.encrypt(&aad, &ALICE.to_string()).await?;
    let mut relabelled = first.value().clone();
    relabelled[1..5].copy_from_slice(&ABSENT_KEY_ID.to_be_bytes());
    let deterministic = keyring
        .encrypt_deterministic(&deterministic_aad, &ALICE.to_string())
        .await?;
    let randomized_keyset = keyring
        .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    let deterministic_keyset = keyring
        .export_bigquery_keyset(KeysetSelection::Single(KeyId::try_from(&deterministic)?))
        .await?;
    let randomized_chain = format!(
        "KEYS.KEYSET_CHAIN('{}', {})",
        randomized_keyset.key_uri(),
        randomized_keyset.to_sql_literal()
    );
    let deterministic_chain = format!(
        "KEYS.KEYSET_CHAIN('{}', {})",
        deterministic_keyset.key_uri(),
        deterministic_keyset.to_sql_literal()
    );

    let row = single_row(
        &project,
        &location,
        format!(
            "WITH users AS (
               SELECT '42' AS id, FROM_HEX('{first}') AS email_first,
                 FROM_HEX('{second}') AS email_second, FROM_HEX('{relabelled}') AS email_relabelled,
                 FROM_HEX('{deterministic}') AS email_det
             )
             SELECT
               AEAD.DECRYPT_STRING({randomized_chain}, u.email_first, CONCAT('user/', u.id, '/email')),
               AEAD.DECRYPT_STRING({randomized_chain}, u.email_second, CONCAT('user/', u.id, '/email')),
               SAFE.AEAD.DECRYPT_STRING({randomized_chain}, u.email_relabelled, CONCAT('user/', u.id, '/email')),
               DETERMINISTIC_DECRYPT_STRING({deterministic_chain}, u.email_det, 'user/email'),
               TO_HEX(DETERMINISTIC_ENCRYPT({deterministic_chain}, '{ALICE}', 'user/email'))
             FROM users u",
            first = hex(first.value()),
            second = hex(second.value()),
            relabelled = hex(&relabelled),
            deterministic = hex(deterministic.value()),
        ),
    )
    .await?;

    assert_eq!(
        randomized_keyset.key_ids(),
        [KeyId::try_from(1)?, KeyId::try_from(2)?]
    );
    assert_eq!(
        row,
        [
            Some(ALICE.to_string()),
            Some(ALICE.to_string()),
            None,
            Some(ALICE.to_string()),
            Some(hex(deterministic.value())),
        ]
    );
    Ok(())
}
