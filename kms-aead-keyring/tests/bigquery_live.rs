//! Values written by the keyring read in BigQuery through an exported keyset, against the Cloud
//! KMS key that `PROJECT_ID`, `PROJECT_LOCATION`, `KMS_KEY_RING` and `KMS_KEY` name, with
//! BigQuery queries run in that project and location under the application default
//! credentials. The principal needs the KMS key's encrypt and decrypt rights and
//! `bigquery.jobs.create` in the project.

use bigquery::{BigQueryDb, BigQueryFieldType, BigQueryLocation};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::DeterministicAlgorithm;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Interop, KeyId, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, KeysetSelection,
    Purpose,
};
use serde::Deserialize;

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

/// The one row of the test's query: a `NULL` cell is `None`.
#[derive(Debug, PartialEq, Deserialize)]
struct Row {
    first: Option<String>,
    second: Option<String>,
    relabelled: Option<String>,
    deterministic: Option<String>,
    deterministic_hex: Option<String>,
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
    let admin: KeyringAdmin<MemoryKeyringStore, GcpKmsProvider, Ring> =
        KeyringRegistry::<MemoryKeyringStore, Ring>::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(
            GcpKmsProvider::new(&key_ref).await?,
            KeyringId::try_from(format!("bigquery-live-{}", uuid::Uuid::now_v7()))?,
            KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
        )
        .await?;
    let keyring: &Keyring<MemoryKeyringStore, GcpKmsProvider, Ring> = admin.keyring();
    let field = EMAIL.with_interop(Interop::BigQuery);
    let aad = field.aad(&EntityId::try_from("42")?);
    let deterministic_aad = field.deterministic_aad();

    let first = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    admin
        .promote_now(admin.rotate(Purpose::Randomized).await?)
        .await?;
    let second = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    let mut relabelled = first.value().to_vec();
    relabelled[1..5].copy_from_slice(&ABSENT_KEY_ID.to_be_bytes());
    let deterministic = keyring
        .sealer()
        .await
        .encrypt_deterministic(&deterministic_aad, &ALICE.to_string())
        .await?;
    let randomized_keyset = admin
        .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
        .await?;
    let deterministic_keyset = admin
        .export_bigquery_keyset(KeysetSelection::Single(deterministic.key_id()))
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

    let db = BigQueryDb::new(&project).await?;
    let rows: Vec<Row> = db
        .fluent()
        .query(format!(
            "WITH users AS (
               SELECT '42' AS id, @first AS email_first, @second AS email_second,
                 @relabelled AS email_relabelled, @deterministic AS email_det
             )
             SELECT
               AEAD.DECRYPT_STRING({randomized_chain}, u.email_first, CONCAT('user/', u.id, '/email')) AS first,
               AEAD.DECRYPT_STRING({randomized_chain}, u.email_second, CONCAT('user/', u.id, '/email')) AS second,
               SAFE.AEAD.DECRYPT_STRING({randomized_chain}, u.email_relabelled, CONCAT('user/', u.id, '/email')) AS relabelled,
               DETERMINISTIC_DECRYPT_STRING({deterministic_chain}, u.email_det, 'user/email') AS deterministic,
               TO_HEX(DETERMINISTIC_ENCRYPT({deterministic_chain}, @alice, 'user/email')) AS deterministic_hex
             FROM users u"
        ))
        .param("first", &first)
        .param("second", &second)
        .param_as(
            "relabelled",
            BigQueryFieldType::Bytes { max_length: None },
            relabelled,
        )
        .param("deterministic", &deterministic)
        .param("alice", ALICE)
        .location(BigQueryLocation::new(location)?)
        .obj::<Row>()
        .query()
        .await?;

    assert_eq!(randomized_keyset.key_ids(), [KeyId::new(1), KeyId::new(2)]);
    assert_eq!(
        rows,
        [Row {
            first: Some(ALICE.to_string()),
            second: Some(ALICE.to_string()),
            relabelled: None,
            deterministic: Some(ALICE.to_string()),
            deterministic_hex: Some(hex(deterministic.value())),
        }]
    );
    Ok(())
}
