//! The OpenTelemetry instruments of the `opentelemetry` feature, read through the SDK's in-memory
//! exporter. The meter provider is global and installed once for the whole test binary, before
//! any keyring call, so each test opens a keyring of its own and reads only that keyring's points.

#![cfg(all(
    feature = "opentelemetry",
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]

use std::sync::OnceLock;

use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Interop, KeyringAdmin, KeyringAlgorithms,
    KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Purpose,
};
use opentelemetry::{KeyValue, Value};
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};

#[cfg(feature = "ring")]
type Backend = kms_aead::backends::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
type Backend = kms_aead::backends::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
type Backend = kms_aead::backends::RustCrypto;

/// The name of `Backend`, the `backend` attribute of a randomised call.
const BACKEND: &str = <Backend as kms_aead::backends::AeadBackend>::NAME;

type LocalKeyringAdmin = KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Backend>, Backend>;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

const ALICE: &str = "alice@example.com";

const ENTITY: &str = "entity-7f3a";

struct Telemetry {
    provider: SdkMeterProvider,
    exporter: InMemoryMetricExporter,
}

/// The global meter provider, installed on first use.
fn telemetry() -> &'static Telemetry {
    static TELEMETRY: OnceLock<Telemetry> = OnceLock::new();
    TELEMETRY.get_or_init(|| {
        let exporter = InMemoryMetricExporter::default();
        let provider = SdkMeterProvider::builder()
            .with_periodic_exporter(exporter.clone())
            .build();
        opentelemetry::global::set_meter_provider(provider.clone());
        Telemetry { provider, exporter }
    })
}

/// A keyring with the default algorithms, on a local KEK, created after the meter provider.
async fn keyring(id: &'static str) -> Result<LocalKeyringAdmin, Box<dyn std::error::Error>> {
    keyring_with(id, KeyringAlgorithms::new()).await
}

async fn keyring_with(
    id: &'static str,
    algorithms: KeyringAlgorithms,
) -> Result<LocalKeyringAdmin, Box<dyn std::error::Error>> {
    telemetry();
    let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
    Ok(KeyringRegistry::<MemoryKeyringStore, Backend>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(provider, KeyringId::from_static(id), algorithms)
    .await?)
}

/// A point of one instrument: its attributes and its value, the count of a histogram.
#[derive(Debug, Clone, PartialEq)]
struct Point {
    attributes: Vec<KeyValue>,
    value: u64,
}

/// The cumulative points of the instrument `name`, as of a flush now.
fn points(name: &str) -> Result<Vec<Point>, Box<dyn std::error::Error>> {
    let telemetry = telemetry();
    telemetry.provider.force_flush()?;
    let exported = telemetry.exporter.get_finished_metrics()?;
    let Some(latest) = exported.last() else {
        return Ok(Vec::new());
    };
    Ok(latest
        .scope_metrics()
        .flat_map(|scope| scope.metrics())
        .filter(|metric| metric.name() == name)
        .flat_map(points_of)
        .collect())
}

fn points_of(metric: &Metric) -> Vec<Point> {
    let point = |attributes: &mut dyn Iterator<Item = &KeyValue>, value| {
        let mut attributes = attributes.cloned().collect::<Vec<_>>();
        attributes.sort_by(|a, b| a.key.cmp(&b.key));
        Point { attributes, value }
    };
    match metric.data() {
        AggregatedMetrics::U64(MetricData::Sum(sum)) => sum
            .data_points()
            .map(|p| point(&mut p.attributes(), p.value()))
            .collect(),
        AggregatedMetrics::F64(MetricData::Histogram(histogram)) => histogram
            .data_points()
            .map(|p| point(&mut p.attributes(), p.count()))
            .collect(),
        _ => Vec::new(),
    }
}

/// The points of `name` whose `keyring` attribute is `keyring`.
fn points_of_keyring(name: &str, keyring: &str) -> Result<Vec<Point>, Box<dyn std::error::Error>> {
    Ok(points(name)?
        .into_iter()
        .filter(|point| {
            point
                .attributes
                .iter()
                .any(|kv| kv.key.as_str() == "keyring" && kv.value.as_str() == keyring)
        })
        .collect())
}

fn sorted(mut attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    attributes.sort_by(|a, b| a.key.cmp(&b.key));
    attributes
}

#[tokio::test]
async fn a_seal_counts_one_value_and_its_plaintext_bytes_under_the_version() -> TestResult {
    let admin = keyring("metrics-seal").await?;
    let keyring = admin.keyring();
    let key_id = keyring
        .record()
        .active(Purpose::Randomized)
        .map(|version| version.id())
        .ok_or("no active version")?;
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let sealer = keyring.sealer().await;
    sealer.encrypt(&aad, &ALICE.to_string()).await?;
    sealer.encrypt(&aad, &ALICE.to_string()).await?;

    let attributes = sorted(vec![
        KeyValue::new("operation", "encrypt"),
        KeyValue::new("mode", "keyring"),
        KeyValue::new("algorithm", "aes-256-gcm"),
        KeyValue::new("backend", BACKEND),
        KeyValue::new("keyring", "metrics-seal"),
        KeyValue::new("purpose", "randomized"),
        KeyValue::new("key_id", i64::from(key_id.as_u32())),
    ]);
    assert_eq!(
        points_of_keyring("kms_aead.values", "metrics-seal")?,
        [Point {
            attributes: attributes.clone(),
            value: 2
        }]
    );
    assert_eq!(
        points_of_keyring("kms_aead.plaintext", "metrics-seal")?,
        [Point {
            attributes,
            value: 2 * ALICE.len() as u64
        }]
    );
    // A keyring seal runs kms-aead's cipher and never its envelope, so no other point counts it.
    let keyring_mode = KeyValue::new("mode", "keyring");
    assert_eq!(
        points("kms_aead.values")?
            .into_iter()
            .filter(|point| !point.attributes.contains(&keyring_mode))
            .collect::<Vec<_>>(),
        []
    );
    Ok(())
}

#[tokio::test]
async fn a_decrypt_counts_one_value_and_its_plaintext_bytes_under_the_version() -> TestResult {
    let admin = keyring("metrics-decrypt").await?;
    let keyring = admin.keyring();
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let value = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    keyring.decrypt(&aad, &value).await?;

    let decrypts = |points: Vec<Point>| {
        points
            .into_iter()
            .filter(|point| {
                point
                    .attributes
                    .contains(&KeyValue::new("operation", "decrypt"))
            })
            .map(|point| point.value)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        decrypts(points_of_keyring("kms_aead.values", "metrics-decrypt")?),
        [1]
    );
    assert_eq!(
        decrypts(points_of_keyring("kms_aead.plaintext", "metrics-decrypt")?),
        [ALICE.len() as u64]
    );
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn a_deterministic_seal_and_open_count_its_plaintext_bytes() -> TestResult {
    let admin = keyring_with(
        "metrics-deterministic",
        KeyringAlgorithms::new().with_deterministic(kms_aead::DeterministicAlgorithm::Aes256Siv),
    )
    .await?;
    let keyring = admin.keyring();
    let aad = EMAIL.deterministic_aad();
    let value = keyring
        .sealer()
        .await
        .encrypt_deterministic(&aad, &ALICE.to_string())
        .await?;
    keyring.decrypt_deterministic(&aad, &value).await?;

    let bytes = points_of_keyring("kms_aead.plaintext", "metrics-deterministic")?
        .into_iter()
        .filter(|point| {
            point
                .attributes
                .contains(&KeyValue::new("purpose", "deterministic"))
        })
        .map(|point| point.value)
        .collect::<Vec<_>>();
    assert_eq!(bytes, [ALICE.len() as u64; 2]);
    Ok(())
}

#[tokio::test]
async fn a_failed_seal_counts_nothing_and_times_the_call_with_its_error_code() -> TestResult {
    let admin = keyring("metrics-failed-seal").await?;
    let keyring = admin.keyring();
    let bigquery_only = EMAIL.with_interop(Interop::BigQuery);
    let aad = bigquery_only.aad(&EntityId::try_from(ENTITY)?);
    let sealed = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await;
    let Err(error @ KeyringError::Interop(_)) = sealed else {
        return Err(format!("expected an interop error, got {sealed:?}").into());
    };

    assert_eq!(
        points_of_keyring("kms_aead.values", "metrics-failed-seal")?,
        []
    );
    assert_eq!(
        points_of_keyring("kms_aead.plaintext", "metrics-failed-seal")?,
        []
    );
    assert_eq!(
        points_of_keyring("kms_aead.operation.duration", "metrics-failed-seal")?,
        [Point {
            attributes: sorted(vec![
                KeyValue::new("operation", "encrypt"),
                KeyValue::new("mode", "keyring"),
                KeyValue::new("algorithm", "aes-256-gcm"),
                KeyValue::new("backend", BACKEND),
                KeyValue::new("keyring", "metrics-failed-seal"),
                KeyValue::new("purpose", "randomized"),
                KeyValue::new("error_code", error.code().to_string()),
            ]),
            value: 1
        }]
    );
    Ok(())
}

#[tokio::test]
async fn a_store_read_is_timed_by_store_and_reason() -> TestResult {
    let admin = keyring("metrics-load").await?;
    admin.keyring().reload().await?;

    let loads = points_of_keyring("kms_aead.store.duration", "metrics-load")?;
    assert!(
        loads.iter().any(|point| point.attributes
            == sorted(vec![
                KeyValue::new("keyring", "metrics-load"),
                KeyValue::new("store", "memory"),
                KeyValue::new("reason", "forced"),
            ])),
        "{loads:?}"
    );
    Ok(())
}

#[tokio::test]
async fn a_kms_call_is_timed_by_provider_and_operation() -> TestResult {
    let admin = keyring("metrics-kms").await?;
    let keyring = admin.keyring();
    keyring.dek_cache().clear();
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;

    let operations = points("kms_aead.kms.duration")?
        .into_iter()
        .filter(|point| {
            point
                .attributes
                .contains(&KeyValue::new("provider", "local"))
        })
        .flat_map(|point| point.attributes)
        .filter(|kv| kv.key.as_str() == "operation")
        .map(|kv| kv.value)
        .collect::<Vec<_>>();
    for operation in ["encrypt_dek", "decrypt_dek"] {
        assert!(
            operations.contains(&Value::from(operation)),
            "{operations:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn no_attribute_carries_the_plaintext_or_the_aad() -> TestResult {
    let admin = keyring("metrics-no-secrets").await?;
    let keyring = admin.keyring();
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let value = keyring
        .sealer()
        .await
        .encrypt(&aad, &ALICE.to_string())
        .await?;
    keyring.decrypt(&aad, &value).await?;

    let names = [
        "kms_aead.values",
        "kms_aead.plaintext",
        "kms_aead.operation.duration",
        "kms_aead.store.duration",
        "kms_aead.kms.duration",
    ];
    let mut attributes = 0;
    for name in names {
        for point in points(name)? {
            for kv in point.attributes {
                attributes += 1;
                let text = kv.value.as_str();
                assert!(
                    !text.contains(ALICE) && !text.contains(ENTITY),
                    "{name}: {kv:?}"
                );
            }
        }
    }
    assert!(attributes > 0);
    Ok(())
}
