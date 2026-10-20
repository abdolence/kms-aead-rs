//! The OpenTelemetry instruments of the `opentelemetry` feature, read through the SDK's in-memory
//! exporter. The meter provider is global and installed once for the whole test binary, before
//! any keyring call, so each test opens a keyring of its own and reads only that keyring's points.

#![cfg(all(
    feature = "opentelemetry",
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]

use std::num::NonZeroU32;
use std::sync::OnceLock;

use kms_aead::formats::Randomized;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, BeaconAlgorithm, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Interop, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions, Purpose,
};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use secret_vault_value::SecretValue;

#[cfg(feature = "ring")]
type Backend = kms_aead::backends::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
type Backend = kms_aead::backends::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
type Backend = kms_aead::backends::RustCrypto;

/// The name of `Backend`, the `kms_aead.backend` attribute of a randomised call.
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

/// A local KEK of fixed material, so that an envelope and a keyring share it.
fn provider() -> Result<LocalKmsProvider<Backend>, Box<dyn std::error::Error>> {
    let kek = LocalKek::from_secret(
        LocalKekVersion::from(NonZeroU32::MIN),
        SecretValue::new(vec![7; 32]),
    )?;
    Ok(LocalKmsProvider::new(
        LocalKekId::try_from("tenant-kek".to_string())?,
        vec![kek],
    )?)
}

/// A keyring with the default algorithms, created after the meter provider.
async fn keyring(id: &'static str) -> Result<LocalKeyringAdmin, Box<dyn std::error::Error>> {
    keyring_with(id, KeyringAlgorithms::new()).await
}

async fn keyring_with(
    id: &'static str,
    algorithms: KeyringAlgorithms,
) -> Result<LocalKeyringAdmin, Box<dyn std::error::Error>> {
    telemetry();
    Ok(KeyringRegistry::<MemoryKeyringStore, Backend>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new().with_watch(false),
    )?
    .create(provider()?, KeyringId::from_static(id), algorithms)
    .await?)
}

/// A point of one histogram: its sorted attributes, its count and, for the plaintext size, its
/// sum.
#[derive(Debug, Clone, PartialEq)]
struct Point {
    attributes: Vec<KeyValue>,
    count: u64,
    sum: Option<u64>,
}

fn sorted(mut attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    attributes.sort_by(|a, b| a.key.cmp(&b.key));
    attributes
}

fn points_of(metric: &Metric) -> Vec<Point> {
    let attributes =
        |attributes: &mut dyn Iterator<Item = &KeyValue>| sorted(attributes.cloned().collect());
    match metric.data() {
        AggregatedMetrics::U64(MetricData::Histogram(histogram)) => histogram
            .data_points()
            .map(|p| Point {
                attributes: attributes(&mut p.attributes()),
                count: p.count(),
                sum: Some(p.sum()),
            })
            .collect(),
        AggregatedMetrics::F64(MetricData::Histogram(histogram)) => histogram
            .data_points()
            .map(|p| Point {
                attributes: attributes(&mut p.attributes()),
                count: p.count(),
                sum: None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

/// The cumulative points of the instrument `name`, as of a flush now, in the order of their
/// attributes.
fn points(name: &str) -> Result<Vec<Point>, Box<dyn std::error::Error>> {
    let telemetry = telemetry();
    telemetry.provider.force_flush()?;
    let exported = telemetry.exporter.get_finished_metrics()?;
    let Some(latest) = exported.last() else {
        return Ok(Vec::new());
    };
    let mut points = latest
        .scope_metrics()
        .flat_map(|scope| scope.metrics())
        .filter(|metric| metric.name() == name)
        .flat_map(points_of)
        .collect::<Vec<_>>();
    points.sort_by_key(|point| format!("{:?}", point.attributes));
    Ok(points)
}

/// The points of `name` whose `kms_aead.keyring` attribute is `keyring`.
fn points_of_keyring(name: &str, keyring: &str) -> Result<Vec<Point>, Box<dyn std::error::Error>> {
    let keyring = KeyValue::new("kms_aead.keyring", keyring.to_string());
    Ok(points(name)?
        .into_iter()
        .filter(|point| point.attributes.contains(&keyring))
        .collect())
}

/// The sorted attributes of a call of `operation` on `keyring`: `extra` beside the common ones.
fn call(operation: &'static str, keyring: &'static str, extra: Vec<KeyValue>) -> Vec<KeyValue> {
    let mut attributes = vec![
        KeyValue::new("kms_aead.operation", operation),
        KeyValue::new("kms_aead.mode", "keyring"),
        KeyValue::new("kms_aead.keyring", keyring),
    ];
    attributes.extend(extra);
    sorted(attributes)
}

#[tokio::test]
async fn a_seal_and_a_decrypt_record_their_values_and_plaintext_bytes_under_the_version(
) -> TestResult {
    let admin = keyring("metrics-values").await?;
    let keyring = admin.keyring();
    let key_id = keyring
        .record()
        .active(Purpose::Randomized)
        .map(|version| version.id())
        .ok_or("no active version")?;
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let sealer = keyring.sealer().await;
    let value = sealer.encrypt(&aad, &ALICE.to_string()).await?;
    sealer.encrypt(&aad, &ALICE.to_string()).await?;
    keyring.decrypt(&aad, &value).await?;

    let value_of = |operation, count| Point {
        attributes: call(
            operation,
            "metrics-values",
            vec![
                KeyValue::new("kms_aead.algorithm", "aes-256-gcm"),
                KeyValue::new("kms_aead.backend", BACKEND),
                KeyValue::new("kms_aead.purpose", "randomized"),
                KeyValue::new("kms_aead.key_id", i64::from(key_id.as_u32())),
            ],
        ),
        count,
        sum: Some(count * ALICE.len() as u64),
    };
    assert_eq!(
        points_of_keyring("kms_aead.plaintext.size", "metrics-values")?,
        [value_of("decrypt", 1), value_of("encrypt", 2)]
    );
    // A keyring call runs kms-aead's ciphers and never its envelope, so no other point counts
    // it. The envelope of the migration test seals under another algorithm.
    let keyring_mode = KeyValue::new("kms_aead.mode", "keyring");
    let aes_256_gcm = KeyValue::new("kms_aead.algorithm", "aes-256-gcm");
    assert_eq!(
        points("kms_aead.plaintext.size")?
            .into_iter()
            .filter(|point| {
                point.attributes.contains(&aes_256_gcm) && !point.attributes.contains(&keyring_mode)
            })
            .collect::<Vec<_>>(),
        []
    );
    Ok(())
}

#[cfg(feature = "deterministic")]
#[tokio::test]
async fn a_deterministic_seal_and_open_record_their_plaintext_bytes() -> TestResult {
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
    keyring
        .deterministic_probes(&aad, &ALICE.to_string())
        .await?;

    let deterministic = KeyValue::new("kms_aead.purpose", "deterministic");
    let values = points_of_keyring("kms_aead.plaintext.size", "metrics-deterministic")?
        .into_iter()
        .filter(|point| point.attributes.contains(&deterministic))
        .map(|point| point.sum)
        .collect::<Vec<_>>();
    assert_eq!(values, [Some(ALICE.len() as u64); 2]);
    // A probe runs under every version at once, so it records no algorithm.
    let probes = points_of_keyring("kms_aead.operation.duration", "metrics-deterministic")?
        .into_iter()
        .filter(|point| {
            point
                .attributes
                .contains(&KeyValue::new("kms_aead.operation", "probe"))
        })
        .map(|point| point.attributes)
        .collect::<Vec<_>>();
    assert_eq!(
        probes,
        [call(
            "probe",
            "metrics-deterministic",
            vec![
                KeyValue::new("kms_aead.backend", "rustcrypto"),
                deterministic,
            ]
        )]
    );
    Ok(())
}

#[tokio::test]
async fn a_failed_seal_records_no_value_and_times_the_call_with_its_error_type() -> TestResult {
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
        points_of_keyring("kms_aead.plaintext.size", "metrics-failed-seal")?,
        []
    );
    assert_eq!(
        points_of_keyring("kms_aead.operation.duration", "metrics-failed-seal")?,
        [Point {
            attributes: call(
                "encrypt",
                "metrics-failed-seal",
                vec![
                    KeyValue::new("kms_aead.algorithm", "aes-256-gcm"),
                    KeyValue::new("kms_aead.backend", BACKEND),
                    KeyValue::new("kms_aead.purpose", "randomized"),
                    KeyValue::new("error.type", error.code().to_string()),
                ]
            ),
            count: 1,
            sum: None
        }]
    );
    Ok(())
}

#[tokio::test]
async fn a_decrypt_that_fails_the_purpose_check_is_timed_without_an_algorithm() -> TestResult {
    let admin = keyring("metrics-purpose").await?;
    let keyring = admin.keyring();
    // Key id 0 is reserved: TINK's prefix, the id, and a nonce and a tag of zeros.
    let mut bytes = vec![0x01, 0, 0, 0, 0];
    bytes.extend([0; 28]);
    let value = Encrypted::<String, Randomized>::try_from(bytes)?;
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let Err(error) = keyring.decrypt(&aad, &value).await else {
        return Err("a value under a reserved key id opened".into());
    };

    assert_eq!(
        points_of_keyring("kms_aead.operation.duration", "metrics-purpose")?,
        [Point {
            attributes: call(
                "decrypt",
                "metrics-purpose",
                vec![
                    KeyValue::new("kms_aead.backend", BACKEND),
                    KeyValue::new("kms_aead.purpose", "randomized"),
                    KeyValue::new("error.type", error.code().to_string()),
                ]
            ),
            count: 1,
            sum: None
        }]
    );
    Ok(())
}

#[tokio::test]
async fn beacons_probes_and_reseals_are_timed() -> TestResult {
    let admin = keyring_with(
        "metrics-beacons",
        KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
    )
    .await?;
    let keyring = admin.keyring();
    let aad = EMAIL.aad(&EntityId::try_from(ENTITY)?);
    let sealer = keyring.sealer().await;
    let value = sealer.encrypt(&aad, &ALICE.to_string()).await?;
    sealer.reseal(&aad, &value).await?;
    sealer.beacon(&EMAIL, &ALICE.to_string()).await?;
    keyring.beacon_probes(&EMAIL, &ALICE.to_string()).await?;

    let timed = points_of_keyring("kms_aead.operation.duration", "metrics-beacons")?
        .into_iter()
        .map(|point| point.attributes)
        .collect::<Vec<_>>();
    let backend = || KeyValue::new("kms_aead.backend", BACKEND);
    let beacon = || KeyValue::new("kms_aead.purpose", "beacon");
    for attributes in [
        call(
            "beacon",
            "metrics-beacons",
            vec![
                KeyValue::new("kms_aead.algorithm", "hmac-sha256"),
                backend(),
                beacon(),
            ],
        ),
        call("probe", "metrics-beacons", vec![backend(), beacon()]),
        call(
            "reseal",
            "metrics-beacons",
            vec![backend(), KeyValue::new("kms_aead.purpose", "randomized")],
        ),
    ] {
        assert!(timed.contains(&attributes), "{timed:?}");
    }
    Ok(())
}

#[tokio::test]
async fn an_envelope_migration_records_its_value_without_a_purpose() -> TestResult {
    let admin = keyring("metrics-migration").await?;
    let envelope = KmsAeadEnvelope::<LocalKmsProvider<Backend>, Backend>::with_options(
        provider()?,
        KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
    )?;
    let value = envelope
        .encrypt("users/42/email", &ALICE.to_string())
        .await?;
    let opened = admin
        .keyring()
        .decrypt_envelope_for_migration("users/42/email", &value, AeadAlgorithm::ChaCha20Poly1305)
        .await?;
    assert_eq!(opened, ALICE);

    assert_eq!(
        points_of_keyring("kms_aead.plaintext.size", "metrics-migration")?,
        [Point {
            attributes: call(
                "decrypt",
                "metrics-migration",
                vec![
                    KeyValue::new("kms_aead.algorithm", "chacha20-poly1305"),
                    KeyValue::new("kms_aead.backend", BACKEND),
                ]
            ),
            count: 1,
            sum: Some(ALICE.len() as u64)
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
                KeyValue::new("kms_aead.keyring", "metrics-load"),
                KeyValue::new("kms_aead.store", "memory"),
                KeyValue::new("kms_aead.reason", "forced"),
            ])),
        "{loads:?}"
    );
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
        "kms_aead.plaintext.size",
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
