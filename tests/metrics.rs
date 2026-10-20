//! The OpenTelemetry instruments of the `opentelemetry` feature, read through the SDK's in-memory
//! exporter. The meter provider is global and installed once for the whole test binary, before
//! any envelope call. The tests run in parallel, so each seals under its own pair of algorithm
//! and mode and reads only the points of that pair.

use std::sync::OnceLock;

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use secret_vault_value::SecretValue;

type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

const SECRET: &str = "4111 1111 1111 1111";

const AAD: &str = "orders/7f3a/card";

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

/// An envelope on a local KEK, created after the meter provider.
fn envelope(
    options: KmsAeadEnvelopeOptions,
) -> Result<KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>, Box<dyn std::error::Error + Send + Sync>>
{
    telemetry();
    let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("orders".to_string())?)?;
    Ok(KmsAeadEnvelope::with_options(provider, options)?)
}

/// A point of one instrument: its sorted attributes and its value, the count of a histogram.
#[derive(Debug, Clone, PartialEq)]
struct Point {
    attributes: Vec<KeyValue>,
    value: u64,
}

fn sorted(mut attributes: Vec<KeyValue>) -> Vec<KeyValue> {
    attributes.sort_by(|a, b| a.key.cmp(&b.key));
    attributes
}

fn points_of(metric: &Metric) -> Vec<Point> {
    let point = |attributes: &mut dyn Iterator<Item = &KeyValue>, value| Point {
        attributes: sorted(attributes.cloned().collect()),
        value,
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

/// The cumulative points of the instrument `name` whose attributes include every one of `with`,
/// as of a flush now.
fn points(
    name: &str,
    with: &[KeyValue],
) -> Result<Vec<Point>, Box<dyn std::error::Error + Send + Sync>> {
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
        .filter(|point| with.iter().all(|kv| point.attributes.contains(kv)))
        .collect())
}

#[tokio::test]
async fn a_per_call_encrypt_and_decrypt_count_one_value_and_its_plaintext_bytes_each() -> TestResult
{
    let envelope = envelope(KmsAeadEnvelopeOptions::new())?;
    let value = envelope
        .encrypt(AAD, &SecretValue::from(SECRET.to_string()))
        .await?;
    let _: SecretValue = envelope.decrypt(AAD, &value).await?;

    let per_call = [
        KeyValue::new("mode", "per_call"),
        KeyValue::new("algorithm", "aes-256-gcm"),
    ];
    let attributes = |operation: &'static str| {
        sorted(vec![
            KeyValue::new("operation", operation),
            KeyValue::new("mode", "per_call"),
            KeyValue::new("algorithm", "aes-256-gcm"),
            KeyValue::new("backend", "ring"),
        ])
    };
    for (name, value) in [
        ("kms_aead.values", 1),
        ("kms_aead.plaintext", SECRET.len() as u64),
    ] {
        let mut recorded = points(name, &per_call)?;
        recorded.sort_by_key(|point| format!("{:?}", point.attributes));
        assert_eq!(
            recorded,
            [
                Point {
                    attributes: attributes("decrypt"),
                    value
                },
                Point {
                    attributes: attributes("encrypt"),
                    value
                },
            ],
            "{name}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_caller_dek_seal_counts_its_plaintext_bytes() -> TestResult {
    let envelope =
        envelope(KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm))?;
    let (dek, _) = envelope.generate_encrypted_dek().await?;
    let value = envelope.encrypt_with_dek(AAD, &SecretValue::from(SECRET.to_string()), &dek)?;
    let _: SecretValue = envelope.decrypt_with_dek(AAD, &value, &dek)?;

    let caller_dek = [
        KeyValue::new("mode", "caller_dek"),
        KeyValue::new("algorithm", "aes-128-gcm"),
    ];
    let bytes = points("kms_aead.plaintext", &caller_dek)?
        .into_iter()
        .map(|point| point.value)
        .collect::<Vec<_>>();
    assert_eq!(bytes, [SECRET.len() as u64; 2]);
    Ok(())
}

#[tokio::test]
async fn a_failed_decrypt_counts_nothing_and_times_the_call_with_its_error_code() -> TestResult {
    let envelope =
        envelope(KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305))?;
    let value = envelope
        .encrypt(AAD, &SecretValue::from(SECRET.to_string()))
        .await?;
    let opened: Result<SecretValue, _> = envelope.decrypt("orders/other/card", &value).await;
    let Err(error) = opened else {
        return Err("a value opened under another AAD".into());
    };

    let decrypts = [
        KeyValue::new("operation", "decrypt"),
        KeyValue::new("algorithm", "chacha20-poly1305"),
    ];
    assert_eq!(points("kms_aead.values", &decrypts)?, []);
    assert_eq!(points("kms_aead.plaintext", &decrypts)?, []);
    assert_eq!(
        points("kms_aead.operation.duration", &decrypts)?,
        [Point {
            attributes: sorted(vec![
                KeyValue::new("operation", "decrypt"),
                KeyValue::new("mode", "per_call"),
                KeyValue::new("algorithm", "chacha20-poly1305"),
                KeyValue::new("backend", "ring"),
                KeyValue::new("error_code", error.code().to_string()),
            ]),
            value: 1
        }]
    );
    Ok(())
}

#[tokio::test]
async fn no_attribute_carries_the_plaintext_or_the_aad() -> TestResult {
    let envelope = envelope(KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()))?;
    let value = envelope
        .encrypt(AAD, &SecretValue::from(SECRET.to_string()))
        .await?;
    let _: SecretValue = envelope.decrypt(AAD, &value).await?;

    let mut attributes = 0;
    for name in [
        "kms_aead.values",
        "kms_aead.plaintext",
        "kms_aead.operation.duration",
        "kms_aead.kms.duration",
    ] {
        for point in points(name, &[])? {
            for kv in point.attributes {
                attributes += 1;
                let text = kv.value.as_str();
                assert!(
                    !text.contains(SECRET) && !text.contains(AAD),
                    "{name}: {kv:?}"
                );
            }
        }
    }
    assert!(
        !points("kms_aead.values", &[KeyValue::new("mode", "store_less")])?.is_empty(),
        "the store-less envelope counts its values"
    );
    assert!(attributes > 0);
    Ok(())
}
