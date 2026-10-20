//! The OpenTelemetry instruments of the `opentelemetry` feature, read through the SDK's in-memory
//! exporter. The meter provider is global and installed once for the whole test binary, before
//! any envelope call. The tests run in parallel, so each seals under its own pair of algorithm
//! and mode, or makes calls no other test makes, and reads only its own points.

use std::sync::OnceLock;

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{
    AeadAlgorithm, BeaconAlgorithm, BeaconBits, BeaconMac, DekReusePolicy,
    EncryptedDataEncryptionKey, KeyId, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
};
use opentelemetry::KeyValue;
use opentelemetry_sdk::metrics::data::{AggregatedMetrics, Metric, MetricData};
use opentelemetry_sdk::metrics::{InMemoryMetricExporter, SdkMeterProvider};
use secret_vault_value::SecretValue;

type TestError = Box<dyn std::error::Error + Send + Sync>;

type TestResult = Result<(), TestError>;

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
) -> Result<KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>, TestError> {
    telemetry();
    let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("orders".to_string())?)?;
    Ok(KmsAeadEnvelope::with_options(provider, options)?)
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

/// The cumulative points of the instrument `name` whose attributes include every one of `with`,
/// as of a flush now, in the order of their attributes.
fn points(name: &str, with: &[KeyValue]) -> Result<Vec<Point>, TestError> {
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
        .filter(|point| with.iter().all(|kv| point.attributes.contains(kv)))
        .collect::<Vec<_>>();
    points.sort_by_key(|point| format!("{:?}", point.attributes));
    Ok(points)
}

/// The sorted attributes of an envelope call of `operation` in `mode` on ring, under `algorithm`
/// when it has one.
fn call(
    operation: &'static str,
    mode: &'static str,
    algorithm: Option<&'static str>,
) -> Vec<KeyValue> {
    let mut attributes = vec![
        KeyValue::new("kms_aead.operation", operation),
        KeyValue::new("kms_aead.mode", mode),
        KeyValue::new("kms_aead.backend", "ring"),
    ];
    attributes.extend(algorithm.map(|algorithm| KeyValue::new("kms_aead.algorithm", algorithm)));
    sorted(attributes)
}

#[tokio::test]
async fn a_per_call_encrypt_and_decrypt_record_one_value_and_its_plaintext_bytes_each() -> TestResult
{
    let envelope = envelope(KmsAeadEnvelopeOptions::new())?;
    let value = envelope
        .encrypt(AAD, &SecretValue::from(SECRET.to_string()))
        .await?;
    let _: SecretValue = envelope.decrypt(AAD, &value).await?;

    let per_call = [
        KeyValue::new("kms_aead.mode", "per_call"),
        KeyValue::new("kms_aead.algorithm", "aes-256-gcm"),
    ];
    let value_of = |operation| Point {
        attributes: call(operation, "per_call", Some("aes-256-gcm")),
        count: 1,
        sum: Some(SECRET.len() as u64),
    };
    assert_eq!(
        points("kms_aead.plaintext.size", &per_call)?,
        [value_of("decrypt"), value_of("encrypt")]
    );
    Ok(())
}

#[tokio::test]
async fn caller_dek_seals_and_opens_record_their_plaintext_bytes() -> TestResult {
    let envelope =
        envelope(KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm))?;
    let (dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;
    let secret = SecretValue::from(SECRET.to_string());
    let value = envelope.encrypt_with_dek(AAD, &secret, &dek)?;
    let _: SecretValue = envelope.decrypt_with_dek(AAD, &value, &dek)?;
    let value = envelope
        .encrypt_with_encrypted_dek(AAD, &secret, &encrypted_dek)
        .await?;
    let _: SecretValue = envelope
        .decrypt_with_encrypted_dek(AAD, &value, &encrypted_dek)
        .await?;

    let caller_dek = [
        KeyValue::new("kms_aead.mode", "caller_dek"),
        KeyValue::new("kms_aead.algorithm", "aes-128-gcm"),
    ];
    let values = points("kms_aead.plaintext.size", &caller_dek)?
        .into_iter()
        .map(|point| (point.count, point.sum))
        .collect::<Vec<_>>();
    assert_eq!(values, [(2, Some(2 * SECRET.len() as u64)); 2]);
    Ok(())
}

#[tokio::test]
async fn a_failed_decrypt_records_no_value_and_times_the_call_with_its_error_type() -> TestResult {
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
        KeyValue::new("kms_aead.operation", "decrypt"),
        KeyValue::new("kms_aead.algorithm", "chacha20-poly1305"),
    ];
    assert_eq!(points("kms_aead.plaintext.size", &decrypts)?, []);
    let mut attributes = call("decrypt", "per_call", Some("chacha20-poly1305"));
    attributes.push(KeyValue::new("error.type", error.code().to_string()));
    assert_eq!(
        points("kms_aead.operation.duration", &decrypts)?,
        [Point {
            attributes: sorted(attributes),
            count: 1,
            sum: None
        }]
    );
    Ok(())
}

#[tokio::test]
async fn beacons_new_deks_and_reencryptions_are_timed() -> TestResult {
    let envelope =
        envelope(KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm))?;
    let (_, encrypted_dek) = envelope.generate_encrypted_dek().await?;
    let value = envelope
        .encrypt(AAD, &SecretValue::from(SECRET.to_string()))
        .await?;
    envelope.reencrypt_dek(&value).await?;
    envelope.reencrypt_encrypted_dek(&encrypted_dek).await?;
    let (_, beacon_key) = BeaconMac::<Ring>::new(BeaconAlgorithm::HmacSha256)
        .generate_encrypted_dek(envelope.provider())
        .await?;
    envelope
        .beacon(
            KeyId::new(1),
            "orders/card",
            BeaconBits::DEFAULT,
            &SecretValue::from(SECRET.to_string()),
            &beacon_key,
        )
        .await?;

    let timed = |operation: &'static str| {
        Ok::<_, TestError>(
            points(
                "kms_aead.operation.duration",
                &[KeyValue::new("kms_aead.operation", operation)],
            )?
            .into_iter()
            .map(|point| (point.attributes, point.count))
            .collect::<Vec<_>>(),
        )
    };
    let generated = timed("generate_dek")?;
    let generate_dek = call("generate_dek", "caller_dek", Some("aes-128-gcm"));
    assert!(
        generated
            .iter()
            .any(|(attributes, _)| *attributes == generate_dek),
        "{generated:?}"
    );
    // The algorithm plays no part in a re-encryption, so it records none.
    let reencryptions = timed("reencrypt_dek")?;
    for mode in ["caller_dek", "per_call"] {
        let reencryption = (call("reencrypt_dek", mode, None), 1);
        assert!(reencryptions.contains(&reencryption), "{reencryptions:?}");
    }
    assert_eq!(
        timed("beacon")?,
        [(call("beacon", "caller_dek", Some("hmac-sha256")), 1)]
    );
    Ok(())
}

#[tokio::test]
async fn a_kms_call_is_timed_by_provider_and_operation_with_its_error_type() -> TestResult {
    let envelope = envelope(KmsAeadEnvelopeOptions::new())?;
    let (_, encrypted_dek) = envelope.generate_encrypted_dek().await?;
    let mut tampered = encrypted_dek.value().clone();
    if let Some(last) = tampered.last_mut() {
        *last ^= 1;
    }
    let reencrypted = envelope
        .reencrypt_encrypted_dek(&EncryptedDataEncryptionKey::new(tampered))
        .await;
    let Err(error) = reencrypted else {
        return Err("a tampered encrypted DEK decrypted".into());
    };

    let local = [KeyValue::new("kms_aead.provider", "local")];
    let attributes = points("kms_aead.kms.duration", &local)?
        .into_iter()
        .map(|point| point.attributes)
        .collect::<Vec<_>>();
    let failed = sorted(vec![
        KeyValue::new("kms_aead.provider", "local"),
        KeyValue::new("kms_aead.operation", "decrypt_dek"),
        KeyValue::new("error.type", error.code().to_string()),
    ]);
    assert!(attributes.contains(&failed), "{attributes:?}");
    for operation in ["encrypt_dek", "decrypt_dek"] {
        let succeeded = sorted(vec![
            KeyValue::new("kms_aead.provider", "local"),
            KeyValue::new("kms_aead.operation", operation),
        ]);
        assert!(attributes.contains(&succeeded), "{attributes:?}");
    }
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
        "kms_aead.plaintext.size",
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
        !points(
            "kms_aead.plaintext.size",
            &[KeyValue::new("kms_aead.mode", "store_less")]
        )?
        .is_empty(),
        "the store-less envelope records its values"
    );
    assert!(attributes > 0);
    Ok(())
}
