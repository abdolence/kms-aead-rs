//! The OpenTelemetry instruments of kms-aead and kms-aead-keyring, of the `opentelemetry`
//! feature. Dashboards and alerts depend on their names, units and attributes, so they change only
//! in a breaking release.
//!
//! Without the feature every call here runs the operation it is given and nothing else.
//!
//! The instruments come from the global meter provider the first time either crate records one,
//! and stay bound to that provider: an application installs its provider before that call, or
//! the instruments record nothing for the life of the process. No attribute carries plaintext,
//! AAD, cipher text or key material, only identifiers, and lengths only as counter increments.

use std::future::Future;

use crate::{AeadAlgorithm, KmsAeadResult};

/// One envelope call, as the attributes of its metrics.
#[cfg_attr(not(feature = "opentelemetry"), allow(dead_code))]
pub(crate) struct EnvelopeCall {
    pub(crate) operation: &'static str,
    pub(crate) mode: &'static str,
    pub(crate) algorithm: AeadAlgorithm,
    pub(crate) backend: &'static str,
}

/// Runs `operation`, which returns its value and the length of the plaintext it sealed or opened,
/// and with the feature records its duration and, when it succeeds, the value and its plaintext
/// bytes.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn measured<T>(
    call: EnvelopeCall,
    operation: impl Future<Output = KmsAeadResult<(T, usize)>>,
) -> KmsAeadResult<T> {
    #[cfg(feature = "opentelemetry")]
    let started = std::time::Instant::now();
    let result = operation.await;
    #[cfg(feature = "opentelemetry")]
    record(&call, started.elapsed(), &result);
    result.map(|(value, _)| value)
}

/// [`measured`] for an operation that does not wait.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) fn measured_now<T>(
    call: EnvelopeCall,
    operation: impl FnOnce() -> KmsAeadResult<(T, usize)>,
) -> KmsAeadResult<T> {
    #[cfg(feature = "opentelemetry")]
    let started = std::time::Instant::now();
    let result = operation();
    #[cfg(feature = "opentelemetry")]
    record(&call, started.elapsed(), &result);
    result.map(|(value, _)| value)
}

#[cfg(feature = "opentelemetry")]
fn record<T>(
    call: &EnvelopeCall,
    elapsed: std::time::Duration,
    result: &KmsAeadResult<(T, usize)>,
) {
    use opentelemetry::KeyValue;

    let attributes = [
        KeyValue::new("operation", call.operation),
        KeyValue::new("mode", call.mode),
        KeyValue::new("algorithm", call.algorithm.as_str()),
        KeyValue::new("backend", call.backend),
    ];
    match result {
        Ok((_, plaintext_len)) => {
            instruments::record_value(&attributes, *plaintext_len);
            instruments::record_operation(&attributes, elapsed, None);
        }
        Err(error) => instruments::record_operation(&attributes, elapsed, Some(error.code())),
    }
}

/// The instruments, shared with kms-aead-keyring so that both crates record into one set. Not part
/// of the public API: the names, units and attributes are, and the book documents them.
#[cfg(feature = "opentelemetry")]
pub mod instruments {
    use std::sync::LazyLock;
    use std::time::Duration;

    use opentelemetry::metrics::{Counter, Histogram};
    use opentelemetry::{InstrumentationScope, KeyValue};

    use crate::{AeadAlgorithm, DeterministicAlgorithm, KekProvider};

    /// The bucket bounds of an encrypt or decrypt call, in seconds: from the microseconds of a
    /// seal with a cached key up to the KMS round trip of a cache miss.
    const OPERATION_DURATION_BOUNDS: [f64; 19] = [
        0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025,
        0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// The bucket bounds of a call over the network, in seconds: those OpenTelemetry's semantic
    /// conventions give for HTTP durations.
    const NETWORK_DURATION_BOUNDS: [f64; 14] = [
        0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
    ];

    struct Instruments {
        values: Counter<u64>,
        plaintext: Counter<u64>,
        operation_duration: Histogram<f64>,
        kms_duration: Histogram<f64>,
        store_duration: Histogram<f64>,
    }

    static INSTRUMENTS: LazyLock<Instruments> = LazyLock::new(|| {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = opentelemetry::global::meter_with_scope(scope);
        Instruments {
            values: meter
                .u64_counter("kms_aead.values")
                .with_unit("{value}")
                .with_description("The values sealed or opened")
                .build(),
            plaintext: meter
                .u64_counter("kms_aead.plaintext")
                .with_unit("By")
                .with_description("The plaintext bytes sealed or opened")
                .build(),
            operation_duration: meter
                .f64_histogram("kms_aead.operation.duration")
                .with_unit("s")
                .with_description("The time an encrypt, decrypt or probe call took")
                .with_boundaries(OPERATION_DURATION_BOUNDS.to_vec())
                .build(),
            kms_duration: meter
                .f64_histogram("kms_aead.kms.duration")
                .with_unit("s")
                .with_description("The time a request to a KMS took, from send to response")
                .with_boundaries(NETWORK_DURATION_BOUNDS.to_vec())
                .build(),
            store_duration: meter
                .f64_histogram("kms_aead.store.duration")
                .with_unit("s")
                .with_description("The time a read of a keyring record from its store took")
                .with_boundaries(NETWORK_DURATION_BOUNDS.to_vec())
                .build(),
        }
    });

    /// Records one value of `plaintext_len` bytes sealed or opened, with `attributes`.
    pub fn record_value(attributes: &[KeyValue], plaintext_len: usize) {
        let instruments = &*INSTRUMENTS;
        instruments.values.add(1, attributes);
        instruments
            .plaintext
            .add(u64::try_from(plaintext_len).unwrap_or(u64::MAX), attributes);
    }

    /// Records one encrypt, decrypt or probe call that took `elapsed`, with `attributes` and, for
    /// a failed call, its `error_code`.
    pub fn record_operation(attributes: &[KeyValue], elapsed: Duration, error_code: Option<&str>) {
        record_duration(
            &INSTRUMENTS.operation_duration,
            attributes,
            elapsed,
            error_code,
        );
    }

    /// Records one read of a keyring record that took `elapsed`, with `attributes` and, for a
    /// failed read, its `error_code`.
    pub fn record_store_load(attributes: &[KeyValue], elapsed: Duration, error_code: Option<&str>) {
        record_duration(&INSTRUMENTS.store_duration, attributes, elapsed, error_code);
    }

    /// The `algorithm` attribute of a randomised algorithm.
    pub fn aead_algorithm_name(algorithm: AeadAlgorithm) -> &'static str {
        algorithm.as_str()
    }

    /// The `algorithm` attribute of a deterministic algorithm.
    pub fn deterministic_algorithm_name(algorithm: DeterministicAlgorithm) -> &'static str {
        algorithm.as_str()
    }

    /// Records one request of `operation` to `provider`'s KMS that took `elapsed`, with
    /// `outcome` `success` or `failure`.
    pub(crate) fn record_kms_call(
        operation: &'static str,
        provider: &KekProvider,
        elapsed: Duration,
        failed: bool,
    ) {
        INSTRUMENTS.kms_duration.record(
            elapsed.as_secs_f64(),
            &[
                KeyValue::new("provider", provider.to_string()),
                KeyValue::new("operation", operation),
                KeyValue::new("outcome", if failed { "failure" } else { "success" }),
            ],
        );
    }

    fn record_duration(
        histogram: &Histogram<f64>,
        attributes: &[KeyValue],
        elapsed: Duration,
        error_code: Option<&str>,
    ) {
        match error_code {
            None => histogram.record(elapsed.as_secs_f64(), attributes),
            Some(code) => {
                let mut attributes = attributes.to_vec();
                attributes.push(KeyValue::new("error_code", code.to_owned()));
                histogram.record(elapsed.as_secs_f64(), &attributes);
            }
        }
    }
}
