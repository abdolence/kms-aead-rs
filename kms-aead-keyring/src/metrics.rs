//! The OpenTelemetry instruments of the keyring, of the `opentelemetry` feature. Dashboards and
//! alerts depend on their names, units and attributes, so they change only in a breaking release.
//!
//! Without the feature every call here runs the operation it is given and nothing else.
//!
//! The instruments come from the global meter provider the first time a keyring call records
//! one, and stay bound to that provider: an application installs its provider before that call,
//! or the instruments record nothing for the life of the process. No attribute carries plaintext,
//! AAD, cipher text or key material, only identifiers, and lengths only as counter increments.

use std::future::Future;

use kms_aead::formats::{Deterministic, Format, Randomized};

use crate::errors::KeyringResult;
use crate::spans::LoadReason;
use crate::store::StoreKind;
use crate::{Encrypted, KeyId, KeyringId, Purpose};

/// The formats of the values a keyring version seals.
pub(crate) trait VersionedFormat: Format + Sized {
    /// The version `value` is sealed under, and the length of its plaintext: the value's length
    /// less Tink's 5-byte output prefix and the algorithm's own overhead.
    #[cfg_attr(not(feature = "opentelemetry"), allow(dead_code))]
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize);
}

/// The 12-byte nonce and the 16-byte tag of every randomised algorithm.
impl VersionedFormat for Randomized {
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize) {
        let overhead = 5 + 12 + 16;
        (value.key_id(), value.value().len().saturating_sub(overhead))
    }
}

/// The 16-byte synthetic IV of AES-SIV.
impl VersionedFormat for Deterministic {
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize) {
        let overhead = 5 + 16;
        (value.key_id(), value.value().len().saturating_sub(overhead))
    }
}

/// The `keyring` attribute of one keyring, built once when the keyring is opened so that a call
/// does not copy the id.
#[derive(Debug)]
pub(crate) struct KeyringAttribute {
    #[cfg(feature = "opentelemetry")]
    value: opentelemetry::StringValue,
}

impl KeyringAttribute {
    #[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
    pub(crate) fn new(id: &KeyringId) -> Self {
        Self {
            #[cfg(feature = "opentelemetry")]
            value: std::sync::Arc::<str>::from(id.as_str()).into(),
        }
    }
}

/// Runs `seal`, a seal of one value under the active version of `purpose`, and with the feature
/// records its duration and, when it succeeds, the value and its plaintext bytes under the
/// version it names.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn encrypt<T, F: VersionedFormat>(
    keyring: &KeyringAttribute,
    purpose: Purpose,
    seal: impl Future<Output = KeyringResult<Encrypted<T, F>>>,
) -> KeyringResult<Encrypted<T, F>> {
    #[cfg(feature = "opentelemetry")]
    {
        let started = std::time::Instant::now();
        let result = seal.await;
        instruments::record_call(
            keyring,
            purpose,
            "encrypt",
            started.elapsed(),
            result.as_ref().err(),
        );
        if let Ok(sealed) = &result {
            instruments::record_value(keyring, purpose, "encrypt", sealed);
        }
        result
    }
    #[cfg(not(feature = "opentelemetry"))]
    seal.await
}

/// Runs `open`, the opening of `value`, and with the feature records its duration and, when it
/// succeeds, the value and its plaintext bytes under the version `value` names.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn decrypt<T, F: VersionedFormat, R>(
    keyring: &KeyringAttribute,
    purpose: Purpose,
    value: &Encrypted<T, F>,
    open: impl Future<Output = KeyringResult<R>>,
) -> KeyringResult<R> {
    #[cfg(feature = "opentelemetry")]
    {
        let started = std::time::Instant::now();
        let result = open.await;
        instruments::record_call(
            keyring,
            purpose,
            "decrypt",
            started.elapsed(),
            result.as_ref().err(),
        );
        if result.is_ok() {
            instruments::record_value(keyring, purpose, "decrypt", value);
        }
        result
    }
    #[cfg(not(feature = "opentelemetry"))]
    open.await
}

/// Runs `probes`, the deterministic probes of one plaintext, and with the feature records its
/// duration. Probes are not stored, so they count no value.
#[cfg(feature = "deterministic")]
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn probe<R>(
    keyring: &KeyringAttribute,
    probes: impl Future<Output = KeyringResult<R>>,
) -> KeyringResult<R> {
    #[cfg(feature = "opentelemetry")]
    {
        let started = std::time::Instant::now();
        let result = probes.await;
        instruments::record_call(
            keyring,
            Purpose::Deterministic,
            "probe",
            started.elapsed(),
            result.as_ref().err(),
        );
        result
    }
    #[cfg(not(feature = "opentelemetry"))]
    probes.await
}

/// With the feature, records one store read of `keyring` for `reason` that took `elapsed`.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) fn record_store_load<T>(
    keyring: &KeyringAttribute,
    store: StoreKind,
    reason: LoadReason,
    elapsed: std::time::Duration,
    result: &KeyringResult<T>,
) {
    #[cfg(feature = "opentelemetry")]
    instruments::record_store_load(keyring, store, reason, elapsed, result.as_ref().err());
}

#[cfg(feature = "opentelemetry")]
mod instruments {
    use std::sync::LazyLock;
    use std::time::Duration;

    use opentelemetry::metrics::{Counter, Histogram};
    use opentelemetry::{InstrumentationScope, KeyValue};

    use super::{KeyringAttribute, VersionedFormat};
    use crate::spans::LoadReason;
    use crate::store::StoreKind;
    use crate::{Encrypted, KeyringError, Purpose};

    /// The bucket bounds of a keyring call, in seconds: from the microsecond of a seal with a
    /// cached key up to the KMS round trip of a cache miss.
    const CALL_DURATION_BOUNDS: [f64; 19] = [
        0.00001, 0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025,
        0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];

    /// The bucket bounds of a store read, in seconds: those OpenTelemetry's semantic
    /// conventions give for HTTP durations.
    const NETWORK_DURATION_BOUNDS: [f64; 14] = [
        0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
    ];

    struct Instruments {
        values: Counter<u64>,
        plaintext: Counter<u64>,
        call_duration: Histogram<f64>,
        store_duration: Histogram<f64>,
    }

    static INSTRUMENTS: LazyLock<Instruments> = LazyLock::new(|| {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = opentelemetry::global::meter_with_scope(scope);
        Instruments {
            values: meter
                .u64_counter("kms_aead_keyring.values")
                .with_unit("{value}")
                .with_description("The values sealed or opened under a key version")
                .build(),
            plaintext: meter
                .u64_counter("kms_aead_keyring.plaintext")
                .with_unit("By")
                .with_description("The plaintext bytes sealed or opened under a key version")
                .build(),
            call_duration: meter
                .f64_histogram("kms_aead_keyring.operation.duration")
                .with_unit("s")
                .with_description("The time a keyring encrypt, decrypt or probe call took")
                .with_boundaries(CALL_DURATION_BOUNDS.to_vec())
                .build(),
            store_duration: meter
                .f64_histogram("kms_aead_keyring.store.duration")
                .with_unit("s")
                .with_description("The time a read of a keyring record from its store took")
                .with_boundaries(NETWORK_DURATION_BOUNDS.to_vec())
                .build(),
        }
    });

    impl KeyringAttribute {
        fn key_value(&self) -> KeyValue {
            KeyValue::new("keyring", self.value.clone())
        }
    }

    pub(super) fn record_value<T, F: VersionedFormat>(
        keyring: &KeyringAttribute,
        purpose: Purpose,
        operation: &'static str,
        value: &Encrypted<T, F>,
    ) {
        let (key_id, plaintext_len) = F::version_and_plaintext_len(value);
        let attributes = [
            keyring.key_value(),
            KeyValue::new("purpose", purpose.as_str()),
            KeyValue::new("key_id", i64::from(key_id.as_u32())),
            KeyValue::new("operation", operation),
        ];
        let instruments = &*INSTRUMENTS;
        instruments.values.add(1, &attributes);
        instruments.plaintext.add(
            u64::try_from(plaintext_len).unwrap_or(u64::MAX),
            &attributes,
        );
    }

    pub(super) fn record_call(
        keyring: &KeyringAttribute,
        purpose: Purpose,
        operation: &'static str,
        elapsed: Duration,
        error: Option<&KeyringError>,
    ) {
        let attributes = [
            keyring.key_value(),
            KeyValue::new("purpose", purpose.as_str()),
            KeyValue::new("operation", operation),
        ];
        record_duration(&INSTRUMENTS.call_duration, attributes, elapsed, error);
    }

    pub(super) fn record_store_load(
        keyring: &KeyringAttribute,
        store: StoreKind,
        reason: LoadReason,
        elapsed: Duration,
        error: Option<&KeyringError>,
    ) {
        let attributes = [
            keyring.key_value(),
            KeyValue::new("store", store.to_string()),
            KeyValue::new("reason", reason.as_str()),
        ];
        record_duration(&INSTRUMENTS.store_duration, attributes, elapsed, error);
    }

    /// Records `elapsed` with `attributes`, and with the code of `error` when the call failed.
    fn record_duration(
        histogram: &Histogram<f64>,
        attributes: [KeyValue; 3],
        elapsed: Duration,
        error: Option<&KeyringError>,
    ) {
        match error {
            None => histogram.record(elapsed.as_secs_f64(), &attributes),
            Some(error) => {
                let mut attributes = attributes.to_vec();
                attributes.push(KeyValue::new("error_code", error.code().to_owned()));
                histogram.record(elapsed.as_secs_f64(), &attributes);
            }
        }
    }
}
