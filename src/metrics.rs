//! The OpenTelemetry metrics of kms-aead and kms-aead-keyring, of the `opentelemetry` feature.
//! Dashboards and alerts depend on the names, units and attributes of the instruments, so they
//! change only in a breaking release. The names follow OpenTelemetry's semantic conventions: the
//! library's own attributes are under `kms_aead.`, and a failed call carries `error.type`. The
//! book's [Metrics](https://kms-aead-rust.abdolence.dev/observability/metrics.html) page lists
//! them.
//!
//! The instruments come from the global meter provider the first time either crate records one,
//! and stay bound to that provider: an application installs its provider before that call, or
//! the instruments record nothing for the life of the process. No attribute carries plaintext,
//! AAD, cipher text or key material, only identifiers; a length is recorded only as the plaintext
//! size of a value.
//!
//! kms-aead records its own calls. The functions here record the calls of a crate built on it,
//! kms-aead-keyring among them, into the same instruments and instrumentation scope, so that an
//! application reads the metrics of both from one scope. The attributes such a crate adds carry
//! identifiers only, as the library's own do.

#[cfg(feature = "opentelemetry")]
pub(crate) use instruments::{Measurement, record_kms_call};
#[cfg(feature = "opentelemetry")]
pub use instruments::{OperationOutcome, count_keyring_record_refusal, record_keyring_store_load};
#[cfg(not(feature = "opentelemetry"))]
pub(crate) use unrecorded::{Measurement, record_kms_call};

/// The attributes every call of either crate carries: `kms_aead.operation`, `kms_aead.mode`,
/// `kms_aead.backend` and, when the call knows it, `kms_aead.algorithm`.
#[cfg_attr(
    not(feature = "opentelemetry"),
    expect(
        dead_code,
        reason = "only the `opentelemetry` feature records the attributes"
    )
)]
pub struct OperationAttributes {
    /// `encrypt`, `decrypt`, `reencrypt`, `beacon`, `probe`, `generate_dek`, `decrypt_dek`,
    /// `reencrypt_dek`, `stream_encrypt`, `stream_decrypt`, `sign`, `verify`, `mac` or
    /// `verify_mac`.
    pub operation: &'static str,
    /// `per_call`, `store_less`, `caller_dek`, `keyring` or `signature`.
    pub mode: &'static str,
    /// The [`AeadBackend::NAME`](crate::backends::AeadBackend::NAME) the call runs on.
    pub backend: &'static str,
    /// The algorithm's `as_str`, or `None` when the call has none or fails before it finds one.
    pub algorithm: Option<&'static str>,
}

/// The instruments, which both crates record into.
#[cfg(feature = "opentelemetry")]
mod instruments {
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};

    use opentelemetry::metrics::{Counter, Histogram};
    use opentelemetry::{InstrumentationScope, KeyValue};

    use super::OperationAttributes;
    use crate::formats::Format;
    use crate::{Encrypted, KeyId, KmsAeadResult, KmsProvider};

    const OPERATION: &str = "kms_aead.operation";
    const MODE: &str = "kms_aead.mode";
    const BACKEND: &str = "kms_aead.backend";
    const ALGORITHM: &str = "kms_aead.algorithm";
    const PROVIDER: &str = "kms_aead.provider";
    const KEY_ID: &str = "kms_aead.key_id";
    /// OpenTelemetry's attribute of the class of error a call ended with, set only on failure.
    const ERROR_TYPE: &str = "error.type";

    /// The bucket bounds of an operation, in seconds: from the microseconds of an encryption with a
    /// cached key up to the KMS round trip of a cache miss.
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
        plaintext_size: Histogram<u64>,
        operation_duration: Histogram<f64>,
        kms_duration: Histogram<f64>,
        store_duration: Histogram<f64>,
        record_refusals: Counter<u64>,
    }

    static INSTRUMENTS: LazyLock<Instruments> = LazyLock::new(|| {
        let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
            .with_version(env!("CARGO_PKG_VERSION"))
            .build();
        let meter = opentelemetry::global::meter_with_scope(scope);
        Instruments {
            // No buckets: its count is the values and its sum their bytes, the two numbers the
            // volume limits of a key bound.
            // The SDK keeps their min and max too, which the API has no setting to leave out:
            // the book's view turns them off.
            plaintext_size: meter
                .u64_histogram("kms_aead.plaintext.size")
                .with_unit("By")
                .with_description("The plaintext size of each value encrypted or decrypted")
                .with_boundaries(Vec::new())
                .build(),
            operation_duration: meter
                .f64_histogram("kms_aead.operation.duration")
                .with_unit("s")
                .with_description("The time a call of the envelope or of a keyring took")
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
            record_refusals: meter
                .u64_counter("kms_aead.record.refusals")
                .with_unit("{record}")
                .with_description(
                    "The keyring records a process refused because of their signature",
                )
                .build(),
        }
    });

    /// How a call ended, as [`OperationAttributes::record`] records it.
    #[non_exhaustive]
    pub enum OperationOutcome<'a> {
        /// It encrypted or decrypted one value. Only [`value`](Self::value) builds it, so that the
        /// size recorded is the plaintext size of a value the call read or wrote.
        #[non_exhaustive]
        Value {
            /// The length of the value's plaintext, in bytes.
            plaintext_len: usize,
            /// The keyring version the value is under, for a keyring call.
            key_id: Option<KeyId>,
        },
        /// It succeeded with no value to count: a beacon, a probe or a call on a DEK.
        Succeeded,
        /// It failed.
        Failed {
            /// The error's code.
            error_type: &'a str,
        },
    }

    impl OperationOutcome<'_> {
        /// A call that encrypted or decrypted `value`, under the keyring version `key_id` for a
        /// keyring call.
        pub fn value<T, F: Format>(value: &Encrypted<T, F>, key_id: Option<KeyId>) -> Self {
            OperationOutcome::Value {
                plaintext_len: F::plaintext_len(value.value()),
                key_id,
            }
        }
    }

    impl OperationAttributes {
        /// Records one call that took `elapsed` and ended with `outcome`: its duration in
        /// `kms_aead.operation.duration`, with these attributes, `extra`, the caller's own, and
        /// `error.type` for a failure, and for a value its plaintext size in
        /// `kms_aead.plaintext.size`, with the same attributes and `kms_aead.key_id`.
        pub fn record(
            &self,
            extra: impl IntoIterator<Item = KeyValue>,
            elapsed: Duration,
            outcome: OperationOutcome<'_>,
        ) {
            let mut attributes = Vec::with_capacity(8);
            attributes.extend([
                KeyValue::new(OPERATION, self.operation),
                KeyValue::new(MODE, self.mode),
                KeyValue::new(BACKEND, self.backend),
            ]);
            attributes.extend(
                self.algorithm
                    .map(|algorithm| KeyValue::new(ALGORITHM, algorithm)),
            );
            attributes.extend(extra);
            let instruments = &*INSTRUMENTS;
            match outcome {
                OperationOutcome::Value {
                    plaintext_len,
                    key_id,
                } => {
                    instruments
                        .operation_duration
                        .record(elapsed.as_secs_f64(), &attributes);
                    // OpenTelemetry has integer attributes in `i64` only.
                    attributes.extend(
                        key_id.map(|key_id| KeyValue::new(KEY_ID, i64::from(key_id.as_u32()))),
                    );
                    instruments.plaintext_size.record(
                        u64::try_from(plaintext_len).unwrap_or(u64::MAX),
                        &attributes,
                    );
                }
                OperationOutcome::Succeeded => instruments
                    .operation_duration
                    .record(elapsed.as_secs_f64(), &attributes),
                OperationOutcome::Failed { error_type } => {
                    attributes.push(KeyValue::new(ERROR_TYPE, error_type.to_owned()));
                    instruments
                        .operation_duration
                        .record(elapsed.as_secs_f64(), &attributes);
                }
            }
        }
    }

    /// Records one read of a keyring record from its store, for kms-aead-keyring: the read's
    /// duration `elapsed` in `kms_aead.store.duration`, with `attributes` and, for a failed read,
    /// `error.type` set to its error code `error_type`.
    pub fn record_keyring_store_load(
        attributes: impl IntoIterator<Item = KeyValue>,
        elapsed: Duration,
        error_type: Option<&str>,
    ) {
        let attributes = attributes
            .into_iter()
            .chain(error_type.map(|code| KeyValue::new(ERROR_TYPE, code.to_owned())))
            .collect::<Vec<_>>();
        INSTRUMENTS
            .store_duration
            .record(elapsed.as_secs_f64(), &attributes);
    }

    /// Counts one keyring record that a process refused because of its signature, for
    /// kms-aead-keyring: one in `kms_aead.record.refusals`, with `attributes` and `error.type` set
    /// to the refusal's code `error_type`.
    pub fn count_keyring_record_refusal(
        attributes: impl IntoIterator<Item = KeyValue>,
        error_type: &str,
    ) {
        let attributes = attributes
            .into_iter()
            .chain([KeyValue::new(ERROR_TYPE, error_type.to_owned())])
            .collect::<Vec<_>>();
        INSTRUMENTS.record_refusals.add(1, &attributes);
    }

    /// Records one request of `operation` to `provider`'s KMS that took `elapsed` and ended with
    /// `result`.
    pub(crate) fn record_kms_call<T>(
        operation: &'static str,
        provider: &KmsProvider,
        elapsed: Duration,
        result: &KmsAeadResult<T>,
    ) {
        let attributes = [
            KeyValue::new(PROVIDER, provider.to_string()),
            KeyValue::new(OPERATION, operation),
        ];
        match result {
            Ok(_) => INSTRUMENTS
                .kms_duration
                .record(elapsed.as_secs_f64(), &attributes),
            Err(error) => {
                let [provider, operation] = attributes;
                INSTRUMENTS.kms_duration.record(
                    elapsed.as_secs_f64(),
                    &[
                        provider,
                        operation,
                        KeyValue::new(ERROR_TYPE, error.code().to_owned()),
                    ],
                );
            }
        }
    }

    /// One call of the envelope, from its start.
    pub(crate) struct Measurement {
        call: OperationAttributes,
        started: Instant,
    }

    impl Measurement {
        pub(crate) fn start(call: OperationAttributes) -> Self {
            Self {
                call,
                started: Instant::now(),
            }
        }

        /// Records the call as ended with `result`, the value it encrypted.
        pub(crate) fn encrypted<T, F: Format>(self, result: &KmsAeadResult<Encrypted<T, F>>) {
            self.finish(result, |encrypted| OperationOutcome::value(encrypted, None));
        }

        /// Records the call as ended with `result`, the decryption of `value`.
        pub(crate) fn decrypted<T, F: Format, R>(
            self,
            value: &Encrypted<T, F>,
            result: &KmsAeadResult<R>,
        ) {
            self.finish(result, |_| OperationOutcome::value(value, None));
        }

        /// Records the call as ended with `result`, which holds no value to count.
        pub(crate) fn finished<R>(self, result: &KmsAeadResult<R>) {
            self.finish(result, |_| OperationOutcome::Succeeded);
        }

        fn finish<'a, R>(
            self,
            result: &'a KmsAeadResult<R>,
            succeeded: impl FnOnce(&'a R) -> OperationOutcome<'a>,
        ) {
            let elapsed = self.started.elapsed();
            let outcome = match result {
                Ok(value) => succeeded(value),
                Err(error) => OperationOutcome::Failed {
                    error_type: error.code(),
                },
            };
            self.call.record([], elapsed, outcome);
        }
    }
}

/// The calls of `instruments` that record nothing, for a build without the feature.
#[cfg(not(feature = "opentelemetry"))]
mod unrecorded {
    use std::time::Duration;

    use super::OperationAttributes;
    use crate::formats::Format;
    use crate::{Encrypted, KmsAeadResult, KmsProvider};

    pub(crate) fn record_kms_call<T>(
        _: &'static str,
        _: &KmsProvider,
        _: Duration,
        _: &KmsAeadResult<T>,
    ) {
    }

    pub(crate) struct Measurement;

    impl Measurement {
        pub(crate) fn start(_: OperationAttributes) -> Self {
            Self
        }

        pub(crate) fn encrypted<T, F: Format>(self, _: &KmsAeadResult<Encrypted<T, F>>) {}

        pub(crate) fn decrypted<T, F: Format, R>(self, _: &Encrypted<T, F>, _: &KmsAeadResult<R>) {}

        pub(crate) fn finished<R>(self, _: &KmsAeadResult<R>) {}
    }
}
