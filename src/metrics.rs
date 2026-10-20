//! The OpenTelemetry metrics of kms-aead and kms-aead-keyring, of the `opentelemetry` feature.
//! Dashboards and alerts depend on the names, units and attributes of the instruments, so they
//! change only in a breaking release. The names follow OpenTelemetry's semantic conventions: the
//! library's own attributes are under `kms_aead.`, and a failed call carries `error.type`.
//!
//! Without the feature a [`Measurement`] records nothing and reads no clock.
//!
//! The instruments come from the global meter provider the first time either crate records one,
//! and stay bound to that provider: an application installs its provider before that call, or
//! the instruments record nothing for the life of the process. No attribute carries plaintext,
//! AAD, cipher text or key material, only identifiers; a length is recorded only as the plaintext
//! size of a value.

#[cfg(feature = "opentelemetry")]
pub(crate) use instruments::{record_kms_call, Measurement};
#[cfg(not(feature = "opentelemetry"))]
pub(crate) use unrecorded::{record_kms_call, Measurement};

/// The attributes every call of either crate carries: `kms_aead.operation`, `kms_aead.mode`,
/// `kms_aead.backend` and, when the call knows it, `kms_aead.algorithm`.
#[cfg_attr(
    not(feature = "opentelemetry"),
    expect(
        dead_code,
        reason = "only the `opentelemetry` feature records the attributes"
    )
)]
pub struct Call {
    /// `encrypt`, `decrypt`, `reseal`, `beacon`, `probe`, `generate_dek` or `reencrypt_dek`.
    pub operation: &'static str,
    /// `per_call`, `store_less`, `caller_dek` or `keyring`.
    pub mode: &'static str,
    /// The [`AeadBackend::NAME`](crate::backends::AeadBackend::NAME) the call runs on.
    pub backend: &'static str,
    /// The algorithm's `as_str`, or `None` when the call has none or fails before it finds one.
    pub algorithm: Option<&'static str>,
}

/// The instruments, shared with kms-aead-keyring so that both crates record into one set. Not part
/// of the public API, so it changes only in a minor release of kms-aead, which kms-aead-keyring
/// requires to match its own. The names, units and attributes are public, and the book documents
/// them.
#[cfg(feature = "opentelemetry")]
pub mod instruments {
    use std::sync::LazyLock;
    use std::time::{Duration, Instant};

    use opentelemetry::metrics::Histogram;
    use opentelemetry::{InstrumentationScope, KeyValue};

    pub use super::Call;
    use crate::formats::Format;
    use crate::{Encrypted, KekProvider, KeyId, KmsAeadResult};

    const OPERATION: &str = "kms_aead.operation";
    const MODE: &str = "kms_aead.mode";
    const BACKEND: &str = "kms_aead.backend";
    const ALGORITHM: &str = "kms_aead.algorithm";
    const PROVIDER: &str = "kms_aead.provider";
    const KEY_ID: &str = "kms_aead.key_id";
    /// OpenTelemetry's attribute of the class of error a call ended with, set only on failure.
    const ERROR_TYPE: &str = "error.type";

    /// The bucket bounds of an operation, in seconds: from the microseconds of a seal with a
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
                .with_description("The plaintext size of each value sealed or opened")
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
        }
    });

    /// How a call ended, as its metrics record it.
    pub enum Outcome<'a> {
        /// It sealed or opened one value.
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

    impl Outcome<'_> {
        /// A call that sealed or opened `value`, under the keyring version `key_id` for a keyring
        /// call.
        pub fn value<T, F: Format>(value: &Encrypted<T, F>, key_id: Option<KeyId>) -> Self {
            Outcome::Value {
                plaintext_len: F::plaintext_len(value.value()),
                key_id,
            }
        }
    }

    /// Records one call with `call`'s attributes and `extra`, the caller's own, that took
    /// `elapsed` and ended with `outcome`. A value is recorded in `kms_aead.plaintext.size` with
    /// the duration's attributes and `kms_aead.key_id`.
    pub fn record_operation(
        call: &Call,
        extra: impl IntoIterator<Item = KeyValue>,
        elapsed: Duration,
        outcome: Outcome<'_>,
    ) {
        let mut attributes = Vec::with_capacity(8);
        attributes.extend([
            KeyValue::new(OPERATION, call.operation),
            KeyValue::new(MODE, call.mode),
            KeyValue::new(BACKEND, call.backend),
        ]);
        attributes.extend(
            call.algorithm
                .map(|algorithm| KeyValue::new(ALGORITHM, algorithm)),
        );
        attributes.extend(extra);
        let instruments = &*INSTRUMENTS;
        match outcome {
            Outcome::Value {
                plaintext_len,
                key_id,
            } => {
                instruments
                    .operation_duration
                    .record(elapsed.as_secs_f64(), &attributes);
                // OpenTelemetry has integer attributes in `i64` only.
                attributes
                    .extend(key_id.map(|key_id| KeyValue::new(KEY_ID, i64::from(key_id.as_u32()))));
                instruments.plaintext_size.record(
                    u64::try_from(plaintext_len).unwrap_or(u64::MAX),
                    &attributes,
                );
            }
            Outcome::Succeeded => instruments
                .operation_duration
                .record(elapsed.as_secs_f64(), &attributes),
            Outcome::Failed { error_type } => {
                attributes.push(KeyValue::new(ERROR_TYPE, error_type.to_owned()));
                instruments
                    .operation_duration
                    .record(elapsed.as_secs_f64(), &attributes);
            }
        }
    }

    /// Records one read of a keyring record with `attributes` that took `elapsed` and, for a
    /// failed read, its error code `error_type`.
    pub fn record_store_load(
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

    /// Records one request of `operation` to `provider`'s KMS that took `elapsed` and ended with
    /// `result`.
    pub(crate) fn record_kms_call<T>(
        operation: &'static str,
        provider: &KekProvider,
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
        call: Call,
        started: Instant,
    }

    impl Measurement {
        pub(crate) fn start(call: Call) -> Self {
            Self {
                call,
                started: Instant::now(),
            }
        }

        /// Records the call as ended with `result`, the value it sealed.
        pub(crate) fn sealed<T, F: Format>(self, result: &KmsAeadResult<Encrypted<T, F>>) {
            self.finish(result, |sealed| Outcome::value(sealed, None));
        }

        /// Records the call as ended with `result`, the opening of `value`.
        pub(crate) fn opened<T, F: Format, R>(
            self,
            value: &Encrypted<T, F>,
            result: &KmsAeadResult<R>,
        ) {
            self.finish(result, |_| Outcome::value(value, None));
        }

        /// Records the call as ended with `result`, which holds no value to count.
        pub(crate) fn finished<R>(self, result: &KmsAeadResult<R>) {
            self.finish(result, |_| Outcome::Succeeded);
        }

        fn finish<'a, R>(
            self,
            result: &'a KmsAeadResult<R>,
            succeeded: impl FnOnce(&'a R) -> Outcome<'a>,
        ) {
            let elapsed = self.started.elapsed();
            let outcome = match result {
                Ok(value) => succeeded(value),
                Err(error) => Outcome::Failed {
                    error_type: error.code(),
                },
            };
            record_operation(&self.call, [], elapsed, outcome);
        }
    }
}

/// The calls of `instruments` that record nothing, for a build without the feature.
#[cfg(not(feature = "opentelemetry"))]
mod unrecorded {
    use std::time::Duration;

    use super::Call;
    use crate::formats::Format;
    use crate::{Encrypted, KekProvider, KmsAeadResult};

    pub(crate) fn record_kms_call<T>(
        _: &'static str,
        _: &KekProvider,
        _: Duration,
        _: &KmsAeadResult<T>,
    ) {
    }

    pub(crate) struct Measurement;

    impl Measurement {
        pub(crate) fn start(_: Call) -> Self {
            Self
        }

        pub(crate) fn sealed<T, F: Format>(self, _: &KmsAeadResult<Encrypted<T, F>>) {}

        pub(crate) fn opened<T, F: Format, R>(self, _: &Encrypted<T, F>, _: &KmsAeadResult<R>) {}

        pub(crate) fn finished<R>(self, _: &KmsAeadResult<R>) {}
    }
}
