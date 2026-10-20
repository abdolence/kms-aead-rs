//! The OpenTelemetry instruments of kms-aead, of the `opentelemetry` feature. Dashboards and
//! alerts depend on their names, units and attributes, so they change only in a breaking release.
//!
//! The instruments come from the global meter provider the first time a KMS call records one,
//! and stay bound to that provider: an application installs its provider before that call, or
//! the instruments record nothing for the life of the process. No attribute carries key material
//! or a KEK name, only the provider and the call.

use std::sync::LazyLock;
use std::time::Duration;

use opentelemetry::metrics::Histogram;
use opentelemetry::{InstrumentationScope, KeyValue};

use crate::KekProvider;

/// The bucket bounds of a call over the network, in seconds: those OpenTelemetry's semantic
/// conventions give for HTTP durations.
const NETWORK_DURATION_BOUNDS: [f64; 14] = [
    0.005, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0,
];

static KMS_DURATION: LazyLock<Histogram<f64>> = LazyLock::new(|| {
    let scope = InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .build();
    opentelemetry::global::meter_with_scope(scope)
        .f64_histogram("kms_aead.kms.duration")
        .with_unit("s")
        .with_description("The time a request to a KMS took, from send to response")
        .with_boundaries(NETWORK_DURATION_BOUNDS.to_vec())
        .build()
});

/// Records one request of `operation` to `provider`'s KMS that took `elapsed`, with
/// `outcome` `success` or `failure`.
pub(crate) fn record_kms_call(
    operation: &'static str,
    provider: &KekProvider,
    elapsed: Duration,
    failed: bool,
) {
    KMS_DURATION.record(
        elapsed.as_secs_f64(),
        &[
            KeyValue::new("provider", provider.to_string()),
            KeyValue::new("operation", operation),
            KeyValue::new("outcome", if failed { "failure" } else { "success" }),
        ],
    );
}
