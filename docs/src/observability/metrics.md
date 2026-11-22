# Metrics

With the `opentelemetry` feature, kms-aead records OpenTelemetry metrics for every envelope call
and KMS request. kms-aead-keyring's `opentelemetry` feature turns it on, and the keyring records
into the same instruments, with its own attributes. Both depend on the `opentelemetry` API crate
only (no SDK): the application installs the SDK and an exporter, such as OTLP with
`opentelemetry-otlp` or Prometheus with `opentelemetry-prometheus`. Without the feature neither
crate depends on OpenTelemetry.

The instruments come from the global meter provider, with an instrumentation scope named after
kms-aead and its version, the first time either crate records, and stay bound to it for the life
of the process. Be aware to install the provider before the first KMS, envelope or keyring call,
otherwise the instruments record nothing:

```rust
use opentelemetry::Key;
use opentelemetry_sdk::metrics::exporter::PushMetricExporter;
use opentelemetry_sdk::metrics::{Aggregation, Instrument, SdkMeterProvider, Stream};

fn install_meter_provider(exporter: impl PushMetricExporter) -> SdkMeterProvider {
    let provider = SdkMeterProvider::builder()
        .with_periodic_exporter(exporter)
        // The plaintext size without its smallest and largest value, see below.
        .with_view(|instrument: &Instrument| {
            if instrument.name() != "kms_aead.plaintext.size" {
                return None;
            }
            Stream::builder()
                .with_aggregation(Aggregation::ExplicitBucketHistogram {
                    boundaries: Vec::new(),
                    record_min_max: false,
                })
                .build()
                .ok()
        })
        // Optional: the durations without `kms_aead.keyring`, see below.
        .with_view(|instrument: &Instrument| {
            let kept: &[&'static str] = match instrument.name() {
                "kms_aead.operation.duration" => &[
                    "kms_aead.operation",
                    "kms_aead.mode",
                    "kms_aead.algorithm",
                    "kms_aead.backend",
                    "kms_aead.purpose",
                    "error.type",
                ],
                "kms_aead.store.duration" => &["kms_aead.store", "kms_aead.reason", "error.type"],
                _ => return None,
            };
            Stream::builder()
                .with_allowed_attribute_keys(kept.iter().map(|key| Key::from_static_str(key)))
                .build()
                .ok()
        })
        .build();
    opentelemetry::global::set_meter_provider(provider.clone());
    provider
}
# let provider = install_meter_provider(opentelemetry_sdk::metrics::InMemoryMetricExporter::default());
# provider.shutdown().unwrap();
```

The names follow OpenTelemetry's semantic conventions: the library's own attributes have the
`kms_aead.` prefix, and a failed call carries `error.type`, the code of its error. A successful
call has no `error.type`.

| Instrument | Type | Unit | Attributes | Keyring calls add |
|---|---|---|---|---|
| `kms_aead.plaintext.size` | histogram, no buckets | `By` | `kms_aead.operation`, `kms_aead.mode`, `kms_aead.algorithm`, `kms_aead.backend` | `kms_aead.keyring`, `kms_aead.purpose`, `kms_aead.key_id` |
| `kms_aead.operation.duration` | histogram | `s` | `kms_aead.operation`, `kms_aead.mode`, `kms_aead.algorithm`, `kms_aead.backend`, `error.type` | `kms_aead.keyring`, `kms_aead.purpose` |
| `kms_aead.kms.duration` | histogram | `s` | `kms_aead.provider`, `kms_aead.operation`, `error.type` | |
| `kms_aead.store.duration` | histogram | `s` | `kms_aead.keyring`, `kms_aead.store`, `kms_aead.reason`, `error.type` | |
| `kms_aead.record.refusals` | counter | `{record}` | `kms_aead.keyring`, `error.type` | |

- `kms_aead.plaintext.size` records the plaintext length of each value encrypted or decrypted: its
  count is the values, and its sum their bytes. It has no buckets. The SDK also keeps the smallest
  and the largest value of each series and OTLP exports them, unless a view turns them off as above.
  A failed call records no value;
- `kms_aead.operation` of a value is `encrypt` or `decrypt`. The envelope also times `beacon`,
  `generate_dek` for `generate_encrypted_dek` and `generate_encrypted_deterministic_dek`,
  `decrypt_dek` for `decrypt_deterministic_dek`, and `reencrypt_dek` for `reencrypt_dek`,
  `reencrypt_encrypted_dek` and the deprecated `upgrade_legacy_value` and
  `upgrade_legacy_encrypted_dek`;
- `kms_aead.mode` is the envelope's `per_call` or `store_less` for `encrypt`, `decrypt`, the
  stream calls, `reencrypt_dek` and `upgrade_legacy_value`, `caller_dek` for the `*_with_dek` and
  `*_with_encrypted_dek` calls, `beacon`, the calls that generate or decrypt a DEK,
  `reencrypt_encrypted_dek` and `upgrade_legacy_encrypted_dek`, and `keyring` for a keyring's
  calls. A `Signer` and a `Verifier` record `sign` and `verify` with the mode `signature`, and an
  `Authenticator` records `mac` and `verify_mac` with the mode `caller_dek`;
- `kms_aead.algorithm` and `kms_aead.backend` are those of the span. `kms_aead.algorithm` is
  absent where it is unknown: on a re-encryption, in which the algorithm plays no part, on a probe,
  which runs under every version, and on a keyring call that fails before it finds its version. A keyring's
  deterministic call has `kms_aead.backend` `rustcrypto`, since AES-SIV runs on RustCrypto
  whatever the keyring's backend;
- a keyring call is recorded once, with `kms_aead.mode` `keyring`: it runs kms-aead's ciphers, never
  its envelope. `encrypt` is an encryptor's `encrypt` and `encrypt_deterministic`, `decrypt` is
  `decrypt`, `decrypt_with_trust` and their deterministic pair, `reencrypt` is `reencrypt` and
  `reencrypt_deterministic`, which also record the `decrypt` and `encrypt` they make, `beacon` is an
  encryptor's `beacon`, and `probe` is `beacon_probes` and `deterministic_probes`.
  `decrypt_envelope_for_migration` is a `decrypt` with no `kms_aead.purpose`. `kms_aead.key_id` is
  the version's key id, as a number;
- probes and beacons record no value. A probe is never stored, and a beacon is an HMAC-SHA256
  output: HMAC takes no nonce, and its bound as a PRF is far beyond the values one key can encrypt.
  Signatures and MACs record no value either. A keyring's MAC calls add no keyring call of their
  own: the `Authenticator` they run records each one;
- `kms_aead.kms.duration` covers the request to the KMS only, as the span's `response_time` does.
  `kms_aead.operation` is `encrypt_dek`, `decrypt_dek`, `random`, `sign` or `public_key`, or
  `encrypt_dek_with_public_key` for an encryption with the public key of an asymmetric KEK, which is
  a local operation and no KMS request, so that the duration tells the two apart.
  `kms_aead.provider` is the span's `provider`. The KEK name is left out;
- `kms_aead.store.duration` covers every read of a keyring record, with the `store` and `reason`
  of the `Keyring load` span;
- the stream calls of an envelope, `stream_encryptor`, `stream_decryptor` and their bare forms, and
  a keyring's `stream_encryptor` and `stream_decryptor` are recorded in
  `kms_aead.operation.duration` with `kms_aead.operation` `stream_encrypt` and `stream_decrypt`. The
  plaintext size instrument records nothing for them, since the size is not known at the call.
  `AeadCipher`'s stream calls open no span;
- `kms_aead.record.refusals` counts each keyring record a process refused because of its
  signature, by code in `error.type`: `RECORD_UNSIGNED`, `RECORD_SIGNATURE_INVALID` or
  `RECORD_SIGNATURE_REMOVED`. It is the metric of the `ERROR` event for a record refused by record verification, see
  [Keyring events](./spans-and-events.md#keyring-events).

No attribute names a DEK, so the envelope's values are recorded per algorithm, not per key. A
store-less envelope needs no alert on them: it renews its DEK at `max_uses` and `max_bytes`, see
[Volume limit](../dek-caching.md#volume-limit).

A Prometheus exporter adds the unit to the name and replaces the dots with underscores:
`kms_aead_plaintext_size_bytes_count` and `kms_aead_plaintext_size_bytes_sum`,
`kms_aead_operation_duration_seconds`, and attributes such as `kms_aead_key_id`. For an alert on
the values and bytes under one keyring version, see
[Alerting on volume](../production/monitoring.md#alerting-on-volume).

The keyring's plaintext size has one time series per keyring, purpose, key version and operation.
With a keyring per tenant, that is a series per tenant and version. Under cumulative temporality,
the default, the SDK keeps a series until the process restarts, also once its version is no longer
used. The SDK keeps at most 2000 attribute sets per instrument and records every further one into
one series with the attribute `otel.metric.overflow`, with no error: an alert per version stops
counting the versions past the limit. Raise the limit with
`Stream::builder().with_cardinality_limit` in a view where the keyrings and their versions come near
it. Key ids are numbered per keyring, so the plaintext size keeps
`kms_aead.keyring`: without it, version 1 of every keyring would add up to one series. The
duration histograms do not need it, and with their buckets they cost the most series, so the view
above drops it from them. The view's `with_allowed_attribute_keys` needs the SDK's
`spec_unstable_metrics_views` feature.
