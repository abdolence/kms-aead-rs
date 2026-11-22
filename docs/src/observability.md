# Observability

kms-aead and kms-aead-keyring report what they do through
[tracing](https://github.com/tokio-rs/tracing) spans and events, and through OpenTelemetry metrics:

- [Spans and events](./observability/spans-and-events.md): one `DEBUG` span for every envelope call,
  KMS call and keyring call, with the fields of each; the events both crates log; how to show the
  spans and export them as OpenTelemetry traces; and the event of a JSON value that does not decode;
- [Metrics](./observability/metrics.md): the OpenTelemetry instruments of the `opentelemetry`
  feature, the views that leave out the smallest and the largest plaintext size and that limit the
  number of series, and the Prometheus names.

## What is never logged

No span field or event carries:

- plaintext, DEKs in any form, plaintext or encrypted, or KEK material;
- AAD content, which can hold entity ids and so personal data;
- cipher text bytes;
- the length of a value or of its AAD. For AES-256-GCM the plaintext length is the value's length
  minus a fixed overhead, and a length tells short values such as `yes`, `no` or a country code
  apart.

The `kms_aead.plaintext.size` histogram is the exception: it adds up plaintext lengths. A keyring or
an envelope that encrypts one value per export interval gives that value's length to whoever reads
the metrics. The SDK also keeps the smallest and the largest value of each series, under cumulative
temporality since the process started, and OTLP exports them: the exact length of the shortest and
the longest value per keyring and version, at any traffic. A Prometheus exporter exports neither.
The OpenTelemetry API gives kms-aead's instrument no setting to leave them out, so the view in
[Metrics](./observability/metrics.md#metrics) turns them off with `record_min_max: false`. Treat
the histogram like the values themselves where traffic is low, and everywhere without that view.

The [`kms_aead::json` event](./observability/spans-and-events.md#json-that-does-not-decode) is the
other exception, under a policy that opts in: its outline then carries the length of the values and
keys of the JSON that did not decode, [which gives away a hidden
boolean](https://docs.rs/kms-aead/latest/kms_aead/redaction/trait.JsonRedaction.html#associatedconstant.SIZES),
and the values the policy reveals. The default policy carries neither, but every policy shows serde_json's message for
a syntax error, which is fixed text and can state a property of a hidden value, such as
`number out of range`.

Key identifiers are recorded: KEK names, key versions and local KEK ids. A KEK name identifies the
project, the location and the key, and a per-tenant KEK name carries the tenant id, so treat the
`key` field accordingly in a trace pipeline.

Errors follow the same rules, see [Error handling](./errors.md#what-errors-never-carry).
