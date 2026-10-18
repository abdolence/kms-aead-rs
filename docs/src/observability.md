# Observability

The library uses [tracing](https://github.com/tokio-rs/tracing). Every envelope call and every KMS
call opens one span at the `DEBUG` level, and the spans carry what a call used besides how long it
took: the mode, the algorithm and backend, whether the DEK came from the cache, the KMS key and
its version, and the error code.

The spans are:

- `KMS AEAD encrypt`: the envelope's `encrypt_value`, `encrypt_value_with_dek` and
  `encrypt_value_with_encrypted_dek`;
- `KMS AEAD decrypt`: the envelope's `decrypt_value`, `decrypt_value_with_dek` and
  `decrypt_value_with_encrypted_dek`;
- `KMS AEAD generate DEK`: `generate_new_dek` and `generate_new_deterministic_dek`;
- `KMS AEAD decrypt DEK`: `decrypt_deterministic_dek`;
- `KMS wrap`: each provider's wrap of a DEK;
- `KMS unwrap`: each provider's unwrap of a DEK;
- `KMS random`: a call to the GCP or AWS KMS generator, when the provider uses it.

The KMS spans nest inside the envelope span, so a DEK the envelope had to unwrap shows its KMS call
as a child, and a DEK served by the cache shows none. `AeadCipher` and `DeterministicCipher` open
no spans: they run once per value inside the caller's span.

## Showing the spans

Any tracing subscriber works. With `tracing-subscriber`, an `EnvFilter` that enables `DEBUG` for
the library and span close events, every span is printed with its fields when it ends:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;
use tracing_subscriber::fmt::format::FmtSpan;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let subscriber = tracing_subscriber::fmt()
    .with_env_filter("kms_aead=debug")
    .with_span_events(FmtSpan::CLOSE)
    .finish();
tracing::subscriber::set_global_default(subscriber)?;

let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

let aad = b"orders/1042";
let encrypted = envelope.encrypt_value(aad, &SecretValue::from("secret")).await?;
let decrypted = envelope.decrypt_value(aad, &encrypted).await?;
# assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

The decrypt prints, without timestamps:

```text
DEBUG KMS AEAD decrypt{/kms_aead/mode="per_call" /kms_aead/algorithm=chacha20-poly1305 /kms_aead/backend=ring /kms_aead/dek_cache=disabled}:KMS unwrap{/kms_aead/provider=local /kms_aead/key="example" /kms_aead/key_version="1" /kms_aead/response_time=0}: kms_aead::spans::kms: close time.busy=16.4µs time.idle=6.95µs
DEBUG KMS AEAD decrypt{/kms_aead/mode="per_call" /kms_aead/algorithm=chacha20-poly1305 /kms_aead/backend=ring /kms_aead/dek_cache=disabled}: kms_aead::spans: close time.busy=62.0µs time.idle=12.3µs
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/tracing.rs),
run it with `cargo run --example tracing --features ring`.

## OpenTelemetry

With [tracing-opentelemetry](https://github.com/tokio-rs/tracing-opentelemetry) every span field
becomes a span attribute with the same name, such as `/kms_aead/key_version`, so the KMS calls and
cache hits show up next to the latency of a request in Cloud Trace, Jaeger, etc.

The fields are declared empty when the span opens and recorded once their value is known, which
`tracing-opentelemetry` exports the same way as fields given at the start. Add its layer to the
subscriber as usual:

```rust,ignore
use opentelemetry::trace::TracerProvider;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
    .with_batch_exporter(exporter) // any exporter, e.g. opentelemetry-otlp
    .build();

tracing_subscriber::registry()
    .with(tracing_subscriber::EnvFilter::new("info,kms_aead=debug"))
    .with(tracing_opentelemetry::layer().with_tracer(provider.tracer("my-service")))
    .init();
```

Be aware the library spans are `DEBUG`, so the filter has to enable that level for `kms_aead`.

## Fields

Every field name has the `/kms_aead/` prefix, such as `/kms_aead/mode`. A value nobody reported is
left unrecorded, never recorded as `0` or an empty string.

### KMS AEAD encrypt and KMS AEAD decrypt

| Field | Value |
|---|---|
| `mode` | `per_call` for `encrypt_value` and `decrypt_value`, `store_less` for both on a store-less envelope, `caller_dek` for the `*_with_dek` and `*_with_encrypted_dek` calls |
| `algorithm` | `chacha20-poly1305`, `aes-128-gcm`, `aes-256-gcm` or `aes-256-gcm-siv` |
| `backend` | `ring`, `aws-lc` or `rustcrypto` |
| `dek_cache` | `disabled` for an envelope without a cache; `hit` or `miss` for a call that unwraps through an enabled cache, a failed unwrap recording `miss`; unrecorded for a call that looks nothing up |
| `error_code` | the code of the error the call returned |

### KMS AEAD generate DEK and KMS AEAD decrypt DEK

| Field | Value |
|---|---|
| `purpose` | `randomized` or `deterministic` |
| `algorithm` | the algorithm of the key, `aes-256-siv` for deterministic keys |
| `backend` | generate DEK only: the envelope's backend, `ring`, `aws-lc` or `rustcrypto` |
| `dek_cache` | decrypt DEK only: `bypassed` beside an enabled cache, since the call never goes through it, `disabled` otherwise |
| `error_code` | the code of the error the call returned |

### KMS wrap, KMS unwrap and KMS random

| Field | Value |
|---|---|
| `provider` | `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of an application's own provider |
| `key` | the KEK, see below; for `KMS random` the GCP location, and unrecorded on AWS |
| `key_version` | wrap and unwrap: from the KMS response on wrap, from the wrapped DEK on unwrap; unrecorded when neither has one |
| `len` | random only: the bytes requested from the KMS generator |
| `response_time` | milliseconds the KMS call took |
| `error_code` | the code of the error the call returned |

The `key` of each provider:

- GCP: the CryptoKey name, `projects/<project>/locations/<location>/keyRings/<ring>/cryptoKeys/<key>`;
- AWS: the key or alias ARN, or the configured key id when no region is known;
- Azure: `<vault URL>/keys/<name>`;
- Vault Transit: `<vault address>/<namespace>/<mount>/keys/<name>`, without the namespace segment
  when none is set;
- local: the KEK id.

## Events

Besides the spans, the library logs:

- `WARN`, inside the KMS span: a GCP or Vault Transit response without a key version;
- `WARN`, once per process and layout: the first read of a pre-0.29 layout with `legacy-formats`;
- `WARN`, when a Vault Transit provider is created: an `http` address to another host, or a system
  CA certificate that cannot be loaded;
- `INFO`, when a local KMS provider is created: its KEK id and versions, each with where it came
  from, in the `key` and `key_versions` fields.

The library retries nothing itself, so there is no retry field.

## What is never logged

No span field or event carries:

- plaintext, DEKs in any form, plaintext or wrapped, or KEK material;
- AAD content, which can hold entity ids and so personal data;
- cipher text bytes;
- the length of a value or of its AAD. For AES-256-GCM the plaintext length is the value's length
  minus a fixed overhead, and a length tells short values such as `yes`, `no` or a country code
  apart.

Key identifiers are recorded: KEK names, key versions and local KEK ids. A KEK name identifies the
project, the location and the key, and a per-tenant KEK name carries the tenant id, so treat the
`key` field accordingly in a trace pipeline.

Errors follow the same rules, see [Error handling](./errors.md#what-errors-never-carry).
