# Observability

The library uses [tracing](https://github.com/tokio-rs/tracing). Every envelope call and every KMS
call opens one span at the `DEBUG` level, and the spans carry what a call used besides how long it
took: the mode, the algorithm and backend, whether the DEK came from the cache, the KMS key and
its version, and the error code.

The spans are:

- `KMS AEAD encrypt`: the envelope's `encrypt`, `encrypt_with_dek` and
  `encrypt_with_encrypted_dek`;
- `KMS AEAD decrypt`: the envelope's `decrypt`, `decrypt_with_dek` and
  `decrypt_with_encrypted_dek`;
- `KMS AEAD generate DEK`: `generate_encrypted_dek` and `generate_encrypted_deterministic_dek`;
- `KMS AEAD decrypt DEK`: `decrypt_deterministic_dek`;
- `KMS AEAD re-encrypt DEK`: `reencrypt_dek` and `reencrypt_encrypted_dek`;
- `KMS AEAD beacon`: the envelope's `beacon`;
- `KMS encrypt DEK`: each provider's encryption of a DEK;
- `KMS decrypt DEK`: each provider's decryption of a DEK;
- `KMS random`: a call to the GCP or AWS KMS generator, when the provider uses it.

The KMS spans nest inside the envelope span, so a DEK the envelope had to decrypt shows its KMS call
as a child, and a DEK served by the cache shows none. `AeadCipher` and `DeterministicCipher` open
no spans: they run once per value inside the caller's span.

## Showing the spans

Any tracing subscriber works. With `tracing-subscriber`, an `EnvFilter` that enables `DEBUG` for
the library and span close events, every span is printed with its fields when it ends:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
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
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let aad = b"orders/1042";
let encrypted: Encrypted<SecretValue, Envelope> =
    envelope.encrypt(aad, &SecretValue::from("secret")).await?;
let decrypted: SecretValue = envelope.decrypt(aad, &encrypted).await?;
# assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

The decrypt prints, without timestamps:

```text
DEBUG KMS AEAD decrypt{/kms_aead/mode="per_call" /kms_aead/algorithm=aes-256-gcm /kms_aead/backend=ring /kms_aead/dek_cache=disabled}:KMS decrypt DEK{/kms_aead/provider=local /kms_aead/key="example" /kms_aead/kek_version="1" /kms_aead/response_time=0}: kms_aead::spans::kms: close time.busy=16.4µs time.idle=6.95µs
DEBUG KMS AEAD decrypt{/kms_aead/mode="per_call" /kms_aead/algorithm=aes-256-gcm /kms_aead/backend=ring /kms_aead/dek_cache=disabled}: kms_aead::spans: close time.busy=62.0µs time.idle=12.3µs
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/tracing.rs),
run it with `cargo run --example tracing --features ring`.

## OpenTelemetry

With [tracing-opentelemetry](https://github.com/tokio-rs/tracing-opentelemetry) every span field
becomes a span attribute with the same name, such as `/kms_aead/kek_version`, so the KMS calls and
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
| `mode` | `per_call` for `encrypt` and `decrypt`, `store_less` for both on a store-less envelope, `caller_dek` for the `*_with_dek` and `*_with_encrypted_dek` calls |
| `algorithm` | `chacha20-poly1305`, `aes-128-gcm`, `aes-256-gcm` or `aes-256-gcm-siv` |
| `backend` | `ring`, `aws-lc` or `rustcrypto` |
| `dek_cache` | `disabled` for an envelope without a cache; `hit` or `miss` for a call that decrypts through an enabled cache, a failed decryption recording `miss`; unrecorded for a call that looks nothing up |
| `error_code` | the code of the error the call returned |

### KMS AEAD generate DEK and KMS AEAD decrypt DEK

| Field | Value |
|---|---|
| `purpose` | `randomized` or `deterministic` |
| `algorithm` | the algorithm of the key, `aes-256-siv` for deterministic keys |
| `backend` | generate DEK only: the envelope's backend, `ring`, `aws-lc` or `rustcrypto` |
| `dek_cache` | decrypt DEK only: `bypassed` beside an enabled cache, since the call never goes through it, `disabled` otherwise |
| `error_code` | the code of the error the call returned |

### KMS AEAD re-encrypt DEK

| Field | Value |
|---|---|
| `dek_cache` | `bypassed` beside an enabled cache, since the call never goes through it, `disabled` otherwise |
| `error_code` | the code of the error the call returned |

Its children are a `KMS decrypt DEK` under the version that encrypted the DEK and a `KMS encrypt DEK`
under the current one.

### KMS encrypt DEK, KMS decrypt DEK and KMS random

| Field | Value |
|---|---|
| `provider` | `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of an application's own provider |
| `key` | the KEK, see below; for `KMS random` the GCP location, and unrecorded on AWS |
| `kek_version` | `KMS encrypt DEK` and `KMS decrypt DEK`: from the KMS response on encryption, from the encrypted DEK's bytes on decryption for Azure, Vault Transit and the local KMS; unrecorded when neither has one, as for AWS and a GCP decryption |
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
- `WARN`, once per process and layout: the first read of a layout of 0.29 or earlier with
  `legacy-formats`;
- `WARN`, when a Vault Transit provider is created: an `http` address to another host, or a system
  CA certificate that cannot be loaded;
- `INFO`, when a local KMS provider is created: its KEK id and versions, each with where it came
  from, in the `key` and `kek_versions` fields.

The library retries nothing itself, so there is no retry field.

## Keyring spans

The `kms-aead-keyring` crate follows the same rules: one `DEBUG` span per call, field names with
the `/kms_aead_keyring/` prefix, and nothing recorded for a value nobody reported. kms-aead's spans
nest inside them, so a `KMS decrypt DEK` under a `Keyring decrypt` is a DEK cache miss, and a
`KMS encrypt DEK` under a `Keyring rotate` is the new version's DEK. Enable `kms_aead_keyring=debug`
in the filter beside `kms_aead=debug`. The spans from `Keyring rotate` to `Keyring export` are
those of `KeyringAdmin` calls, under the `admin` feature.

| Span | Opened by | Fields |
|---|---|---|
| `Keyring encrypt` | a sealer's `encrypt` and `encrypt_deterministic`, `deterministic_probes` | `keyring`, `purpose`, `key_id`, `algorithm`, `backend`, `dek_cache`, `error_code` |
| `Keyring decrypt` | `decrypt`, `decrypt_with_trust`, their deterministic pair, `decrypt_envelope_for_migration` | `keyring`, `purpose`, `key_id`, `key_state`, `reload`, `dek_cache`, `error_code` |
| `Keyring load` | every store read: `open`, a revalidation, a reload, the read before a write of a `KeyringAdmin` | `keyring`, `store`, `reason`, `changed`, `revision`, `response_time`, `error_code` |
| `Keyring beacon` | a sealer's `beacon`, `beacon_probes` | `keyring`, `key_id`, `algorithm`, `dek_cache`, `error_code` |
| `Keyring rotate` | `rotate`, `change_algorithm` | `keyring`, `purpose`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring promote` | `promote` | `keyring`, `key_id`, `from_key_id`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring mark compromised` | `mark_compromised` | `keyring`, `key_id`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring retire`, `Keyring reinstate`, `Keyring destroy` | the call of that name | `keyring`, `key_id`, `cas_retries`, `error_code` |
| `Keyring destroy all versions` | `dangerously_destroy_all_versions` | `keyring`, `cas_retries`, `error_code` |
| `Keyring re-encrypt DEKs` | `reencrypt_deks` | `keyring`, `versions`, `dek_cache`, `cas_retries`, `error_code` |
| `Keyring export` | `export_bigquery_keyset`, `export_tink_keyset` | `keyring`, `purpose`, `versions`, `dek_cache`, `error_code` |
| `Keyring sweep` | `sweep::run` | `keyring`, `scanned`, `resealed`, `resealed_from_compromised`, `skipped`, `failed` |

| Field | Value |
|---|---|
| `keyring` | the keyring id, which can name a tenant |
| `purpose` | `randomized`, `deterministic` or `beacon` |
| `key_id` | the decimal key id; unrecorded for an envelope value, which names no version, and for `deterministic_probes` and `beacon_probes`, which run under several |
| `algorithm` | the version's algorithm, such as `aes-256-gcm` or `hmac-sha256`; unrecorded for `deterministic_probes` and `beacon_probes` |
| `backend` | `ring`, `aws-lc` or `rustcrypto`; unrecorded for deterministic calls, since AES-SIV runs on RustCrypto whatever the keyring's backend |
| `key_state` | `pending`, `active`, `decrypt_only`, `retired`, `destroyed`, `compromised`, or `unknown` for a key id the record does not have |
| `reload` | what an unknown key id caused: `none`, `reloaded` or `rate_limited` |
| `dek_cache` | `hit`, `miss` or `disabled`; `bypassed` for `reencrypt_deks`, the export, and a compromised version read past the cache; unrecorded for `deterministic_probes` and `beacon_probes` |
| `store` | `memory`, `firestore`, `postgres`, `gcs`, `s3`, or an application store's name |
| `reason` | `open`, `ttl`, `watch`, `unknown_key_id`, `pending_key_id` for a re-seal under a version the cached record holds as pending, `forced` for `Keyring::reload`, `export` for the read a keyset export selects its versions from, `admin` for the read before a write |
| `changed` | `true` for a new record taken, `false`, or `regressed` for one refused because it moves a version backwards |
| `revision` | the store's revision of the record read, as text |
| `response_time` | milliseconds the store call took |
| `from_key_id`, `to_key_id` | the version a promotion or a compromise replaced, and the new active one; for `rotate`, `to_key_id` is the staged version |
| `cas_retries` | the compare-and-swap conflicts before the write landed |
| `versions` | the versions `reencrypt_deks` encrypted again, or an export put in the keyset |
| `scanned`, `resealed`, `resealed_from_compromised`, `skipped`, `failed` | the counts of the `SweepReport` |
| `error_code` | `KeyringError::code()` of the error returned: kms-aead's code for a KMS or AEAD error, such as `DECRYPT`, and the variant's name in upper snake case otherwise, such as `KEY_VERSION_COMPROMISED` |

### Keyring events

- `WARN`: a read of a compromised version under the `Allow` policy, with the key id;
- `WARN`: a read refused because its version is retired or destroyed, for an operator watching a
  sweep;
- `WARN`: a failed revalidation, and a record the store no longer holds, the cached one staying in
  use;
- `ERROR`: a refreshed record refused because it moves a version backwards, with the first rule it
  breaks. Alert on it: it is the detection of a rewritten or restored record;
- `WARN`: a compromised flag written without a rotation because the new DEK could not be encrypted;
- `INFO`: the active version of a purpose changed, with the old and new key ids;
- `WARN`: the store's listener disconnected, reconnected, or did not start, and a keyring
  opened with no tokio runtime to follow the store's signals;
- `WARN`: a `KeyringRegistry` dropped while its background tasks run, which aborts them, with the
  count of open keyrings, and a `shutdown` whose timeout aborted the tasks still running, with
  their count;
- `WARN`: a record a sweep could not re-seal, with the `Display` of the application's candidate
  in `record` and of its error in `error`. Both are the application's own text, so it keeps
  values, secrets and personal data out of them. A record id is often an entity id, so the
  sweep's log is an administrative log;
- `DEBUG`: a rate-limited reload for an unknown key id, and a compare-and-swap conflict that is
  retried.

The keyring's spans, events and errors leave out everything kms-aead's do, listed below. The AAD
rule matters most there, since the default AAD holds the entity id: neither the AAD nor an
`EntityId` appears anywhere. Key ids, keyring ids and store names are identifiers and appear.

## What is never logged

No span field or event carries:

- plaintext, DEKs in any form, plaintext or encrypted, or KEK material;
- AAD content, which can hold entity ids and so personal data;
- cipher text bytes;
- the length of a value or of its AAD. For AES-256-GCM the plaintext length is the value's length
  minus a fixed overhead, and a length tells short values such as `yes`, `no` or a country code
  apart.

Key identifiers are recorded: KEK names, key versions and local KEK ids. A KEK name identifies the
project, the location and the key, and a per-tenant KEK name carries the tenant id, so treat the
`key` field accordingly in a trace pipeline.

Errors follow the same rules, see [Error handling](./errors.md#what-errors-never-carry).
