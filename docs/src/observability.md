# Observability

The library uses [tracing](https://github.com/tokio-rs/tracing). Every envelope call and every KMS
call opens one span at the `DEBUG` level, and the spans carry what a call used besides how long it
took: the mode, the algorithm and backend, whether the DEK came from the cache, the KMS key and
its version, and the error code.

The spans are:

- `KMS AEAD encrypt`: the envelope's `encrypt`, `encrypt_with_dek`, `encrypt_with_encrypted_dek`,
  `stream_encryptor` and `stream_encryptor_bare`;
- `KMS AEAD decrypt`: the envelope's `decrypt`, `decrypt_with_dek`, `decrypt_with_encrypted_dek`,
  `stream_decryptor` and `stream_decryptor_bare`;
- `KMS AEAD generate DEK`: `generate_encrypted_dek` and `generate_encrypted_deterministic_dek`;
- `KMS AEAD decrypt DEK`: `decrypt_deterministic_dek`;
- `KMS AEAD re-encrypt DEK`: `reencrypt_dek` and `reencrypt_encrypted_dek`;
- `KMS AEAD beacon`: the envelope's `beacon`;
- `KMS encrypt DEK`: each provider's encryption of a DEK, or its encryption with a public key;
- `KMS decrypt DEK`: each provider's decryption of a DEK;
- `KMS random`: a call to the GCP or AWS KMS generator, when the provider uses it;
- `Signature sign`: a `Signer`'s `sign`, `sign_attached` and `sign_digest`;
- `Signature verify`: a `Verifier`'s `verify`, `verify_signed` and `verify_digest`;
- `MAC compute`: an `Authenticator`'s `mac` and `mac_attached`;
- `MAC verify`: an `Authenticator`'s `verify` and `verify_with_mac`;
- `KMS sign`: each signing provider's sign request;
- `KMS public key`: each signing provider's request for the public key of its key, and each KMS
  provider's `public_key` of an asymmetric KEK.

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
| `mode` | `per_call` for `encrypt`, `decrypt` and the stream calls, `store_less` for them on a store-less envelope, `caller_dek` for the `*_with_dek` and `*_with_encrypted_dek` calls |
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

### KMS AEAD beacon

| Field | Value |
|---|---|
| `algorithm` | `hmac-sha256` |
| `backend` | `ring`, `aws-lc` or `rustcrypto` |
| `dek_cache` | `disabled` for an envelope without a cache; `hit` or `miss` with one, a failed decryption of the beacon key recording `miss` |
| `error_code` | the code of the error the call returned |

A beacon key the cache did not hold shows its `KMS decrypt DEK` as a child.

### KMS encrypt DEK, KMS decrypt DEK and KMS random

| Field | Value |
|---|---|
| `provider` | `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of an application's own provider |
| `key` | the KEK, see below; for `KMS random` the GCP location, and unrecorded on AWS |
| `kek_version` | `KMS encrypt DEK` and `KMS decrypt DEK`: from the KMS response on encryption, and the public key's version on an encryption with a public key; from the encrypted DEK's bytes on decryption for Azure, Vault Transit, the local KMS and every DEK a public key encrypted; unrecorded when neither has one, as for AWS and a GCP decryption of a symmetric key |
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

### Signature sign, Signature verify, MAC compute and MAC verify

| Field | Value |
|---|---|
| `algorithm` | `ed25519` or `ecdsa-p256-sha256` for a signature; `mac-hmac-sha256` or `mac-hmac-sha512` for a MAC |
| `backend` | `ring`, `aws-lc` or `rustcrypto` |
| `key_id` | the decimal key id the signature or MAC names |
| `payload_type` | the `PAYLOAD_TYPE` of the signed type |
| `error_code` | the code of the error the call returned |

### KMS sign and KMS public key

| Field | Value |
|---|---|
| `provider` | `gcp`, `aws`, `azure`, `hc_vault_transit`, `local`, or the name of an application's own provider |
| `key` | the signing key, see `SigningKeyRef::key`, or the KEK of an asymmetric KEK's public key |
| `kek_version` | the public key of an asymmetric KEK only: the version asked for, or the one the response names when none was |
| `response_time` | milliseconds the KMS call took |
| `error_code` | the code of the error the call returned |

With the `opentelemetry` feature the signing and MAC calls record their duration as the envelope
calls do. The spans carry no payload, signature, tag or key bytes.

## Events

Besides the spans, the library logs:

- `WARN`, inside the KMS span: a GCP or Vault Transit response without a key version;
- `WARN`, once per process and layout: the first read of a layout of 0.29 or earlier with
  `legacy-formats`;
- `WARN`, when a Vault Transit provider is created: an `http` address to another host, or a system
  CA certificate that cannot be loaded;
- `WARN`, on the `kms_aead::json` target: a `JsonEncoded` value that does not decode, see
  [JSON that does not decode](#json-that-does-not-decode);
- `INFO`, when a provider that holds the public key of an asymmetric KEK is created
  (`PublicKeyKekProvider`, `AsymmetricKekProvider` and `LocalAsymmetricKmsProvider`): the KEK, its
  version and the public key's fingerprint, the SHA-256 of its SubjectPublicKeyInfo in hex, so that
  an operator compares the producer's and the administration's;
- `INFO`, when a local KMS provider is created: its KEK id and versions, each with where it came
  from, in the `key` and `kek_versions` fields;
- `INFO`, when a local signing provider is created: its key id and versions, each with its
  algorithm, key id and where it came from, in the `key` and `key_versions` fields.

The library retries nothing itself, so there is no retry field.

## JSON that does not decode

A `JsonEncoded` value whose bytes are not the JSON of its type, a decrypted plaintext or the
payload of an attached signature or MAC after it verified, fails with `INVALID_PLAINTEXT` or
`INVALID_PAYLOAD`. The error never quotes the bytes, and names serde_json's category of failure
(`Syntax`, `Data` or `Eof`) without the line and column, which are byte offsets that give
away the length of the values before them. The library logs one `WARN` event on the
`kms_aead::json` target beside it, with an outline of the JSON.

| Field | Value |
|---|---|
| `error_code` | `INVALID_PLAINTEXT` or `INVALID_PAYLOAD` |
| `decoded_type` | the Rust type the JSON does not decode to |
| `payload_type` | the `PAYLOAD_TYPE` of a signed type; unrecorded for a plaintext |
| `json_error` | serde_json's error: the message of a syntax error, such as `EOF while parsing a string`, or `Data error` for JSON of another shape than the type, with the line and column under `SIZES` |
| `outline` | the outline of the JSON |

By default the outline shows the shape of the JSON: the type of every value, `<key>` for every
key, the nesting, and where serde_json stopped reading it, with serde_json's message for a syntax
error. That message is fixed text, and it can state a property of a value the outline hides, such
as `number out of range`, `invalid unicode code point` or `unexpected end of hex escape`. The
default shows no length and no position, since [a length gives away a hidden
boolean](https://docs.rs/kms-aead/latest/kms_aead/redaction/trait.JsonRedaction.html#associatedconstant.SIZES).

A type opts into more with a policy, the second type parameter of `JsonEncoded`.
A signed payload is often public, so its policy may show more than an encrypted plaintext's. See
[JSON that does not decode](./stored-values.md#json-that-does-not-decode) for a policy and the
outlines it produces.
`kms_aead::json=off` in an `EnvFilter` turns the event off.

An application outlines JSON of its own with `RedactedJson`, with no encryption involved, see
[Log JSON payloads without leaking data](./use-cases/log-json-payloads.md).

## Keyring spans

The `kms-aead-keyring` crate follows the same rules: one `DEBUG` span per call, field names with
the `/kms_aead_keyring/` prefix, and nothing recorded for a value nobody reported. kms-aead's spans
nest inside them, so a `KMS decrypt DEK` under a `Keyring decrypt` is a DEK cache miss, and a
`KMS encrypt DEK` under a `Keyring rotate` is the new version's DEK. Enable `kms_aead_keyring=debug`
in the filter beside `kms_aead=debug`. The spans from `Keyring rotate` to `Keyring export` are
those of `KeyringAdmin` calls, under the `admin` feature.

| Span | Opened by | Fields |
|---|---|---|
| `Keyring encrypt` | an encryptor's `encrypt` and `encrypt_deterministic`, `deterministic_probes`, and `stream_encryptor` | `keyring`, `purpose`, `key_id`, `algorithm`, `backend`, `dek_cache`, `error_code` |
| `Keyring decrypt` | `decrypt`, `decrypt_with_trust`, their deterministic pair, `decrypt_envelope_for_migration`, and `stream_decryptor` | `keyring`, `purpose`, `key_id`, `key_state`, `reload`, `dek_cache`, `error_code` |
| `Keyring load` | every store read: `open`, a revalidation, a reload, the read before a write of a `KeyringAdmin`, including a `shred` | `keyring`, `store`, `reason`, `changed`, `revision`, `response_time`, `error_code` |
| `Keyring beacon` | an encryptor's `beacon`, `beacon_probes` | `keyring`, `key_id`, `algorithm`, `dek_cache`, `error_code` |
| `Keyring mac` | an encryptor's `mac` and `mac_attached` | `keyring`, `key_id`, `algorithm`, `dek_cache`, `error_code` |
| `Keyring verify mac` | `verify_mac`, `verify_mac_with_trust` and `verify_with_mac` | `keyring`, `purpose`, `key_id`, `key_state`, `reload`, `dek_cache`, `error_code` |
| `Keyring rotate` | `rotate`, `change_algorithm` | `keyring`, `purpose`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring promote` | `promote` | `keyring`, `key_id`, `from_key_id`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring mark compromised` | `mark_compromised` | `keyring`, `key_id`, `to_key_id`, `cas_retries`, `error_code` |
| `Keyring retire`, `Keyring reinstate`, `Keyring destroy` | the call of that name | `keyring`, `key_id`, `cas_retries`, `error_code` |
| `Keyring destroy all versions` | `dangerously_destroy_all_versions` | `keyring`, `cas_retries`, `error_code` |
| `Keyring shred` | `shred` | `keyring`, `cas_retries`, `error_code` |
| `Keyring re-encrypt DEKs` | `reencrypt_deks` | `keyring`, `versions`, `dek_cache`, `cas_retries`, `error_code` |
| `Keyring export` | `export_bigquery_keyset`, `export_tink_keyset` | `keyring`, `purpose`, `versions`, `dek_cache`, `error_code` |
| `Keyring sign record` | each write of a signed record by the administration | `keyring`, `key_id`, `error_code` |
| `Keyring sweep` | `sweep::reencrypt_records`, `sweep::reencrypt_records_batched` | `keyring`, `scanned`, `reencrypted`, `reencrypted_from_compromised`, `skipped`, `failed` |

| Field | Value |
|---|---|
| `keyring` | the keyring id, which can name a tenant |
| `purpose` | `randomized`, `deterministic`, `beacon` or `mac` |
| `key_id` | the decimal key id; unrecorded for an envelope value, which names no version, and for `deterministic_probes` and `beacon_probes`, which run under several |
| `algorithm` | the version's algorithm, such as `aes-256-gcm`, `hmac-sha256` or `mac-hmac-sha256`; unrecorded for `deterministic_probes` and `beacon_probes` |
| `backend` | `ring`, `aws-lc` or `rustcrypto`; unrecorded for deterministic calls, since AES-SIV runs on RustCrypto whatever the keyring's backend |
| `key_state` | `pending`, `active`, `decrypt_only`, `retired`, `destroyed`, `compromised`, or `unknown` for a key id the record does not have |
| `reload` | what an unknown key id caused: `none`, `reloaded` or `rate_limited` |
| `dek_cache` | `hit`, `miss` or `disabled`; `bypassed` for `reencrypt_deks`, the export, and a compromised version read past the cache; unrecorded for `deterministic_probes` and `beacon_probes` |
| `store` | `memory`, `firestore`, `postgres`, `gcs`, `s3`, or an application store's name |
| `reason` | `open`, `ttl`, `watch`, `unknown_key_id`, `pending_key_id` for a re-encryption under a version the cached record holds as pending, `forced` for `Keyring::reload`, `export` for the read a keyset export selects its versions from, `admin` for the read before a write |
| `changed` | `true` for a new record taken, `false`, `regressed` for one refused because it moves a version backwards, `refused` for one refused by record verification, or `deleted` for a read that found the store holds no record, which the process takes as a shredded keyring |
| `revision` | the store's revision of the record read, as text |
| `response_time` | milliseconds the store call took |
| `from_key_id`, `to_key_id` | the version a promotion or a compromise replaced, and the new active one; for `rotate`, `to_key_id` is the staged version |
| `cas_retries` | the compare-and-swap conflicts before the write landed |
| `versions` | the versions `reencrypt_deks` encrypted again, or an export put in the keyset |
| `scanned`, `reencrypted`, `reencrypted_from_compromised`, `skipped`, `failed` | the counts of the `SweepReport` |
| `error_code` | `KeyringError::code()` of the error returned: kms-aead's code for a KMS or AEAD error, such as `DECRYPT`, and the variant's name in upper snake case otherwise, such as `KEY_VERSION_COMPROMISED` |

### Keyring events

- `WARN`: a read of a compromised version under the `Allow` policy, with the key id;
- `WARN`: a read refused because its version is retired or destroyed, for an operator watching a
  sweep;
- `WARN`: a record that holds a DEK encrypted with a public key, loaded under any record
  verification mode but `Required`, with the keyring id, once per record loaded. Under an asymmetric
  KEK anyone holding the public key can plant a version, see [Keyrings under an asymmetric
  KEK](./asymmetric-kek.md#keyrings-under-an-asymmetric-kek);
- `WARN`: a `KeyringAdmin` without a record signer built over a provider whose
  `encrypts_with_public_key()` is `true`;
- `WARN`: a failed revalidation, the cached record staying in use;
- `WARN`: "The keyring store no longer holds the keyring record; every version is destroyed in this
  process", when a read finds the record gone: the process then holds the record with every
  version destroyed and stops revalidating the keyring, see
  [A record gone from the store](./keyring/record-cache.md#a-record-gone-from-the-store). It is an
  `INFO`, "The keyring store no longer holds the keyring record of a shredded keyring; every
  version is destroyed in this process", when the record the process held had every version
  destroyed already, which a [shred](./operations/runbook.md#shredding-a-keyring) leaves before it
  deletes the record. The process that ran the shred logs nothing for it;
- `ERROR`: a refreshed record refused because it moves a version backwards, with the first rule it
  breaks. Alert on it: it is the detection of a rewritten or restored record;
- `ERROR`: a refreshed record refused by record verification, with its code,
  `RECORD_UNSIGNED`, `RECORD_SIGNATURE_INVALID` or `RECORD_SIGNATURE_REMOVED`; the process keeps
  the record it holds, and the `Keyring load` span records the code. Alert on it as on the previous
  one;
- `WARN`: a compromised flag written without a rotation because the new DEK could not be encrypted;
- `INFO`: the active version of a purpose changed, with the old and new key ids;
- `WARN`: the store's listener disconnected, reconnected, or did not start, and a keyring
  opened with no tokio runtime to follow the store's signals;
- `WARN`: a `KeyringRegistry` dropped while its background tasks run, which aborts them, with the
  count of open keyrings, and a `shutdown` whose timeout aborted the tasks still running, with
  their count;
- `WARN`: a record a sweep could not re-encrypt, with the `Display` of the application's candidate
  in `record` and of its error in `error`. Both are the application's own text, so it keeps
  values, secrets and personal data out of them. A record id is often an entity id, so the
  sweep's log is an administrative log;
- `WARN`: a candidate the sweep's stream returned as an error, with the `Display` of the error in
  `error`;
- `WARN`: a batch of `sweep::reencrypt_records_batched` whose re-encryption failed as a whole, with its number of
  candidates in `candidates` and the `Display` of the error in `error`, and a batch that returned
  a different number of outcomes from it was given candidates, with both counts in `candidates` and
  `outcomes`;
- `DEBUG`: a rate-limited reload for an unknown key id, and a compare-and-swap conflict that is
  retried.

The keyring's spans, events and errors leave out everything kms-aead's do, listed below. The AAD
rule matters most there, since the default AAD holds the entity id: neither the AAD nor an
`EntityId` appears anywhere. Key ids, keyring ids and store names are identifiers and appear.

## Metrics

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
  `RECORD_SIGNATURE_REMOVED`. It is the metric of the `ERROR` event above.

No attribute names a DEK, so the envelope's values are recorded per algorithm, not per key. A
store-less envelope needs no alert on them: it renews its DEK at `max_uses` and `max_bytes`, see
[Volume limit](./dek-caching.md#volume-limit).

A Prometheus exporter adds the unit to the name and replaces the dots with underscores:
`kms_aead_plaintext_size_bytes_count` and `kms_aead_plaintext_size_bytes_sum`,
`kms_aead_operation_duration_seconds`, and attributes such as `kms_aead_key_id`. For an alert on
the values and bytes under one keyring version, see
[Alerting on volume](./operations/rotation.md#alerting-on-volume).

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
[Metrics](#metrics) turns them off with `record_min_max: false`. Treat the histogram like the values
themselves where traffic is low, and everywhere without that view.

The `kms_aead::json` event is the other exception, under a policy that opts in: its outline then
carries the length of the values and keys of the JSON that did not decode, [which gives away a
hidden boolean](https://docs.rs/kms-aead/latest/kms_aead/redaction/trait.JsonRedaction.html#associatedconstant.SIZES), and the values the
policy reveals. The default policy carries neither, but every policy shows serde_json's message for
a syntax error, which is fixed text and can state a property of a hidden value, such as
`number out of range`.

Key identifiers are recorded: KEK names, key versions and local KEK ids. A KEK name identifies the
project, the location and the key, and a per-tenant KEK name carries the tenant id, so treat the
`key` field accordingly in a trace pipeline.

Errors follow the same rules, see [Error handling](./errors.md#what-errors-never-carry).
