# Cargo features

## kms-aead

The crate has no default features.

| Feature | What it adds |
|---|---|
| `gcp-kms-encryption` | Google Cloud KMS, with the native TLS roots of the system. Be aware it also turns on native-tls in reqwest, so in the same build the Azure provider uses native-tls whatever its TLS feature |
| `gcp-kms-encryption-webpki` | Google Cloud KMS with the bundled WebPKI roots |
| `gcp-kms-encryption-base` | Google Cloud KMS without a TLS root store or crypto provider. The application enables them with its own `gcloud-sdk` features, such as `tls-roots` or `tls-webpki-roots`, and the crate does not build without one |
| `aws-kms-encryption` | AWS KMS |
| `azure-kms-encryption` | Azure Key Vault and Managed HSM, with rustls and the aws-lc-rs crypto provider |
| `azure-kms-encryption-tls-aws-lc-rs` | the same as `azure-kms-encryption` |
| `azure-kms-encryption-tls-no-provider` | Azure with rustls and the crypto provider the application installs. The application must install a process-default rustls `CryptoProvider` before creating the provider, otherwise rustls panics |
| `azure-kms-encryption-native-tls` | Azure with the platform TLS library |
| `hashicorp-vault-transit-kms-encryption` | HashiCorp Vault Transit, with the system root certificates and the aws-lc-rs crypto provider |
| `hashicorp-vault-transit-kms-encryption-base` | Vault Transit without a root store or crypto provider, to combine with one of each below |
| `hashicorp-vault-transit-kms-encryption-tls-roots` | Vault Transit with the system root certificates |
| `hashicorp-vault-transit-kms-encryption-tls-webpki` | Vault Transit with the bundled WebPKI roots |
| `hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs` | Vault Transit with the aws-lc-rs crypto provider |
| `hashicorp-vault-transit-kms-encryption-tls-ring` | Vault Transit with the ring crypto provider |
| `ring` | the ring backend, see [Crypto backends](./crypto-backends.md) |
| `aws-lc` | the aws-lc-rs backend |
| `aws-lc-fips` | the aws-lc-rs backend on the AWS-LC FIPS module. Needs CMake and Go to build |
| `rustcrypto` | the backend on the pure Rust RustCrypto crates, no C compiler needed |
| `deterministic` | deterministic encryption with AES-SIV, see [Deterministic encryption](./deterministic.md) |
| `legacy-formats` | reads the layouts written by 0.29 and earlier. Deprecated, see [Formats](./formats.md) |
| `serde` | `Serialize` and `Deserialize` for `Encrypted`, as bytes, for `KmsAeadErrorPublicGenericDetails` and for `SecretValue`, see [Storing](./stored-values.md#storing) |
| `serde-json` | `Json`, a typed field's plaintext of any serde type, stored as its JSON |
| `postgres` | `ToSql` and `FromSql` of postgres-types for `Encrypted`, as `BYTEA`, for tokio-postgres |
| `sqlx` | sqlx's PostgreSQL traits for `Encrypted`, as `BYTEA`, without a sqlx runtime or TLS stack |
| `opentelemetry` | OpenTelemetry metrics on the API crate: counters of the values and plaintext bytes sealed and opened, and histograms of the time each call, KMS request and keyring store read takes, see [Metrics](./observability.md#metrics) |

The local KMS provider, `LocalKmsProvider`, is in every build and needs no feature.

### Feature rules

The crate refuses some feature combinations at compile time with `compile_error!`:

- a provider feature without a backend feature fails with "kms-aead needs a crypto backend for
  its KMS providers: enable "ring", "aws-lc", "aws-lc-fips" or "rustcrypto"";
- HashiCorp Vault Transit needs exactly one of `-tls-roots` and `-tls-webpki`, and exactly one
  of `-tls-aws-lc-rs` and `-tls-ring`. `hashicorp-vault-transit-kms-encryption` already enables
  `-tls-roots` and `-tls-aws-lc-rs`, so combine the other variants with
  `hashicorp-vault-transit-kms-encryption-base` instead;
- Azure needs exactly one of `azure-kms-encryption-tls-aws-lc-rs` (or `azure-kms-encryption`),
  `azure-kms-encryption-tls-no-provider` and `azure-kms-encryption-native-tls`.

The `aws-lc-rs` feature that `aws-lc` and `aws-lc-fips` enable is not a backend choice: enabled
alone, the aws-lc-rs build fails. Use `aws-lc` or `aws-lc-fips`.

A build without any backend feature compiles, and `LocalKmsProvider` is in it, but nothing that
seals or encrypts can be constructed, since no type implements `AeadBackend`.

## kms-aead-keyring

The crate has no default features.

| Feature | What it adds |
|---|---|
| `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto` | the crypto backends of kms-aead, see [Crypto backends](./crypto-backends.md). A keyring names its backend as a type parameter, such as `kms_aead::backends::Ring` |
| `admin` | `KeyringAdmin`, the registry's `create`, `open_or_create` and `admin`, and the types of the administrative calls, `Rotation`, `EncryptedKeyset`, `KeysetSelection` and the `encodings` module, see [Applications and administration](./keyring/deployment.md) |
| `deterministic` | deterministic key versions and every call on them, `encrypt_deterministic` and `reseal_deterministic` on a `Sealer`, and `decrypt_deterministic`, `decrypt_deterministic_with_trust` and `deterministic_probes` on a `Keyring`, see [Deterministic fields](./keyring/deterministic.md). The deterministic types exist in every build, so a process without the feature keeps a record's deterministic versions intact |
| `serde` | `Serialize` and `Deserialize` for `Encrypted` and `SealMarker`, as bytes |
| `serde-json` | `serde`, and `Json<T>`, a plaintext stored as its JSON |
| `firestore` | the Firestore keyring store, see [Keyring stores](./keyring/stores.md) |
| `postgres` | the PostgreSQL keyring store, and `Encrypted` and `SealMarker` in tokio-postgres, as `BYTEA` |
| `gcs` | the Cloud Storage keyring store, with the TLS variants listed in [Keyring stores](./keyring/stores.md#cloud-storage) |
| `s3` | the S3 keyring store |
| `sqlx` | `Encrypted` and `SealMarker` in sqlx on PostgreSQL, as `BYTEA` |
| `bigquery-export` | `admin`, and `export_bigquery_keyset`, see [Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery) |
| `opentelemetry` | kms-aead's `opentelemetry`, with the keyring's calls recorded per keyring and key version, see [Metrics](./observability.md#metrics) |

Beacons need no feature, and `export_tink_keyset` needs `admin` only. The KMS providers come from
kms-aead and its provider features, and secret-vault-value's `SecretValue` is what an application
type's `Plaintext` encodes to.
