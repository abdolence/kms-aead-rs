# Cargo features

Both crates enable no default features. This page lists every feature of kms-aead and
kms-aead-keyring. Pick one crypto backend, the KMS providers you use and, for kms-aead-keyring, your
keyring store and optional modes; the choice of a provider and a backend is in
[Choose a provider and a backend](./getting-started/choosing.md).

## kms-aead

The crate has no default features.

| Feature | What it adds |
|---|---|
| `gcp-kms-encryption` | Google Cloud KMS, with the native TLS roots of the system, and the `crc32c` crate for the checksums of its requests, see the notes below |
| `gcp-kms-encryption-webpki` | Google Cloud KMS with the bundled WebPKI roots, and the `crc32c` crate |
| `gcp-kms-encryption-base` | Google Cloud KMS without a TLS root store or crypto provider, and the `crc32c` crate, see the notes below |
| `aws-kms-encryption` | AWS KMS, with the credentials of an `aws login` session among others, see [AWS KMS](./providers/aws.md#configuration-authentication-and-permissions) |
| `azure-kms-encryption` | Azure Key Vault and Managed HSM, with rustls and the aws-lc-rs crypto provider |
| `azure-kms-encryption-tls-aws-lc-rs` | the same as `azure-kms-encryption` |
| `azure-kms-encryption-tls-no-provider` | Azure with rustls and the crypto provider the application installs, see the notes below |
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
| `rustcrypto` | the backend on the pure Rust RustCrypto crates, no C compiler needed. Adds `p256` and `ed25519-dalek` for signatures, and `rsa` for RSA-OAEP, see [Asymmetric KEKs](./asymmetric-kek.md#what-each-backend-does) |
| `deterministic` | deterministic encryption with AES-SIV, see [Deterministic encryption](./deterministic.md) |
| `stream` | streaming encryption of values of any length, see the notes below. Turns on tokio's `io-util` and brings in `bytes` and `futures-core` |
| `postgres` | `ToSql` and `FromSql` of postgres-types for `Encrypted`, as `BYTEA`, for tokio-postgres |
| `sqlx` | sqlx's PostgreSQL traits for `Encrypted`, as `BYTEA`, without a sqlx runtime or TLS stack |
| `opentelemetry` | OpenTelemetry metrics on the API crate only (no SDK), see the notes below and [Metrics](./observability/metrics.md#metrics) |

Notes on the rows:

- `gcp-kms-encryption` also turns on native-tls in reqwest, so in the same build the Azure provider
  uses native-tls whatever its TLS feature;
- `gcp-kms-encryption-base`: the application enables a root store and a crypto provider with its
  own `gcloud-sdk` features, such as `tls-roots` or `tls-webpki-roots`, and the crate does not build
  without one;
- `azure-kms-encryption-tls-no-provider`: the application must install a process-default rustls
  `CryptoProvider` before creating the provider, otherwise rustls panics;
- `stream` adds `StreamEncryptor` and `StreamDecryptor`, the tokio adapters `EncryptingWriter` and
  `DecryptingReader`, the `Stream` adapters `EncryptingStream` and `DecryptingStream`, the
  `stream_encryptor` and `stream_decryptor` calls of `AeadCipher` and `KmsAeadEnvelope`, with their
  bare forms, and `KmsAeadEnvelope::decrypting_stream` and `decrypting_reader`, which read the
  header from the whole stored value;
- `opentelemetry` records the plaintext size of each value encrypted and decrypted, and the time
  each call, KMS request and keyring store read takes.

The local KMS provider, `LocalKmsProvider`, is in every build and needs no feature.

Every build adds `serde`, `serde_bytes`, `serde_json`, secret-vault-value's `serde` feature, `sha2`,
`base64ct` and the RustCrypto crates `der`, `spki`, `pkcs8`, `sec1` and `pem-rfc7468`:

- `sha2` computes the thumbprint of a public key and, in kms-aead-keyring, the canonical digest of
  a record, where no backend is named;
- the RustCrypto crates parse and write the framing of keys and signatures: PEM, the text armour
  around base64 bytes; SubjectPublicKeyInfo, the DER structure of a public key, DER being a binary
  encoding; PKCS#8, the DER structure of a private key; and the DER encoding of an ECDSA signature;
- `serde_json` reads and writes JSON Web Keys (JWK), the JSON form of a key, so
  `PublicKeyFormat::Jwk`, `encode(Jwk)` and the JWK Set functions of `VerifyingKeySet` are in every
  build, as are `JsonEncoded<T>` and the serde implementations of the library's types.

### Feature rules

The crate refuses some feature combinations at compile time with `compile_error!`:

- a provider feature without a backend feature fails: enable `ring`, `aws-lc`, `aws-lc-fips` or
  `rustcrypto` beside it;
- HashiCorp Vault Transit needs exactly one of `-tls-roots` and `-tls-webpki`, and exactly one
  of `-tls-aws-lc-rs` and `-tls-ring`. `hashicorp-vault-transit-kms-encryption` already enables
  `-tls-roots` and `-tls-aws-lc-rs`, so combine the other variants with
  `hashicorp-vault-transit-kms-encryption-base` instead;
- Azure needs exactly one of `azure-kms-encryption-tls-aws-lc-rs` (or `azure-kms-encryption`),
  `azure-kms-encryption-tls-no-provider` and `azure-kms-encryption-native-tls`.

The `aws-lc-rs` feature that `aws-lc` and `aws-lc-fips` enable is not a backend choice: enabled
alone, the aws-lc-rs build fails. Use `aws-lc` or `aws-lc-fips`.

A build without any backend feature compiles, and `LocalKmsProvider` is in it, but nothing that
encrypts can be constructed, since no type implements `AeadBackend`.

## kms-aead-keyring

The crate has no default features.

| Feature | What it adds |
|---|---|
| `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto` | the crypto backends of kms-aead, see [Crypto backends](./crypto-backends.md). A keyring names its backend as a type parameter, such as `kms_aead::backends::Ring` |
| `admin` | `KeyringAdmin`, the registry's `create`, `open_or_create` and `admin`, and the types of the administrative calls, see [Permissions: applications and administration](./production/permissions.md) |
| `deterministic` | deterministic key versions and every call on them, see the notes below and [Deterministic fields](./keyring/deterministic.md) |
| `firestore` | the Firestore keyring store, on firestore-rs without its default features: no TLS root store and no crypto provider. Enable one of the two below, or a root store feature of firestore-rs or gcloud-sdk, see [Keyring stores](./keyring/stores.md#firestore) |
| `firestore-tls-roots` | `firestore` with the system's native roots, firestore-rs's `tls-roots`, which brings native-tls and so OpenSSL on Linux, and firestore-rs's `auth-default-crypto` |
| `firestore-tls-webpki` | `firestore` on rustls, with the bundled WebPKI roots for the gRPC connection to Firestore and no native TLS, and firestore-rs's `auth-default-crypto` |
| `postgres` | the PostgreSQL keyring store, and `Encrypted` and `EncryptionMarker` in tokio-postgres, as `BYTEA` |
| `gcs` | the Cloud Storage keyring store, on gcloud-sdk without a TLS root store or crypto provider. Enable one of the two below, or a root store feature of gcloud-sdk, see [Keyring stores](./keyring/stores.md#cloud-storage) |
| `gcs-tls-roots` | `gcs` with the system's native roots, gcloud-sdk's `tls-roots`, which brings native-tls and so OpenSSL on Linux, and gcloud-sdk's `auth-default-crypto` |
| `gcs-tls-webpki` | `gcs` on rustls, with the bundled WebPKI roots for the gRPC connection to Cloud Storage and no native TLS, and gcloud-sdk's `auth-default-crypto` |
| `s3` | the S3 keyring store |
| `sqlx` | `Encrypted` and `EncryptionMarker` in sqlx on PostgreSQL, as `BYTEA` |
| `stream` | kms-aead's `stream`, `Encryptor::stream_encryptor`, `Keyring::stream_decryptor`, `decrypting_stream` and `decrypting_reader`, and the `stream` module re-exported. Needs a backend feature, see [Streaming encryption](./streaming.md) |
| `bigquery-export` | `admin`, and `export_bigquery_keyset`, see [Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery) |
| `opentelemetry` | kms-aead's `opentelemetry`, with the keyring's calls recorded per keyring and key version, see [Metrics](./observability/metrics.md#metrics) |

Notes on the rows:

- `admin` also adds the types `Rotation`, `EncryptedKeyset`, `KeysetSelection` and the `encodings`
  module;
- `deterministic` adds `encrypt_deterministic` and `reencrypt_deterministic` on an `Encryptor`, and
  `decrypt_deterministic`, `decrypt_deterministic_with_trust` and `deterministic_probes` on a
  `Keyring`. The deterministic types exist in every build, so a process without the feature keeps a
  record's deterministic versions intact.

Beacons need no feature, and `export_tink_keyset` needs `admin` only. The KMS providers come from
kms-aead and its provider features, and secret-vault-value's `SecretValue` is what an application
type's `Plaintext` encodes to.
