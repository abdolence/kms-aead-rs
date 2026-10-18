# Getting started

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.30", features = ["gcp-kms-encryption", "aws-lc"] }
```

The crate has no default features. A build makes three choices, and they do not constrain each
other:

1. the KMS providers, any number of them, or none for AEAD without a KMS;
2. the TLS root store and the TLS crypto provider of each provider that has a choice;
3. the crypto backends that run the AEAD algorithms, one or more.

## Features

KMS providers:

- `gcp-kms-encryption`: Google Cloud KMS, with the native TLS roots of the system. Be aware it
  also turns on native-tls in reqwest, so in the same build the Azure provider uses native-tls
  whatever its TLS feature;
- `gcp-kms-encryption-webpki`: Google Cloud KMS with the bundled WebPKI roots;
- `gcp-kms-encryption-base`: Google Cloud KMS without a TLS root store or crypto provider. The
  application enables them with its own `gcloud-sdk` features, such as `tls-roots` or
  `tls-webpki-roots`, and the crate does not build without one;
- `aws-kms-encryption`: AWS KMS;
- `azure-kms-encryption`: Azure Key Vault and Managed HSM, with rustls and the aws-lc-rs crypto
  provider. Other TLS variants, choose one:
    - `azure-kms-encryption-tls-aws-lc-rs`, the same as `azure-kms-encryption`;
    - `azure-kms-encryption-tls-no-provider`, rustls with the crypto provider the application
      installs. The application must install a process-default rustls `CryptoProvider` before
      creating the provider, otherwise rustls panics;
    - `azure-kms-encryption-native-tls`, the platform TLS library;
- `hashicorp-vault-transit-kms-encryption`: HashiCorp Vault Transit, with the system root
  certificates and the aws-lc-rs crypto provider. To choose them, enable one root store and one
  crypto provider instead:
    - `hashicorp-vault-transit-kms-encryption-tls-roots` or
      `hashicorp-vault-transit-kms-encryption-tls-webpki`;
    - `hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs` or
      `hashicorp-vault-transit-kms-encryption-tls-ring`.

The local KMS provider, `LocalKmsProvider`, is in every build and needs no feature.

Crypto backends, see [Crypto backends](./crypto-backends.md):

- `ring`: the ring library;
- `aws-lc`: the aws-lc-rs library;
- `aws-lc-fips`: the aws-lc-rs library on the AWS-LC FIPS module. Needs CMake and Go to build;
- `rustcrypto`: the pure Rust RustCrypto crates, no C compiler needed.

Other features:

- `deterministic`: deterministic encryption with AES-SIV, see
  [Deterministic encryption](./deterministic.md);
- `legacy-formats`: reads the layouts written by 0.29 and earlier. Deprecated, see
  [Formats](./formats.md);
- `serde`: `Serialize` and `Deserialize` for `Encrypted`, as bytes, for
  `KmsAeadErrorPublicGenericDetails` and for `SecretValue`;
- `serde-json`: `Json`, a typed field's plaintext of any serde type, stored as its JSON;
- `postgres`: `ToSql` and `FromSql` of postgres-types for `Encrypted`, as `BYTEA`, for
  tokio-postgres;
- `sqlx`: sqlx's PostgreSQL traits for `Encrypted`, as `BYTEA`, without a sqlx runtime or TLS
  stack.

See [Stored values](./stored-values.md).

## Choosing a backend

The default features of the four cloud providers already build aws-lc-rs for TLS, so `aws-lc` is
the backend that adds no second crypto library to a provider build. `ring` and `rustcrypto` work
with every provider too, and a build may enable several backends at once. Each feature adds a type
to `kms_aead::backends`, `Ring`, `AwsLc` or `RustCrypto`, and every type that seals or encrypts
takes one as its backend type parameter:

```rust
# fn example() -> kms_aead::KmsAeadResult<()> {
use kms_aead::backends::AwsLc;
use kms_aead::{AeadAlgorithm, AeadCipher};

let cipher = AeadCipher::<AwsLc>::new(AeadAlgorithm::Aes256Gcm)?;
# let _ = cipher;
# Ok(())
# }
```

There is no default backend. Code generic over the backend bounds it with `B: AeadBackend` and
nothing else, see [Crypto backends](./crypto-backends.md#code-generic-over-the-backend).

## Feature rules

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

## First example

The local KMS needs no cloud account, so it is the quickest way to try the library. An
ephemeral KEK lives as long as the process:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let aad = b"orders/1042";
let secret = SecretValue::from("4111 1111 1111 1111");

let encrypted: Encrypted<SecretValue, Envelope> = envelope.encrypt(aad, &secret).await?;
let decrypted: SecretValue = envelope.decrypt(aad, &encrypted).await?;

assert_eq!(decrypted, secret);
# Ok(())
# }
```

To move to a cloud KMS, replace the provider, see [KMS providers](./providers.md). The rest of
the code stays the same.

## MSRV

The minimum supported Rust version is 1.99, for every feature.
