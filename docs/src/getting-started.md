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

Every feature of both crates is in [Cargo features](./features.md).

## Choosing a backend

There is no default backend: each backend feature adds a type to `kms_aead::backends`, `Ring`,
`AwsLc` or `RustCrypto`, and every type that seals or encrypts takes one as its backend type
parameter. Which one fits a build, FIPS and the C toolchain included, is in
[Choose a provider and a backend](./use-cases/choosing.md#crypto-backends).

## With an envelope

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

## With a keyring

<!-- The included file compiles as a doctest of kms-aead-keyring, see its src/book.rs. -->
{{#include ./getting-started/with-a-keyring.md}}

## MSRV

The minimum supported Rust version is 1.99, for every feature.
