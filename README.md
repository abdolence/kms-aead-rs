[![Cargo](https://img.shields.io/crates/v/kms-aead.svg)](https://crates.io/crates/kms-aead)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)
![license](https://img.shields.io/github/license/abdolence/kms-aead-rs)

# KMS envelope encryption for Rust

Library provides envelope encryption with a key encryption key held by a KMS, and AEAD
encryption without a KMS:

- KMS providers for Google Cloud KMS, AWS KMS, Azure Key Vault and Managed HSM, HashiCorp Vault
  Transit, and a local KMS for development, tests and single-host installs;
- AEAD algorithms ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM and AES-256-GCM-SIV;
- Crypto backends chosen at runtime: ring, aws-lc-rs (including its FIPS module) and RustCrypto,
  with values readable across all of them;
- Per-call envelopes, store-less DEK reuse, and an in-process cache of unwrapped data encryption
  keys;
- Deterministic encryption with AES-SIV;
- Optional KMS-side random generators for GCP and AWS;
- Tracing spans for every operation and every KMS call;
- No unsafe code.

## Documentation

Please follow to the official website: <https://kms-aead-rust.abdolence.dev>.

## Quick start

Cargo.toml:

```toml
[dependencies]
kms-aead = { version = "0.30", features = ["gcp-kms-encryption", "aws-lc"] }
```

Every build with a KMS provider needs a crypto backend feature: `ring`, `aws-lc`, `aws-lc-fips` or
`rustcrypto`. The features are listed in
[Getting started](https://kms-aead-rust.abdolence.dev/getting-started.html#features).

```rust,no_run
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadBackend, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let kms_ref = GcpKmsKeyRef::new(
        "my-project".to_string(),
        "europe-north1".to_string(),
        "my-key-ring".to_string(),
        "my-key".to_string(),
    );
    let envelope =
        KmsAeadEnvelope::new(GcpKmsProvider::new(&kms_ref).await?, AeadBackend::AwsLc)?;

    let aad = b"orders/1042";
    let secret = SecretValue::from("4111 1111 1111 1111");

    // The cipher text with its wrapped data encryption key, to store
    let encrypted = envelope.encrypt_value(aad, &secret).await?;

    let decrypted = envelope.decrypt_value(aad, &encrypted).await?;
    assert_eq!(decrypted, secret);

    Ok(())
}
```

Other providers:
[AWS KMS](https://kms-aead-rust.abdolence.dev/providers/aws.html),
[Azure Key Vault](https://kms-aead-rust.abdolence.dev/providers/azure.html),
[HashiCorp Vault Transit](https://kms-aead-rust.abdolence.dev/providers/hc-vault-transit.html),
[Local KMS](https://kms-aead-rust.abdolence.dev/providers/local.html).

All examples available in the [examples](examples) directory.

## Migrating from 0.29

0.30 makes ring optional and selects the crypto backend at runtime, so a provider feature needs a
backend feature next to it, and most names changed. See the [migration guide](MIGRATION.md) and
[Migrating from 0.29](https://kms-aead-rust.abdolence.dev/migrating-from-0.29.html).

Values written by 0.28.1 and earlier read only with the deprecated `legacy-formats` feature, see
[Formats](https://kms-aead-rust.abdolence.dev/formats.html).

## Security

See [Security considerations](https://kms-aead-rust.abdolence.dev/security.html) for the threat
model, nonce budgets, key lifetime and what rotation does not protect, and
[SECURITY.md](SECURITY.md) to report a vulnerability.

## Licence

Apache Software License (ASL)

## Author

Abdulla Abdurakhmanov
