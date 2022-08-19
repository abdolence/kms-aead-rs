[![Cargo](https://img.shields.io/crates/v/kms-aead.svg)](https://crates.io/crates/kms-aead)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/kms-aead-rs/workflows/security%20audit/badge.svg)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)
![license](https://img.shields.io/github/license/abdolence/secret-vault-rs)

# KMS/AEAD envelope encryption for GCP/AWS KMS and Ring AEAD for Rust

Features:
- Envelope encryption using automatically generated or provided data encryption keys;
- Provides a public and simple implementation for Ring based AEAD encryption without using KMS;
- Opt-in for KMS based secure random generator for GCP and AWS instead of Ring;

Available KMS providers:
- Google Cloud Platform KMS
- Amazon Web Services KMS

## Quick start

Cargo.toml:
```toml
[dependencies]
kms-aead = { version = "0.8", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for Secret Vault:
- `gcp-kms-encryption` for Google KMS envelope encryption support
- `aws-kms-encryption` for Amazon KMS envelope encryption support
- `ring-aead-encryption` using API for Ring AEAD only without any KMS envelope encryption

## Example
```rust
 let kms_ref = kms_aead::providers::AwsKmsKeyRef::new(aws_account_id, aws_key_id);

 let encryption: KmsAeadRingEnvelopeEncryption<AwsKmsProvider> =
     kms_aead::KmsAeadRingEnvelopeEncryption::new(providers::AwsKmsProvider::new(&kms_ref).await?)
         .await?;

 let secret_value = SecretValue::from("test-secret");
 let test_aad = "test-aad".to_string();

 let cipher_text = encryption.encrypt_value(&test_aad, &secret_value).await?;

 let secret_value: SecretValue = encryption
     .decrypt_value(&test_aad, &cipher_text)
     .await?;
```

All examples available at [examples](examples) directory.

## GCP/AWS secure random generators
To use GCP/AWS KMS API for secure random generator you should enable it using options.

For AWS:
```rust
    providers::AwsKmsProvider::with_options(
            &kms_ref,
            AwsKmsProviderOptions::new().with_use_kms_random_gen(true),
    ).await?
```

For GCP:
```rust
    providers::GcpKmsProvider::with_options(
            &kms_ref,
            GcpKmsProviderOptions::new().with_use_kms_random_gen(true),
    ).await?
```

## Security considerations and risks

### OSS
Open source code is created through voluntary collaboration of software developers.
The original authors license the code so that anyone can see it, modify it, and
distribute new versions of it.
You should manage all OSS using the same procedures and tools that you use for
commercial products. As always, train your employees on
cyber security best practices that can help them securely 
use and manage software products.
You should not solely rely on individuals, especially on the projects like this
reading sensitive information.

### Versioning
Please don't use broad version dependency management not to include
a new version of dependency automatically without auditing the changes.

### Security implementation details and recommendations
The library uses random 96 bit [nonces](https://en.wikipedia.org/wiki/Cryptographic_nonce)
and [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) algorithm by default.
Depends on your security requirements to avoid nonce collisions it is recommended
to either rotate random DEK frequently using `rotate_current_key` or
even use a new random DEK per encryption using `encrypt_value_with_new_key`/`encrypt_value`.

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov
