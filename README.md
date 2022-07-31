[![Cargo](https://img.shields.io/crates/v/kms-aead.svg)](https://crates.io/crates/kms-aead)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/kms-aead-rs/workflows/security%20audit/badge.svg)

# KMS/AEAD envelope encryption for GCP/AWS KMS and Ring AEAD for Rust

Available providers for:
 - Google Cloud Platform KMS
 - Amazon Web Services KMS

## Quick start

Cargo.toml:
```toml
[dependencies]
kms-aead = { version = "0.4", features=["..."] }
```
See security consideration below about versioning.

### Available optional features for Secret Vault:
- `gcp-kms-encryption` for Google KMS envelope encryption support
- `aws-kms-encryption` for Amazon KMS envelope encryption support

All examples available at [examples](examples) directory.

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

### Protect your secrets in GCP/AWS using IAM and service accounts
Don't expose all of your secrets to the apps. 
Use IAM and different service accounts to give access only on as-needed basis.

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov
