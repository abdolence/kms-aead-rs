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

### Security implementation details and recommendations
The library uses random 96 bit [nonces](https://en.wikipedia.org/wiki/Cryptographic_nonce)
and [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) algorithm by default.
Depends on your security requirements to avoid nonce collisions it is recommended
to either rotate random DEK frequently using `rotate_session_key` or
even use a new random DEK per encryption using `encrypt_value_with_new_session_key`.


## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov
