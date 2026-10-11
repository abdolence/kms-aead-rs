[![Cargo](https://img.shields.io/crates/v/kms-aead.svg)](https://crates.io/crates/kms-aead)
![tests and formatting](https://github.com/abdolence/kms-aead-rs/workflows/tests%20&amp;%20formatting/badge.svg)
![security audit](https://github.com/abdolence/kms-aead-rs/workflows/security%20audit/badge.svg)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-success.svg)
![license](https://img.shields.io/github/license/abdolence/secret-vault-rs)

# KMS/AEAD envelope encryption for GCP/AWS/Azure KMS and Ring AEAD for Rust

Features:
- Envelope encryption using automatically generated or provided data encryption keys;
- Provides a public and simple implementation for Ring based AEAD encryption without using KMS;
- Opt-in for KMS based secure random generator for GCP and AWS instead of Ring;

Available KMS providers:
- Google Cloud Platform KMS
- Amazon Web Services KMS
- HashiCorp Vault Transit secrets engine
- Azure Key Vault keys

## Quick start

Cargo.toml:
```toml
[dependencies]
kms-aead = { version = "0.28", features=["..."] }
```
See security consideration below about versioning.

### Available features:
- `gcp-kms-encryption` for Google KMS envelope encryption support. Be aware it also turns on native-tls in reqwest, so the Azure provider uses native-tls whatever its TLS feature
- `gcp-kms-encryption-webpki` for Google KMS envelope encryption with the bundled WebPKI root certificates
- `gcp-kms-encryption-base` for Google KMS envelope encryption without a TLS root store or crypto provider. The application enables them with its own `gcloud-sdk` features, such as `tls-roots` or `tls-webpki-roots`, and the crate does not build without one
- `aws-kms-encryption` for Amazon KMS envelope encryption support
- `vault-transit-kms-encryption` for HashiCorp Vault Transit envelope encryption support,
  with system root certificates and the aws-lc-rs crypto provider. To choose them, enable one of
  `vault-transit-kms-encryption-tls-roots`/`-tls-webpki` and one of
  `vault-transit-kms-encryption-tls-aws-lc-rs`/`-tls-ring` instead.
  A CA certificate from `VAULT_CACERT` or `ca_certificate` adds to the root store and does not
  replace it, unlike in the Vault CLI.
  See [examples/vault_transit_kms.rs](examples/vault_transit_kms.rs)
- `azure-kms-encryption` for Azure Key Vault envelope encryption support, with rustls and the aws-lc-rs crypto provider. Other TLS variants, choose one:
  - `azure-kms-encryption-tls-aws-lc-rs`, the same as `azure-kms-encryption`;
  - `azure-kms-encryption-tls-no-provider` for rustls with the crypto provider the application installs. The application must install a process-default rustls `CryptoProvider` before creating the provider, otherwise rustls panics;
  - `azure-kms-encryption-native-tls` for the platform TLS library.

  Full example available [here](examples/azure_kms.rs)
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

### Envelope layout
Since 0.29.0 `CipherTextWithEncryptedKey` is written in layout v1:
- the `0x01` layout tag;
- the version of the KMS key that wrapped the data encryption key, when the provider reports one (GCP, Vault Transit, Azure);
- the wrapped data encryption key;
- the AEAD cipher text.

The library reads every layout written since 0.8.0, including the 4-byte length prefix
written on 32-bit targets before 0.24.0.

Since 0.29.0 `EncryptedDataEncryptionKey::to_bytes` and `to_hex_string` write the key for the
`*_with_encrypted_dek` APIs with its key version:
- the `0xFF` magic and the `0x01` layout tag;
- the KMS key version, when the provider reports one;
- the wrapped data encryption key.

`TryFrom<&[u8]>` and `try_from_hex_string` read this layout and the bare wrapped key that
`value` and `to_hex_string` returned up to 0.28.1, so a key stored by any version reads with them.
Keys stored up to 0.28.1 come only from GCP and AWS: GCP wrapped keys start with `0x0a` and AWS
ones with `0x01`, so a stored key is never read in the wrong layout.

Up to 0.28.1 a stored key was written with `value()` or `to_hex_string()` and read with
`From<Vec<u8>>`. Since 0.29.0 write it with `to_bytes()` or `to_hex_string()` and read it with
`TryFrom<&[u8]>` or `try_from_hex_string()`. Be aware not to read stored keys with
`EncryptedDataEncryptionKey::new`: it takes the bytes a KMS returned, so it reads keys stored
before the upgrade and fails at the KMS on keys written after it.

Be aware that 0.28.1 and earlier cannot read either layout, so upgrade every reader before the first write.

### Security implementation details and recommendations
The library uses 96 bit [nonces](https://en.wikipedia.org/wiki/Cryptographic_nonce)
and [ChaCha20-Poly1305](https://tools.ietf.org/html/rfc7539) algorithm by default.

Nonces generates as:
- (current default implementation) A random 96-bit buffer generated by cryptographic pseudo-random number generator;

## Licence
Apache Software License (ASL)

## Author
Abdulla Abdurakhmanov
