//! Envelope encryption with a key encryption key (KEK) held by a KMS, and AEAD without one.
//!
//! A value is sealed under a data encryption key (DEK) with an AEAD algorithm, and the DEK is
//! wrapped by the KEK. [`KmsAeadEnvelope`] does both and stores the wrapped DEK with the cipher
//! text. [`AeadCipher`] seals with a DEK the caller holds, without a KMS.
//!
//! # Providers
//!
//! A provider wraps and unwraps DEKs with one KEK. Each one is a type in [`providers`], enabled by
//! its feature where the table names one, and implements [`KmsAeadEncryptionProvider`], which an
//! application can also implement for a KMS of its own.
//!
//! | KMS | Type | Feature |
//! |---|---|---|
//! | Google Cloud KMS | `GcpKmsProvider` | `gcp-kms-encryption` |
//! | AWS KMS | `AwsKmsProvider` | `aws-kms-encryption` |
//! | Azure Key Vault and Managed HSM | `AzureKmsProvider` | `azure-kms-encryption` |
//! | HashiCorp Vault Transit | `HcVaultTransitProvider` | `hashicorp-vault-transit-kms-encryption` |
//! | A KEK the process holds | `LocalKmsProvider` | none, in every build |
//!
//! The GCP, Azure and HashiCorp Vault Transit features have variants that choose the TLS stack,
//! the root store or the crypto provider of their HTTP client; `Cargo.toml` lists them. A build
//! with a provider needs a backend.
//!
//! A wrap and an unwrap take an optional [`DekBinding`], which the KMS authenticates with the
//! wrapped key: GCP as additional authenticated data, AWS as an encryption context, Vault Transit
//! as associated data and the local KMS in its AAD. The Azure provider has no such input and
//! refuses a binding. [`KmsAeadEnvelope`] wraps unbound.
//!
//! An AWS KMS unwrap names the configured key. Configure the key ARN rather than an alias: a key
//! wrapped under an alias that later moves to another key fails to unwrap with
//! `IncorrectKeyException`. Outside the `aws` partition, such as in GovCloud or China, give the
//! full ARN, since a key id or an alias name becomes an `arn:aws:` ARN.
//!
//! # Backends
//!
//! The AEAD runs on a crypto library that a feature compiles in and an [`AeadBackend`] value
//! selects at runtime, passed to [`AeadCipher::new`] and to the [`KmsAeadEnvelope`]
//! constructors. A build may enable any number of them, and there is no default one.
//!
//! | Feature | Variant | Algorithms |
//! |---|---|---|
//! | `ring` | `AeadBackend::Ring` | ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM |
//! | `aws-lc` | `AeadBackend::AwsLc` | every [`AeadAlgorithm`] |
//! | `aws-lc-fips` | `AeadBackend::AwsLc`, on the FIPS module | every [`AeadAlgorithm`] |
//! | `rustcrypto` | `AeadBackend::RustCrypto` | every [`AeadAlgorithm`] |
//!
//! `aws-lc-fips` builds only the FIPS module, and does not need `aws-lc`. A build with both
//! compiles both C libraries, and aws-lc-rs runs on the FIPS module. The `aws-lc-rs` feature
//! both of them enable is not a backend choice: on its own, aws-lc-rs's build fails.
//!
//! A value sealed by one backend opens with any other that implements its algorithm.
//!
//! A build without a backend feature compiles, and
//! [`LocalKmsProvider`](providers::LocalKmsProvider) is in it, but nothing that seals or wraps
//! can be constructed: [`AeadBackend`] has no variant.
//!
//! # Store-less mode and the DEK cache
//!
//! A [`KmsAeadEnvelope`] built with a [`DekReusePolicy`] encrypts many values under one DEK and
//! renews it by age, by count, or once it has left the cache, so that a write calls the KMS only
//! to renew it. Its DEK, and the DEKs of the values it reads, live in a
//! [`cache::DekCache`], which serves each plaintext DEK for a TTL and zeroizes it as it leaves the
//! cache: at the cache's next call after the TTL, or at
//! [`purge_expired`](cache::DekCache::purge_expired). The per-call envelope, the default, keeps
//! no DEK past the call. The KMS SDKs and HTTP clients the providers use keep copies of each
//! plaintext DEK in request and response buffers that kms-aead cannot zeroize.
//!
//! # Other features
//!
//! - `deterministic`: deterministic encryption with AES-SIV, [`DeterministicAlgorithm`].
//! - `legacy-formats`: reads the layouts written up to 0.28.1. Deprecated.
//! - `serde`: `Serialize` and `Deserialize` for [`errors::KmsAeadErrorPublicGenericDetails`] and
//!   for `SecretValue`.
//!
//! # Examples
//!
//! Envelope encryption with AWS KMS, on the ring backend:
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "aws-kms-encryption", feature = "ring"))]
//! # async fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider};
//! use kms_aead::{AeadBackend, KmsAeadEnvelope};
//! use secret_vault_value::SecretValue;
//!
//! let kms_ref = AwsKmsKeyRef::new(
//!     "123456789012".into(),
//!     "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab".into(),
//! );
//! let encryption = KmsAeadEnvelope::new(AwsKmsProvider::new(&kms_ref).await?, AeadBackend::Ring)?;
//!
//! let secret_value = SecretValue::from("4111 1111 1111 1111");
//! let aad = b"orders/1042";
//!
//! let cipher_text = encryption.encrypt_value(aad, &secret_value).await?;
//! let decrypted = encryption.decrypt_value(aad, &cipher_text).await?;
//!
//! assert_eq!(decrypted, secret_value);
//! # Ok(())
//! # }
//! ```
//!
//! AEAD with a key the caller holds, on the ring backend:
//!
//! ```rust
//! # #[cfg(feature = "ring")]
//! # fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::{AeadAlgorithm, AeadBackend, AeadCipher, CipherText, ValueStruct};
//! use secret_vault_value::SecretValue;
//!
//! let cipher = AeadCipher::new(AeadBackend::Ring, AeadAlgorithm::Aes256Gcm)?;
//! let key = cipher.generate_key()?;
//! let secret_value = SecretValue::from("4111 1111 1111 1111");
//! let aad = b"orders/1042";
//!
//! let cipher_text = cipher.encrypt_value(aad, &secret_value, &key)?;
//! let stored: &[u8] = cipher_text.value();
//! let decrypted = cipher.decrypt_value(aad, &CipherText(stored.to_vec()), &key)?;
//!
//! assert_eq!(decrypted, secret_value);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-base",
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-roots"),
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-webpki")
))]
compile_error!(
    "You must enable either \"hashicorp-vault-transit-kms-encryption-tls-roots\" or \"hashicorp-vault-transit-kms-encryption-tls-webpki\" when using HashiCorp Vault Transit features"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-tls-roots",
    feature = "hashicorp-vault-transit-kms-encryption-tls-webpki"
))]
compile_error!(
    "You cannot enable both \"hashicorp-vault-transit-kms-encryption-tls-roots\" (enabled by \"hashicorp-vault-transit-kms-encryption\") and \"hashicorp-vault-transit-kms-encryption-tls-webpki\" at the same time"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-base",
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs"),
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-ring")
))]
compile_error!(
    "You must enable either \"hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs\" or \"hashicorp-vault-transit-kms-encryption-tls-ring\" when using HashiCorp Vault Transit features"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs",
    feature = "hashicorp-vault-transit-kms-encryption-tls-ring"
))]
compile_error!(
    "You cannot enable both \"hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs\" (enabled by \"hashicorp-vault-transit-kms-encryption\") and \"hashicorp-vault-transit-kms-encryption-tls-ring\" at the same time"
);

#[cfg(all(
    any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ),
    not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))
))]
compile_error!(
    "kms-aead needs a crypto backend for its KMS providers: enable \"ring\", \"aws-lc\", \"aws-lc-fips\" or \"rustcrypto\""
);

#[cfg(all(
    feature = "azure-kms-encryption-base",
    not(feature = "azure-kms-encryption-tls-aws-lc-rs"),
    not(feature = "azure-kms-encryption-tls-no-provider"),
    not(feature = "azure-kms-encryption-native-tls")
))]
compile_error!(
    "You must enable one of \"azure-kms-encryption-tls-aws-lc-rs\" (or \"azure-kms-encryption\"), \"azure-kms-encryption-tls-no-provider\" or \"azure-kms-encryption-native-tls\" when using Azure features"
);

#[cfg(any(
    all(
        feature = "azure-kms-encryption-tls-aws-lc-rs",
        feature = "azure-kms-encryption-tls-no-provider"
    ),
    all(
        feature = "azure-kms-encryption-tls-aws-lc-rs",
        feature = "azure-kms-encryption-native-tls"
    ),
    all(
        feature = "azure-kms-encryption-tls-no-provider",
        feature = "azure-kms-encryption-native-tls"
    )
))]
compile_error!(
    "You can enable only one of \"azure-kms-encryption-tls-aws-lc-rs\" (enabled by \"azure-kms-encryption\"), \"azure-kms-encryption-tls-no-provider\" and \"azure-kms-encryption-native-tls\""
);

/// The result of every fallible operation of the crate.
pub type KmsAeadResult<T> = std::result::Result<T, errors::KmsAeadError>;

mod api;
pub use api::*;

mod algorithm;
pub use algorithm::*;

mod backend;
pub use backend::AeadBackend;

mod aead_cipher;
pub use aead_cipher::*;

pub mod cache;

mod deterministic;
pub use deterministic::*;

pub mod errors;

mod kms_envelope_encryption;
pub use kms_envelope_encryption::*;

mod spans;

mod types;
pub use types::*;

/// The trait whose `value()` and `into_value()` read the bytes of [`CipherText`],
/// [`CipherTextWithEncryptedKey`] and [`DeterministicCipherText`].
pub use rvstruct::ValueStruct;

pub mod providers;

#[cfg(test)]
mod test_provider;

#[cfg(test)]
#[cfg(any(
    feature = "aws-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption-base"
))]
mod test_http;
