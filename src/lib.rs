//! # KMS/AEAD envelope encryption for GCP/AWS/Azure KMS and HashiCorp Vault Transit
//!
//! Available providers:
//! - Google Cloud Platform KMS
//! - Amazon Web Services KMS
//! - HashiCorp Vault Transit secrets engine
//! - Azure Key Vault keys
//!
//! Features:
//! - Envelope encryption using automatically generated or provided data encryption keys;
//! - AEAD encryption without a KMS, with [`AeadCipher`];
//! - ring, aws-lc-rs or RustCrypto as the AEAD backend, chosen with the `ring`, `aws-lc` and
//!   `rustcrypto` features and named as a type from [`backend`];
//! - Opt-in for KMS based secure random generator for GCP and AWS instead of the backend's;
//!
//! ## Examples:
//!
//! For AWS, with the ring backend:
//! ```rust,no_run
//! # #[cfg(all(feature = "aws-kms-encryption", feature = "ring"))]
//! # async fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::backend::Ring;
//! use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider};
//! use kms_aead::*;
//! use secret_vault_value::SecretValue;
//!
//! let kms_ref = AwsKmsKeyRef::new("123456789012".into(), "my-key-id".into());
//! let encryption: KmsAeadEnvelope<AwsKmsProvider, Ring> =
//!     KmsAeadEnvelope::new(AwsKmsProvider::new(&kms_ref).await?).await?;
//!
//! let secret_value = SecretValue::from("test-secret");
//! let test_aad = "test-aad".to_string();
//!
//! let cipher_text = encryption.encrypt_value(&test_aad, &secret_value).await?;
//! let decrypted = encryption.decrypt_value(&test_aad, &cipher_text).await?;
//!
//! assert_eq!(decrypted, secret_value);
//! # Ok(())
//! # }
//! ```
//!
//! More examples are available at [github](https://github.com/abdolence/kms-aead-rs)
//!

#![allow(unused_parens, clippy::new_without_default)]
#![forbid(unsafe_code)]

#[cfg(all(
    feature = "vault-transit-kms-encryption-base",
    not(feature = "vault-transit-kms-encryption-tls-roots"),
    not(feature = "vault-transit-kms-encryption-tls-webpki")
))]
compile_error!(
    "You must enable either \"vault-transit-kms-encryption-tls-roots\" or \"vault-transit-kms-encryption-tls-webpki\" when using Vault Transit features"
);

#[cfg(all(
    feature = "vault-transit-kms-encryption-tls-roots",
    feature = "vault-transit-kms-encryption-tls-webpki"
))]
compile_error!(
    "You cannot enable both \"vault-transit-kms-encryption-tls-roots\" (enabled by \"vault-transit-kms-encryption\") and \"vault-transit-kms-encryption-tls-webpki\" at the same time"
);

#[cfg(all(
    feature = "vault-transit-kms-encryption-base",
    not(feature = "vault-transit-kms-encryption-tls-aws-lc-rs"),
    not(feature = "vault-transit-kms-encryption-tls-ring")
))]
compile_error!(
    "You must enable either \"vault-transit-kms-encryption-tls-aws-lc-rs\" or \"vault-transit-kms-encryption-tls-ring\" when using Vault Transit features"
);

#[cfg(all(
    feature = "vault-transit-kms-encryption-tls-aws-lc-rs",
    feature = "vault-transit-kms-encryption-tls-ring"
))]
compile_error!(
    "You cannot enable both \"vault-transit-kms-encryption-tls-aws-lc-rs\" (enabled by \"vault-transit-kms-encryption\") and \"vault-transit-kms-encryption-tls-ring\" at the same time"
);

extern crate core;

#[cfg(all(
    any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "vault-transit-kms-encryption-base"
    ),
    not(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))
))]
compile_error!(
    "kms-aead needs a crypto backend for its KMS providers: enable \"ring\", \"aws-lc\" or \"rustcrypto\""
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

pub type KmsAeadResult<T> = std::result::Result<T, errors::KmsAeadError>;

mod api;
pub use api::*;

mod algorithm;
pub use algorithm::*;

pub mod backend;

mod aead_cipher;
pub use aead_cipher::*;

mod deterministic;
pub use deterministic::*;

pub mod errors;

mod kms_envelope_encryption;
pub use kms_envelope_encryption::*;

mod spans;

mod types;
pub use types::*;

pub mod providers;

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod test_provider;
