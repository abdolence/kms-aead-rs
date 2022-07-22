//! # KMS/AEAD envelope encryption for GCP/AWS KMS and Ring AEAD encryption
//!
//! Available providers:
//! - Google Cloud Platform KMS
//! - Amazon Web Services KMS
//!
//! ## Examples:
//! Available at github: https://github.com/abdolence/kms-aead-rs
//!
//! ```

#![allow(unused_parens, clippy::new_without_default)]

use rvstruct::*;
use secret_vault_value::SecretValue;
pub type KmsAeadResult<T> = std::result::Result<T, errors::KmsAeadError>;

mod kms_aead;
pub use kms_aead::*;

pub mod errors;

#[cfg(feature = "encrypted-ring")]
pub mod ring_encryption;

#[cfg(feature = "encrypted-ring")]
mod ring_encryption_support;

#[cfg(feature = "encrypted-ring")]
pub mod ring_envelope_encryption;

#[cfg(feature = "encrypted-ring")]
pub use ring_envelope_encryption::*;

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct EncryptedSecretValue(pub SecretValue);

#[derive(Debug, Clone, PartialEq, ValueStruct)]
pub struct EncryptedSessionKey(pub SecretValue);

impl EncryptedSessionKey {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value().ref_sensitive_value())
    }
}

pub mod providers;
