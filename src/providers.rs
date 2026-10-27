//! The KMS providers, one per feature: `GcpKmsProvider` (`gcp-kms-encryption`),
//! `AwsKmsProvider` (`aws-kms-encryption`), `AzureKmsProvider` (`azure-kms-encryption`) and
//! `HcVaultTransitProvider` (`hashicorp-vault-transit-kms-encryption`), each with the key
//! reference and options types it is built from. `LocalKmsProvider`, with a key encryption key
//! the application holds, is in every build.
//!
//! The asymmetric KEKs, whose public half encrypts DEKs in the producer's process, are in every
//! build too: `PublicKeyKekProvider` for a producer, which holds the public key and decrypts
//! nothing; `AsymmetricKekProvider` for the administration, which encrypts with the public key and
//! decrypts through a KMS provider; and `LocalAsymmetricKmsProvider`, an RSA key pair the process
//! holds. Each fails at construction on a backend without the algorithm, as ring has no RSA.
//!
//! Each of the four has a signing provider under the same feature: `GcpKmsSigningProvider`,
//! `AwsKmsSigningProvider`, `AzureKmsSigningProvider` and `HcVaultTransitSigningProvider`, as
//! `LocalSigningProvider` is in every build.

pub(crate) mod kms_key_version;
pub use kms_key_version::KmsKeyVersion;

pub(crate) mod local_key_source;

mod local_kek_versions;
pub(crate) use local_kek_versions::LocalKekVersions;

mod local_kms_encryption;
pub use local_kms_encryption::*;

mod public_key_kek;
pub use public_key_kek::{AsymmetricKekProvider, PublicKeyKekProvider};

mod local_asymmetric_kms;
pub use local_asymmetric_kms::{LocalAsymmetricKek, LocalAsymmetricKmsProvider};

mod local_signing;
pub use local_signing::{
    LocalSigningKey, LocalSigningKeyName, LocalSigningKeyVersion, LocalSigningProvider,
};

#[cfg(feature = "aws-kms-encryption")]
mod aws_kms_encryption;
#[cfg(feature = "aws-kms-encryption")]
pub use aws_kms_encryption::*;

#[cfg(feature = "gcp-kms-encryption-base")]
mod gcp_kms_encryption;
#[cfg(feature = "gcp-kms-encryption-base")]
pub use gcp_kms_encryption::*;

#[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
mod hc_vault_transit_kms_encryption;
#[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
pub use hc_vault_transit_kms_encryption::*;
#[cfg(feature = "azure-kms-encryption-base")]
mod azure_kms_encryption;
#[cfg(feature = "azure-kms-encryption-base")]
pub use azure_kms_encryption::*;

#[cfg(feature = "aws-kms-encryption")]
mod aws_kms_signing;
#[cfg(feature = "aws-kms-encryption")]
pub use aws_kms_signing::{AwsKmsSigningKeyRef, AwsKmsSigningProvider};

#[cfg(feature = "gcp-kms-encryption-base")]
mod gcp_kms_signing;
#[cfg(feature = "gcp-kms-encryption-base")]
pub use gcp_kms_signing::{GcpKmsSigningKeyRef, GcpKmsSigningProvider};

#[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
mod hc_vault_transit_signing;
#[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
pub use hc_vault_transit_signing::{HcVaultTransitSigningKeyRef, HcVaultTransitSigningProvider};

#[cfg(feature = "azure-kms-encryption-base")]
mod azure_kms_signing;
#[cfg(feature = "azure-kms-encryption-base")]
pub use azure_kms_signing::{AzureKmsSigningKeyRef, AzureKmsSigningProvider};
