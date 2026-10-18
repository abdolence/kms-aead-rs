//! The KMS providers, one per feature: `GcpKmsProvider` (`gcp-kms-encryption`),
//! `AwsKmsProvider` (`aws-kms-encryption`), `AzureKmsProvider` (`azure-kms-encryption`) and
//! `HcVaultTransitProvider` (`hashicorp-vault-transit-kms-encryption`), each with the key
//! reference and options types it is built from. `LocalKmsProvider`, with a key encryption key
//! the application holds, is in every build.

mod kms_key_version;
pub use kms_key_version::KmsKeyVersion;

mod local_kms_encryption;
pub use local_kms_encryption::*;

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
