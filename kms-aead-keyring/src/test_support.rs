//! What the unit tests share.

use crate::KeyringId;

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) const TENANT: KeyringId = KeyringId::from_static("tenant-42");

#[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
mod doubles;
#[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
pub(crate) use doubles::*;
