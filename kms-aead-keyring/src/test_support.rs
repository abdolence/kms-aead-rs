//! What the unit tests share.

use crate::KeyringId;

pub(crate) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(crate) const TENANT: KeyringId = KeyringId::from_static("tenant-42");

/// The code of the error in `result`, or `Ok` when it succeeded. The values the keyring returns
/// are not `Debug`, so a success cannot show its value.
#[cfg(all(
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
pub(crate) fn error_code_of<V>(result: crate::KeyringResult<V>) -> String {
    match result {
        Ok(_) => "Ok".to_string(),
        Err(error) => error.code().to_string(),
    }
}

#[cfg(all(
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod doubles;
#[cfg(all(
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
pub(crate) use doubles::*;

#[cfg(all(feature = "admin", any(feature = "aws-lc", feature = "rustcrypto")))]
mod asymmetric;
#[cfg(all(feature = "admin", any(feature = "aws-lc", feature = "rustcrypto")))]
pub(crate) use asymmetric::*;

#[cfg(all(feature = "admin", any(feature = "aws-lc", feature = "rustcrypto")))]
mod events;
#[cfg(all(feature = "admin", any(feature = "aws-lc", feature = "rustcrypto")))]
pub(crate) use events::*;
