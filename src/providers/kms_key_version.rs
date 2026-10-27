use std::fmt::{Display, Formatter};
use std::num::NonZeroU32;

use super::LocalKekVersion;
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::KmsAeadResult;

/// The version of a KMS key: of the KEK that encrypted a data encryption key, the KEK version, or
/// of a signing key. 1 to 255 ASCII alphanumeric characters, such as the version of an Azure Key
/// Vault key, the number of a Cloud KMS CryptoKeyVersion or of a Vault Transit key version, or a
/// local KEK version in decimal.
///
/// The same rule validates every key version read back from the Azure provider's encrypted DEKs,
/// from the layouts of 0.29 and from keyring records, so it may only ever loosen: a stricter rule
/// makes stored data unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsKeyVersion(String);

impl KmsKeyVersion {
    /// The version as the KMS names it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The local KEK version this version names: the decimal digits `From<LocalKekVersion>`
    /// writes, without a leading zero, or `None` for any other form.
    pub(crate) fn local_kek_version(&self) -> Option<LocalKekVersion> {
        let version = self.0.parse::<NonZeroU32>().ok()?;
        (version.to_string() == self.0).then_some(LocalKekVersion::from(version))
    }
}

/// The decimal digits of the version, which always fit the rule.
impl From<LocalKekVersion> for KmsKeyVersion {
    fn from(version: LocalKekVersion) -> Self {
        Self(version.to_string())
    }
}

/// The KEK version that `bytes` hold, read from storage or from a KMS response. The error reports
/// the length and the class of the first rejected byte, never the bytes themselves, which end up
/// in logs.
pub(crate) fn read_kek_version(bytes: &[u8]) -> KmsAeadResult<KmsKeyVersion> {
    let rejected = if bytes.is_empty() || bytes.len() > usize::from(u8::MAX) {
        Some("is not 1 to 255 bytes long")
    } else {
        bytes
            .iter()
            .find(|byte| !byte.is_ascii_alphanumeric())
            .map(|byte| {
                if !byte.is_ascii() {
                    "contains a non-ASCII byte"
                } else if byte.is_ascii_control() {
                    "contains an ASCII control byte"
                } else {
                    "contains ASCII punctuation or a space"
                }
            })
    };
    match rejected {
        Some(reason) => Err(KmsAeadEncryptionError::create(
            "INVALID_KEY_VERSION",
            &format!("KMS key version of {} bytes {reason}", bytes.len()),
        )),
        None => Ok(KmsKeyVersion(
            bytes.iter().copied().map(char::from).collect(),
        )),
    }
}

impl TryFrom<String> for KmsKeyVersion {
    type Error = KmsAeadError;

    fn try_from(value: String) -> KmsAeadResult<Self> {
        read_kek_version(value.as_bytes())
    }
}

impl Display for KmsKeyVersion {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kek_version_is_1_to_255_ascii_alphanumeric_characters() {
        assert!(KmsKeyVersion::try_from("a".repeat(255)).is_ok());
        for invalid in [String::new(), "a".repeat(256), "1/2".into(), "v 1".into()] {
            let result = KmsKeyVersion::try_from(invalid.clone());
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_VERSION"),
                "{invalid:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_kek_version_error_echoes_no_stored_bytes() {
        let error = KmsKeyVersion::try_from("marker/18".to_string()).unwrap_err();

        assert!(
            !format!("{error} {error:?}").contains("marker"),
            "{error:?}"
        );
    }
}
