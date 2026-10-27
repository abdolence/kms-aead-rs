use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::providers::kms_key_version::read_kek_version;
use crate::providers::KmsKeyVersion;
use crate::KmsAeadResult;

/// The bytes the Azure provider returns from an encryption and takes to decrypt, kms-aead's own
/// layout, since Key Vault decrypts only with the key version that encrypted and no Tink client
/// exists for Azure:
///
/// ```text
/// [0x01][k: u8][key version: k ASCII alphanumerics][Key Vault encrypted DEK]
/// ```
#[derive(Debug, PartialEq)]
pub(crate) struct AzureEncryptedDek<'e> {
    pub(crate) kek_version: KmsKeyVersion,
    pub(crate) ciphertext: &'e [u8],
}

impl AzureEncryptedDek<'_> {
    /// The version of the layout, its first byte.
    const LAYOUT: u8 = 0x01;

    /// The bytes of the layout.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_VERSION` when the key version is longer than 255 bytes, which a
    /// [`KmsKeyVersion`] never is.
    pub(crate) fn to_bytes(&self) -> KmsAeadResult<Vec<u8>> {
        let version = self.kek_version.as_str().as_bytes();
        let version_len = u8::try_from(version.len()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                "A KMS key version is longer than 255 bytes",
            )
        })?;
        let mut bytes = Vec::with_capacity(2 + version.len() + self.ciphertext.len());
        bytes.push(Self::LAYOUT);
        bytes.push(version_len);
        bytes.extend_from_slice(version);
        bytes.extend_from_slice(self.ciphertext);
        Ok(bytes)
    }
}

impl<'e> TryFrom<&'e [u8]> for AzureEncryptedDek<'e> {
    type Error = KmsAeadError;

    /// # Errors
    ///
    /// `AZURE_ENCRYPTED_DEK_FORMAT` when `bytes` are not in the layout, and `INVALID_KEY_VERSION`
    /// when the key version is not ASCII alphanumeric.
    fn try_from(bytes: &'e [u8]) -> KmsAeadResult<Self> {
        let [Self::LAYOUT, rest @ ..] = bytes else {
            return Err(Self::malformed());
        };
        let (kek_version, ciphertext) = super::split_u8_length_prefixed(rest)
            .filter(|(kek_version, _)| !kek_version.is_empty())
            .ok_or_else(Self::malformed)?;
        Ok(Self {
            kek_version: read_kek_version(kek_version)?,
            ciphertext,
        })
    }
}

impl AzureEncryptedDek<'_> {
    fn malformed() -> KmsAeadError {
        KmsAeadEncryptionError::create(
            "AZURE_ENCRYPTED_DEK_FORMAT",
            "The encrypted data encryption key is not in the layout of the Azure provider",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";

    #[test]
    fn the_layout_is_pinned() -> KmsAeadResult<()> {
        let azure_dek = AzureEncryptedDek {
            kek_version: KmsKeyVersion::try_from(KEY_VERSION.to_string())?,
            ciphertext: b"wrapped",
        };

        let bytes = azure_dek.to_bytes()?;

        assert_eq!(
            hex::encode(&bytes),
            format!("0120{}77726170706564", hex::encode(KEY_VERSION))
        );
        assert_eq!(AzureEncryptedDek::try_from(bytes.as_slice())?, azure_dek);
        Ok(())
    }

    #[test]
    fn bytes_in_another_layout_are_refused() {
        let refused: [&[u8]; 5] = [
            &[],
            &[0x02, 0x01, b'1', 0xAA],
            &[0x01],
            &[0x01, 0x00, 0xAA],
            &[0x01, 0x05, b'1'],
        ];
        for bytes in refused {
            let result = AzureEncryptedDek::try_from(bytes);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "AZURE_ENCRYPTED_DEK_FORMAT"),
                "{bytes:02x?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_key_version_outside_ascii_alphanumerics_is_refused() {
        let result = AzureEncryptedDek::try_from([0x01, 0x03, b'1', b'/', b'2', 0xAA].as_slice());

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_VERSION"),
            "{result:?}"
        );
    }
}
