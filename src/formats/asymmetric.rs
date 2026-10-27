use super::split_u8_length_prefixed;
use crate::asymmetric_kek::ASYMMETRIC_KEK_RSA_BITS;
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::providers::kms_key_version::read_kek_version;
use crate::providers::KmsKeyVersion;
use crate::{AsymmetricKekAlgorithm, KmsAeadResult};

/// An encrypted DEK that a public key encrypted, the one layout of every provider:
///
/// ```text
/// [0x02][a: u8][i: u8][KEK id: i bytes][k: u8][KEK version: k ASCII alphanumerics][RSA block]
/// ```
///
/// `a` is the algorithm, `0x01` for RSA-OAEP with SHA-256; the KEK id is the local KEK's id and
/// empty for a cloud KEK, whose KMS refuses a block of another key; the KEK version is the one
/// the reader names to its KMS, and empty under AWS KMS. Nothing in the header is authenticated:
/// a changed byte names a key or an algorithm the block does not decrypt under, and a changed
/// block fails OAEP's check.
#[derive(Debug, PartialEq)]
pub(crate) struct PublicKeyEncryptedDek<'e> {
    pub(crate) algorithm: AsymmetricKekAlgorithm,
    pub(crate) kek_id: &'e [u8],
    pub(crate) kek_version: Option<KmsKeyVersion>,
    pub(crate) block: &'e [u8],
}

impl<'e> PublicKeyEncryptedDek<'e> {
    /// The first byte, which no other encrypted DEK of a built-in provider starts with.
    const LAYOUT: u8 = 0x02;

    /// The `a` byte of `algorithm`.
    fn algorithm_byte(algorithm: AsymmetricKekAlgorithm) -> u8 {
        match algorithm {
            AsymmetricKekAlgorithm::RsaOaepSha256 => 0x01,
        }
    }

    /// The bytes of the layout.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` when the KEK id or version is longer than 255 bytes,
    /// which neither a `LocalKekId` nor a [`KmsKeyVersion`] ever is.
    pub(crate) fn to_bytes(&self) -> KmsAeadResult<Vec<u8>> {
        let kek_version = self
            .kek_version
            .as_ref()
            .map_or(&[][..], |version| version.as_str().as_bytes());
        let too_long = |_| {
            KmsAeadEncryptionError::asymmetric_encrypted_dek_format(
                "A KEK id or version is longer than 255 bytes",
            )
        };
        let kek_id_len = u8::try_from(self.kek_id.len()).map_err(too_long)?;
        let kek_version_len = u8::try_from(kek_version.len()).map_err(too_long)?;
        let mut bytes =
            Vec::with_capacity(4 + self.kek_id.len() + kek_version.len() + self.block.len());
        bytes.push(Self::LAYOUT);
        bytes.push(Self::algorithm_byte(self.algorithm));
        bytes.push(kek_id_len);
        bytes.extend_from_slice(self.kek_id);
        bytes.push(kek_version_len);
        bytes.extend_from_slice(kek_version);
        bytes.extend_from_slice(self.block);
        Ok(bytes)
    }

    /// The parts of `bytes`, or `None` when they do not start with the layout's byte and belong to
    /// another layout.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` for an unknown algorithm, a header past the end, a KEK
    /// version that is not ASCII alphanumeric, or a block that is not 256, 384 or 512 bytes.
    pub(crate) fn read(bytes: &'e [u8]) -> Option<KmsAeadResult<Self>> {
        let [Self::LAYOUT, rest @ ..] = bytes else {
            return None;
        };
        Some(Self::read_after_layout(rest))
    }

    fn read_after_layout(bytes: &'e [u8]) -> KmsAeadResult<Self> {
        let (&algorithm, rest) = bytes
            .split_first()
            .ok_or_else(|| Self::malformed("ends before its algorithm"))?;
        let algorithm = match algorithm {
            0x01 => AsymmetricKekAlgorithm::RsaOaepSha256,
            _ => {
                return Err(Self::malformed(
                    "names an algorithm the library does not know",
                ))
            }
        };
        let (kek_id, rest) = split_u8_length_prefixed(rest)
            .ok_or_else(|| Self::malformed("ends inside its KEK id"))?;
        let (kek_version, block) = split_u8_length_prefixed(rest)
            .ok_or_else(|| Self::malformed("ends inside its KEK version"))?;
        let kek_version = match kek_version {
            [] => None,
            version => Some(read_kek_version(version).map_err(|_| {
                Self::malformed("has a KEK version that is not ASCII alphanumeric")
            })?),
        };
        if !ASYMMETRIC_KEK_RSA_BITS
            .iter()
            .any(|bits| bits / 8 == block.len())
        {
            return Err(Self::malformed(&format!(
                "has a block of {} bytes, not of 256, 384 or 512",
                block.len()
            )));
        }
        Ok(Self {
            algorithm,
            kek_id,
            kek_version,
            block,
        })
    }

    /// The version and the block of a DEK given to a cloud KMS that decrypts with a named
    /// version: Cloud KMS, Key Vault and Vault Transit.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` for a KEK id, which a cloud KEK never has, or no version.
    #[cfg_attr(
        all(
            not(test),
            not(any(
                feature = "gcp-kms-encryption-base",
                feature = "azure-kms-encryption-base",
                feature = "hashicorp-vault-transit-kms-encryption-base"
            ))
        ),
        expect(dead_code, reason = "the cloud KMSs with versions read it")
    )]
    pub(crate) fn into_versioned_block(self) -> KmsAeadResult<(KmsKeyVersion, &'e [u8])> {
        if !self.kek_id.is_empty() {
            return Err(Self::malformed("names a local KEK id for a cloud KEK"));
        }
        let kek_version = self
            .kek_version
            .ok_or_else(|| Self::malformed("names no KEK version for a KMS that needs one"))?;
        Ok((kek_version, self.block))
    }

    /// The block of a DEK given to AWS KMS, which has no versions.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` for a KEK id or a version.
    #[cfg_attr(
        all(not(test), not(feature = "aws-kms-encryption")),
        expect(dead_code, reason = "AWS KMS is the one KMS without versions")
    )]
    pub(crate) fn into_unversioned_block(self) -> KmsAeadResult<&'e [u8]> {
        if !self.kek_id.is_empty() {
            return Err(Self::malformed("names a local KEK id for a cloud KEK"));
        }
        if self.kek_version.is_some() {
            return Err(Self::malformed(
                "names a KEK version for a KMS without versions",
            ));
        }
        Ok(self.block)
    }

    pub(crate) fn malformed(reason: &str) -> KmsAeadError {
        KmsAeadEncryptionError::asymmetric_encrypted_dek_format(&format!(
            "The encrypted DEK encrypted with a public key {reason}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::RsaOaepSuite;

    const BLOCK: [u8; 256] = [0xB1; 256];

    fn kms_key_version(version: &str) -> KmsKeyVersion {
        KmsKeyVersion::try_from(version.to_string()).unwrap()
    }

    fn assert_malformed<T: std::fmt::Debug>(result: KmsAeadResult<T>) {
        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "ASYMMETRIC_ENCRYPTED_DEK_FORMAT"),
            "{result:?}"
        );
    }

    #[test]
    fn a_header_reads_back_as_written() -> KmsAeadResult<()> {
        let encrypted_dek = PublicKeyEncryptedDek {
            algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
            kek_id: b"orders",
            kek_version: Some(kms_key_version("7")),
            block: &BLOCK,
        };

        let bytes = encrypted_dek.to_bytes()?;

        assert_eq!(bytes[..10], *b"\x02\x01\x06orders\x01");
        assert_eq!(
            PublicKeyEncryptedDek::read(&bytes).transpose()?,
            Some(encrypted_dek)
        );
        Ok(())
    }

    /// The layout under each cloud KMS, pinned byte for byte around the block of Wycheproof's
    /// 2048-bit case 7; the local KMS's is pinned with its provider.
    #[test]
    fn the_cloud_layouts_are_pinned() -> KmsAeadResult<()> {
        let block = hex::decode(&RsaOaepSuite::of_bits(2048).case(7).ct).unwrap();
        let headers = [
            // Cloud KMS, CryptoKeyVersion 3.
            (Some("3"), "0201000133"),
            // AWS KMS, which has no versions.
            (None, "02010000"),
            // Key Vault, a 32-character version.
            (
                Some("4387e9f3d6e14c459867679a90fd0f79"),
                "020100203433383765396633643665313463343539383637363739613930666430663739",
            ),
            // Vault Transit, version 2.
            (Some("2"), "0201000132"),
        ];
        for (kek_version, header) in headers {
            let encrypted_dek = PublicKeyEncryptedDek {
                algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                kek_id: b"",
                kek_version: kek_version.map(kms_key_version),
                block: &block,
            };

            let bytes = encrypted_dek.to_bytes()?;

            assert_eq!(
                hex::encode(&bytes),
                format!("{header}{}", hex::encode(&block))
            );
            assert_eq!(
                PublicKeyEncryptedDek::read(&bytes).transpose()?,
                Some(encrypted_dek)
            );
        }
        Ok(())
    }

    #[test]
    fn bytes_of_another_layout_are_not_read() {
        for first in [0x00, 0x01, 0x0a, b'v', 0xFF] {
            assert!(PublicKeyEncryptedDek::read(&[first, 0x01, 0x00, 0x00]).is_none());
        }
    }

    /// Every refusal of a header, before any KMS call.
    #[test]
    fn a_header_of_another_shape_is_refused() {
        let with_block =
            |header: &[u8], block_len: usize| [header, &vec![0xB1; block_len]].concat();
        let refused = [
            vec![0x02],
            with_block(&[0x02, 0x02, 0x00, 0x00], 256),
            vec![0x02, 0x01, 0x05, b'a'],
            vec![0x02, 0x01, 0x00, 0x03, b'1'],
            with_block(&[0x02, 0x01, 0x00, 0x01, b'/'], 256),
            with_block(&[0x02, 0x01, 0x00, 0x00], 255),
            with_block(&[0x02, 0x01, 0x00, 0x00], 513),
        ];
        for bytes in refused {
            let read = PublicKeyEncryptedDek::read(&bytes).expect("the layout's first byte");
            assert_malformed(read);
        }
    }

    #[test]
    fn a_cloud_reader_refuses_a_kek_id_and_the_version_shape_of_another_kms() -> KmsAeadResult<()> {
        let read = |kek_id: &'static [u8], kek_version: Option<&str>| PublicKeyEncryptedDek {
            algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
            kek_id,
            kek_version: kek_version.map(kms_key_version),
            block: &BLOCK,
        };

        assert_eq!(
            read(b"", Some("3")).into_versioned_block()?,
            (kms_key_version("3"), &BLOCK[..])
        );
        assert_eq!(read(b"", None).into_unversioned_block()?, &BLOCK[..]);
        assert_malformed(read(b"orders", Some("3")).into_versioned_block());
        assert_malformed(read(b"", None).into_versioned_block());
        assert_malformed(read(b"orders", None).into_unversioned_block());
        assert_malformed(read(b"", Some("3")).into_unversioned_block());
        Ok(())
    }
}
