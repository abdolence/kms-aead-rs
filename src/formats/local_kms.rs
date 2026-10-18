use std::num::NonZeroU32;

use crate::errors::KmsAeadSystemError;
use crate::providers::LocalKekVersion;
use crate::KmsAeadResult;

/// An encrypted DEK of the local KMS:
///
/// ```text
/// [0x01][i: u8][KEK id: i bytes][KEK version: u32 BE][nonce: 12][sealed key][tag: 16]
/// ```
///
/// The header, up to the version, is the associated data of the AES-256-GCM seal, so neither
/// the id nor the version can be changed without the decryption failing.
pub(crate) struct LocalEncryptedDek<'w> {
    /// `[0x01][i][KEK id][KEK version]`, the associated data.
    pub(crate) header: &'w [u8],
    pub(crate) kek_id: &'w [u8],
    pub(crate) kek_version: LocalKekVersion,
    /// `[nonce][sealed key][tag]`, the cipher text of the seal.
    pub(crate) sealed: &'w [u8],
}

impl<'w> LocalEncryptedDek<'w> {
    /// The version of the layout, its first byte.
    const LAYOUT: u8 = 0x01;

    /// The header of a key encrypted under `kek_id` at `kek_version`.
    ///
    /// # Errors
    ///
    /// `INVALID_LOCAL_KEK_ID` when the id is longer than 255 bytes, which a
    /// [`LocalKekId`](crate::providers::LocalKekId) never is.
    pub(crate) fn header(kek_id: &str, kek_version: LocalKekVersion) -> KmsAeadResult<Vec<u8>> {
        let id = kek_id.as_bytes();
        let id_len = u8::try_from(id.len()).map_err(|_| {
            KmsAeadSystemError::create(
                "INVALID_LOCAL_KEK_ID",
                "A local KEK id is longer than 255 bytes",
            )
        })?;
        let mut header = Vec::with_capacity(2 + id.len() + 4);
        header.push(Self::LAYOUT);
        header.push(id_len);
        header.extend_from_slice(id);
        header.extend_from_slice(&kek_version.0.get().to_be_bytes());
        Ok(header)
    }

    /// The parts of `encrypted`, or `None` when it is not in the layout.
    pub(crate) fn split(encrypted: &'w [u8]) -> Option<Self> {
        let [Self::LAYOUT, id_len, rest @ ..] = encrypted else {
            return None;
        };
        let (kek_id, rest) = rest.split_at_checked(usize::from(*id_len))?;
        let (kek_version, sealed) = rest.split_first_chunk::<4>()?;
        Some(Self {
            header: &encrypted[..encrypted.len() - sealed.len()],
            kek_id,
            kek_version: LocalKekVersion::from(NonZeroU32::new(u32::from_be_bytes(*kek_version))?),
            sealed,
        })
    }
}
