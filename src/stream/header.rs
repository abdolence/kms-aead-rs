//! The header of a streamed value: the key reference of its form, then the Cobblestone header,
//! the salt and the key commitment.

use std::fmt::{Debug, Formatter};

use super::cipher::{Commitment, Salt, STREAM_KEY_COMMITMENT_LEN, STREAM_SALT_LEN};
use super::{StreamFormat, BARE_HEADER_LEN, PREFIXED_HEADER_LEN};
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::formats::envelope::{split_encrypted_dek_len, ENCRYPTED_DEK_LEN_FIELD_SIZE};
use crate::formats::{split_tink_output_prefix, TINK_OUTPUT_PREFIX_LEN};
use crate::{EncryptedDataEncryptionKey, KeyId, KmsAeadResult};

/// The first 61 bytes of a prefixed streamed value, read before any chunk: Tink's output prefix,
/// `[0x01][key id: u32 BE]`, then the 24-byte salt and the 32-byte key commitment.
///
/// It checks the layout only, the first byte: whether the header belongs to a key is known when
/// a decryptor is made for it. A bare value's header, its first 56 bytes, has nothing to check and
/// no type: [`stream_decryptor_bare`](crate::AeadCipher::stream_decryptor_bare) takes the bytes
/// themselves. The header of the envelope form is an [`EnvelopeStreamHeader`].
#[derive(Clone)]
pub struct PrefixedStreamHeader {
    key_id: KeyId,
    bytes: [u8; PREFIXED_HEADER_LEN],
}

impl PrefixedStreamHeader {
    /// The id of the key the value names: the keyring version, or the caller's [`KeyId`]. It is
    /// not authenticated: a value relabelled with another id decrypts under no other key.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The bytes, to write in front of a value copied elsewhere.
    pub fn value(&self) -> &[u8; PREFIXED_HEADER_LEN] {
        &self.bytes
    }

    /// The Cobblestone header after the prefix.
    pub(crate) fn cobblestone(&self) -> CobblestoneHeader {
        let mut bare = [0; BARE_HEADER_LEN];
        bare.copy_from_slice(&self.bytes[TINK_OUTPUT_PREFIX_LEN..]);
        CobblestoneHeader::from(&bare)
    }
}

/// Exactly 61 bytes starting with `0x01`.
///
/// # Errors
///
/// `INVALID_CIPHER_TEXT_FORMAT` for bytes of another length or another first byte.
impl TryFrom<&[u8]> for PrefixedStreamHeader {
    type Error = KmsAeadError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <[u8; PREFIXED_HEADER_LEN]>::try_from(bytes)
            .ok()
            .and_then(|bytes| {
                split_tink_output_prefix(&bytes).map(|(key_id, _)| Self { key_id, bytes })
            })
            .ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "INVALID_CIPHER_TEXT_FORMAT",
                    "A stream header is 61 bytes starting with 0x01, Tink's output prefix",
                )
            })
    }
}

/// Shows the key id and nothing of the bytes.
impl Debug for PrefixedStreamHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrefixedStreamHeader")
            .field("key_id", &self.key_id())
            .finish_non_exhaustive()
    }
}

/// The first `4 + w + 56` bytes of a streamed value in the envelope form, read before any chunk:
/// `w`, the length of the encrypted DEK, as a `u32` big-endian, the encrypted DEK, then the
/// 24-byte salt and the 32-byte key commitment. It is the header of Tink's KMS envelope in front
/// of a bare value's header, so the bytes from `4 + w` on are a Cobblestone-256 message.
///
/// A reader learns the header's length from the value's first 4 bytes with
/// [`header_len`](Self::header_len), then fetches that many bytes from the start of the value
/// and parses them with `TryFrom`. Both check `w` before anything else, so a hostile length costs
/// neither an allocation nor a KMS call. Whether the encrypted DEK decrypts the value is known when
/// a decryptor is made for it.
#[derive(Clone)]
pub struct EnvelopeStreamHeader {
    encrypted_dek: EncryptedDataEncryptionKey,
    bare_header: [u8; BARE_HEADER_LEN],
}

impl EnvelopeStreamHeader {
    /// The length of the header of the envelope-form value whose first bytes are `prefix`, 4 or
    /// more of them: `4 + w + 56` bytes, at most 4,156, by `w` in the first 4.
    ///
    /// # Errors
    ///
    /// `INVALID_CIPHER_TEXT_FORMAT` when `prefix` is shorter than 4 bytes, or `w` is not 1 to
    /// 4,096, the encrypted DEK lengths Tink reads.
    pub fn header_len(prefix: &[u8]) -> KmsAeadResult<usize> {
        let (encrypted_dek_len, _) = Self::checked_encrypted_dek_len(prefix)?;
        Ok(StreamFormat::Envelope { encrypted_dek_len }.header_len())
    }

    /// `w` and the bytes after it, or the error of a `w` that is out of bounds or missing.
    fn checked_encrypted_dek_len(bytes: &[u8]) -> KmsAeadResult<(usize, &[u8])> {
        split_encrypted_dek_len(bytes).ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "An envelope stream header starts with an encrypted DEK length of 1 to 4,096 \
                     bytes, which its first {} bytes do not hold",
                    bytes.len().min(ENCRYPTED_DEK_LEN_FIELD_SIZE)
                ),
            )
        })
    }

    /// The encrypted DEK that decrypts the value, the key reference of the envelope form. It
    /// carries no KEK version, as one read back from storage does not.
    pub fn encrypted_dek(&self) -> &EncryptedDataEncryptionKey {
        &self.encrypted_dek
    }

    /// The form of the value, which carries the length of its encrypted DEK: the receiver of
    /// [`plan_chunk_read`](StreamFormat::plan_chunk_read) for a value in the envelope form.
    pub fn form(&self) -> StreamFormat {
        StreamFormat::Envelope {
            encrypted_dek_len: self.encrypted_dek.value().len(),
        }
    }

    /// The Cobblestone header after the encrypted DEK, a bare value's first 56 bytes.
    pub(crate) fn bare_header(&self) -> &[u8] {
        &self.bare_header
    }
}

/// Exactly the `4 + w + 56` bytes of the header that
/// [`header_len`](EnvelopeStreamHeader::header_len) gives for them.
///
/// # Errors
///
/// `INVALID_CIPHER_TEXT_FORMAT` for the errors of `header_len`, and for bytes of another length.
impl TryFrom<&[u8]> for EnvelopeStreamHeader {
    type Error = KmsAeadError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let (encrypted_dek_len, rest) = Self::checked_encrypted_dek_len(bytes)?;
        let wrong_len = || {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "An envelope stream header with an encrypted DEK of {encrypted_dek_len} bytes \
                     is {} bytes long, not {}",
                    StreamFormat::Envelope { encrypted_dek_len }.header_len(),
                    bytes.len()
                ),
            )
        };
        let (encrypted_dek, bare_header) = rest
            .split_at_checked(encrypted_dek_len)
            .ok_or_else(wrong_len)?;
        let bare_header = bare_header.try_into().map_err(|_| wrong_len())?;
        Ok(Self {
            encrypted_dek: EncryptedDataEncryptionKey::new(encrypted_dek.to_vec()),
            bare_header,
        })
    }
}

/// Shows the encrypted DEK's length and nothing of the bytes.
impl Debug for EnvelopeStreamHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvelopeStreamHeader")
            .field("encrypted_dek", &self.encrypted_dek)
            .finish_non_exhaustive()
    }
}

/// The 56 bytes of the specification's header: the salt, then the key commitment.
pub(crate) struct CobblestoneHeader {
    pub(crate) salt: Salt,
    pub(crate) commitment: Commitment,
}

impl CobblestoneHeader {
    /// The 56 bytes of the header.
    pub(crate) fn to_bytes(&self) -> [u8; BARE_HEADER_LEN] {
        let mut bytes = [0; BARE_HEADER_LEN];
        bytes[..STREAM_SALT_LEN].copy_from_slice(&self.salt);
        bytes[STREAM_SALT_LEN..].copy_from_slice(&self.commitment);
        bytes
    }
}

impl From<&[u8; BARE_HEADER_LEN]> for CobblestoneHeader {
    fn from(bytes: &[u8; BARE_HEADER_LEN]) -> Self {
        let mut salt = [0; STREAM_SALT_LEN];
        salt.copy_from_slice(&bytes[..STREAM_SALT_LEN]);
        let mut commitment = [0; STREAM_KEY_COMMITMENT_LEN];
        commitment.copy_from_slice(&bytes[STREAM_SALT_LEN..]);
        Self { salt, commitment }
    }
}

/// Exactly 56 bytes, a bare value's header.
///
/// # Errors
///
/// `INVALID_CIPHER_TEXT_FORMAT` for bytes of another length.
impl TryFrom<&[u8]> for CobblestoneHeader {
    type Error = KmsAeadError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        <&[u8; BARE_HEADER_LEN]>::try_from(bytes)
            .map(Self::from)
            .map_err(|_| {
                KmsAeadEncryptionError::create(
                    "INVALID_CIPHER_TEXT_FORMAT",
                    &format!(
                        "A bare stream header is the 56 bytes of the salt and the key \
                         commitment, not {} bytes",
                        bytes.len()
                    ),
                )
            })
    }
}
