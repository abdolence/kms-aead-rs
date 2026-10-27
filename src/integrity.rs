//! The four stored values of signatures and MACs, which share Tink's output prefix: a detached
//! signature or MAC, `[0x01][key id: u32 BE][signature or tag]`, and an attached one,
//! `[0x01][key id: u32 BE][w: u16 BE][signature or tag: w][payload]`. The key id is a hint that
//! selects the key and is not authenticated.

use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSignatureError};
use crate::formats::{split_tink_output_prefix, tink_output_prefix, TINK_OUTPUT_PREFIX_LEN};
use crate::mac::MacAlgorithm;
use crate::{KeyId, KmsAeadResult};

#[cfg(feature = "postgres")]
mod postgres;
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// The length of `w`, the big-endian `u16` before the signature or tag of an attached value.
const ATTACHED_TAG_LEN_FIELD_SIZE: usize = 2;

/// The signature or tag and the payload of the attached value `rest`, the bytes after the
/// prefix, or `None` when `w` is missing or runs past the end.
fn split_attached_tag_and_payload(rest: &[u8]) -> Option<(&[u8], &[u8])> {
    let (len, rest) = rest.split_first_chunk::<ATTACHED_TAG_LEN_FIELD_SIZE>()?;
    rest.split_at_checked(usize::from(u16::from_be_bytes(*len)))
}

/// `[prefix][w][tag][payload]` of the detached value `detached`, whose tag is after the prefix.
fn attached_value_from_detached(detached: &[u8], payload: &[u8]) -> Option<Vec<u8>> {
    let (prefix, tag) = detached.split_at(TINK_OUTPUT_PREFIX_LEN);
    let len = u16::try_from(tag.len()).ok()?;
    let mut bytes =
        Vec::with_capacity(detached.len() + ATTACHED_TAG_LEN_FIELD_SIZE + payload.len());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(&len.to_be_bytes());
    bytes.extend_from_slice(tag);
    bytes.extend_from_slice(payload);
    Some(bytes)
}

/// Whether `len` is the tag length of a MAC algorithm.
fn is_mac_tag_len(len: usize) -> bool {
    [MacAlgorithm::HmacSha256, MacAlgorithm::HmacSha512]
        .iter()
        .any(|algorithm| algorithm.tag_len() == len)
}

/// A detached signature of a `T`, the bytes to store beside the payload:
///
/// ```text
/// [0x01][key id: u32 BE][signature]
/// ```
///
/// 69 bytes for Ed25519 and P-256. The key id names the key that signed; the verifying key fixes
/// the algorithm, so it is not in the value. `T` names the signed type and is not held.
///
/// Bytes read back become a signature through `TryFrom<Vec<u8>>`, which checks the layout; whether
/// the signature is authentic is known at verification. serde writes the bytes, `postgres` and
/// `sqlx` store them as `BYTEA`, as for [`Encrypted`](crate::Encrypted). It implements no
/// `PartialEq`: two ECDSA signatures of one payload differ. `Debug` shows the key id and the
/// length.
pub struct Signature<T> {
    bytes: Vec<u8>,
    key_id: KeyId,
    /// Tags the bytes with the signed type; holds no `T`.
    marker: PhantomData<T>,
}

/// Not derived: a derive would require `T: Clone`, and `T` is only a marker.
impl<T> Clone for Signature<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            key_id: self.key_id,
            marker: PhantomData,
        }
    }
}

impl<T> Signature<T> {
    /// The id of the key that signed, from the prefix.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes to store, taking the signature.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The signature after the prefix: the 64 bytes a DSSE `sig` or a Tink verifier takes.
    pub fn raw(&self) -> &[u8] {
        &self.bytes[TINK_OUTPUT_PREFIX_LEN..]
    }

    /// The lowercase hex of the bytes.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX`, then the errors of `TryFrom<Vec<u8>>`.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded)
            .map_err(|error| KmsAeadEncryptionError::invalid_hex("The signature", error))?;
        Self::try_from(bytes)
    }

    /// The signature of the key `key_id` whose raw signature is `raw`, 1 to 65,535 bytes.
    pub(crate) fn from_raw(key_id: KeyId, raw: &[u8]) -> KmsAeadResult<Self> {
        Self::try_from([&tink_output_prefix(key_id)[..], raw].concat())
    }
}

/// Reads stored bytes as a detached signature.
///
/// # Errors
///
/// `INVALID_SIGNATURE_FORMAT` unless the bytes are `0x01`, four bytes of key id and 1 to 65,535
/// bytes of signature. The message never quotes the bytes.
impl<T> TryFrom<Vec<u8>> for Signature<T> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        match split_tink_output_prefix(&bytes) {
            Some((key_id, signature)) if (1..=usize::from(u16::MAX)).contains(&signature.len()) => {
                Ok(Self {
                    key_id,
                    bytes,
                    marker: PhantomData,
                })
            }
            _ => Err(KmsAeadSignatureError::invalid_format(
                bytes.len(),
                "`[0x01][key id: u32 BE]` and 1 to 65,535 bytes of signature",
            )),
        }
    }
}

/// The key id and the length.
impl<T> Debug for Signature<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("key_id", &self.key_id.as_u32())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// An attached signature of a `T`, which carries the payload after the signature:
///
/// ```text
/// [0x01][key id: u32 BE][w: u16 BE][signature: w][payload]
/// ```
///
/// 71 bytes and the payload for Ed25519 and P-256. The payload is reached only through
/// [`Verifier::verify_signed`](crate::signing::Verifier::verify_signed), which verifies before it
/// decodes, and [`unverified_payload`](Self::unverified_payload) exposes it by that name. Stored
/// and shown as [`Signature`] is.
pub struct Signed<T> {
    bytes: Vec<u8>,
    key_id: KeyId,
    signature_len: usize,
    /// Tags the bytes with the signed type; holds no `T`.
    marker: PhantomData<T>,
}

/// Not derived: a derive would require `T: Clone`, and `T` is only a marker.
impl<T> Clone for Signed<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            key_id: self.key_id,
            signature_len: self.signature_len,
            marker: PhantomData,
        }
    }
}

impl<T> Signed<T> {
    /// The offset of the signature: after the prefix and `w`.
    const SIGNATURE_OFFSET: usize = TINK_OUTPUT_PREFIX_LEN + ATTACHED_TAG_LEN_FIELD_SIZE;

    /// `signature` and `payload` joined.
    ///
    /// # Errors
    ///
    /// `INVALID_SIGNATURE_FORMAT` when the signature is longer than 65,535 bytes.
    pub fn join(signature: &Signature<T>, payload: &[u8]) -> KmsAeadResult<Self> {
        attached_value_from_detached(signature.value(), payload)
            .ok_or_else(|| {
                KmsAeadSignatureError::invalid_format(
                    signature.value().len(),
                    "a signature that `w` holds",
                )
            })
            .and_then(Self::try_from)
    }

    /// The id of the key that signed, from the prefix.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The detached signature, copied out.
    pub fn signature(&self) -> Signature<T> {
        Signature {
            bytes: [&self.bytes[..TINK_OUTPUT_PREFIX_LEN], self.raw_signature()].concat(),
            key_id: self.key_id,
            marker: PhantomData,
        }
    }

    /// The raw signature, after `w`.
    pub(crate) fn raw_signature(&self) -> &[u8] {
        &self.bytes[Self::SIGNATURE_OFFSET..Self::SIGNATURE_OFFSET + self.signature_len]
    }

    /// The payload bytes, which nothing has verified:
    /// [`Verifier::verify_signed`](crate::signing::Verifier::verify_signed) returns the verified
    /// value.
    pub fn unverified_payload(&self) -> &[u8] {
        &self.bytes[Self::SIGNATURE_OFFSET + self.signature_len..]
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes to store, taking the value.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The lowercase hex of the bytes.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX`, then the errors of `TryFrom<Vec<u8>>`.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded)
            .map_err(|error| KmsAeadEncryptionError::invalid_hex("The signed value", error))?;
        Self::try_from(bytes)
    }
}

/// Reads stored bytes as an attached signature.
///
/// # Errors
///
/// `INVALID_SIGNATURE_FORMAT` unless the bytes are `0x01`, a key id, a `w` of 1 or more that ends
/// within the value, and the payload. The message never quotes the bytes.
impl<T> TryFrom<Vec<u8>> for Signed<T> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        let parsed = split_tink_output_prefix(&bytes).and_then(|(key_id, rest)| {
            split_attached_tag_and_payload(rest)
                .filter(|(signature, _)| !signature.is_empty())
                .map(|(signature, _)| (key_id, signature.len()))
        });
        match parsed {
            Some((key_id, signature_len)) => Ok(Self {
                key_id,
                signature_len,
                bytes,
                marker: PhantomData,
            }),
            None => Err(KmsAeadSignatureError::invalid_format(
                bytes.len(),
                "`[0x01][key id: u32 BE][w: u16 BE]`, a signature of `w` bytes and the payload",
            )),
        }
    }
}

/// The key id and the length.
impl<T> Debug for Signed<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signed")
            .field("key_id", &self.key_id.as_u32())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// A detached MAC of a `T`, the bytes to store beside the payload:
///
/// ```text
/// [0x01][key id: u32 BE][tag]
/// ```
///
/// 37 bytes under HMAC-SHA256 and 69 under HMAC-SHA512: the tag is the full HMAC output, never
/// truncated, and the key version's algorithm fixes its length. Bytes read back become a MAC
/// through `TryFrom<Vec<u8>>`, which checks the layout; whether the tag has the key version's
/// length, and is authentic, is known at verification. serde writes the bytes, `postgres` and
/// `sqlx` store them as `BYTEA`. It implements no `PartialEq`: equal tags say that the payload
/// and the key are equal, which verification says too. `Debug` shows the key id and the length.
pub struct Mac<T> {
    bytes: Vec<u8>,
    key_id: KeyId,
    /// Tags the bytes with the authenticated type; holds no `T`.
    marker: PhantomData<T>,
}

/// Not derived: a derive would require `T: Clone`, and `T` is only a marker.
impl<T> Clone for Mac<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            key_id: self.key_id,
            marker: PhantomData,
        }
    }
}

impl<T> Mac<T> {
    /// The id of the key version that computed the tag, from the prefix.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes to store, taking the MAC.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The tag after the prefix, 32 or 64 bytes.
    pub fn raw(&self) -> &[u8] {
        &self.bytes[TINK_OUTPUT_PREFIX_LEN..]
    }

    /// The lowercase hex of the bytes.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX`, then the errors of `TryFrom<Vec<u8>>`.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded)
            .map_err(|error| KmsAeadEncryptionError::invalid_hex("The MAC", error))?;
        Self::try_from(bytes)
    }

    /// The MAC of the key `key_id` whose tag is `tag`, 32 or 64 bytes.
    pub(crate) fn from_tag(key_id: KeyId, tag: &[u8]) -> KmsAeadResult<Self> {
        Self::try_from([&tink_output_prefix(key_id)[..], tag].concat())
    }
}

/// Reads stored bytes as a detached MAC.
///
/// # Errors
///
/// `INVALID_MAC_FORMAT` unless the bytes are `0x01`, a key id and 32 or 64 bytes of tag. The
/// message never quotes the bytes.
impl<T> TryFrom<Vec<u8>> for Mac<T> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        match split_tink_output_prefix(&bytes) {
            Some((key_id, tag)) if is_mac_tag_len(tag.len()) => Ok(Self {
                key_id,
                bytes,
                marker: PhantomData,
            }),
            _ => Err(KmsAeadEncryptionError::invalid_mac_format(
                bytes.len(),
                "`[0x01][key id: u32 BE]` and a tag of 32 or 64 bytes",
            )),
        }
    }
}

/// The key id and the length.
impl<T> Debug for Mac<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mac")
            .field("key_id", &self.key_id.as_u32())
            .field("len", &self.bytes.len())
            .finish()
    }
}

/// An attached MAC of a `T`, which carries the payload after the tag:
///
/// ```text
/// [0x01][key id: u32 BE][w: u16 BE][tag: w][payload]
/// ```
///
/// with `w` 32 or 64, so the payload starts at offset `7 + w`: 39 or 71 bytes and the payload. The
/// payload is reached only through a call that verifies before it decodes,
/// [`Authenticator::verify_with_mac`](crate::mac::Authenticator::verify_with_mac) or a keyring's
/// `verify_with_mac`, and [`unverified_payload`](Self::unverified_payload) exposes it by that
/// name. Stored and shown as [`Mac`] is.
pub struct WithMac<T> {
    bytes: Vec<u8>,
    key_id: KeyId,
    tag_len: usize,
    /// Tags the bytes with the authenticated type; holds no `T`.
    marker: PhantomData<T>,
}

/// Not derived: a derive would require `T: Clone`, and `T` is only a marker.
impl<T> Clone for WithMac<T> {
    fn clone(&self) -> Self {
        Self {
            bytes: self.bytes.clone(),
            key_id: self.key_id,
            tag_len: self.tag_len,
            marker: PhantomData,
        }
    }
}

impl<T> WithMac<T> {
    /// The offset of the tag: after the prefix and `w`.
    const TAG_OFFSET: usize = TINK_OUTPUT_PREFIX_LEN + ATTACHED_TAG_LEN_FIELD_SIZE;

    /// `mac` and `payload` joined.
    ///
    /// # Errors
    ///
    /// None today: a MAC's tag always fits `w`. The result is fallible as
    /// [`Signed::join`]'s is.
    pub fn join(mac: &Mac<T>, payload: &[u8]) -> KmsAeadResult<Self> {
        attached_value_from_detached(mac.value(), payload)
            .ok_or_else(|| {
                KmsAeadEncryptionError::invalid_mac_format(
                    mac.value().len(),
                    "a tag that `w` holds",
                )
            })
            .and_then(Self::try_from)
    }

    /// The id of the key version that computed the tag, from the prefix.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The detached MAC, copied out.
    pub fn mac(&self) -> Mac<T> {
        Mac {
            bytes: [&self.bytes[..TINK_OUTPUT_PREFIX_LEN], self.tag()].concat(),
            key_id: self.key_id,
            marker: PhantomData,
        }
    }

    /// The tag, after `w`.
    pub(crate) fn tag(&self) -> &[u8] {
        &self.bytes[Self::TAG_OFFSET..Self::TAG_OFFSET + self.tag_len]
    }

    /// The payload bytes, which nothing has verified.
    pub fn unverified_payload(&self) -> &[u8] {
        &self.bytes[Self::TAG_OFFSET + self.tag_len..]
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.bytes
    }

    /// The bytes to store, taking the value.
    pub fn into_value(self) -> Vec<u8> {
        self.bytes
    }

    /// The lowercase hex of the bytes.
    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.bytes)
    }

    /// Reads the hex, in either case, that [`to_hex_string`](Self::to_hex_string) writes.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX`, then the errors of `TryFrom<Vec<u8>>`.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded).map_err(|error| {
            KmsAeadEncryptionError::invalid_hex("The authenticated value", error)
        })?;
        Self::try_from(bytes)
    }
}

/// Reads stored bytes as an attached MAC.
///
/// # Errors
///
/// `INVALID_MAC_FORMAT` unless the bytes are `0x01`, a key id, a `w` of 32 or 64, the tag and the
/// payload. The message never quotes the bytes.
impl<T> TryFrom<Vec<u8>> for WithMac<T> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        let parsed = split_tink_output_prefix(&bytes).and_then(|(key_id, rest)| {
            split_attached_tag_and_payload(rest)
                .filter(|(tag, _)| is_mac_tag_len(tag.len()))
                .map(|(tag, _)| (key_id, tag.len()))
        });
        match parsed {
            Some((key_id, tag_len)) => Ok(Self {
                key_id,
                tag_len,
                bytes,
                marker: PhantomData,
            }),
            None => Err(KmsAeadEncryptionError::invalid_mac_format(
                bytes.len(),
                "`[0x01][key id: u32 BE][w: u16 BE]` with `w` 32 or 64, the tag and the payload",
            )),
        }
    }
}

/// The key id and the length.
impl<T> Debug for WithMac<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WithMac")
            .field("key_id", &self.key_id.as_u32())
            .field("len", &self.bytes.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::error_code_of;

    const PREFIX: [u8; 5] = [0x01, 0x90, 0xfa, 0xca, 0xfe];
    const PAYLOAD: &[u8] = br#"{"id":1}"#;

    #[test]
    fn a_signature_is_read_in_its_layout_only() {
        let signature = Signature::<()>::try_from([&PREFIX[..], &[0xAB; 64]].concat()).unwrap();
        assert_eq!(signature.key_id(), KeyId::new(0x90fa_cafe));
        assert_eq!(signature.raw(), [0xAB; 64]);

        for refused in [
            vec![0x02, 0x90, 0xfa, 0xca, 0xfe, 0xAB],
            PREFIX.to_vec(),
            [&PREFIX[..], &vec![0xAB; 65_536]].concat(),
        ] {
            assert_eq!(
                error_code_of(Signature::<()>::try_from(refused)),
                "INVALID_SIGNATURE_FORMAT"
            );
        }
    }

    #[test]
    fn an_attached_signature_splits_at_w() {
        let signature = Signature::<()>::try_from([&PREFIX[..], &[0xAB; 64]].concat()).unwrap();

        let signed = Signed::join(&signature, PAYLOAD).unwrap();

        assert_eq!(signed.value()[5..7], [0x00, 0x40]);
        assert_eq!(signed.unverified_payload(), PAYLOAD);
        assert_eq!(signed.signature().value(), signature.value());
        assert_eq!(
            Signed::<()>::try_from(signed.value().to_vec())
                .unwrap()
                .unverified_payload(),
            PAYLOAD
        );
    }

    #[test]
    fn an_attached_signature_whose_w_runs_past_the_end_is_refused() {
        for refused in [
            [&PREFIX[..], &[0x00, 0x41], &[0xAB; 64]].concat(),
            [&PREFIX[..], &[0x00, 0x00], PAYLOAD].concat(),
            [&PREFIX[..], &[0x00]].concat(),
        ] {
            assert_eq!(
                error_code_of(Signed::<()>::try_from(refused)),
                "INVALID_SIGNATURE_FORMAT"
            );
        }
    }

    #[test]
    fn a_mac_takes_a_tag_of_32_or_64_bytes_only() {
        for tag_len in [32, 64] {
            let mac = Mac::<()>::try_from([&PREFIX[..], &vec![0xCD; tag_len]].concat()).unwrap();
            let authenticated = WithMac::join(&mac, PAYLOAD).unwrap();
            assert_eq!(authenticated.mac().value(), mac.value());
            assert_eq!(authenticated.unverified_payload(), PAYLOAD);
        }
        for tag_len in [31, 33, 63] {
            assert_eq!(
                error_code_of(Mac::<()>::try_from(
                    [&PREFIX[..], &vec![0xCD; tag_len]].concat()
                )),
                "INVALID_MAC_FORMAT"
            );
            let w = u16::try_from(tag_len).unwrap().to_be_bytes();
            assert_eq!(
                error_code_of(WithMac::<()>::try_from(
                    [&PREFIX[..], &w, &vec![0xCD; tag_len], PAYLOAD].concat()
                )),
                "INVALID_MAC_FORMAT"
            );
        }
    }

    #[test]
    fn a_value_is_cloned_whether_or_not_the_type_it_covers_is() {
        struct NotClone;
        let signature =
            Signature::<NotClone>::try_from([&PREFIX[..], &[0xAB; 64]].concat()).unwrap();
        let mac = Mac::<NotClone>::try_from([&PREFIX[..], &[0xCD; 32]].concat()).unwrap();
        let signed = Signed::join(&signature, PAYLOAD).unwrap();
        let authenticated = WithMac::join(&mac, PAYLOAD).unwrap();

        assert_eq!(signature.clone().value(), signature.value());
        assert_eq!(signed.clone().value(), signed.value());
        assert_eq!(mac.clone().value(), mac.value());
        assert_eq!(authenticated.clone().value(), authenticated.value());
    }

    #[test]
    fn debug_shows_no_signature_or_tag_bytes() {
        let signature = Signature::<()>::try_from([&PREFIX[..], &[0xAB; 64]].concat()).unwrap();
        let mac = Mac::<()>::try_from([&PREFIX[..], &[0xCD; 32]].concat()).unwrap();

        let printed = format!(
            "{signature:?} {:?} {mac:?} {:?}",
            Signed::join(&signature, PAYLOAD).unwrap(),
            WithMac::join(&mac, PAYLOAD).unwrap()
        );

        for rendering in crate::test_provider::renderings(&[0xAB; 8])
            .into_iter()
            .chain(crate::test_provider::renderings(&[0xCD; 8]))
            .chain(crate::test_provider::renderings(PAYLOAD))
        {
            assert!(!printed.contains(&rendering), "{printed}");
        }
    }
}
