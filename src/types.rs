use crate::errors::*;
use crate::KmsAeadResult;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::fmt::{Debug, Display, Formatter};
use subtle::ConstantTimeEq;

/// A value sealed by an [`AeadAlgorithm`](crate::AeadAlgorithm): `[nonce][ciphertext][tag]`.
/// It holds no key, so it is not a storage form for envelope encryption without the wrapped key
/// that opens it.
#[derive(Debug, Clone, ValueStruct)]
pub struct CipherText(pub Vec<u8>);

impl CipherText {
    /// The lowercase hex of the value.
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &Self) -> bool {
        self.value().ct_eq(other.value()).into()
    }
}

/// A plaintext data encryption key, zeroized on drop and shown as `***` by `Debug`. Equality
/// compares in constant time.
#[derive(Debug, Clone)]
pub struct DataEncryptionKey(SecretValue);

impl DataEncryptionKey {
    /// The key bytes.
    pub fn value(&self) -> &SecretValue {
        &self.0
    }
}

impl From<SecretValue> for DataEncryptionKey {
    fn from(value: SecretValue) -> Self {
        Self(value)
    }
}

impl PartialEq for DataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.value()
            .as_sensitive_bytes()
            .ct_eq(other.value().as_sensitive_bytes())
            .into()
    }
}

/// The version of the KMS key that wrapped a data encryption key: 1 to 255 ASCII alphanumeric
/// characters, such as the `N` of a GCP `cryptoKeyVersions/N`.
///
/// The same rule validates every key version read back from envelope layout v1 and from the
/// encrypted key layout, so it may only ever loosen: a stricter rule makes stored data unreadable.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsKeyVersion(String);

impl KmsKeyVersion {
    /// The version as the KMS names it.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    // The error reports the length and the class of the first rejected byte, never the bytes
    // themselves: they come from storage and end up in logs.
    fn from_ascii(bytes: &[u8]) -> KmsAeadResult<Self> {
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
            None => Ok(Self(bytes.iter().copied().map(char::from).collect())),
        }
    }

    // `[k: u8][key version: k bytes]`, `k = 0` when none is recorded: the key version field of
    // envelope layout v1 and of the encrypted key layout, persisted by both.
    fn write_field(key_version: Option<&Self>, out: &mut Vec<u8>) -> KmsAeadResult<()> {
        let version = key_version.map_or("", Self::as_str).as_bytes();
        let len = u8::try_from(version.len()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                "KMS key version is longer than 255 bytes",
            )
        })?;
        out.push(len);
        out.extend_from_slice(version);
        Ok(())
    }

    fn split_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let (&len, rest) = bytes.split_first()?;
        rest.split_at_checked(usize::from(len))
    }

    fn from_field(bytes: &[u8]) -> KmsAeadResult<Option<Self>> {
        match bytes {
            [] => Ok(None),
            version => Self::from_ascii(version).map(Some),
        }
    }
}

impl TryFrom<String> for KmsKeyVersion {
    type Error = KmsAeadError;

    fn try_from(value: String) -> KmsAeadResult<Self> {
        Self::from_ascii(value.as_bytes())
    }
}

impl Display for KmsKeyVersion {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A data encryption key wrapped by a KMS, with the version of the KMS key that wrapped it when
/// the provider records one.
///
/// [`to_bytes`](Self::to_bytes) and [`to_hex_string`](Self::to_hex_string) store both, so a key
/// kept for the `*_with_encrypted_dek` APIs keeps its version:
///
/// ```text
/// [0xFF][0x01][k: u8][key version: k bytes][wrapped key to the end]
/// ```
///
/// `0xFF` marks the layout, `0x01` is its version and `k = 0` records no key version.
/// `TryFrom<&[u8]>` and [`try_from_hex_string`](Self::try_from_hex_string) also read the bare
/// wrapped key that 0.28.1 and earlier stored, as a key with no version. Those keys come only from
/// GCP, a protobuf message starting with `0x0a` (`0xFF` would be the undefined wire type 7), and
/// from AWS, starting with `0x01`, so none of them reads as the layout.
#[derive(Clone)]
pub struct EncryptedDataEncryptionKey {
    wrapped: Vec<u8>,
    key_version: Option<KmsKeyVersion>,
}

impl EncryptedDataEncryptionKey {
    const LAYOUT_MAGIC: u8 = 0xFF;
    const LAYOUT_V1: u8 = 0x01;

    /// Takes the bytes a KMS returned. A stored key is read with
    /// [`try_from_hex_string`](Self::try_from_hex_string) or `TryFrom<&[u8]>`.
    pub fn new(wrapped: Vec<u8>, key_version: Option<KmsKeyVersion>) -> Self {
        Self {
            wrapped,
            key_version,
        }
    }

    /// The bytes the KMS returned, unchanged. Not a storage form, because it drops the key
    /// version: store [`to_bytes`](Self::to_bytes) or [`to_hex_string`](Self::to_hex_string).
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }

    /// The version of the KMS key that wrapped this key, when the KMS reported one.
    pub fn key_version(&self) -> Option<&KmsKeyVersion> {
        self.key_version.as_ref()
    }

    /// Writes the layout in the type docs, with the key version.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_VERSION` when the key version is longer than 255 bytes, which a
    /// [`KmsKeyVersion`] never is.
    pub fn to_bytes(&self) -> KmsAeadResult<Vec<u8>> {
        let mut bytes = vec![Self::LAYOUT_MAGIC, Self::LAYOUT_V1];
        KmsKeyVersion::write_field(self.key_version(), &mut bytes)?;
        bytes.extend_from_slice(&self.wrapped);
        Ok(bytes)
    }

    /// The lowercase hex of [`to_bytes`](Self::to_bytes).
    ///
    /// # Errors
    ///
    /// As [`to_bytes`](Self::to_bytes).
    pub fn to_hex_string(&self) -> KmsAeadResult<String> {
        self.to_bytes().map(hex::encode)
    }

    /// Reads the hex, in either case, of what `TryFrom<&[u8]>` reads.
    ///
    /// # Errors
    ///
    /// `INVALID_HEX` when `encoded` is not hex, and the errors of `TryFrom<&[u8]>`.
    pub fn try_from_hex_string(encoded: &str) -> KmsAeadResult<Self> {
        let bytes = hex::decode(encoded).map_err(|e| {
            KmsAeadEncryptionError::create("INVALID_HEX", &format!("Encrypted key is not hex: {e}"))
        })?;
        Self::try_from(bytes.as_slice())
    }
}

impl TryFrom<&[u8]> for EncryptedDataEncryptionKey {
    type Error = KmsAeadError;

    /// Reads the layout when `bytes` starts with `0xFF`, and bare wrapped bytes otherwise.
    ///
    /// # Errors
    ///
    /// `INVALID_ENCRYPTED_KEY_FORMAT` on empty input or a key version running past the end,
    /// `UNKNOWN_ENCRYPTED_KEY_LAYOUT` on an unknown layout tag, and `INVALID_KEY_VERSION` on a
    /// key version that is not ASCII alphanumeric.
    fn try_from(bytes: &[u8]) -> KmsAeadResult<Self> {
        match bytes {
            [] => Err(KmsAeadEncryptionError::create(
                "INVALID_ENCRYPTED_KEY_FORMAT",
                "The encrypted key is empty",
            )),
            [Self::LAYOUT_MAGIC, Self::LAYOUT_V1, fields @ ..] => {
                let (key_version, wrapped) =
                    KmsKeyVersion::split_field(fields).ok_or_else(|| {
                        KmsAeadEncryptionError::create(
                            "INVALID_ENCRYPTED_KEY_FORMAT",
                            "The key version length runs past the end of the encrypted key",
                        )
                    })?;
                Ok(Self::new(
                    wrapped.to_vec(),
                    KmsKeyVersion::from_field(key_version)?,
                ))
            }
            [Self::LAYOUT_MAGIC, tag, ..] => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ENCRYPTED_KEY_LAYOUT",
                &format!("Unknown encrypted key layout tag {tag:#04x}"),
            )),
            [Self::LAYOUT_MAGIC] => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ENCRYPTED_KEY_LAYOUT",
                "Encrypted key ends after the layout magic, with no layout tag",
            )),
            bare => Ok(Self::new(bare.to_vec(), None)),
        }
    }
}

/// The length of the wrapped key and the key version, never the wrapped key itself.
impl Debug for EncryptedDataEncryptionKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedDataEncryptionKey")
            .field("wrapped_len", &self.wrapped.len())
            .field("key_version", &self.key_version)
            .finish()
    }
}

impl PartialEq for EncryptedDataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        // The key version is not secret, so it compares in variable time.
        bool::from(self.wrapped.ct_eq(&other.wrapped)) && self.key_version == other.key_version
    }
}

/// A cipher text with the wrapped data encryption key that decrypts it, as stored.
///
/// [`new`](Self::new) writes layout v1:
///
/// ```text
/// [0x01][k: u8][key version: k bytes][w: u16 BE][wrapped key: w bytes][cipher text to the end]
/// ```
///
/// `k = 0` records no key version. [`separate`](Self::separate) also reads the legacy layout
/// written up to 0.28.1, `[length: u64 BE][wrapped key][cipher text]`, including its 4-byte
/// length form written on 32-bit targets before 0.24.0.
///
/// The header is not authenticated, so a header field is only ever an address or an audit
/// value. A field that selects an algorithm, a mode or a transform needs a new layout tag with
/// an authenticated header.
#[derive(Clone)]
pub struct CipherTextWithEncryptedKey(pub Vec<u8>);

impl CipherTextWithEncryptedKey {
    const LAYOUT_V1: u8 = 0x01;

    /// Writes layout v1 of `cipher_text` and the wrapped key that opens it.
    ///
    /// # Errors
    ///
    /// `INVALID_CIPHER_TEXT_FORMAT` when the wrapped key is longer than 65,535 bytes.
    pub fn new(
        cipher_text: &CipherText,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Self> {
        let wrapped = encrypted_dek.wrapped();
        let wrapped_len = u16::try_from(wrapped.len()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "Wrapped key of {} bytes is longer than the 65535 bytes the layout stores",
                    wrapped.len()
                ),
            )
        })?;

        let mut value = Vec::with_capacity(4 + wrapped.len() + cipher_text.value().len());
        value.push(Self::LAYOUT_V1);
        KmsKeyVersion::write_field(encrypted_dek.key_version(), &mut value)?;
        value.extend_from_slice(&wrapped_len.to_be_bytes());
        value.extend_from_slice(wrapped);
        value.extend_from_slice(cipher_text.value());
        Ok(Self(value))
    }

    /// Reads layout v1 and the legacy layout into the cipher text and the wrapped key.
    ///
    /// # Errors
    ///
    /// `UNKNOWN_CIPHER_TEXT_LAYOUT` on an empty value or an unknown layout tag,
    /// `INVALID_CIPHER_TEXT_FORMAT` on a length that runs past the end of the value, and
    /// `INVALID_KEY_VERSION` on a key version that is not ASCII alphanumeric.
    pub fn separate(&self) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
        let fields = match self.value().split_first() {
            Some((&Self::LAYOUT_V1, header)) => Self::split_v1(header),
            // The legacy layout starts with the top byte of its length, zero for any wrapped
            // key a KMS returns.
            Some((0x00, _)) => Self::split_legacy(self.value()),
            Some((tag, _)) => {
                return Err(KmsAeadEncryptionError::create(
                    "UNKNOWN_CIPHER_TEXT_LAYOUT",
                    &format!("Unknown cipher text layout tag {tag:#04x}"),
                ))
            }
            None => {
                return Err(KmsAeadEncryptionError::create(
                    "UNKNOWN_CIPHER_TEXT_LAYOUT",
                    "Empty cipher text has no layout tag",
                ))
            }
        };
        let (key_version, wrapped, cipher_text) = fields.ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                "A length in the cipher text header runs past the end of the buffer",
            )
        })?;
        Ok((
            CipherText(cipher_text.to_vec()),
            EncryptedDataEncryptionKey::new(
                wrapped.to_vec(),
                KmsKeyVersion::from_field(key_version)?,
            ),
        ))
    }

    /// The layout the first byte names, as the `format` span field records it.
    /// [`separate`](Self::separate) reads and checks the rest.
    pub(crate) fn layout_name(&self) -> Option<&'static str> {
        match self.value().first() {
            Some(&Self::LAYOUT_V1) => Some("envelope_v1"),
            Some(0x00) => Some("envelope_legacy"),
            _ => None,
        }
    }

    fn split_v1(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        let (key_version, rest) = KmsKeyVersion::split_field(bytes)?;
        let (wrapped_len, rest) = rest.split_first_chunk::<2>()?;
        let (wrapped, cipher_text) =
            rest.split_at_checked(usize::from(u16::from_be_bytes(*wrapped_len)))?;
        Some((key_version, wrapped, cipher_text))
    }

    fn split_legacy(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        // 32-bit targets before 0.24.0 wrote the length as a 4-byte `usize`, all other writers
        // as 8 bytes. For lengths 1 to 2^24 - 1, bytes 1 to 3 are zero only in the 8-byte form.
        let (wrapped_len, rest) = match bytes.get(1..4) {
            Some([0, 0, 0]) => bytes
                .split_first_chunk::<8>()
                .map(|(len, rest)| (u64::from_be_bytes(*len), rest))?,
            _ => bytes
                .split_first_chunk::<4>()
                .map(|(len, rest)| (u64::from(u32::from_be_bytes(*len)), rest))?,
        };
        let (wrapped, cipher_text) = rest.split_at_checked(usize::try_from(wrapped_len).ok()?)?;
        Some((&[], wrapped, cipher_text))
    }

    /// The lowercase hex of the value.
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }

    /// The stored bytes.
    #[inline]
    pub fn value(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for CipherTextWithEncryptedKey {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

/// The length only: the value holds the wrapped data encryption key.
impl Debug for CipherTextWithEncryptedKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CipherTextWithEncryptedKey")
            .field("len", &self.0.len())
            .finish()
    }
}

impl PartialEq for CipherTextWithEncryptedKey {
    fn eq(&self, other: &Self) -> bool {
        self.value().ct_eq(other.value()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const GOLDEN_CIPHER_TEXT: &[u8] = b"sealed";
    const GOLDEN_WRAPPED_KEY: &[u8] = b"wrapped";

    fn error_code<T: std::fmt::Debug>(result: KmsAeadResult<T>) -> String {
        match result {
            Err(KmsAeadError::EncryptionError(error)) => error.public.code,
            other => panic!("expected an encryption error, got {other:?}"),
        }
    }

    #[test]
    fn kms_key_version_is_1_to_255_ascii_alphanumeric_characters() {
        assert!(KmsKeyVersion::try_from("a".repeat(255)).is_ok());
        for invalid in [String::new(), "a".repeat(256), "1/2".into(), "v 1".into()] {
            assert_eq!(
                error_code(KmsKeyVersion::try_from(invalid.clone())),
                "INVALID_KEY_VERSION",
                "{invalid:?}"
            );
        }
    }

    #[test]
    fn layout_v1_with_key_version_is_pinned() {
        let cipher_text = CipherText(GOLDEN_CIPHER_TEXT.to_vec());
        let encrypted_dek = EncryptedDataEncryptionKey::new(
            GOLDEN_WRAPPED_KEY.to_vec(),
            Some(KmsKeyVersion::try_from("18".to_string()).unwrap()),
        );

        let envelope = CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek).unwrap();

        assert_eq!(
            envelope.to_hex_string(),
            "010231380007777261707065647365616c6564"
        );
        assert_eq!(envelope.separate().unwrap(), (cipher_text, encrypted_dek));
    }

    #[test]
    fn layout_v1_without_key_version_is_pinned() {
        let cipher_text = CipherText(GOLDEN_CIPHER_TEXT.to_vec());
        let encrypted_dek = EncryptedDataEncryptionKey::new(GOLDEN_WRAPPED_KEY.to_vec(), None);

        let envelope = CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek).unwrap();

        assert_eq!(
            envelope.to_hex_string(),
            "01000007777261707065647365616c6564"
        );
        assert_eq!(envelope.separate().unwrap(), (cipher_text, encrypted_dek));
    }

    proptest! {
        #[test]
        fn layout_v1_round_trips(
            cipher_text in prop::collection::vec(any::<u8>(), 0..256),
            wrapped in prop::collection::vec(any::<u8>(), 0..8192),
            key_version in proptest::option::of("[a-zA-Z0-9]{1,255}"),
        ) {
            let cipher_text = CipherText(cipher_text);
            let key_version = key_version.map(|version| KmsKeyVersion::try_from(version).unwrap());
            let encrypted_dek = EncryptedDataEncryptionKey::new(wrapped, key_version);

            let envelope = CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek).unwrap();

            prop_assert_eq!(envelope.separate().unwrap(), (cipher_text, encrypted_dek));
        }
    }

    #[test]
    fn wrapped_key_above_65535_bytes_is_rejected_on_write() {
        let cipher_text = CipherText(GOLDEN_CIPHER_TEXT.to_vec());
        let largest = EncryptedDataEncryptionKey::new(vec![0xAA; 65_535], None);
        let too_large = EncryptedDataEncryptionKey::new(vec![0xAA; 65_536], None);

        assert!(CipherTextWithEncryptedKey::new(&cipher_text, &largest).is_ok());
        assert_eq!(
            error_code(CipherTextWithEncryptedKey::new(&cipher_text, &too_large)),
            "INVALID_CIPHER_TEXT_FORMAT"
        );
    }

    #[test]
    fn unknown_layout_tags_are_rejected() {
        let empty = CipherTextWithEncryptedKey::from(vec![]);
        assert_eq!(error_code(empty.separate()), "UNKNOWN_CIPHER_TEXT_LAYOUT");

        for tag in 0x02..=0xFF {
            let envelope = CipherTextWithEncryptedKey::from(vec![tag; 64]);
            assert_eq!(
                error_code(envelope.separate()),
                "UNKNOWN_CIPHER_TEXT_LAYOUT",
                "tag {tag:#04x}"
            );
        }
    }

    #[test]
    fn length_fields_past_the_buffer_are_rejected() {
        let truncated: [&[u8]; 9] = [
            // Layout v1
            &[0x01],
            &[0x01, 0x02, b'1'],
            &[0x01, 0x00, 0x00],
            &[0x01, 0x00, 0x00, 0x05, 0xAA],
            // Legacy layout, 4-byte and 8-byte lengths
            &[0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x20, 0xAA],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 0x01, 0x02, 0x03,
            ],
            &[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA],
        ];
        for envelope in truncated {
            assert_eq!(
                error_code(CipherTextWithEncryptedKey::from(envelope.to_vec()).separate()),
                "INVALID_CIPHER_TEXT_FORMAT",
                "{envelope:02x?}"
            );
        }
    }

    #[test]
    fn key_version_outside_ascii_alphanumeric_is_rejected_on_read_without_echoing_it() {
        let stored_version = b"marker/18";
        let mut envelope = vec![0x01, stored_version.len() as u8];
        envelope.extend_from_slice(stored_version);
        envelope.extend_from_slice(&[0x00, 0x01, 0xAA, 0xBB]);

        let error = CipherTextWithEncryptedKey::from(envelope)
            .separate()
            .unwrap_err();

        assert!(
            !format!("{error} {error:?}").contains("marker"),
            "{error:?}"
        );
        assert_eq!(error_code::<()>(Err(error)), "INVALID_KEY_VERSION");
    }

    proptest! {
        #[test]
        fn separate_returns_on_arbitrary_bytes(
            tag in prop_oneof![Just(0x00u8), Just(0x01), any::<u8>()],
            // Bytes 1 to 3 pick the legacy length width and are almost never all zero at random.
            width in prop_oneof![Just(vec![0u8; 3]), prop::collection::vec(any::<u8>(), 0..=3)],
            rest in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut bytes = vec![tag];
            bytes.extend(width);
            bytes.extend(rest);
            let _ = CipherTextWithEncryptedKey::from(bytes).separate();
        }
    }

    #[test]
    fn serialized_key_with_key_version_is_pinned() {
        let encrypted_dek = EncryptedDataEncryptionKey::new(
            b"vault:v1:AbCd".to_vec(),
            Some(KmsKeyVersion::try_from("1".to_string()).unwrap()),
        );
        let serialized = "ff0101317661756c743a76313a41624364";

        assert_eq!(
            encrypted_dek.to_bytes().unwrap(),
            hex::decode(serialized).unwrap()
        );
        assert_eq!(encrypted_dek.to_hex_string().unwrap(), serialized);
        assert_eq!(
            EncryptedDataEncryptionKey::try_from_hex_string(serialized).unwrap(),
            encrypted_dek
        );
    }

    #[test]
    fn serialized_key_without_key_version_is_pinned() {
        let encrypted_dek = EncryptedDataEncryptionKey::new(GOLDEN_WRAPPED_KEY.to_vec(), None);
        let serialized = "ff010077726170706564";

        assert_eq!(
            encrypted_dek.to_bytes().unwrap(),
            hex::decode(serialized).unwrap()
        );
        assert_eq!(encrypted_dek.to_hex_string().unwrap(), serialized);
        assert_eq!(
            EncryptedDataEncryptionKey::try_from_hex_string(serialized).unwrap(),
            encrypted_dek
        );
    }

    proptest! {
        #[test]
        fn serialized_key_round_trips(
            wrapped in prop::collection::vec(any::<u8>(), 0..512),
            key_version in proptest::option::of("[a-zA-Z0-9]{1,255}"),
        ) {
            let key_version = key_version.map(|version| KmsKeyVersion::try_from(version).unwrap());
            let encrypted_dek = EncryptedDataEncryptionKey::new(wrapped, key_version);

            let bytes = encrypted_dek.to_bytes().unwrap();
            let hex_string = encrypted_dek.to_hex_string().unwrap();

            prop_assert_eq!(
                EncryptedDataEncryptionKey::try_from(bytes.as_slice()).unwrap(),
                encrypted_dek.clone()
            );
            prop_assert_eq!(
                EncryptedDataEncryptionKey::try_from_hex_string(&hex_string).unwrap(),
                encrypted_dek
            );
        }

        #[test]
        fn serialized_key_parser_returns_on_arbitrary_input(
            layout in prop_oneof![Just(vec![0x01u8]), prop::collection::vec(any::<u8>(), 0..=1)],
            rest in prop::collection::vec(any::<u8>(), 0..300),
        ) {
            let mut bytes = vec![EncryptedDataEncryptionKey::LAYOUT_MAGIC];
            bytes.extend(layout);
            bytes.extend(rest);
            let _ = EncryptedDataEncryptionKey::try_from(bytes.as_slice());
        }
    }

    #[test]
    fn empty_encrypted_key_is_rejected() {
        assert_eq!(
            error_code(EncryptedDataEncryptionKey::try_from([].as_slice())),
            "INVALID_ENCRYPTED_KEY_FORMAT"
        );
    }

    #[test]
    fn serialized_key_with_an_unknown_layout_tag_is_rejected() {
        let tags: [&[u8]; 2] = [&[], &[0x02]];
        for tag in tags {
            let mut bytes = vec![EncryptedDataEncryptionKey::LAYOUT_MAGIC];
            bytes.extend_from_slice(tag);
            assert_eq!(
                error_code(EncryptedDataEncryptionKey::try_from(bytes.as_slice())),
                "UNKNOWN_ENCRYPTED_KEY_LAYOUT",
                "{tag:02x?}"
            );
        }
    }

    #[test]
    fn serialized_key_with_a_key_version_past_the_end_is_rejected() {
        let bodies: [&[u8]; 2] = [&[0x01], &[0x01, 0x02, b'1']];
        for body in bodies {
            let mut bytes = vec![EncryptedDataEncryptionKey::LAYOUT_MAGIC];
            bytes.extend_from_slice(body);
            assert_eq!(
                error_code(EncryptedDataEncryptionKey::try_from(bytes.as_slice())),
                "INVALID_ENCRYPTED_KEY_FORMAT",
                "{body:02x?}"
            );
        }
    }

    #[test]
    fn hex_that_does_not_decode_is_rejected() {
        assert_eq!(
            error_code(EncryptedDataEncryptionKey::try_from_hex_string("zz")),
            "INVALID_HEX"
        );
    }

    /// The wrapped key as `Debug` prints a byte slice, without the brackets.
    fn debug_listed(bytes: &[u8]) -> String {
        let listed = format!("{bytes:?}");
        listed[1..listed.len() - 1].to_string()
    }

    #[test]
    fn encrypted_key_debug_shows_no_wrapped_key_bytes() {
        let encrypted_dek = EncryptedDataEncryptionKey::new(
            GOLDEN_WRAPPED_KEY.to_vec(),
            Some(KmsKeyVersion::try_from("18".to_string()).unwrap()),
        );

        let debug = format!("{encrypted_dek:?}");

        assert!(
            !debug.contains(&debug_listed(GOLDEN_WRAPPED_KEY)),
            "{debug}"
        );
        assert!(!debug.contains(&hex::encode(GOLDEN_WRAPPED_KEY)), "{debug}");
        assert!(debug.contains("18"), "{debug}");
    }

    #[test]
    fn envelope_debug_shows_no_wrapped_key_bytes() {
        let envelope = CipherTextWithEncryptedKey::new(
            &CipherText(GOLDEN_CIPHER_TEXT.to_vec()),
            &EncryptedDataEncryptionKey::new(GOLDEN_WRAPPED_KEY.to_vec(), None),
        )
        .unwrap();

        let debug = format!("{envelope:?}");

        assert!(
            !debug.contains(&debug_listed(GOLDEN_WRAPPED_KEY)),
            "{debug}"
        );
        assert!(!debug.contains(&hex::encode(GOLDEN_WRAPPED_KEY)), "{debug}");
    }

    #[test]
    fn encrypted_keys_are_equal_with_equal_wrapped_keys_and_key_versions() {
        let version = KmsKeyVersion::try_from("1".to_string()).unwrap();
        let dek1 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], Some(version.clone()));
        let dek2 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], Some(version.clone()));
        let dek3 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 6], Some(version));
        let dek4 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], None);

        assert_eq!(dek1, dek2);
        assert_ne!(dek1, dek3);
        assert_ne!(dek1, dek4);
    }

    #[test]
    fn envelopes_are_equal_with_equal_bytes() {
        let ct1 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 5]);
        let ct2 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 5]);
        let ct3 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 6]);

        assert_eq!(ct1, ct2);
        assert_ne!(ct1, ct3);
    }

    #[test]
    fn cipher_texts_are_equal_with_equal_bytes() {
        let cipher1 = CipherText(vec![1, 2, 3, 4, 5]);
        let cipher2 = CipherText(vec![1, 2, 3, 4, 5]);
        let cipher3 = CipherText(vec![1, 2, 3, 4, 6]);

        assert_eq!(cipher1, cipher2);
        assert_ne!(cipher1, cipher3);
    }

    #[test]
    fn data_encryption_keys_are_equal_with_equal_bytes() {
        let dek1 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 5]));
        let dek2 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 5]));
        let dek3 = DataEncryptionKey::from(SecretValue::new(vec![1, 2, 3, 4, 6]));

        assert_eq!(dek1, dek2);
        assert_ne!(dek1, dek3);
    }

    #[test]
    fn test_cipher_text_hex_encoding() {
        let cipher = CipherText::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cipher.to_hex_string(), "deadbeef");
    }

    #[test]
    fn test_cipher_text_with_key_hex_encoding() {
        let ct = CipherTextWithEncryptedKey::from(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(ct.to_hex_string(), "01020304");
    }
}
