use crate::errors::*;
use crate::KmsAeadResult;
use rvstruct::*;
use secret_vault_value::SecretValue;
use std::fmt::{Display, Formatter};
use subtle::ConstantTimeEq;

#[derive(Debug, Clone, ValueStruct)]
pub struct CipherText(pub Vec<u8>);

impl CipherText {
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }
}

impl ConstantTimeEq for CipherText {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

impl PartialEq for CipherText {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[derive(Debug, Clone, ValueStruct)]
pub struct DataEncryptionKey(pub SecretValue);

impl ConstantTimeEq for DataEncryptionKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value()
            .as_sensitive_bytes()
            .ct_eq(other.value().as_sensitive_bytes())
    }
}

impl PartialEq for DataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// The version of the KMS key that wrapped a data encryption key: 1 to 255 ASCII alphanumeric
/// characters, such as the `N` of a GCP `cryptoKeyVersions/N`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KmsKeyVersion(String);

impl KmsKeyVersion {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KmsKeyVersion {
    type Error = KmsAeadError;

    fn try_from(value: String) -> KmsAeadResult<Self> {
        if value.is_empty()
            || value.len() > usize::from(u8::MAX)
            || !value.bytes().all(|byte| byte.is_ascii_alphanumeric())
        {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                &format!("KMS key version {value:?} is not 1 to 255 ASCII alphanumeric characters"),
            ));
        }
        Ok(Self(value))
    }
}

impl Display for KmsKeyVersion {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A data encryption key wrapped by a KMS, with the version of the KMS key that wrapped it when
/// the provider records one.
#[derive(Debug, Clone)]
pub struct EncryptedDataEncryptionKey {
    wrapped: Vec<u8>,
    key_version: Option<KmsKeyVersion>,
}

impl EncryptedDataEncryptionKey {
    pub fn new(wrapped: Vec<u8>, key_version: Option<KmsKeyVersion>) -> Self {
        Self {
            wrapped,
            key_version,
        }
    }

    /// The bytes the KMS returned, unchanged.
    pub fn wrapped(&self) -> &[u8] {
        &self.wrapped
    }

    pub fn key_version(&self) -> Option<&KmsKeyVersion> {
        self.key_version.as_ref()
    }

    pub fn to_hex_string(&self) -> String {
        hex::encode(&self.wrapped)
    }
}

impl ConstantTimeEq for EncryptedDataEncryptionKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        // The key version is not secret, so it compares in variable time.
        self.wrapped.ct_eq(&other.wrapped)
            & subtle::Choice::from(u8::from(self.key_version == other.key_version))
    }
}

impl PartialEq for EncryptedDataEncryptionKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
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
#[derive(Debug, Clone)]
pub struct CipherTextWithEncryptedKey(pub Vec<u8>);

impl CipherTextWithEncryptedKey {
    const LAYOUT_V1: u8 = 0x01;

    /// Fails when the wrapped key is longer than 65,535 bytes.
    pub fn new(
        cipher_text: &CipherText,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Self> {
        let key_version = encrypted_dek
            .key_version()
            .map_or("", KmsKeyVersion::as_str)
            .as_bytes();
        let key_version_len = u8::try_from(key_version.len()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                "KMS key version is longer than 255 bytes",
            )
        })?;
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

        let mut value =
            Vec::with_capacity(4 + key_version.len() + wrapped.len() + cipher_text.value().len());
        value.push(Self::LAYOUT_V1);
        value.push(key_version_len);
        value.extend_from_slice(key_version);
        value.extend_from_slice(&wrapped_len.to_be_bytes());
        value.extend_from_slice(wrapped);
        value.extend_from_slice(cipher_text.value());
        Ok(Self(value))
    }

    /// Reads layout v1 and the legacy layout. Fails on an unknown layout tag, on a length that
    /// runs past the end of the buffer and on a key version that is not ASCII alphanumeric.
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
        let key_version = match key_version {
            [] => None,
            version => Some(KmsKeyVersion::try_from(
                String::from_utf8_lossy(version).into_owned(),
            )?),
        };

        Ok((
            CipherText(cipher_text.to_vec()),
            EncryptedDataEncryptionKey::new(wrapped.to_vec(), key_version),
        ))
    }

    /// Splits the layout v1 bytes after the tag into key version, wrapped key and cipher text.
    fn split_v1(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
        let (&key_version_len, rest) = bytes.split_first()?;
        let (key_version, rest) = rest.split_at_checked(usize::from(key_version_len))?;
        let (wrapped_len, rest) = rest.split_first_chunk::<2>()?;
        let (wrapped, cipher_text) =
            rest.split_at_checked(usize::from(u16::from_be_bytes(*wrapped_len)))?;
        Some((key_version, wrapped, cipher_text))
    }

    /// Splits the legacy layout into an empty key version, wrapped key and cipher text.
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

    pub fn to_hex_string(&self) -> String {
        hex::encode(self.value())
    }

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

impl ConstantTimeEq for CipherTextWithEncryptedKey {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.value().ct_eq(other.value())
    }
}

impl PartialEq for CipherTextWithEncryptedKey {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
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
    fn key_version_outside_ascii_alphanumeric_is_rejected_on_read() {
        let envelope = CipherTextWithEncryptedKey::from(
            [0x01, 0x03, b'1', b'/', b'2', 0x00, 0x01, 0xAA, 0xBB].to_vec(),
        );
        assert_eq!(error_code(envelope.separate()), "INVALID_KEY_VERSION");
    }

    proptest! {
        #[test]
        fn separate_returns_on_arbitrary_bytes(
            tag in prop_oneof![Just(0x00u8), Just(0x01), any::<u8>()],
            rest in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut bytes = vec![tag];
            bytes.extend(rest);
            let _ = CipherTextWithEncryptedKey::from(bytes).separate();
        }
    }

    #[test]
    fn test_constant_time_encrypted_dek_comparison() {
        let version = KmsKeyVersion::try_from("1".to_string()).unwrap();
        let dek1 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], Some(version.clone()));
        let dek2 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], Some(version.clone()));
        let dek3 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 6], Some(version));
        let dek4 = EncryptedDataEncryptionKey::new(vec![1, 2, 3, 4, 5], None);

        // PartialEq uses constant-time comparison internally
        assert_eq!(dek1, dek2);
        assert_ne!(dek1, dek3);
        assert_ne!(dek1, dek4);
    }

    #[test]
    fn test_constant_time_cipher_text_with_key_comparison() {
        let ct1 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 5]);
        let ct2 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 5]);
        let ct3 = CipherTextWithEncryptedKey::from(vec![1, 2, 3, 4, 6]);

        // PartialEq uses constant-time comparison internally
        assert_eq!(ct1, ct2);
        assert_ne!(ct1, ct3);
    }

    #[test]
    fn test_cipher_text_hex_encoding() {
        let cipher = CipherText::from(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(cipher.to_hex_string(), "deadbeef");
    }

    #[test]
    fn test_encrypted_dek_hex_encoding() {
        let dek = EncryptedDataEncryptionKey::new(vec![0xCA, 0xFE, 0xBA, 0xBE], None);
        assert_eq!(dek.to_hex_string(), "cafebabe");
    }

    #[test]
    fn test_cipher_text_with_key_hex_encoding() {
        let ct = CipherTextWithEncryptedKey::from(vec![0x01, 0x02, 0x03, 0x04]);
        assert_eq!(ct.to_hex_string(), "01020304");
    }
}
