use std::fmt::{Debug, Formatter};

use prost::encoding::{self, WireType};
use prost::Message;
use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
use crate::{
    AeadAlgorithm, DataEncryptionKey, DeterministicAlgorithm, KeyId, KmsAeadEncryptionProvider,
    KmsAeadResult, ValueStruct,
};

/// A Tink key type: the `google.crypto.tink` message a key of an algorithm is serialised as, with
/// `version` 0 and the key in `key_value`, as Tink writes it into a keyset and encrypts it in a KMS
/// envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TinkKeyType {
    /// `AesGcmKey`, of [`AeadAlgorithm::Aes128Gcm`] and [`AeadAlgorithm::Aes256Gcm`].
    AesGcm,
    /// `AesGcmSivKey`, of [`AeadAlgorithm::Aes256GcmSiv`].
    AesGcmSiv,
    /// `ChaCha20Poly1305Key`, of [`AeadAlgorithm::ChaCha20Poly1305`].
    ChaCha20Poly1305,
    /// `AesSivKey`, of [`DeterministicAlgorithm::Aes256Siv`].
    AesSiv,
}

impl From<AeadAlgorithm> for TinkKeyType {
    fn from(algorithm: AeadAlgorithm) -> Self {
        match algorithm {
            AeadAlgorithm::ChaCha20Poly1305 => TinkKeyType::ChaCha20Poly1305,
            AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256Gcm => TinkKeyType::AesGcm,
            AeadAlgorithm::Aes256GcmSiv => TinkKeyType::AesGcmSiv,
        }
    }
}

impl From<DeterministicAlgorithm> for TinkKeyType {
    fn from(algorithm: DeterministicAlgorithm) -> Self {
        match algorithm {
            DeterministicAlgorithm::Aes256Siv => TinkKeyType::AesSiv,
        }
    }
}

/// The field of `version` in every Tink key message.
const KEY_MESSAGE_VERSION_FIELD: u32 = 1;

impl TinkKeyType {
    /// The type URL of the message, `KeyData.type_url` in a keyset.
    fn type_url(self) -> &'static str {
        match self {
            TinkKeyType::AesGcm => "type.googleapis.com/google.crypto.tink.AesGcmKey",
            TinkKeyType::AesGcmSiv => "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
            TinkKeyType::ChaCha20Poly1305 => {
                "type.googleapis.com/google.crypto.tink.ChaCha20Poly1305Key"
            }
            TinkKeyType::AesSiv => "type.googleapis.com/google.crypto.tink.AesSivKey",
        }
    }

    /// Whether a key of `len` bytes is a key of this type.
    fn takes_key_len(self, len: usize) -> bool {
        match self {
            TinkKeyType::AesGcm | TinkKeyType::AesGcmSiv => matches!(len, 16 | 32),
            TinkKeyType::ChaCha20Poly1305 => len == 32,
            TinkKeyType::AesSiv => len == 64,
        }
    }

    /// The field of `key_value` in the message, from Tink's `aes_gcm.proto`,
    /// `aes_gcm_siv.proto`, `chacha20_poly1305.proto` and `aes_siv.proto`.
    fn key_value_field(self) -> u32 {
        match self {
            TinkKeyType::AesGcm | TinkKeyType::AesGcmSiv => 3,
            TinkKeyType::ChaCha20Poly1305 | TinkKeyType::AesSiv => 2,
        }
    }
}

/// `dek` serialised as a key of `key_type`. `version` 0 is proto3's default and so is not
/// written, as Tink writes it.
pub(crate) fn serialize_tink_key(key_type: TinkKeyType, dek: &DataEncryptionKey) -> SecretValue {
    let key = dek.value().ref_sensitive_value();
    let field = key_type.key_value_field();
    // Sized up front, since growing the buffer would leave a copy of the key in freed memory.
    let mut serialized =
        SecretValue::new(Vec::with_capacity(encoding::bytes::encoded_len(field, key)));
    encoding::bytes::encode(field, key, serialized.ref_sensitive_value_mut());
    serialized
}

/// The key a serialised Tink key holds: an `AesGcmKey` or `AesGcmSivKey` of 16 or 32 bytes, a
/// `ChaCha20Poly1305Key` of 32 bytes or an `AesSivKey` of 64 bytes, with `version` 0 and no
/// other field. The message does not name its type, so a key of one type is read as a key
/// of another of the same field and length: AES-256-GCM and AES-256-GCM-SIV keys are written
/// alike, in Tink too, which reads them as the type it is configured with.
///
/// # Errors
///
/// `INVALID_KEY_FORMAT` for any other bytes, such as a serialised keyset. The message never
/// quotes them.
pub(crate) fn read_tink_key(serialized: &[u8]) -> KmsAeadResult<DataEncryptionKey> {
    let invalid = || {
        KmsAeadEncryptionError::create(
            "INVALID_KEY_FORMAT",
            &format!(
                "The decrypted key of {} bytes is not a serialised Tink AES-GCM, AES-GCM-SIV, \
                 ChaCha20-Poly1305 or AES-SIV key",
                serialized.len()
            ),
        )
    };
    let mut rest = serialized;
    let mut key = None;
    while !rest.is_empty() {
        match encoding::decode_key(&mut rest).map_err(|_| invalid())? {
            (KEY_MESSAGE_VERSION_FIELD, WireType::Varint) => {
                if encoding::decode_varint(&mut rest).map_err(|_| invalid())? != 0 {
                    return Err(invalid());
                }
            }
            (field @ (2 | 3), WireType::LengthDelimited) if key.is_none() => {
                let len = encoding::decode_varint(&mut rest).map_err(|_| invalid())?;
                let len = usize::try_from(len).map_err(|_| invalid())?;
                let (value, after) = rest.split_at_checked(len).ok_or_else(invalid)?;
                key = Some((field, value));
                rest = after;
            }
            _ => return Err(invalid()),
        }
    }
    match key {
        Some((field, value)) if matches!((field, value.len()), (2, 32 | 64) | (3, 16 | 32)) => {
            Ok(DataEncryptionKey::from(SecretValue::new(value.to_vec())))
        }
        _ => Err(invalid()),
    }
}

/// The length of Tink's output prefix of type TINK, `[0x01][key id: u32 BE]`.
pub(crate) const TINK_OUTPUT_PREFIX_LEN: usize = 5;

/// The first byte of Tink's output prefix of type TINK.
const TINK_OUTPUT_PREFIX_VERSION: u8 = 0x01;

/// Tink's output prefix of type TINK of the key `key_id`, the first bytes of every value the key
/// writes.
pub(crate) fn tink_output_prefix(key_id: KeyId) -> [u8; TINK_OUTPUT_PREFIX_LEN] {
    let [a, b, c, d] = key_id.as_u32().to_be_bytes();
    [TINK_OUTPUT_PREFIX_VERSION, a, b, c, d]
}

/// The key id of Tink's output prefix of type TINK at the start of `value` and the bytes after
/// it, or `None` when `value` does not start with one.
pub(crate) fn split_tink_output_prefix(value: &[u8]) -> Option<(KeyId, &[u8])> {
    match value {
        [TINK_OUTPUT_PREFIX_VERSION, a, b, c, d, rest @ ..] => {
            Some((KeyId::new(u32::from_be_bytes([*a, *b, *c, *d])), rest))
        }
        _ => None,
    }
}

/// A Tink keyset, the serialised `google.crypto.tink.Keyset` of keys that are all enabled,
/// symmetric and TINK-prefixed, as `tinkey` writes one. It is the plaintext of the keyset that
/// BigQuery's `KEYS.KEYSET_CHAIN` decrypts.
///
/// It holds the key bytes, zeroised when it is dropped. `Debug` shows the key ids only.
pub struct TinkKeyset(Keyset);

impl TinkKeyset {
    /// An empty keyset whose primary key, the one Tink encrypts with, is `primary_key_id`.
    pub fn new(primary_key_id: KeyId) -> Self {
        Self(Keyset {
            primary_key_id: primary_key_id.as_u32(),
            key: Vec::new(),
        })
    }

    /// Adds `dek` as the enabled key `key_id` of `key_type`. Tink requires the ids of a keyset
    /// to be unique, and the primary id to name one of its keys.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when `dek` does not have a length of `key_type`: 16 or 32 bytes for
    /// `AesGcm` and `AesGcmSiv`, 32 for `ChaCha20Poly1305` and 64 for `AesSiv`.
    pub fn add_key(
        &mut self,
        key_id: KeyId,
        key_type: TinkKeyType,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<()> {
        let len = dek.value().ref_sensitive_value().len();
        if !key_type.takes_key_len(len) {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!("A key of {len} bytes is not a {}", key_type.type_url()),
            ));
        }
        self.0.key.push(Key {
            key_data: Some(KeyData {
                type_url: key_type.type_url().to_string(),
                value: std::mem::take(serialize_tink_key(key_type, dek).ref_sensitive_value_mut()),
                key_material_type: KEY_MATERIAL_SYMMETRIC,
            }),
            status: KEY_STATUS_ENABLED,
            key_id: key_id.as_u32(),
            output_prefix_type: OUTPUT_PREFIX_TINK,
        });
        Ok(())
    }

    /// The serialised keyset.
    pub fn to_bytes(&self) -> SecretValue {
        SecretValue::new(self.0.encode_to_vec())
    }

    /// The keyset encrypted by `provider`, serialised as Tink serialises an encrypted keyset: a
    /// `google.crypto.tink.EncryptedKeyset` whose `encrypted_keyset` is the KMS ciphertext of
    /// [`to_bytes`](Self::to_bytes), encrypted with no associated data, and with no
    /// `keyset_info`.
    ///
    /// Tink reads it with the KMS AEAD of the KEK's
    /// [`tink_key_uri`](crate::KekRef::tink_key_uri): `KeysetHandle.read` or
    /// `TinkProtoKeysetFormat.parseEncryptedKeyset` in Java, `keyset.Read` in Go and
    /// `tink.read_keyset_handle` in Python. A KEK without a Tink key URI encrypts it as well, but
    /// no Tink KMS client reads it.
    ///
    /// It takes the keyset so that its keys are zeroised before the KMS call, leaving the
    /// serialised keyset as their one copy while the call is in flight.
    ///
    /// # Errors
    ///
    /// The provider's errors.
    pub async fn into_encrypted_bytes<P>(self, provider: &P) -> KmsAeadResult<Vec<u8>>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let keyset_dek = DataEncryptionKey::from(self.to_bytes());
        drop(self);
        let encrypted_keyset = provider
            .encrypt_data_encryption_key(&keyset_dek)
            .await?
            .into_value();
        Ok(EncryptedKeyset { encrypted_keyset }.encode_to_vec())
    }
}

/// The primary and the key ids, never the keys.
impl Debug for TinkKeyset {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TinkKeyset")
            .field("primary_key_id", &self.0.primary_key_id)
            .field(
                "key_ids",
                &self.0.key.iter().map(|key| key.key_id).collect::<Vec<_>>(),
            )
            .finish()
    }
}

/// `google.crypto.tink.KeyStatusType.ENABLED`.
const KEY_STATUS_ENABLED: i32 = 1;
/// `google.crypto.tink.OutputPrefixType.TINK`.
const OUTPUT_PREFIX_TINK: i32 = 1;
/// `google.crypto.tink.KeyData.KeyMaterialType.SYMMETRIC`.
const KEY_MATERIAL_SYMMETRIC: i32 = 1;

/// `google.crypto.tink.Keyset`, from Tink's `tink.proto`.
#[derive(Message)]
struct Keyset {
    #[prost(uint32, tag = "1")]
    primary_key_id: u32,
    #[prost(message, repeated, tag = "2")]
    key: Vec<Key>,
}

/// `google.crypto.tink.Keyset.Key`.
#[derive(Message)]
struct Key {
    #[prost(message, optional, tag = "1")]
    key_data: Option<KeyData>,
    #[prost(int32, tag = "2")]
    status: i32,
    #[prost(uint32, tag = "3")]
    key_id: u32,
    #[prost(int32, tag = "4")]
    output_prefix_type: i32,
}

/// `google.crypto.tink.EncryptedKeyset`, from Tink's `tink.proto`, without `keyset_info`: Tink
/// never reads it, and its binary keyset writers leave it out.
#[derive(Message)]
struct EncryptedKeyset {
    #[prost(bytes = "vec", tag = "2")]
    encrypted_keyset: Vec<u8>,
}

/// `google.crypto.tink.KeyData`. `value` is the serialised key, so it is zeroised on drop and
/// left out of `Debug`.
#[derive(Message)]
#[prost(skip_debug)]
struct KeyData {
    #[prost(string, tag = "1")]
    type_url: String,
    #[prost(bytes = "vec", tag = "2")]
    value: Vec<u8>,
    #[prost(int32, tag = "3")]
    key_material_type: i32,
}

impl Debug for KeyData {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyData")
            .field("type_url", &self.type_url)
            .finish_non_exhaustive()
    }
}

impl Drop for KeyData {
    fn drop(&mut self) {
        // Dropping the bytes inside a SecretValue zeroises them.
        drop(SecretValue::new(std::mem::take(&mut self.value)));
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::errors::KmsAeadError;

    struct SerializedKey {
        key_type: TinkKeyType,
        key: &'static str,
        serialized: &'static str,
    }

    /// `KeyData.value` of a new key of each template, and the `key_value` Tink reads from it:
    /// from Tink 1.16.1 for Python, which has no ChaCha20Poly1305Key, and that one from Tink
    /// 1.24.0 for Java.
    const TINK_KEYS: &[SerializedKey] = &[
        SerializedKey {
            key_type: TinkKeyType::ChaCha20Poly1305,
            key: "774e520c6ed404f30ed102d1d159ded4309878531d51b8c7b574ad1e491731f1",
            serialized: "1220774e520c6ed404f30ed102d1d159ded4309878531d51b8c7b574ad1e491731f1",
        },
        SerializedKey {
            key_type: TinkKeyType::AesGcm,
            key: "651130bd5e51f119150414c3976b1f74",
            serialized: "1a10651130bd5e51f119150414c3976b1f74",
        },
        SerializedKey {
            key_type: TinkKeyType::AesGcm,
            key: "a637fbbc7a96def9ea67b785b1fb0b5cc6888250a27a9ff91a388b5fa92c5324",
            serialized: "1a20a637fbbc7a96def9ea67b785b1fb0b5cc6888250a27a9ff91a388b5fa92c5324",
        },
        SerializedKey {
            key_type: TinkKeyType::AesGcmSiv,
            key: "7e48e40802a763533bc9f483347cccb576921f0caf622bddceb055f8d1844fae",
            serialized: "1a207e48e40802a763533bc9f483347cccb576921f0caf622bddceb055f8d1844fae",
        },
        SerializedKey {
            key_type: TinkKeyType::AesSiv,
            key: "c6b98ad941a2ab1b053d5acea06573bb47315fdee8bddc890402308851dbf3baeb2235599a078bcda1e25c23b6c2c3829874757bad185f496db1f799eeb7d5e9",
            serialized: "1240c6b98ad941a2ab1b053d5acea06573bb47315fdee8bddc890402308851dbf3baeb2235599a078bcda1e25c23b6c2c3829874757bad185f496db1f799eeb7d5e9",
        },
    ];

    #[test]
    fn keys_serialize_as_tink_writes_them_and_read_back() -> KmsAeadResult<()> {
        for tink_key in TINK_KEYS {
            let dek = DataEncryptionKey::from(SecretValue::new(hex::decode(tink_key.key).unwrap()));
            let serialized = hex::decode(tink_key.serialized).unwrap();

            assert_eq!(
                *serialize_tink_key(tink_key.key_type, &dek).ref_sensitive_value(),
                serialized,
                "{:?}",
                tink_key.key_type
            );
            assert_eq!(read_tink_key(&serialized)?, dek);
        }
        Ok(())
    }

    proptest! {
        #[test]
        fn every_algorithm_key_reads_back(
            algorithm in prop::sample::select(AeadAlgorithm::ALL.to_vec()),
            byte in any::<u8>(),
        ) {
            let dek = DataEncryptionKey::from(SecretValue::new(vec![byte; algorithm.key_len()]));

            let serialized = serialize_tink_key(TinkKeyType::from(algorithm), &dek);

            prop_assert_eq!(
                read_tink_key(serialized.ref_sensitive_value()).unwrap(),
                dek
            );
        }

        #[test]
        fn reading_returns_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
            let _ = read_tink_key(&bytes);
        }
    }

    #[test]
    fn bytes_that_are_no_tink_key_are_refused() {
        let key = [0x42; 32];
        let refused: [Vec<u8>; 7] = [
            Vec::new(),
            // A version other than 0.
            [&[0x08, 0x01, 0x1a, 0x20][..], &key].concat(),
            // A key of a length no algorithm takes.
            [&[0x1a, 0x18][..], &key[..24]].concat(),
            // Two keys.
            [&[0x1a, 0x20][..], &key, &[0x12, 0x20], &key].concat(),
            // A field no key message has.
            [&[0x1a, 0x20][..], &key, &[0x20, 0x01]].concat(),
            // A length past the end.
            [&[0x1a, 0x21][..], &key].concat(),
            // The start of a keyset: `primary_key_id` and a `Key`.
            vec![0x08, 0xaf, 0xb6, 0xc1, 0xc4, 0x01, 0x12, 0x64, 0x0a, 0x58],
        ];
        for bytes in refused {
            let result = read_tink_key(&bytes);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_FORMAT"),
                "{bytes:02x?}: {result:?}"
            );
        }
    }

    #[test]
    fn an_explicit_version_0_is_read() -> KmsAeadResult<()> {
        let key = [0x42; 32];

        let dek = read_tink_key(&[&[0x08, 0x00, 0x12, 0x20][..], &key].concat())?;

        assert_eq!(dek, DataEncryptionKey::from(SecretValue::new(key.to_vec())));
        Ok(())
    }

    // The keysets below were written by tinkey 1.14.0, from
    // https://storage.googleapis.com/tinkey/tinkey-1.14.0.tar.gz:
    //
    //   tinkey create-keyset --key-template AES256_GCM --out-format json --out gcm1.json
    //   tinkey add-key --key-template AES256_GCM --in gcm1.json --in-format json \
    //     --out-format json --out gcm2.json
    //   tinkey convert-keyset --in gcm2.json --in-format json --out gcm2.bin --out-format binary
    //   tinkey create-keyset --key-template AES256_SIV --out-format json --out siv.json
    //   tinkey convert-keyset --in siv.json --in-format json --out siv.bin --out-format binary
    //
    // The keys are the `key_value` fields of the keys' `value`, read from the JSON keysets.

    /// `gcm2.bin`: two AES-256-GCM keys, 412113711 the primary and 2776353560.
    const TINKEY_AES_GCM_KEYSET: [u8; 210] = [
        0x08, 0xaf, 0xb6, 0xc1, 0xc4, 0x01, 0x12, 0x64, 0x0a, 0x58, 0x0a, 0x30, 0x74, 0x79, 0x70,
        0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f,
        0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f,
        0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x47, 0x63, 0x6d, 0x4b, 0x65, 0x79,
        0x12, 0x22, 0x1a, 0x20, 0x26, 0x9f, 0x89, 0x22, 0xaf, 0xa5, 0xdd, 0xac, 0xf8, 0x0e, 0x5c,
        0xab, 0x8a, 0x6e, 0x02, 0x8b, 0xfe, 0xc2, 0x0a, 0x63, 0x3b, 0xfd, 0x13, 0xf5, 0x86, 0x50,
        0x30, 0xb9, 0x67, 0x97, 0xbc, 0x7f, 0x18, 0x01, 0x10, 0x01, 0x18, 0xaf, 0xb6, 0xc1, 0xc4,
        0x01, 0x20, 0x01, 0x12, 0x64, 0x0a, 0x58, 0x0a, 0x30, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x67,
        0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74, 0x6f, 0x2e, 0x74, 0x69,
        0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x47, 0x63, 0x6d, 0x4b, 0x65, 0x79, 0x12, 0x22, 0x1a,
        0x20, 0x41, 0xcc, 0xbb, 0x34, 0x57, 0xc4, 0xbe, 0x99, 0x79, 0x08, 0x7c, 0x27, 0x9c, 0x5b,
        0x86, 0x8f, 0xe1, 0x56, 0x4e, 0xf8, 0xad, 0x6f, 0x0d, 0x01, 0xd6, 0xd5, 0xbd, 0x62, 0x49,
        0xe3, 0x44, 0x71, 0x18, 0x01, 0x10, 0x01, 0x18, 0x98, 0x96, 0xef, 0xab, 0x0a, 0x20, 0x01,
    ];

    const TINKEY_AES_GCM_PRIMARY: KeyId = KeyId::new(412_113_711);
    const TINKEY_AES_GCM_PRIMARY_KEY: [u8; 32] = [
        0x26, 0x9f, 0x89, 0x22, 0xaf, 0xa5, 0xdd, 0xac, 0xf8, 0x0e, 0x5c, 0xab, 0x8a, 0x6e, 0x02,
        0x8b, 0xfe, 0xc2, 0x0a, 0x63, 0x3b, 0xfd, 0x13, 0xf5, 0x86, 0x50, 0x30, 0xb9, 0x67, 0x97,
        0xbc, 0x7f,
    ];
    const TINKEY_AES_GCM_SECOND: KeyId = KeyId::new(2_776_353_560);
    const TINKEY_AES_GCM_SECOND_KEY: [u8; 32] = [
        0x41, 0xcc, 0xbb, 0x34, 0x57, 0xc4, 0xbe, 0x99, 0x79, 0x08, 0x7c, 0x27, 0x9c, 0x5b, 0x86,
        0x8f, 0xe1, 0x56, 0x4e, 0xf8, 0xad, 0x6f, 0x0d, 0x01, 0xd6, 0xd5, 0xbd, 0x62, 0x49, 0xe3,
        0x44, 0x71,
    ];

    /// `siv.bin`: one AES-SIV key, 767014583.
    const TINKEY_AES_SIV_KEYSET: [u8; 141] = [
        0x08, 0xb7, 0xed, 0xde, 0xed, 0x02, 0x12, 0x84, 0x01, 0x0a, 0x78, 0x0a, 0x30, 0x74, 0x79,
        0x70, 0x65, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x61, 0x70, 0x69, 0x73, 0x2e, 0x63,
        0x6f, 0x6d, 0x2f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x72, 0x79, 0x70, 0x74,
        0x6f, 0x2e, 0x74, 0x69, 0x6e, 0x6b, 0x2e, 0x41, 0x65, 0x73, 0x53, 0x69, 0x76, 0x4b, 0x65,
        0x79, 0x12, 0x42, 0x12, 0x40, 0x02, 0x88, 0xd5, 0x3a, 0xa1, 0x86, 0x0f, 0xae, 0x9d, 0xe2,
        0x05, 0xc8, 0x9f, 0x88, 0x69, 0x27, 0xa5, 0x19, 0xe4, 0xbf, 0x33, 0x74, 0xa5, 0xc4, 0x85,
        0x88, 0xb7, 0xa0, 0xf1, 0x26, 0x28, 0x69, 0x3a, 0xa2, 0x2d, 0x60, 0x41, 0x15, 0xb8, 0xb4,
        0x4a, 0x0a, 0xfb, 0x77, 0xe1, 0x25, 0x0e, 0x4a, 0x57, 0x29, 0x5d, 0x44, 0xab, 0x1d, 0xd2,
        0xf9, 0xcc, 0x68, 0x89, 0x76, 0xc8, 0x32, 0xc7, 0xfd, 0x18, 0x01, 0x10, 0x01, 0x18, 0xb7,
        0xed, 0xde, 0xed, 0x02, 0x20, 0x01,
    ];

    const TINKEY_AES_SIV: KeyId = KeyId::new(767_014_583);
    const TINKEY_AES_SIV_KEY: [u8; 64] = [
        0x02, 0x88, 0xd5, 0x3a, 0xa1, 0x86, 0x0f, 0xae, 0x9d, 0xe2, 0x05, 0xc8, 0x9f, 0x88, 0x69,
        0x27, 0xa5, 0x19, 0xe4, 0xbf, 0x33, 0x74, 0xa5, 0xc4, 0x85, 0x88, 0xb7, 0xa0, 0xf1, 0x26,
        0x28, 0x69, 0x3a, 0xa2, 0x2d, 0x60, 0x41, 0x15, 0xb8, 0xb4, 0x4a, 0x0a, 0xfb, 0x77, 0xe1,
        0x25, 0x0e, 0x4a, 0x57, 0x29, 0x5d, 0x44, 0xab, 0x1d, 0xd2, 0xf9, 0xcc, 0x68, 0x89, 0x76,
        0xc8, 0x32, 0xc7, 0xfd,
    ];

    /// The keyset of `gcm2.bin`.
    fn tinkey_aes_gcm_keyset() -> KmsAeadResult<TinkKeyset> {
        let mut aes_gcm = TinkKeyset::new(TINKEY_AES_GCM_PRIMARY);
        for (key_id, key) in [
            (TINKEY_AES_GCM_PRIMARY, TINKEY_AES_GCM_PRIMARY_KEY),
            (TINKEY_AES_GCM_SECOND, TINKEY_AES_GCM_SECOND_KEY),
        ] {
            aes_gcm.add_key(
                key_id,
                TinkKeyType::from(AeadAlgorithm::Aes256Gcm),
                &DataEncryptionKey::from(SecretValue::new(key.to_vec())),
            )?;
        }
        Ok(aes_gcm)
    }

    #[test]
    fn keysets_are_the_ones_tinkey_writes() -> KmsAeadResult<()> {
        let aes_gcm = tinkey_aes_gcm_keyset()?;
        let mut aes_siv = TinkKeyset::new(TINKEY_AES_SIV);
        aes_siv.add_key(
            TINKEY_AES_SIV,
            TinkKeyType::from(DeterministicAlgorithm::Aes256Siv),
            &DataEncryptionKey::from(SecretValue::new(TINKEY_AES_SIV_KEY.to_vec())),
        )?;

        assert_eq!(
            *aes_gcm.to_bytes().ref_sensitive_value(),
            TINKEY_AES_GCM_KEYSET
        );
        assert_eq!(
            *aes_siv.to_bytes().ref_sensitive_value(),
            TINKEY_AES_SIV_KEYSET
        );
        Ok(())
    }

    /// The start of `gcm2.bin` as Tink 1.16.1 for Python writes it encrypted,
    /// `handle.write(tink.BinaryKeysetWriter(out), kms)` under a KMS AEAD whose ciphertext is its
    /// plaintext, as the test provider's is: `encrypted_keyset`, field 2, of 210 bytes, then the
    /// keyset. Tink writes no `keyset_info`.
    const TINK_ENCRYPTED_AES_GCM_KEYSET_HEADER: [u8; 3] = [0x12, 0xd2, 0x01];

    #[tokio::test]
    async fn encrypted_keysets_are_the_ones_tink_writes() -> KmsAeadResult<()> {
        let keyset = tinkey_aes_gcm_keyset()?;

        let encrypted = keyset
            .into_encrypted_bytes(&crate::test_provider::TestKmsProvider::Working)
            .await?;

        assert_eq!(
            encrypted,
            [
                &TINK_ENCRYPTED_AES_GCM_KEYSET_HEADER[..],
                &TINKEY_AES_GCM_KEYSET[..]
            ]
            .concat()
        );
        Ok(())
    }

    #[test]
    fn a_key_of_another_length_than_its_type_is_refused() {
        let cases = [
            (TinkKeyType::AesGcm, 24),
            (TinkKeyType::AesGcmSiv, 64),
            (TinkKeyType::ChaCha20Poly1305, 16),
            (TinkKeyType::AesSiv, 32),
        ];
        for (key_type, len) in cases {
            let mut keyset = TinkKeyset::new(TINKEY_AES_SIV);

            let result = keyset.add_key(
                TINKEY_AES_SIV,
                key_type,
                &DataEncryptionKey::from(SecretValue::new(vec![0x42; len])),
            );

            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_KEY_LENGTH"),
                "{key_type:?}, {len} bytes: {result:?}"
            );
        }
    }

    #[test]
    fn keyset_debug_shows_the_key_ids_only() -> KmsAeadResult<()> {
        let mut keyset = TinkKeyset::new(TINKEY_AES_SIV);
        keyset.add_key(
            TINKEY_AES_SIV,
            TinkKeyType::AesSiv,
            &DataEncryptionKey::from(SecretValue::new(TINKEY_AES_SIV_KEY.to_vec())),
        )?;

        let debug = format!("{keyset:?}");

        assert!(debug.contains("767014583"), "{debug}");
        for rendering in crate::test_provider::renderings(&TINKEY_AES_SIV_KEY) {
            assert!(!debug.contains(&rendering), "{debug}");
        }
        Ok(())
    }
}
