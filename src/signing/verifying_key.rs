use std::fmt::{Debug, Display, Formatter};

use base64ct::{Base64UrlUnpadded, Encoding};
use der::asn1::BitStringRef;
use der::{AnyRef, Decode, Encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};

use super::SigningAlgorithm;
use crate::errors::KmsAeadSignatureError;
use crate::formats::PublicKeyFormat;
use crate::{KeyId, KmsAeadResult};

/// `id-Ed25519` of RFC 8410.
pub(crate) const ID_ED25519: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.101.112");
/// `id-ecPublicKey` of RFC 5480.
pub(crate) const ID_EC_PUBLIC_KEY: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
/// `prime256v1`, the named curve P-256, of RFC 5480.
pub(crate) const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

/// The encodings of the Ed25519 points of order 8 or less, in little-endian `y` with the sign bit
/// cleared: no private key stands behind such a public key, and the verification equation can be
/// met without one. ring and aws-lc-rs verify under them, so the refusal is made when a key is
/// built, whichever backend verifies. The list is libsodium's.
const SMALL_ORDER_ED25519_KEYS: [[u8; 32]; 7] = [
    // y = 0, order 4
    [
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // y = 1, the identity
    [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ],
    // y = p - 1, order 2
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p, non-canonical y = 0
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p + 1, non-canonical y = 1
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // order 8
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // order 8
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// The public key of a signing key: its algorithm, the raw public key and its key id, derived from
/// the key unless set.
///
/// The key id of a key is the first four bytes, big-endian, of its RFC 7638 thumbprint with
/// SHA-256: the SHA-256 of the key's required JWK members in lexicographic order with no
/// whitespace, `{"crv":"Ed25519","kty":"OKP","x":…}` or
/// `{"crv":"P-256","kty":"EC","x":…,"y":…}`.
/// A publisher with a numbering of its own sets the id with [`with_key_id`](Self::with_key_id).
/// What a verifier trusts is its [`VerifyingKeySet`]'s mapping of an id to one key either way.
///
/// Equality compares the algorithm, the key and the key id. `Debug` shows the algorithm, the key
/// id and the thumbprint.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct VerifyingKey {
    algorithm: SigningAlgorithm,
    public_key: Vec<u8>,
    thumbprint: JwkThumbprint,
    key_id: KeyId,
}

/// The RFC 7638 thumbprint of a [`VerifyingKey`] with SHA-256: the JWK `kid` the library writes.
/// `Display` writes it as base64url without padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwkThumbprint([u8; 32]);

/// Base64url without padding.
impl Display for JwkThumbprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&Base64UrlUnpadded::encode_string(&self.0))
    }
}

impl VerifyingKey {
    /// `bytes` as the public key of `algorithm` in `format`. The algorithm is needed for
    /// [`Raw`](PublicKeyFormat::Raw), whose bytes carry none, and is checked against the
    /// encoding's own identifier for [`SpkiDer`](PublicKeyFormat::SpkiDer),
    /// [`SpkiPem`](PublicKeyFormat::SpkiPem) and [`Jwk`](PublicKeyFormat::Jwk): `id-Ed25519`,
    /// `id-ecPublicKey` on `prime256v1`, `OKP`/`Ed25519` or `EC`/`P-256`. Every variant is taken;
    /// a JWK is read as [`VerifyingKeySet::from_jwks`] reads each key, and keeps the
    /// `kms_aead_key_id` it carries.
    ///
    /// # Errors
    ///
    /// `INVALID_PUBLIC_KEY` for bytes that are not the format, a raw key of another length, a
    /// point not starting with `0x04` or an Ed25519 point of order 8 or less;
    /// `SIGNING_ALGORITHM_MISMATCH` when the encoding names another algorithm than `algorithm`.
    /// Whether a point is on the curve is checked by [`Verifier::new`](super::Verifier::new).
    pub fn from_bytes(
        algorithm: SigningAlgorithm,
        bytes: &[u8],
        format: PublicKeyFormat,
    ) -> KmsAeadResult<Self> {
        let key = match format {
            PublicKeyFormat::Raw => Self::from_raw(algorithm, bytes.to_vec())?,
            PublicKeyFormat::SpkiDer => Self::from_spki_der(bytes)?,
            PublicKeyFormat::SpkiPem => {
                let der = PublicKeyFormat::spki_der_of_pem(bytes).map_err(|reason| {
                    KmsAeadSignatureError::invalid_public_key(&format!("The public key {reason}"))
                })?;
                Self::from_spki_der(&der)?
            }
            PublicKeyFormat::Jwk => {
                let jwk = serde_json::from_slice(bytes).map_err(|error| {
                    KmsAeadSignatureError::invalid_public_key(&format!(
                        "The public key is not a JWK: {:?} error at line {} column {}",
                        error.classify(),
                        error.line(),
                        error.column()
                    ))
                })?;
                Self::from_jwk(jwk).map_err(|reason| {
                    KmsAeadSignatureError::invalid_public_key(&format!("The JWK {reason}"))
                })?
            }
        };
        if key.algorithm != algorithm {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                &format!(
                    "The public key is a key of {}, not of {algorithm}",
                    key.algorithm
                ),
            ));
        }
        Ok(key)
    }

    /// `public_key`, the raw key of `algorithm`, under its derived key id.
    pub(crate) fn from_raw(
        algorithm: SigningAlgorithm,
        public_key: Vec<u8>,
    ) -> KmsAeadResult<Self> {
        if public_key.len() != algorithm.public_key_len() {
            return Err(KmsAeadSignatureError::invalid_public_key(&format!(
                "A raw public key of {} bytes is not a key of {algorithm}, which is {} bytes",
                public_key.len(),
                algorithm.public_key_len()
            )));
        }
        if algorithm == SigningAlgorithm::Ed25519 && Self::is_small_order_ed25519(&public_key) {
            return Err(KmsAeadSignatureError::invalid_public_key(
                "The Ed25519 public key is a point of order 8 or less, which no private key stands \
                 behind",
            ));
        }
        if algorithm == SigningAlgorithm::EcdsaP256Sha256 && public_key.first() != Some(&0x04) {
            return Err(KmsAeadSignatureError::invalid_public_key(
                "A P-256 public key is not an uncompressed point, which starts with 0x04",
            ));
        }
        let thumbprint: [u8; 32] =
            Sha256::digest(Self::thumbprint_input(algorithm, &public_key)).into();
        let key_id = KeyId::new(u32::from_be_bytes([
            thumbprint[0],
            thumbprint[1],
            thumbprint[2],
            thumbprint[3],
        ]));
        Ok(Self {
            algorithm,
            public_key,
            thumbprint: JwkThumbprint(thumbprint),
            key_id,
        })
    }

    /// Whether `public_key`, 32 bytes, encodes a point of order 8 or less, whichever sign bit it
    /// carries.
    fn is_small_order_ed25519(public_key: &[u8]) -> bool {
        let mut y = [0_u8; 32];
        y.copy_from_slice(public_key);
        y[31] &= 0x7f;
        SMALL_ORDER_ED25519_KEYS.contains(&y)
    }

    /// The RFC 7638 thumbprint input of the key: its required JWK members in lexicographic order,
    /// with no whitespace. base64url needs no JSON escaping.
    fn thumbprint_input(algorithm: SigningAlgorithm, public_key: &[u8]) -> String {
        match JwkCoordinates::of(algorithm, public_key) {
            JwkCoordinates::Okp { x } => {
                format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#)
            }
            JwkCoordinates::Ec { x, y } => {
                format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#)
            }
        }
    }

    fn from_spki_der(der: &[u8]) -> KmsAeadResult<Self> {
        let spki = SubjectPublicKeyInfoRef::from_der(der).map_err(|error| {
            KmsAeadSignatureError::invalid_public_key(&format!(
                "The public key is not a DER SubjectPublicKeyInfo: {}",
                error.kind()
            ))
        })?;
        let algorithm =
            match spki.algorithm.oids() {
                Ok((ID_ED25519, None)) => SigningAlgorithm::Ed25519,
                Ok((ID_EC_PUBLIC_KEY, Some(PRIME256V1))) => SigningAlgorithm::EcdsaP256Sha256,
                _ => return Err(KmsAeadSignatureError::create(
                    "SIGNING_ALGORITHM_MISMATCH",
                    "The SubjectPublicKeyInfo is not an id-Ed25519 key or an id-ecPublicKey key \
                     on prime256v1",
                )),
            };
        let public_key = spki.subject_public_key.as_bytes().ok_or_else(|| {
            KmsAeadSignatureError::invalid_public_key(
                "The public key of the SubjectPublicKeyInfo has unused bits",
            )
        })?;
        Self::from_raw(algorithm, public_key.to_vec())
    }

    /// The key a parsed JWK holds, or why it holds none, to follow "The JWK" in the error.
    fn from_jwk(jwk: Jwk) -> Result<Self, String> {
        let algorithm = match (jwk.kty.as_str(), jwk.crv.as_deref()) {
            ("OKP", Some("Ed25519")) => SigningAlgorithm::Ed25519,
            ("EC", Some("P-256")) => SigningAlgorithm::EcdsaP256Sha256,
            _ => return Err("is not an OKP Ed25519 or an EC P-256 key".to_string()),
        };
        if jwk.d.is_some() {
            return Err("carries the private member d".to_string());
        }
        if jwk
            .key_use
            .as_deref()
            .is_some_and(|key_use| key_use != "sig")
        {
            return Err("has a use other than sig".to_string());
        }
        if jwk
            .key_ops
            .as_ref()
            .is_some_and(|key_ops| !key_ops.iter().any(|op| op == "verify"))
        {
            return Err("has key_ops without verify".to_string());
        }
        if jwk
            .alg
            .as_deref()
            .is_some_and(|alg| alg != algorithm.jwk_alg())
        {
            return Err(format!("has an alg other than {}", algorithm.jwk_alg()));
        }
        let coordinate = |value: Option<&str>, name: &str| {
            value
                .and_then(|value| Base64UrlUnpadded::decode_vec(value).ok())
                .filter(|bytes| bytes.len() == 32)
                .ok_or_else(|| format!("has no {name} of 32 bytes in base64url without padding"))
        };
        let public_key = match algorithm {
            SigningAlgorithm::Ed25519 => {
                if jwk.y.is_some() {
                    return Err("is an OKP key with a y".to_string());
                }
                coordinate(jwk.x.as_deref(), "x")?
            }
            SigningAlgorithm::EcdsaP256Sha256 => [
                &[0x04][..],
                &coordinate(jwk.x.as_deref(), "x")?,
                &coordinate(jwk.y.as_deref(), "y")?,
            ]
            .concat(),
        };
        let key = Self::from_raw(algorithm, public_key)
            .map_err(|_| format!("is not a public key of {algorithm}"))?;
        match jwk.kms_aead_key_id {
            None => Ok(key),
            Some(value) => value
                .as_u64()
                .and_then(|key_id| u32::try_from(key_id).ok())
                .map(|key_id| key.with_key_id(KeyId::new(key_id)))
                .ok_or_else(|| {
                    "has a kms_aead_key_id that is not an integer from 0 to 2^32 - 1".to_string()
                }),
        }
    }

    /// The same key under `key_id` in place of the derived id, for a publisher with a numbering
    /// of its own. `encode(PublicKeyFormat::Jwk)` then writes it as `kms_aead_key_id`.
    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self { key_id, ..self }
    }

    /// The algorithm of the key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    /// The first four bytes of the thumbprint, big-endian, or the id
    /// [`with_key_id`](Self::with_key_id) set.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The RFC 7638 thumbprint with SHA-256, base64url without padding: the JWK `kid`.
    pub fn thumbprint(&self) -> JwkThumbprint {
        self.thumbprint
    }

    /// The raw key: 32 bytes for Ed25519 and the 65-byte uncompressed point for P-256.
    pub(crate) fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Whether the key id is the one derived from the key, rather than one a publisher set.
    fn has_derived_key_id(&self) -> bool {
        self.key_id.as_u32().to_be_bytes() == self.thumbprint.0[..4]
    }

    /// The key in `format`: the raw key for [`Raw`](PublicKeyFormat::Raw), 32 bytes for Ed25519
    /// and the 65-byte uncompressed point for P-256; the SubjectPublicKeyInfo for
    /// [`SpkiDer`](PublicKeyFormat::SpkiDer); its `PUBLIC KEY` PEM block for
    /// [`SpkiPem`](PublicKeyFormat::SpkiPem), as UTF-8; and for [`Jwk`](PublicKeyFormat::Jwk)
    /// the UTF-8 JSON of the JWK with `kty`, `crv`, `x` (and `y`), `kid`, `use: "sig"` and
    /// `alg`, and `kms_aead_key_id` when the id was set. [`VerifyingKeySet::to_jwks`] writes a
    /// whole set.
    ///
    /// # Errors
    ///
    /// `INVALID_PUBLIC_KEY` for a variant this type does not take, which is none today, and when
    /// the encoding cannot be written.
    pub fn encode(&self, format: PublicKeyFormat) -> KmsAeadResult<Vec<u8>> {
        match format {
            PublicKeyFormat::Raw => Ok(self.public_key.clone()),
            PublicKeyFormat::SpkiDer => self.to_spki_der(),
            PublicKeyFormat::SpkiPem => pem_rfc7468::encode_string(
                PublicKeyFormat::PEM_LABEL,
                pem_rfc7468::LineEnding::LF,
                &self.to_spki_der()?,
            )
            .map(String::into_bytes)
            .map_err(|error| {
                KmsAeadSignatureError::invalid_public_key(&format!(
                    "Unable to write the PEM: {error}"
                ))
            }),
            PublicKeyFormat::Jwk => self.to_jwk().map(String::into_bytes),
        }
    }

    fn to_spki_der(&self) -> KmsAeadResult<Vec<u8>> {
        let algorithm = match self.algorithm {
            SigningAlgorithm::Ed25519 => AlgorithmIdentifierRef {
                oid: ID_ED25519,
                parameters: None,
            },
            SigningAlgorithm::EcdsaP256Sha256 => AlgorithmIdentifierRef {
                oid: ID_EC_PUBLIC_KEY,
                parameters: Some(AnyRef::from(&PRIME256V1)),
            },
        };
        let unwritable = |error: der::Error| {
            KmsAeadSignatureError::invalid_public_key(&format!(
                "Unable to write the SubjectPublicKeyInfo: {}",
                error.kind()
            ))
        };
        SubjectPublicKeyInfoRef {
            algorithm,
            subject_public_key: BitStringRef::from_bytes(&self.public_key).map_err(unwritable)?,
        }
        .to_der()
        .map_err(unwritable)
    }

    /// The JWK of the key, with its members in the order of RFC 7517's examples.
    fn to_jwk(&self) -> KmsAeadResult<String> {
        serialize_public_key_document("JWK", &JwkMembers::from(self))
    }
}

/// The algorithm, the key id and the thumbprint.
impl Debug for VerifyingKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("algorithm", &self.algorithm)
            .field("key_id", &self.key_id.as_u32())
            .field("thumbprint", &self.thumbprint().to_string())
            .finish()
    }
}

/// The base64url coordinates of a raw public key, as a JWK carries them.
enum JwkCoordinates {
    Okp { x: String },
    Ec { x: String, y: String },
}

impl JwkCoordinates {
    /// The coordinates of `public_key`, a raw key of `algorithm` whose length is checked.
    fn of(algorithm: SigningAlgorithm, public_key: &[u8]) -> Self {
        match algorithm {
            SigningAlgorithm::Ed25519 => JwkCoordinates::Okp {
                x: Base64UrlUnpadded::encode_string(public_key),
            },
            SigningAlgorithm::EcdsaP256Sha256 => {
                let (x, y) = public_key[1..].split_at(32);
                JwkCoordinates::Ec {
                    x: Base64UrlUnpadded::encode_string(x),
                    y: Base64UrlUnpadded::encode_string(y),
                }
            }
        }
    }
}

/// A JWK as written, its members in the order of RFC 7517's examples. serde writes the fields of
/// a struct in declaration order.
#[derive(Serialize)]
struct JwkMembers {
    kty: &'static str,
    crv: &'static str,
    x: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    kid: String,
    #[serde(rename = "use")]
    key_use: &'static str,
    alg: &'static str,
    /// Present only for a key id the publisher set.
    #[serde(skip_serializing_if = "Option::is_none")]
    kms_aead_key_id: Option<u32>,
}

impl From<&VerifyingKey> for JwkMembers {
    fn from(key: &VerifyingKey) -> Self {
        let (kty, crv, x, y) = match JwkCoordinates::of(key.algorithm, &key.public_key) {
            JwkCoordinates::Okp { x } => ("OKP", "Ed25519", x, None),
            JwkCoordinates::Ec { x, y } => ("EC", "P-256", x, Some(y)),
        };
        Self {
            kty,
            crv,
            x,
            y,
            kid: key.thumbprint().to_string(),
            key_use: "sig",
            alg: key.algorithm.jwk_alg(),
            kms_aead_key_id: (!key.has_derived_key_id()).then(|| key.key_id.as_u32()),
        }
    }
}

/// A JWK Set as written.
#[derive(Serialize)]
struct JwkSetMembers {
    keys: Vec<JwkMembers>,
}

/// The JSON of a document made of strings and integers, `what` naming it in the error.
fn serialize_public_key_document<T: Serialize>(what: &str, document: &T) -> KmsAeadResult<String> {
    serde_json::to_string(document).map_err(|error| {
        KmsAeadSignatureError::invalid_public_key(&format!("Unable to write the {what}: {error}"))
    })
}

/// A JWK as read: the members the library knows, every other one ignored as RFC 7517 requires.
/// `kid` is not read: the key id comes from the key, or from `kms_aead_key_id`.
#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: Option<String>,
    x: Option<String>,
    y: Option<String>,
    d: Option<serde::de::IgnoredAny>,
    #[serde(rename = "use")]
    key_use: Option<String>,
    key_ops: Option<Vec<String>>,
    alg: Option<String>,
    kms_aead_key_id: Option<serde_json::Value>,
}

/// A JWK Set as read: its keys, each read on its own so that an error names its position.
#[derive(Deserialize)]
struct JwkSet {
    keys: Vec<serde_json::Value>,
}

/// The public keys a verifier trusts, in insertion order, one key per key id: its trust root. A
/// key in it verifies, a key removed from it verifies nothing, whatever the KMS still holds. Every
/// key in a set is trusted alike, so keep one set per publisher.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyingKeySet {
    keys: Vec<VerifyingKey>,
}

impl VerifyingKeySet {
    /// A set of `keys`. The same key given twice is held once.
    ///
    /// # Errors
    ///
    /// `DUPLICATE_KEY_ID` when two different keys share an id.
    pub fn new(keys: impl IntoIterator<Item = VerifyingKey>) -> KmsAeadResult<Self> {
        let mut set = Self::default();
        for key in keys {
            set.insert(key)?;
        }
        Ok(set)
    }

    /// Adds `key`: `Ok(true)` when the key was not in the set, and `Ok(false)` for the same key
    /// again.
    ///
    /// # Errors
    ///
    /// `DUPLICATE_KEY_ID` for another key under an id the set holds, which leaves the set as it
    /// was.
    pub fn insert(&mut self, key: VerifyingKey) -> KmsAeadResult<bool> {
        match self.key_with_id(key.key_id) {
            Some(held) if *held == key => Ok(false),
            Some(_) => Err(KmsAeadSignatureError::create(
                "DUPLICATE_KEY_ID",
                &format!(
                    "The key set holds another key under the key id {}",
                    key.key_id.as_u32()
                ),
            )),
            None => {
                self.keys.push(key);
                Ok(true)
            }
        }
    }

    /// Removes `key`, and returns whether the set held it.
    pub fn remove(&mut self, key: &VerifyingKey) -> bool {
        let len = self.keys.len();
        self.keys.retain(|held| held != key);
        self.keys.len() != len
    }

    /// The keys, in insertion order.
    pub fn keys(&self) -> &[VerifyingKey] {
        &self.keys
    }

    /// The key with `key_id`, if any.
    pub fn key_with_id(&self, key_id: KeyId) -> Option<&VerifyingKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// The number of keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether the set holds no key.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// A JWK Set (RFC 7517) of every key, each as [`VerifyingKey::encode`] writes a JWK: the
    /// document a Rust server and a browser's `importKey("jwk")` share.
    ///
    /// # Errors
    ///
    /// `INVALID_PUBLIC_KEY` when the document cannot be written.
    pub fn to_jwks(&self) -> KmsAeadResult<String> {
        serialize_public_key_document(
            "JWK Set",
            &JwkSetMembers {
                keys: self.keys.iter().map(JwkMembers::from).collect(),
            },
        )
    }

    /// Reads a JWK Set, strictly, since the set is a trust root and an entry that cannot be used
    /// is a misconfiguration: every key is `OKP`/`Ed25519` or `EC`/`P-256` with its coordinates,
    /// `use` is `sig` or absent, `key_ops` holds `verify` or is absent, `alg` is the key's or
    /// absent, and `d` is absent. `kms_aead_key_id` is the key id the publisher set; without it
    /// the id is derived. Members the library does not know are ignored, as RFC 7517 requires,
    /// and a `kid` is not trusted.
    ///
    /// # Errors
    ///
    /// `INVALID_PUBLIC_KEY` when the document is not a JWK Set or a key breaks the rules above,
    /// and `DUPLICATE_KEY_ID` when two keys share an id. The error names the key's position,
    /// never its bytes.
    pub fn from_jwks(jwks: &str) -> KmsAeadResult<Self> {
        let set: JwkSet = serde_json::from_str(jwks).map_err(|error| {
            KmsAeadSignatureError::invalid_public_key(&format!(
                "The document is not a JWK Set: {:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        })?;
        let mut keys = Self::default();
        for (position, value) in set.keys.into_iter().enumerate() {
            let key = serde_json::from_value::<Jwk>(value)
                .map_err(|error| format!("is not a JWK: {:?} error", error.classify()))
                .and_then(VerifyingKey::from_jwk)
                .map_err(|reason| {
                    KmsAeadSignatureError::invalid_public_key(&format!(
                        "The key at position {position} of the JWK Set {reason}"
                    ))
                })?;
            keys.insert(key)?;
        }
        Ok(keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 8032 test 1 key, which is also the RFC 8037 example key.
    const ED25519_PUBLIC_KEY: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    /// The RFC 6979 A.2.5 key.
    const P256_PUBLIC_KEY: &str = "0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6\
                                   7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

    fn ed25519_verifying_key() -> VerifyingKey {
        VerifyingKey::from_bytes(
            SigningAlgorithm::Ed25519,
            &hex::decode(ED25519_PUBLIC_KEY).unwrap(),
            PublicKeyFormat::Raw,
        )
        .unwrap()
    }

    fn p256_verifying_key() -> VerifyingKey {
        VerifyingKey::from_bytes(
            SigningAlgorithm::EcdsaP256Sha256,
            &hex::decode(P256_PUBLIC_KEY).unwrap(),
            PublicKeyFormat::Raw,
        )
        .unwrap()
    }

    #[test]
    fn the_key_ids_are_the_thumbprints_of_the_test_vectors() {
        assert_eq!(
            ed25519_verifying_key().thumbprint().to_string(),
            "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
        );
        assert_eq!(ed25519_verifying_key().key_id(), KeyId::new(0x90fa_cafe));
        assert_eq!(
            p256_verifying_key().thumbprint().to_string(),
            "DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0"
        );
        assert_eq!(p256_verifying_key().key_id(), KeyId::new(0x0ceb_f1bc));
    }

    #[test]
    fn every_format_reads_back_the_same_key() -> KmsAeadResult<()> {
        for key in [
            ed25519_verifying_key(),
            p256_verifying_key(),
            ed25519_verifying_key().with_key_id(KeyId::new(7)),
        ] {
            for format in [
                PublicKeyFormat::Raw,
                PublicKeyFormat::SpkiDer,
                PublicKeyFormat::SpkiPem,
                PublicKeyFormat::Jwk,
            ] {
                let read = VerifyingKey::from_bytes(key.algorithm(), &key.encode(format)?, format)?;
                let expected = match format {
                    PublicKeyFormat::Jwk => key.clone(),
                    _ => VerifyingKey::from_raw(key.algorithm(), key.public_key().to_vec())?,
                };
                assert_eq!(read, expected, "{format:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn the_spki_der_is_the_one_of_the_test_vectors() -> KmsAeadResult<()> {
        assert_eq!(
            hex::encode(ed25519_verifying_key().encode(PublicKeyFormat::SpkiDer)?),
            format!("302a300506032b6570032100{ED25519_PUBLIC_KEY}")
        );
        assert_eq!(
            hex::encode(p256_verifying_key().encode(PublicKeyFormat::SpkiDer)?),
            format!("3059301306072a8648ce3d020106082a8648ce3d030107034200{P256_PUBLIC_KEY}")
        );
        Ok(())
    }

    #[test]
    fn an_encoding_of_another_algorithm_is_refused() -> KmsAeadResult<()> {
        for format in [
            PublicKeyFormat::SpkiDer,
            PublicKeyFormat::SpkiPem,
            PublicKeyFormat::Jwk,
        ] {
            let result = VerifyingKey::from_bytes(
                SigningAlgorithm::EcdsaP256Sha256,
                &ed25519_verifying_key().encode(format)?,
                format,
            );
            assert!(
                matches!(&result, Err(error) if error.code() == "SIGNING_ALGORITHM_MISMATCH"),
                "{format:?}: {result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_raw_key_of_another_shape_is_refused() {
        let compressed = [&[0x02][..], &[0x60; 32]].concat();
        for (algorithm, bytes) in [
            (SigningAlgorithm::Ed25519, vec![0x11; 31]),
            (SigningAlgorithm::EcdsaP256Sha256, compressed),
            (SigningAlgorithm::EcdsaP256Sha256, vec![0x05; 65]),
        ] {
            let result = VerifyingKey::from_bytes(algorithm, &bytes, PublicKeyFormat::Raw);
            assert!(
                matches!(&result, Err(error) if error.code() == "INVALID_PUBLIC_KEY"),
                "{result:?}"
            );
        }
    }

    #[test]
    fn a_jwk_set_reads_back_with_the_ids_the_publisher_set() -> KmsAeadResult<()> {
        let set = VerifyingKeySet::new([
            ed25519_verifying_key(),
            p256_verifying_key().with_key_id(KeyId::new(42)),
        ])?;

        let jwks = set.to_jwks()?;

        assert!(jwks.contains(r#""kms_aead_key_id":42"#), "{jwks}");
        assert_eq!(VerifyingKeySet::from_jwks(&jwks)?, set);
        Ok(())
    }

    #[test]
    fn the_jwk_set_is_written_as_the_book_shows_it() {
        let jwks = VerifyingKeySet::new([ed25519_verifying_key(), p256_verifying_key()])
            .unwrap()
            .to_jwks()
            .unwrap();

        assert_eq!(
            jwks,
            r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","use":"sig","alg":"EdDSA"},{"kty":"EC","crv":"P-256","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y","y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk","kid":"DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0","use":"sig","alg":"ES256"}]}"#
        );
    }

    #[test]
    fn two_keys_under_one_id_are_refused_at_new_insert_and_from_jwks() {
        let derived = ed25519_verifying_key();
        let set_to_the_same_id = p256_verifying_key().with_key_id(derived.key_id());
        fn duplicate<V>(result: KmsAeadResult<V>) -> bool {
            matches!(result, Err(error) if error.code() == "DUPLICATE_KEY_ID")
        }

        assert!(duplicate(VerifyingKeySet::new([
            derived.clone(),
            set_to_the_same_id.clone()
        ])));
        let mut set = VerifyingKeySet::new([derived.clone()]).unwrap();
        assert!(duplicate(set.insert(set_to_the_same_id.clone())));
        assert!(!set.insert(derived.clone()).unwrap());
        let jwks = format!(
            r#"{{"keys":[{},{}]}}"#,
            String::from_utf8(derived.encode(PublicKeyFormat::Jwk).unwrap()).unwrap(),
            String::from_utf8(set_to_the_same_id.encode(PublicKeyFormat::Jwk).unwrap()).unwrap()
        );
        assert!(duplicate(VerifyingKeySet::from_jwks(&jwks)));
    }

    #[test]
    fn a_jwk_set_with_a_key_it_cannot_use_is_refused() {
        let ed25519 =
            r#""kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo""#;
        for refused in [
            r#"{"kty":"RSA","n":"AQAB","e":"AQAB"}"#.to_string(),
            format!(r#"{{{ed25519},"d":"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"}}"#),
            format!(r#"{{{ed25519},"use":"enc"}}"#),
            format!(r#"{{{ed25519},"key_ops":["sign"]}}"#),
            format!(r#"{{{ed25519},"alg":"ES256"}}"#),
            format!(r#"{{{ed25519},"kms_aead_key_id":4294967296}}"#),
            format!(r#"{{{ed25519},"kms_aead_key_id":-1}}"#),
            r#"{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo="}"#
                .to_string(),
            // 32 zero bytes, a placeholder that is the order-4 point.
            r#"{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#
                .to_string(),
        ] {
            let result = VerifyingKeySet::from_jwks(&format!(r#"{{"keys":[{refused}]}}"#));
            assert!(
                matches!(&result, Err(error) if error.code() == "INVALID_PUBLIC_KEY"),
                "{refused}: {result:?}"
            );
        }
    }

    #[test]
    fn members_a_jwk_set_adds_are_ignored() -> KmsAeadResult<()> {
        let jwks = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo","kid":"anything","status":"retiring","key_ops":["verify"]}],"issuer":"orders"}"#;

        assert_eq!(
            VerifyingKeySet::from_jwks(jwks)?.keys(),
            [ed25519_verifying_key()]
        );
        Ok(())
    }
}
