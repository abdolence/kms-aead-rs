use std::fmt::{Display, Formatter};

use base64ct::{Base64UrlUnpadded, Encoding};
use der::asn1::{BitStringRef, UintRef};
use der::{AnyRef, Decode, Encode, Sequence};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::{AlgorithmIdentifierRef, ObjectIdentifier, SubjectPublicKeyInfoRef};

use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::formats::PublicKeyFormat;
use crate::providers::{KmsKeyVersion, LocalKekId};
use crate::{AsymmetricKekAlgorithm, KekRef, KmsAeadResult, KmsProvider};

/// `rsaEncryption` of RFC 8017, the algorithm of an RSA SubjectPublicKeyInfo and PKCS#8 key.
pub(crate) const RSA_ENCRYPTION: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");

/// The modulus lengths of the RSA keys an asymmetric KEK takes, in bits: the key sizes every KMS
/// offers for RSA-OAEP. Each gives a block of a length the encrypted DEK's header check takes.
pub(crate) const ASYMMETRIC_KEK_RSA_BITS: [usize; 3] = [2048, 3072, 4096];

/// The `RSAPublicKey` of RFC 8017, appendix A.1.1, inside an RSA SubjectPublicKeyInfo.
#[derive(Sequence)]
struct RsaPublicKeyComponents<'a> {
    modulus: UintRef<'a>,
    public_exponent: UintRef<'a>,
}

impl RsaPublicKeyComponents<'_> {
    /// The length of the modulus in bits.
    fn modulus_bits(&self) -> usize {
        let modulus = self.modulus.as_bytes();
        modulus.first().map_or(0, |first| {
            modulus.len() * 8 - usize::try_from(first.leading_zeros()).unwrap_or(8)
        })
    }
}

/// The public half of an asymmetric KEK, with what a reader needs to decrypt what it encrypts:
/// the KEK, the KEK version where the KMS decrypts with one, and the algorithm. The key is held as
/// a SubjectPublicKeyInfo in DER, an RSA key of 2048, 3072 or 4096 bits; 2048 bits is deprecated
/// and stays for the keys that exist. It is read and written in a named [`PublicKeyFormat`]:
/// [`SpkiDer`](PublicKeyFormat::SpkiDer), [`SpkiPem`](PublicKeyFormat::SpkiPem) and
/// [`Jwk`](PublicKeyFormat::Jwk), and never [`Raw`](PublicKeyFormat::Raw).
///
/// A producer pins it in its configuration: a producer that takes a public key from an
/// unauthenticated place encrypts for whoever supplied it. [`to_json`](Self::to_json) and
/// [`try_from_json`](Self::try_from_json), and serde, read and write the document
///
/// ```json
/// {"kek": {"provider": "gcp", "key": "projects/…/cryptoKeys/k"}, "kek_version": "3",
///  "algorithm": "rsa-oaep-sha256", "public_key": "-----BEGIN PUBLIC KEY-----\n…"}
/// ```
///
/// with the key as [`SpkiPem`](PublicKeyFormat::SpkiPem), and `kek_version` absent for an AWS KEK.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "PublicKeyDocument")]
pub struct AsymmetricKekPublicKey {
    kek: KekRef,
    kek_version: Option<KmsKeyVersion>,
    algorithm: AsymmetricKekAlgorithm,
    spki_der: Vec<u8>,
}

impl AsymmetricKekPublicKey {
    /// The key `bytes` in `format`: the DER of [`SpkiDer`](PublicKeyFormat::SpkiDer), the text of
    /// [`SpkiPem`](PublicKeyFormat::SpkiPem), or the JSON of a [`Jwk`](PublicKeyFormat::Jwk) with
    /// `kty` `RSA`, `n` and `e`. The format is never guessed from the bytes.
    ///
    /// The KEK version is the one the reader names to its KMS: `None` for an AWS KEK, which has
    /// no versions, and the version for a GCP, Azure, Vault Transit or local KEK, whose readers
    /// decrypt with a named one; a local KEK's version is its decimal [`LocalKekVersion`]. Either
    /// form is taken for [`KmsProvider::Other`], whose rule is the application's provider's.
    ///
    /// [`LocalKekVersion`]: crate::providers::LocalKekVersion
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` when `bytes` are not in `format`, when `format` is `Raw`, which
    /// an RSA key has no meaning in, when the key is not an RSA key of 2048, 3072 or 4096 bits,
    /// when `kek_version` is `None` for a GCP, Azure, Vault Transit or local KEK, `Some` for an AWS
    /// KEK, or not a local version for a local KEK, and when a local KEK's key is not a
    /// [`LocalKekId`]. The backend of the provider built from the key parses the RSA key itself.
    pub fn new(
        kek: KekRef,
        kek_version: Option<KmsKeyVersion>,
        algorithm: AsymmetricKekAlgorithm,
        bytes: Vec<u8>,
        format: PublicKeyFormat,
    ) -> KmsAeadResult<Self> {
        let spki_der = match format {
            PublicKeyFormat::SpkiDer => bytes,
            PublicKeyFormat::SpkiPem => {
                PublicKeyFormat::spki_der_of_pem(&bytes).map_err(|reason| {
                    KmsAeadSystemError::asymmetric_public_key(&format!("The public key {reason}"))
                })?
            }
            PublicKeyFormat::Jwk => RsaJwk::spki_der(&bytes)?,
            PublicKeyFormat::Raw => {
                return Err(KmsAeadSystemError::asymmetric_public_key(
                    "An RSA public key has no raw form: give it as SpkiDer, SpkiPem or Jwk",
                ))
            }
        };
        let key = Self {
            kek,
            kek_version,
            algorithm,
            spki_der,
        };
        key.rsa_components()?;
        key.check_kek_version()?;
        Ok(key)
    }

    /// The key from the big-endian `modulus` and `public_exponent` of an RSA key, as Key Vault's
    /// JSON Web Key carries them.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    #[cfg(feature = "azure-kms-encryption-base")]
    pub(crate) fn from_rsa_components(
        kek: KekRef,
        kek_version: Option<KmsKeyVersion>,
        algorithm: AsymmetricKekAlgorithm,
        modulus: &[u8],
        public_exponent: &[u8],
    ) -> KmsAeadResult<Self> {
        Self::new(
            kek,
            kek_version,
            algorithm,
            rsa_spki_der(modulus, public_exponent)?,
            PublicKeyFormat::SpkiDer,
        )
    }

    /// The length in bytes of an RSA block under this key, which is its modulus.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` when the key is not an RSA key of an accepted size, which
    /// [`new`](Self::new) already refuses.
    pub(crate) fn rsa_block_len(&self) -> KmsAeadResult<usize> {
        Ok(self.rsa_components()?.modulus.as_bytes().len())
    }

    /// The modulus and the exponent of the SubjectPublicKeyInfo, which must be an RSA key of one
    /// of [`ASYMMETRIC_KEK_RSA_BITS`].
    fn rsa_components(&self) -> KmsAeadResult<RsaPublicKeyComponents<'_>> {
        let spki = SubjectPublicKeyInfoRef::from_der(&self.spki_der).map_err(|error| {
            KmsAeadSystemError::asymmetric_public_key(&format!(
                "The public key is not a DER SubjectPublicKeyInfo: {}",
                error.kind()
            ))
        })?;
        if spki.algorithm.oid != RSA_ENCRYPTION
            || spki
                .algorithm
                .parameters
                .is_some_and(|parameters| !parameters.is_null())
        {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The SubjectPublicKeyInfo is not an rsaEncryption key",
            ));
        }
        let components = spki
            .subject_public_key
            .as_bytes()
            .and_then(|bytes| RsaPublicKeyComponents::from_der(bytes).ok())
            .ok_or_else(|| {
                KmsAeadSystemError::asymmetric_public_key(
                    "The SubjectPublicKeyInfo holds no RSAPublicKey",
                )
            })?;
        let bits = components.modulus_bits();
        if !ASYMMETRIC_KEK_RSA_BITS.contains(&bits) {
            return Err(KmsAeadSystemError::asymmetric_public_key(&format!(
                "The public key is an RSA key of {bits} bits, not of 2048, 3072 or 4096"
            )));
        }
        Ok(components)
    }

    /// Whether the KEK version is what a reader of the KEK's KMS names to decrypt.
    fn check_kek_version(&self) -> KmsAeadResult<()> {
        let refused = match (self.kek.provider(), &self.kek_version) {
            (KmsProvider::Aws, Some(_)) => Some("An AWS KMS key has no versions"),
            (
                KmsProvider::Gcp
                | KmsProvider::Azure
                | KmsProvider::HcVaultTransit
                | KmsProvider::Local,
                None,
            ) => Some("The KMS of the KEK decrypts with a named version, and none is given"),
            (KmsProvider::Local, Some(version)) if version.local_kek_version().is_none() => {
                Some("A local KEK's version is a positive decimal number")
            }
            (KmsProvider::Local, Some(_))
                if LocalKekId::try_from(self.kek.key().to_string()).is_err() =>
            {
                Some("The key of a local KEK is not a local KEK id")
            }
            _ => None,
        };
        match refused {
            Some(reason) => Err(KmsAeadSystemError::asymmetric_public_key(&format!(
                "{reason}: the public key of {}",
                self.kek
            ))),
            None => Ok(()),
        }
    }

    /// The key in `format`: the DER for [`SpkiDer`](PublicKeyFormat::SpkiDer), a `PUBLIC KEY` PEM
    /// block for [`SpkiPem`](PublicKeyFormat::SpkiPem), or `{"kty":"RSA","n":"…","e":"…"}` for
    /// [`Jwk`](PublicKeyFormat::Jwk). Text formats are UTF-8 bytes.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` for [`Raw`](PublicKeyFormat::Raw).
    pub fn encode(&self, format: PublicKeyFormat) -> KmsAeadResult<Vec<u8>> {
        match format {
            PublicKeyFormat::SpkiDer => Ok(self.spki_der.clone()),
            PublicKeyFormat::SpkiPem => Ok(self.to_pem()?.into_bytes()),
            PublicKeyFormat::Jwk => {
                let components = self.rsa_components()?;
                let jwk = RsaJwkMembers {
                    kty: "RSA",
                    n: Base64UrlUnpadded::encode_string(components.modulus.as_bytes()),
                    e: Base64UrlUnpadded::encode_string(components.public_exponent.as_bytes()),
                };
                serde_json::to_vec(&jwk).map_err(|_| {
                    KmsAeadSystemError::asymmetric_public_key("Unable to write the JWK")
                })
            }
            PublicKeyFormat::Raw => Err(KmsAeadSystemError::asymmetric_public_key(
                "An RSA public key has no raw form: write it as SpkiDer, SpkiPem or Jwk",
            )),
        }
    }

    fn to_pem(&self) -> KmsAeadResult<String> {
        pem_rfc7468::encode_string(
            PublicKeyFormat::PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            &self.spki_der,
        )
        .map_err(|error| {
            KmsAeadSystemError::asymmetric_public_key(&format!("Unable to write the PEM: {error}"))
        })
    }

    /// The JSON document of the type docs.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` when the document cannot be written.
    pub fn to_json(&self) -> KmsAeadResult<String> {
        serde_json::to_string(self).map_err(|_| {
            KmsAeadSystemError::asymmetric_public_key("Unable to write the public key document")
        })
    }

    /// Reads the document [`to_json`](Self::to_json) writes.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` when `json` is not the document, with serde_json's category and
    /// position and never its message, which quotes the input; the errors of
    /// [`new`](Self::new) for a document that holds no valid key; `UNKNOWN_ALGORITHM` for another
    /// algorithm and `INVALID_KEY_VERSION` for a version of another form.
    pub fn try_from_json(json: &str) -> KmsAeadResult<Self> {
        let document: PublicKeyDocument = serde_json::from_str(json).map_err(|error| {
            KmsAeadSystemError::asymmetric_public_key(&format!(
                "The public key document is not JSON of its form: {:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        })?;
        Self::try_from(document)
    }

    /// The KEK the key encrypts for.
    pub fn kek(&self) -> &KekRef {
        &self.kek
    }

    /// The KEK version the reader names to its KMS, `None` under AWS KMS.
    pub fn kek_version(&self) -> Option<&KmsKeyVersion> {
        self.kek_version.as_ref()
    }

    /// The algorithm the key encrypts with.
    pub fn algorithm(&self) -> AsymmetricKekAlgorithm {
        self.algorithm
    }

    /// The SubjectPublicKeyInfo in DER.
    pub fn spki_der(&self) -> &[u8] {
        &self.spki_der
    }

    /// The SHA-256 of the SubjectPublicKeyInfo, the value that
    /// [`PublicKeyKekProvider::pinned`](crate::providers::PublicKeyKekProvider::pinned) compares.
    /// An operator who holds the key, as PEM or JSON, computes it here and writes it into the
    /// producer's configuration, from a copy of the key that the producer's own source does not
    /// supply.
    pub fn fingerprint(&self) -> AsymmetricKekFingerprint {
        AsymmetricKekFingerprint(Sha256::digest(&self.spki_der).into())
    }
}

/// The SubjectPublicKeyInfo DER of the RSA key of `modulus` and `public_exponent`, big-endian.
fn rsa_spki_der(modulus: &[u8], public_exponent: &[u8]) -> KmsAeadResult<Vec<u8>> {
    let unwritable = |error: der::Error| {
        KmsAeadSystemError::asymmetric_public_key(&format!(
            "Unable to write the RSA SubjectPublicKeyInfo: {}",
            error.kind()
        ))
    };
    let rsa_public_key = RsaPublicKeyComponents {
        modulus: UintRef::new(modulus).map_err(unwritable)?,
        public_exponent: UintRef::new(public_exponent).map_err(unwritable)?,
    }
    .to_der()
    .map_err(unwritable)?;
    SubjectPublicKeyInfoRef {
        algorithm: AlgorithmIdentifierRef {
            oid: RSA_ENCRYPTION,
            parameters: Some(AnyRef::NULL),
        },
        subject_public_key: BitStringRef::from_bytes(&rsa_public_key).map_err(unwritable)?,
    }
    .to_der()
    .map_err(unwritable)
}

/// An RSA JSON Web Key as read: the members the library knows, every other one ignored as RFC 7517
/// requires.
#[derive(Deserialize)]
struct RsaJwk {
    kty: String,
    n: Option<String>,
    e: Option<String>,
    d: Option<serde::de::IgnoredAny>,
}

impl RsaJwk {
    /// The SubjectPublicKeyInfo DER of the RSA JWK in `json`.
    fn spki_der(json: &[u8]) -> KmsAeadResult<Vec<u8>> {
        let jwk: RsaJwk = serde_json::from_slice(json).map_err(|error| {
            KmsAeadSystemError::asymmetric_public_key(&format!(
                "The public key is not a JWK: {:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        })?;
        if jwk.kty != "RSA" {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The JWK is not an RSA key",
            ));
        }
        if jwk.d.is_some() {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The JWK carries the private member d",
            ));
        }
        let member = |value: Option<&str>, name: &str| {
            value
                .and_then(|value| Base64UrlUnpadded::decode_vec(value).ok())
                .ok_or_else(|| {
                    KmsAeadSystemError::asymmetric_public_key(&format!(
                        "The JWK has no {name} in base64url without padding"
                    ))
                })
        };
        rsa_spki_der(
            &member(jwk.n.as_deref(), "n")?,
            &member(jwk.e.as_deref(), "e")?,
        )
    }
}

/// An RSA JSON Web Key as written.
#[derive(Serialize)]
struct RsaJwkMembers {
    kty: &'static str,
    n: String,
    e: String,
}

/// The JSON document of an [`AsymmetricKekPublicKey`], its key as PEM.
#[derive(Serialize, Deserialize)]
struct PublicKeyDocument {
    kek: KekRef,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kek_version: Option<String>,
    algorithm: String,
    public_key: String,
}

impl TryFrom<&AsymmetricKekPublicKey> for PublicKeyDocument {
    type Error = KmsAeadError;

    fn try_from(key: &AsymmetricKekPublicKey) -> KmsAeadResult<Self> {
        Ok(Self {
            kek: key.kek.clone(),
            kek_version: key.kek_version.as_ref().map(KmsKeyVersion::to_string),
            algorithm: key.algorithm.to_string(),
            public_key: key.to_pem()?,
        })
    }
}

/// Writes the document of the type docs, as [`to_json`](AsymmetricKekPublicKey::to_json) does.
impl Serialize for AsymmetricKekPublicKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        PublicKeyDocument::try_from(self)
            .map_err(serde::ser::Error::custom)?
            .serialize(serializer)
    }
}

impl TryFrom<PublicKeyDocument> for AsymmetricKekPublicKey {
    type Error = KmsAeadError;

    fn try_from(document: PublicKeyDocument) -> KmsAeadResult<Self> {
        Self::new(
            document.kek,
            document
                .kek_version
                .map(KmsKeyVersion::try_from)
                .transpose()?,
            document.algorithm.parse()?,
            document.public_key.into_bytes(),
            PublicKeyFormat::SpkiPem,
        )
    }
}

/// The SHA-256 of a public key's SubjectPublicKeyInfo DER, for comparing a producer's key with
/// the administration's. `Display` writes 64 lowercase hex digits, as the providers log it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AsymmetricKekFingerprint([u8; 32]);

impl AsymmetricKekFingerprint {
    /// The digest.
    pub fn value(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for AsymmetricKekFingerprint {
    fn from(digest: [u8; 32]) -> Self {
        Self(digest)
    }
}

/// 64 lowercase hex digits.
impl Display for AsymmetricKekFingerprint {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

/// Reads the hex `Display` writes, in either case.
///
/// # Errors
///
/// `INVALID_HEX` when `value` is not the hex of 32 bytes.
impl TryFrom<String> for AsymmetricKekFingerprint {
    type Error = KmsAeadError;

    fn try_from(value: String) -> KmsAeadResult<Self> {
        let mut digest = [0; 32];
        hex::decode_to_slice(&value, &mut digest)
            .map_err(|error| KmsAeadEncryptionError::invalid_hex("The fingerprint", error))?;
        Ok(Self(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_provider::{assert_code, RsaOaepSuite};

    const CRYPTO_KEY: &str = "projects/orders/locations/europe-north1/keyRings/r/cryptoKeys/k";

    fn gcp_kek() -> KekRef {
        KekRef::new(KmsProvider::Gcp, CRYPTO_KEY)
    }

    fn kms_key_version(version: &str) -> Option<KmsKeyVersion> {
        Some(KmsKeyVersion::try_from(version.to_string()).unwrap())
    }

    /// The public key of the Wycheproof 2048-bit key under the Cloud KMS KEK, version 3.
    fn gcp_public_key() -> KmsAeadResult<AsymmetricKekPublicKey> {
        AsymmetricKekPublicKey::new(
            gcp_kek(),
            kms_key_version("3"),
            AsymmetricKekAlgorithm::RsaOaepSha256,
            RsaOaepSuite::of_bits(2048).public_jwk(),
            PublicKeyFormat::Jwk,
        )
    }

    #[test]
    fn a_key_reads_back_in_every_format_an_rsa_key_has() -> KmsAeadResult<()> {
        let key = gcp_public_key()?;

        for format in [
            PublicKeyFormat::SpkiDer,
            PublicKeyFormat::SpkiPem,
            PublicKeyFormat::Jwk,
        ] {
            let read_back = AsymmetricKekPublicKey::new(
                gcp_kek(),
                kms_key_version("3"),
                AsymmetricKekAlgorithm::RsaOaepSha256,
                key.encode(format)?,
                format,
            )?;
            assert_eq!(read_back, key, "{format:?}");
        }
        assert_eq!(
            key.encode(PublicKeyFormat::Jwk)?,
            RsaOaepSuite::of_bits(2048).public_jwk()
        );
        assert_code(
            key.encode(PublicKeyFormat::Raw),
            "ASYMMETRIC_KEK_PUBLIC_KEY",
        );
        assert_code(
            AsymmetricKekPublicKey::new(
                gcp_kek(),
                kms_key_version("3"),
                AsymmetricKekAlgorithm::RsaOaepSha256,
                key.spki_der().to_vec(),
                PublicKeyFormat::Raw,
            ),
            "ASYMMETRIC_KEK_PUBLIC_KEY",
        );
        Ok(())
    }

    /// The framing writes the SubjectPublicKeyInfo the backends write for the same key.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[test]
    fn the_spki_of_a_jwk_is_the_one_the_backend_derives_from_the_private_key() -> KmsAeadResult<()>
    {
        use crate::backends::AeadBackendOps;
        use crate::test_provider::RsaTestBackend;
        let private_key = RsaTestBackend::rsa_private_key(
            RsaOaepSuite::of_bits(2048)
                .pkcs8_der()
                .ref_sensitive_value(),
        )
        .unwrap();

        assert_eq!(
            gcp_public_key()?.spki_der(),
            RsaTestBackend::rsa_public_key_der(&private_key).unwrap()
        );
        Ok(())
    }

    #[test]
    fn a_key_of_another_size_or_kind_is_refused() {
        let jwk = |n: &[u8], extra: &str| {
            format!(
                r#"{{"kty":"RSA","n":"{}","e":"AQAB"{extra}}}"#,
                Base64UrlUnpadded::encode_string(n)
            )
            .into_bytes()
        };
        let mut modulus_1024 = vec![0xC5; 128];
        modulus_1024[127] = 0x01;
        let refused = [
            (jwk(&modulus_1024, ""), PublicKeyFormat::Jwk),
            (jwk(&[0xC5; 256], r#","d":"AQAB""#), PublicKeyFormat::Jwk),
            (
                br#"{"kty":"EC","crv":"P-256","x":"AQAB","y":"AQAB"}"#.to_vec(),
                PublicKeyFormat::Jwk,
            ),
            (vec![0x30, 0x03, 0x02, 0x01, 0x01], PublicKeyFormat::SpkiDer),
            (b"not PEM".to_vec(), PublicKeyFormat::SpkiPem),
        ];
        for (bytes, format) in refused {
            assert_code(
                AsymmetricKekPublicKey::new(
                    gcp_kek(),
                    kms_key_version("3"),
                    AsymmetricKekAlgorithm::RsaOaepSha256,
                    bytes,
                    format,
                ),
                "ASYMMETRIC_KEK_PUBLIC_KEY",
            );
        }
    }

    /// A version where the reader's KMS names one, none under AWS KMS, a decimal local version,
    /// and either form for an application's own KMS.
    #[test]
    fn the_kek_version_is_the_one_the_reader_names() -> KmsAeadResult<()> {
        let spki_der = gcp_public_key()?.spki_der().to_vec();
        let key = |provider, kek: &str, kek_version: Option<KmsKeyVersion>| {
            AsymmetricKekPublicKey::new(
                KekRef::new(provider, kek),
                kek_version,
                AsymmetricKekAlgorithm::RsaOaepSha256,
                spki_der.clone(),
                PublicKeyFormat::SpkiDer,
            )
        };
        let aws = "arn:aws:kms:eu-north-1:111122223333:key/1234abcd";
        let azure = "https://orders.vault.azure.net/keys/orders";
        let other = || KmsProvider::Other("orders-hsm".to_string());

        key(KmsProvider::Aws, aws, None)?;
        key(KmsProvider::Local, "orders", kms_key_version("7"))?;
        key(other(), "orders", None)?;
        key(other(), "orders", kms_key_version("7"))?;
        for (provider, kek, kek_version) in [
            (KmsProvider::Aws, aws, kms_key_version("1")),
            (KmsProvider::Gcp, CRYPTO_KEY, None),
            (KmsProvider::Azure, azure, None),
            (KmsProvider::Local, "orders", kms_key_version("07")),
            (KmsProvider::Local, "orders/eu", kms_key_version("7")),
        ] {
            assert_code(key(provider, kek, kek_version), "ASYMMETRIC_KEK_PUBLIC_KEY");
        }
        Ok(())
    }

    #[test]
    fn the_document_holds_the_key_as_pem_and_reads_back() -> KmsAeadResult<()> {
        let key = gcp_public_key()?;

        let json = key.to_json()?;
        let document: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(
            document,
            serde_json::json!({
                "kek": {"provider": "gcp", "key": CRYPTO_KEY},
                "kek_version": "3",
                "algorithm": "rsa-oaep-sha256",
                "public_key": String::from_utf8(key.encode(PublicKeyFormat::SpkiPem)?).unwrap(),
            })
        );
        assert_eq!(AsymmetricKekPublicKey::try_from_json(&json)?, key);
        assert_eq!(
            serde_json::from_value::<AsymmetricKekPublicKey>(document).unwrap(),
            key
        );
        Ok(())
    }

    #[test]
    fn a_document_of_another_form_or_key_is_refused() -> KmsAeadResult<()> {
        let json = gcp_public_key()?.to_json()?;

        assert_code(
            AsymmetricKekPublicKey::try_from_json(&json.replace("rsa-oaep-sha256", "rsa-pss")),
            "UNKNOWN_ALGORITHM",
        );
        assert_code(
            AsymmetricKekPublicKey::try_from_json(&json.replace(r#""kek_version":"3","#, "")),
            "ASYMMETRIC_KEK_PUBLIC_KEY",
        );
        assert_code(
            AsymmetricKekPublicKey::try_from_json("{\"kek\": 1}"),
            "ASYMMETRIC_KEK_PUBLIC_KEY",
        );
        Ok(())
    }

    #[test]
    fn a_fingerprint_reads_back_from_its_hex() -> KmsAeadResult<()> {
        let fingerprint = gcp_public_key()?.fingerprint();

        let hex = fingerprint.to_string();

        assert_eq!(hex.len(), 64);
        assert_eq!(
            AsymmetricKekFingerprint::try_from(hex.to_uppercase())?,
            fingerprint
        );
        for invalid in [&hex[..62], "zz", ""] {
            assert_code(
                AsymmetricKekFingerprint::try_from(invalid.to_string()),
                "INVALID_HEX",
            );
        }
        Ok(())
    }
}
