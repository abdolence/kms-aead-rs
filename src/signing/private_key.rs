use der::asn1::OctetStringRef;
use der::Decode;
use pkcs8::PrivateKeyInfoRef;
use sec1::{EcParameters, EcPrivateKey};
use secret_vault_value::SecretValue;

use super::verifying_key::{ID_EC_PUBLIC_KEY, ID_ED25519, PRIME256V1};
use super::SigningAlgorithm;

/// The length of an Ed25519 seed and of a P-256 scalar.
const RAW_PRIVATE_KEY_LEN: usize = 32;

/// A private signing key read from a PKCS#8 `PrivateKeyInfo`: the Ed25519 seed or the P-256
/// scalar, zeroised on drop, and the raw public key where the document carries it. P-256 keys
/// always carry it; an Ed25519 key carries it only in a PKCS#8 v2 document.
pub(crate) struct Pkcs8SigningKey {
    pub(crate) algorithm: SigningAlgorithm,
    pub(crate) private_key: SecretValue,
    pub(crate) public_key: Option<Vec<u8>>,
}

impl Pkcs8SigningKey {
    /// The key `der` holds, parsed with the `pkcs8` and `sec1` crates, or why it holds none, to
    /// follow "The PKCS#8 key" in an error. An `id-Ed25519` key is the 32-byte seed, and an
    /// `id-ecPublicKey` key on `prime256v1` the 32-byte scalar with its public point.
    pub(crate) fn from_der(der: &[u8]) -> Result<Self, &'static str> {
        let info = PrivateKeyInfoRef::from_der(der)
            .map_err(|_| "is not a DER PKCS#8 PrivateKeyInfo, or is encrypted")?;
        match info.algorithm.oids() {
            Ok((ID_ED25519, None)) => {
                let seed = <&OctetStringRef>::from_der(info.private_key.as_bytes())
                    .map_err(|_| "holds no Ed25519 CurvePrivateKey")?
                    .as_bytes();
                if seed.len() != RAW_PRIVATE_KEY_LEN {
                    return Err("holds an Ed25519 seed of another length than 32 bytes");
                }
                let public_key = match info.public_key {
                    Some(public_key) => Some(
                        public_key
                            .as_bytes()
                            .ok_or("holds a public key with unused bits")?
                            .to_vec(),
                    ),
                    None => None,
                };
                Ok(Self {
                    algorithm: SigningAlgorithm::Ed25519,
                    private_key: SecretValue::new(seed.to_vec()),
                    public_key,
                })
            }
            Ok((ID_EC_PUBLIC_KEY, Some(PRIME256V1))) => {
                let key = EcPrivateKey::from_der(info.private_key.as_bytes())
                    .map_err(|_| "holds no SEC1 ECPrivateKey")?;
                if key
                    .parameters
                    .is_some_and(|parameters| parameters != EcParameters::NamedCurve(PRIME256V1))
                {
                    return Err("holds an ECPrivateKey of another curve than P-256");
                }
                if key.private_key.len() != RAW_PRIVATE_KEY_LEN {
                    return Err("holds a P-256 scalar of another length than 32 bytes");
                }
                let public_key = key
                    .public_key
                    .ok_or("holds a P-256 key without its public point")?;
                Ok(Self {
                    algorithm: SigningAlgorithm::EcdsaP256Sha256,
                    private_key: SecretValue::new(key.private_key.to_vec()),
                    public_key: Some(public_key.to_vec()),
                })
            }
            _ => Err("is not an id-Ed25519 key or an id-ecPublicKey key on prime256v1"),
        }
    }
}
