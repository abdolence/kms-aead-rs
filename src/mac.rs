//! MACs: keyed hashes under a symmetric key, for integrity inside one trust domain, where every
//! verifier holds the key that computes and is trusted to compute as well. A MAC never proves
//! origin to anyone who could not have computed it; a signature does, see
//! [`signing`](crate::signing).
//!
//! An [`Authenticator`] computes and verifies a [`Mac`] or a [`WithMac`] value with a key
//! the caller holds, over the same pre-image as a signature: DSSE's Pre-Authentication
//! Encoding (PAE) of the type's [`SignedPayloadType`] and the SHA-256 of the payload.
//! kms-aead-keyring computes them under the MAC versions of a keyring.
//!
//! ```text
//! detached: [0x01][key id: u32 BE][tag: 32 or 64]
//! attached: [0x01][key id: u32 BE][w: u16 BE][tag: w][payload]
//! ```

use std::fmt::{Display, Formatter};
use std::marker::PhantomData;
use std::str::FromStr;

use subtle::ConstantTimeEq;

use crate::backends::{self, AeadBackend};
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::formats::TinkKeyType;
use crate::metrics::{self, Measurement};
use crate::signable::PreImage;
use crate::spans::{self, IntegritySpan};
use crate::types::checked_key_bytes;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KeyId, KmsAeadEncryptionProvider, KmsAeadResult,
    Signable, SignedPayloadType,
};

pub use crate::integrity::{Mac, WithMac};

/// A MAC algorithm. Tags are never truncated, and a key is as long as its tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MacAlgorithm {
    /// HMAC-SHA256 under a 32-byte key, with the full 32-byte tag.
    HmacSha256,
    /// HMAC-SHA512 under a 64-byte key, with the full 64-byte tag.
    HmacSha512,
}

impl MacAlgorithm {
    /// `mac-hmac-sha256` or `mac-hmac-sha512`: the name [`Display`] writes, the `algorithm` span
    /// field and the keyring record's name of a MAC version, distinct from the beacons'
    /// `hmac-sha256`.
    pub fn as_str(self) -> &'static str {
        match self {
            MacAlgorithm::HmacSha256 => "mac-hmac-sha256",
            MacAlgorithm::HmacSha512 => "mac-hmac-sha512",
        }
    }

    /// 32 or 64: a key is as long as its tag.
    pub fn key_len(self) -> usize {
        self.tag_len()
    }

    /// 32 or 64. Tags are never truncated.
    pub fn tag_len(self) -> usize {
        match self {
            MacAlgorithm::HmacSha256 => 32,
            MacAlgorithm::HmacSha512 => 64,
        }
    }
}

/// `mac-hmac-sha256` or `mac-hmac-sha512`.
impl Display for MacAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for MacAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "mac-hmac-sha256" => Ok(MacAlgorithm::HmacSha256),
            "mac-hmac-sha512" => Ok(MacAlgorithm::HmacSha512),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of a MAC algorithm: the names are mac-hmac-sha256 and \
                 mac-hmac-sha512",
            )),
        }
    }
}

/// Computes and verifies MACs with a key the caller holds, on the backend `B`, as
/// [`BeaconMac`](crate::BeaconMac) computes beacons. The keyring uses it for its MAC versions.
#[derive(Debug, Clone, Copy)]
pub struct Authenticator<B> {
    algorithm: MacAlgorithm,
    backend: PhantomData<B>,
}

impl<B: AeadBackend> Authenticator<B> {
    /// An authenticator for `algorithm` on the backend `B`.
    ///
    /// # Errors
    ///
    /// None today: every backend implements every [`MacAlgorithm`].
    pub fn new(algorithm: MacAlgorithm) -> KmsAeadResult<Self> {
        Ok(Self {
            algorithm,
            backend: PhantomData,
        })
    }

    /// The algorithm this authenticator computes MACs with.
    pub fn algorithm(&self) -> MacAlgorithm {
        self.algorithm
    }

    /// A random key of the algorithm's length from the backend's CSPRNG. It makes no KMS call.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn generate_dek(&self) -> KmsAeadResult<DataEncryptionKey> {
        B::generate_random_bytes(self.algorithm.key_len()).map(DataEncryptionKey::from)
    }

    /// A random key and the same key encrypted by `provider`, as
    /// [`BeaconMac::generate_encrypted_dek`](crate::BeaconMac::generate_encrypted_dek): the key
    /// comes from the KMS generator when the provider is configured to use one, and it is
    /// encrypted as a serialised Tink key with the key in field 3, as Tink's `HmacKey` holds it,
    /// so that [`DekCache::with_dek`](crate::cache::DekCache::with_dek) decrypts it.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material
    /// of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
    pub async fn generate_encrypted_dek<P: KmsAeadEncryptionProvider>(
        &self,
        provider: &P,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
        // Tink's `HmacKey` and `AesGcmKey` both hold their key in field 3, `key_value`, so a MAC
        // key serialises to the bytes of an `AesGcmKey` of its length. Field 2 of a 64-byte key
        // would be an AES-SIV key, which a deterministic version decrypts.
        crate::formats::generate_encrypted_dek::<B, P>(
            TinkKeyType::AesGcm,
            self.algorithm.key_len(),
            provider,
        )
        .await
    }

    /// The MAC of `value` under `key`, named `key_id`. The key id first and the key last, as
    /// [`AeadCipher::encrypt`](crate::AeadCipher::encrypt) and
    /// [`BeaconMac::beacon`](crate::BeaconMac::beacon) take them.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH`, `INVALID_PAYLOAD` from `to_payload`, and `MAC` when the backend
    /// fails.
    pub fn mac<T: Signable>(
        &self,
        key_id: KeyId,
        value: &T,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<Mac<T>> {
        self.measured(
            "mac",
            IntegritySpan::MacCompute,
            key_id,
            T::PAYLOAD_TYPE,
            || {
                let tag = self.tag(&value.to_payload()?, T::PAYLOAD_TYPE, key)?;
                Mac::from_tag(key_id, &tag)
            },
        )
    }

    /// [`mac`](Self::mac), joined with the payload.
    ///
    /// # Errors
    ///
    /// As [`mac`](Self::mac).
    pub fn mac_attached<T: Signable>(
        &self,
        key_id: KeyId,
        value: &T,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<WithMac<T>> {
        self.measured(
            "mac",
            IntegritySpan::MacCompute,
            key_id,
            T::PAYLOAD_TYPE,
            || {
                let payload = value.to_payload()?;
                let tag = self.tag(&payload, T::PAYLOAD_TYPE, key)?;
                WithMac::join(&Mac::from_tag(key_id, &tag)?, &payload)
            },
        )
    }

    /// Verifies `mac` for `value` under `key`, in constant time. The key id is the caller's to
    /// check: this call takes the key it is given.
    ///
    /// # Errors
    ///
    /// `MAC_INVALID` when the tag does not match or is not the algorithm's length,
    /// `INVALID_KEY_LENGTH`, and `INVALID_PAYLOAD` from `to_payload`.
    pub fn verify<T: Signable>(
        &self,
        value: &T,
        mac: &Mac<T>,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<()> {
        self.measured(
            "verify_mac",
            IntegritySpan::MacVerify,
            mac.key_id(),
            T::PAYLOAD_TYPE,
            || self.check(&value.to_payload()?, T::PAYLOAD_TYPE, mac.raw(), key),
        )
    }

    /// Verifies the payload of `with_mac` and decodes it with `from_payload`, in that order:
    /// bytes that did not verify are never parsed.
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify), and `INVALID_PAYLOAD` from `from_payload`.
    pub fn verify_with_mac<T: Signable>(
        &self,
        with_mac: &WithMac<T>,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<T> {
        self.measured(
            "verify_mac",
            IntegritySpan::MacVerify,
            with_mac.key_id(),
            T::PAYLOAD_TYPE,
            || {
                let payload = with_mac.unverified_payload();
                self.check(payload, T::PAYLOAD_TYPE, with_mac.tag(), key)?;
                T::from_payload(payload.to_vec())
            },
        )
    }

    /// Runs `operation` in the span `name` and records it as `operation_name`.
    fn measured<R>(
        &self,
        operation_name: &'static str,
        name: IntegritySpan,
        key_id: KeyId,
        payload_type: SignedPayloadType,
        operation: impl FnOnce() -> KmsAeadResult<R>,
    ) -> KmsAeadResult<R> {
        let measurement = Measurement::start(metrics::Call {
            operation: operation_name,
            mode: "caller_dek",
            backend: B::NAME,
            algorithm: Some(self.algorithm.as_str()),
        });
        let span = spans::signature(
            name,
            Some(self.algorithm.as_str()),
            B::NAME,
            key_id,
            payload_type,
        );
        let result = spans::in_scope(span, operation);
        measurement.finished(&result);
        result
    }

    /// The full tag of `payload` of `payload_type` under `key`.
    fn tag(
        &self,
        payload: &[u8],
        payload_type: SignedPayloadType,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<Vec<u8>> {
        let key = checked_key_bytes(
            key.value().ref_sensitive_value(),
            self.algorithm,
            self.algorithm.key_len(),
        )?;
        let pre_image = PreImage::new(payload_type, &backends::sha256::<B>(payload)?);
        match self.algorithm {
            MacAlgorithm::HmacSha256 => B::hmac_sha256(key, pre_image.as_bytes()).map(Vec::from),
            MacAlgorithm::HmacSha512 => {
                let mut tag: backends::HmacSha512 = [0; 64];
                B::hmac_sha512(key, &[pre_image.as_bytes()], &mut tag).map(|()| tag.to_vec())
            }
        }
        .map_err(|_| KmsAeadEncryptionError::create("MAC", "Unable to calculate the MAC"))
    }

    /// Whether `tag` is the tag of `payload` under `key`, compared in constant time.
    fn check(
        &self,
        payload: &[u8],
        payload_type: SignedPayloadType,
        tag: &[u8],
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<()> {
        let expected = self.tag(payload, payload_type, key)?;
        if tag.len() == expected.len() && bool::from(tag.ct_eq(&expected)) {
            Ok(())
        } else {
            Err(KmsAeadEncryptionError::create(
                "MAC_INVALID",
                &format!(
                    "The tag of {} bytes is not the {} tag of the payload under the key",
                    tag.len(),
                    self.algorithm
                ),
            ))
        }
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::test_provider::{
        error_code_of, Invoice, TestBackend, INVOICE_PAYLOAD, OTHER_INVOICE_PAYLOAD,
    };

    const KEY_ID: KeyId = KeyId::new(3_221_225_473);

    #[test]
    fn a_tag_that_does_not_match_or_has_another_length_is_refused() -> KmsAeadResult<()> {
        let sha256 = Authenticator::<TestBackend>::new(MacAlgorithm::HmacSha256)?;
        let sha512 = Authenticator::<TestBackend>::new(MacAlgorithm::HmacSha512)?;
        let key_32 = DataEncryptionKey::from(secret_vault_value::SecretValue::new(vec![0x42; 32]));
        let key_64 = DataEncryptionKey::from(secret_vault_value::SecretValue::new(vec![0x42; 64]));
        let invoice = Invoice(INVOICE_PAYLOAD.to_vec());
        let mac = sha256.mac(KEY_ID, &invoice, &key_32)?;
        let long_tag = sha512.mac(KEY_ID, &invoice, &key_64)?;

        assert_eq!(
            error_code_of(sha256.verify(&Invoice(OTHER_INVOICE_PAYLOAD.to_vec()), &mac, &key_32)),
            "MAC_INVALID"
        );
        assert_eq!(
            error_code_of(sha256.verify(&invoice, &long_tag, &key_32)),
            "MAC_INVALID"
        );
        assert_eq!(
            error_code_of(sha256.mac(KEY_ID, &invoice, &key_64)),
            "INVALID_KEY_LENGTH"
        );
        Ok(())
    }

    #[test]
    fn every_name_parses_back_and_another_name_is_refused() {
        for algorithm in [MacAlgorithm::HmacSha256, MacAlgorithm::HmacSha512] {
            assert_eq!(
                algorithm.as_str().parse::<MacAlgorithm>().ok(),
                Some(algorithm)
            );
        }
        let beacon = "hmac-sha256".parse::<MacAlgorithm>();
        assert!(
            matches!(&beacon, Err(error) if error.code() == "UNKNOWN_ALGORITHM"),
            "{beacon:?}"
        );
    }
}
