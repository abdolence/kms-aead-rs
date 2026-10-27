use std::fmt::{Display, Formatter};

use crate::backends::Sha256Digest;
use crate::errors::KmsAeadEncryptionError;
use crate::redaction::JsonRedaction;
use crate::{JsonEncoded, KmsAeadResult};

/// The payload type bound into every signature and MAC of a [`Signable`] type: 1 to 255 bytes of
/// visible ASCII, `0x21` to `0x7E`, such as `application/vnd.example.invoice+json` or
/// `example.com/orders/v1`. It is the `type` of DSSE's Pre-Authentication Encoding (PAE), so a
/// signature over one kind of document never verifies as another kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SignedPayloadType(&'static str);

impl SignedPayloadType {
    /// The longest payload type, so that the pre-image stays within 302 bytes.
    const MAX_LEN: usize = 255;

    /// `payload_type` as a payload type, for the `PAYLOAD_TYPE` constant of a
    /// [`SignableType`].
    ///
    /// # Panics
    ///
    /// When `payload_type` is empty, longer than 255 bytes, or holds a byte outside `0x21` to
    /// `0x7E`. Evaluated in a `const`, as a `PAYLOAD_TYPE` is, that fails the build.
    pub const fn from_static(payload_type: &'static str) -> Self {
        match Self::checked(payload_type) {
            Some(checked) => checked,
            None => panic!("a payload type is 1 to 255 bytes of visible ASCII, 0x21 to 0x7E"),
        }
    }

    /// `payload_type` when it follows the rule of [`from_static`](Self::from_static).
    const fn checked(payload_type: &'static str) -> Option<Self> {
        let bytes = payload_type.as_bytes();
        if bytes.is_empty() || bytes.len() > Self::MAX_LEN {
            return None;
        }
        let mut index = 0;
        while index < bytes.len() {
            if !matches!(bytes[index], 0x21..=0x7E) {
                return None;
            }
            index += 1;
        }
        Some(Self(payload_type))
    }

    /// The payload type as the pre-image carries it.
    pub fn as_str(&self) -> &str {
        self.0
    }
}

/// The payload type as written.
impl Display for SignedPayloadType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}

/// A type with a payload type: enough to sign or verify the SHA-256 of a payload of it, for a
/// caller that holds the digest and not the bytes, through
/// [`Signer::sign_digest`](crate::signing::Signer::sign_digest) and
/// [`Verifier::verify_digest`](crate::signing::Verifier::verify_digest).
pub trait SignableType {
    /// The payload type of every value of this type, in the pre-image of every signature and
    /// MAC.
    const PAYLOAD_TYPE: SignedPayloadType;
}

/// A type that is signed or authenticated: its payload type and the bytes that stand for a value.
/// The library signs the SHA-256 of [`to_payload`](Self::to_payload) and parses nothing of it, so
/// an application that may serialise a document again later canonicalises it, for example with
/// RFC 8785, before it returns the bytes.
///
/// A serde type implements [`SignableType`] to name its payload type and is wrapped in
/// [`JsonEncoded`], which implements `Signable` with the compact JSON of the value as the payload.
/// The wrapper at the call site and the outer type, such as [`Signature`](crate::signing::Signature)
/// or [`Mac`](crate::mac::Mac), say what the bytes are for.
///
/// ```rust
/// use kms_aead::{JsonEncoded, SignableType, SignedPayloadType};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct Invoice {
///     number: String,
///     customer: String,
///     currency: String,
///     total_cents: u64,
/// }
///
/// impl SignableType for Invoice {
///     const PAYLOAD_TYPE: SignedPayloadType =
///         SignedPayloadType::from_static("application/vnd.example.invoice+json");
/// }
///
/// // `signer.sign(&JsonEncoded::new(invoice))` signs the invoice, and `verify_signed` returns a
/// // `JsonEncoded<Invoice>`.
/// ```
///
/// Another encoding implements `Signable` itself. This statement is signed as the UTF-8 bytes of
/// its text:
///
/// ```rust
/// use kms_aead::errors::KmsAeadEncryptionError;
/// use kms_aead::{KmsAeadResult, Signable, SignableType, SignedPayloadType};
///
/// struct Statement(String);
///
/// impl SignableType for Statement {
///     const PAYLOAD_TYPE: SignedPayloadType =
///         SignedPayloadType::from_static("text/vnd.example.statement");
/// }
///
/// impl Signable for Statement {
///     fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
///         Ok(self.0.clone().into_bytes())
///     }
///
///     fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
///         String::from_utf8(payload).map(Statement).map_err(|_| {
///             KmsAeadEncryptionError::create("INVALID_PAYLOAD", "The payload is not UTF-8 text")
///         })
///     }
/// }
/// ```
pub trait Signable: SignableType + Sized {
    /// The bytes that are signed, the application's canonical form of the value.
    ///
    /// # Errors
    ///
    /// `INVALID_PAYLOAD` when the value has no payload, such as a document that does not
    /// serialise.
    fn to_payload(&self) -> KmsAeadResult<Vec<u8>>;

    /// The value the verified payload of an attached form stands for. Called only after the
    /// bytes verified.
    ///
    /// # Errors
    ///
    /// `INVALID_PAYLOAD` when the bytes are not a value of this type.
    fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self>;
}

/// A value in [`JsonEncoded`] has the payload type of the value.
impl<T: SignableType, P> SignableType for JsonEncoded<T, P> {
    const PAYLOAD_TYPE: SignedPayloadType = T::PAYLOAD_TYPE;
}

/// The payload of a value is its compact JSON, so the value signs and verifies as the document it
/// serialises to; the bytes are not canonicalised, see [`Signable`].
impl<T, P> Signable for JsonEncoded<T, P>
where
    T: SignableType + serde::Serialize + serde::de::DeserializeOwned,
    P: JsonRedaction,
{
    /// # Errors
    ///
    /// `INVALID_PAYLOAD` when `T`'s `Serialize` fails, with serde_json's category of the error and
    /// none of its message or position.
    fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
        serde_json::to_vec(&self.0)
            .map_err(|error| KmsAeadEncryptionError::invalid_json_payload::<T>(&error))
    }

    /// # Errors
    ///
    /// `INVALID_PAYLOAD` when the bytes are not the JSON of a `T`, with serde_json's category of
    /// the error and none of its message, which quotes the input, or its position. The error is
    /// logged first as a `WARN` event on the `kms_aead::json` target with the outline of the bytes
    /// under `P`.
    fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
        Self::from_json(
            &payload,
            Some(T::PAYLOAD_TYPE),
            KmsAeadEncryptionError::invalid_json_payload::<T>,
        )
    }
}

/// What every signature and MAC is computed over: DSSE's Pre-Authentication Encoding (PAE) of
/// the payload type and the payload's SHA-256,
///
/// ```text
/// "DSSEv1" SP DEC(len(type)) SP type SP "32" SP SHA-256(payload)
/// ```
///
/// with `SP` the byte `0x20` and `DEC` the length in ASCII decimal: 46 to 302 bytes.
pub(crate) struct PreImage(Vec<u8>);

impl PreImage {
    /// The pre-image of a payload of `payload_type` whose SHA-256 is `payload_sha256`.
    pub(crate) fn new(payload_type: SignedPayloadType, payload_sha256: &Sha256Digest) -> Self {
        let payload_type = payload_type.as_str();
        let type_len = payload_type.len().to_string();
        let digest_len = payload_sha256.len().to_string();
        let mut bytes = Vec::with_capacity(
            "DSSEv1".len()
                + 4
                + type_len.len()
                + payload_type.len()
                + digest_len.len()
                + payload_sha256.len(),
        );
        for part in [
            b"DSSEv1".as_slice(),
            b" ",
            type_len.as_bytes(),
            b" ",
            payload_type.as_bytes(),
            b" ",
            digest_len.as_bytes(),
            b" ",
            payload_sha256,
        ] {
            bytes.extend_from_slice(part);
        }
        Self(bytes)
    }

    /// The bytes that are signed.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INVOICE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.invoice+json");
    /// The SHA-256 of the invoice payload of the book's test vectors.
    const INVOICE_SHA256: &str = "7b43154b748a12c6909cba38acd83fff12a11b6345effb807b21c7ce465e4cd1";
    /// The SHA-256 of the empty payload.
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    fn sha256_digest_from_hex(hex_digest: &str) -> Sha256Digest {
        let mut digest = [0; 32];
        hex::decode_to_slice(hex_digest, &mut digest).expect("a test digest is 64 hex digits");
        digest
    }

    #[test]
    fn the_pre_image_is_the_dsse_encoding_of_the_type_and_the_digest() {
        let pre_image = PreImage::new(INVOICE, &sha256_digest_from_hex(INVOICE_SHA256));

        assert_eq!(
            hex::encode(pre_image.as_bytes()),
            "445353457631203336206170706c69636174696f6e2f766e642e6578616d706c652e\
             696e766f6963652b6a736f6e203332207b43154b748a12c6909cba38acd83fff12a1\
             1b6345effb807b21c7ce465e4cd1"
        );
    }

    #[test]
    fn a_payload_type_is_1_to_255_bytes_of_visible_ascii() {
        let longest: &'static str = "t".repeat(255).leak();
        let pre_image = PreImage::new(
            SignedPayloadType::checked(longest).expect("255 visible bytes"),
            &sha256_digest_from_hex(EMPTY_SHA256),
        );
        assert_eq!(pre_image.as_bytes().len(), 302);
        assert!(SignedPayloadType::checked("t").is_some());

        let too_long: &'static str = "t".repeat(256).leak();
        for refused in ["", too_long, "a b", "a\u{7}b", "a\u{7f}b", "é"] {
            assert!(SignedPayloadType::checked(refused).is_none(), "{refused:?}");
        }
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod json_tests {
    use serde::{Deserialize, Serialize};

    use super::*;
    use crate::mac::{Authenticator, MacAlgorithm};
    use crate::providers::{LocalSigningKeyName, LocalSigningProvider};
    use crate::signing::{Signer, SigningAlgorithm, Verifier, VerifyingKeySet};
    use crate::test_provider::{renderings, TestBackend};
    use crate::KeyId;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Order {
        id: u64,
        customer: String,
    }

    impl SignableType for Order {
        const PAYLOAD_TYPE: SignedPayloadType =
            SignedPayloadType::from_static("application/vnd.example.order+json");
    }

    fn order() -> JsonEncoded<Order> {
        JsonEncoded::new(Order {
            id: 1042,
            customer: "Northwind Traders".to_string(),
        })
    }

    #[tokio::test]
    async fn a_json_value_signs_and_verifies_detached_and_attached() -> KmsAeadResult<()> {
        let signer = Signer::<_, TestBackend>::new(LocalSigningProvider::<TestBackend>::ephemeral(
            LocalSigningKeyName::try_from("orders".to_string())?,
            SigningAlgorithm::Ed25519,
        )?)
        .await?;
        let verifier =
            Verifier::<TestBackend>::new(VerifyingKeySet::new([signer.verifying_key().clone()])?)?;

        let detached = signer.sign(&order()).await?;
        verifier.verify(&order(), &detached)?;

        let attached = signer.sign_attached(&order()).await?;
        let (verified, _) = verifier.verify_signed(&attached)?;
        assert_eq!(verified, order());
        Ok(())
    }

    #[test]
    fn a_json_value_has_a_mac_detached_and_attached() -> KmsAeadResult<()> {
        let authenticator = Authenticator::<TestBackend>::new(MacAlgorithm::HmacSha256)?;
        let key = authenticator.generate_dek()?;
        let key_id = KeyId::new(7);

        let mac = authenticator.mac(key_id, &order(), &key)?;
        authenticator.verify(&order(), &mac, &key)?;

        let attached = authenticator.mac_attached(key_id, &order(), &key)?;
        let verified = authenticator.verify_with_mac(&attached, &key)?;
        assert_eq!(verified, order());
        Ok(())
    }

    #[test]
    fn a_payload_that_is_not_the_json_of_the_type_is_refused_without_quoting_it() {
        let payload = br#"{"id":"not-a-number","customer":"Northwind Traders"}"#;

        let error = <JsonEncoded<Order> as Signable>::from_payload(payload.to_vec())
            .expect_err("the id is not a number");

        assert_eq!(error.code(), "INVALID_PAYLOAD");
        let message = format!("{error} {error:?}");
        for rendering in renderings(payload)
            .into_iter()
            .chain(["not-a-number".to_string(), "Northwind".to_string()])
        {
            assert!(
                !message.contains(&rendering),
                "{rendering:?} in {message:?}"
            );
        }
    }
}
