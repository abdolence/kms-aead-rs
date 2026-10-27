use std::num::NonZeroU32;

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use hyper::Uri;
use rsb_derive::Builder;
use serde::{Deserialize, Serialize};

use super::hc_vault_transit_kms_encryption::{
    parse_vault_response, KeyData, TransitResponse, VaultTransport,
};
use super::{HcVaultTransitKeyRef, HcVaultTransitProviderOptions};
use crate::errors::{KmsAeadError, KmsAeadSignatureError, KmsAeadSystemError};
use crate::formats::PublicKeyFormat;
use crate::signing::{
    KmsSigningProvider, RawSignature, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
};
use crate::spans::{self, kms};
use crate::{KmsAeadResult, KmsProvider};

/// The `hash_algorithm` of every sign request, set in the body so that the request path is the
/// one a policy on `<mount>/sign/<name>` names. Vault ignores it for an `ed25519` key and takes
/// the digest as it is for a `prehashed` request.
const HASH_ALGORITHM: &str = "sha2-256";

/// The `marshaling_algorithm` of a sign request: `r || s` in base64url without padding, as the
/// JWS `ES256` of RFC 7518 writes it, in place of Vault's default of DER.
const MARSHALING_ALGORITHM: &str = "jws";

/// One version of a Transit key of HashiCorp Vault that signs.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct HcVaultTransitSigningKeyRef {
    /// The name of the Transit key.
    pub key_name: String,
    /// Mount path of the Transit secrets engine,
    /// [`DEFAULT_MOUNT`](HcVaultTransitKeyRef::DEFAULT_MOUNT) by default.
    #[default = "HcVaultTransitKeyRef::DEFAULT_MOUNT.into()"]
    pub mount: String,
    /// The key version, required: Vault's `key_version: 0`, the latest, is never sent.
    pub version: NonZeroU32,
    /// [`Ed25519`](SigningAlgorithm::Ed25519) for an `ed25519` key,
    /// [`EcdsaP256Sha256`](SigningAlgorithm::EcdsaP256Sha256) for `ecdsa-p256`.
    pub algorithm: SigningAlgorithm,
}

impl HcVaultTransitSigningKeyRef {
    /// The `type` of a Transit key that signs with [`algorithm`](Self::algorithm).
    fn key_type(&self) -> &'static str {
        match self.algorithm {
            SigningAlgorithm::Ed25519 => "ed25519",
            SigningAlgorithm::EcdsaP256Sha256 => "ecdsa-p256",
        }
    }
}

/// Signs with one version of a key of the HashiCorp Vault Transit secrets engine. It needs one
/// TLS root store feature and one crypto provider feature, as
/// [`HcVaultTransitProvider`](super::HcVaultTransitProvider) does.
///
/// The Ed25519 pre-image goes to `sign` as `input`, and a P-256 signer sends the SHA-256 of the
/// pre-image as a `prehashed` `input`. Vault returns `vault:vN:<base64url>` with the 64-byte
/// Ed25519 signature or `r || s` for P-256. A response whose `vN` is not the configured version is
/// `SIGNING_KEY_MISMATCH`.
///
/// The error codes are those of the encryption provider: `VAULT_STATUS_<status>` is a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError) for a server error or a rate limit
/// and a [`SignatureError`](crate::errors::KmsAeadError::SignatureError) otherwise, `VAULT_HTTP`
/// and `VAULT_TIMEOUT` are network errors, and `VAULT_RESPONSE` and `VAULT_RESPONSE_TOO_LARGE`
/// signature errors.
///
/// The token needs `update` on `<mount>/sign/<name>` and `read` on `<mount>/keys/<name>`.
#[derive(Clone)]
pub struct HcVaultTransitSigningProvider {
    transport: VaultTransport,
    sign_uri: Uri,
    key_uri: Uri,
    key_version: NonZeroU32,
    key_type: &'static str,
    signing_key: SigningKeyRef,
    algorithm: SigningAlgorithm,
}

impl HcVaultTransitSigningProvider {
    /// A provider with the options from [`HcVaultTransitProviderOptions::from_env`].
    ///
    /// # Errors
    ///
    /// As [`HcVaultTransitProviderOptions::from_env`] and [`with_options`](Self::with_options).
    pub fn new(key_ref: &HcVaultTransitSigningKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(key_ref, HcVaultTransitProviderOptions::from_env()?)
    }

    /// A provider for the key version at `key_ref` with `options`. It sends no request.
    ///
    /// # Errors
    ///
    /// As [`HcVaultTransitProvider::with_options`](super::HcVaultTransitProvider::with_options).
    pub fn with_options(
        key_ref: &HcVaultTransitSigningKeyRef,
        options: HcVaultTransitProviderOptions,
    ) -> KmsAeadResult<Self> {
        let transport = VaultTransport::new(options)?;
        Ok(Self {
            sign_uri: transport.endpoint(&key_ref.mount, "sign", &key_ref.key_name)?,
            key_uri: transport.endpoint(&key_ref.mount, "keys", &key_ref.key_name)?,
            key_version: key_ref.version,
            key_type: key_ref.key_type(),
            signing_key: SigningKeyRef::new(
                KmsProvider::HcVaultTransit,
                format!(
                    "{}/v{}",
                    transport.key_url(&key_ref.mount, &key_ref.key_name),
                    key_ref.version
                ),
            ),
            algorithm: key_ref.algorithm,
            transport,
        })
    }

    /// The body of a sign request for the configured version: the pre-image for Ed25519, the
    /// digest and `prehashed` for P-256.
    fn sign_request(&self, input: &SigningInput<'_>) -> KmsAeadResult<Vec<u8>> {
        let (message, prehashed) = match *input {
            SigningInput::Ed25519 { pre_image } => (pre_image, None),
            SigningInput::EcdsaP256Sha256 { digest, .. } => (digest.as_slice(), Some(true)),
        };
        serde_json::to_vec(&SignRequest {
            input: &Base64::encode_string(message),
            key_version: self.key_version,
            hash_algorithm: HASH_ALGORITHM,
            marshaling_algorithm: MARSHALING_ALGORITHM,
            prehashed,
        })
        .map_err(|error| KmsAeadSystemError::create("VAULT_REQUEST", &error.to_string()))
    }

    /// The raw signature in `signature`, which Vault writes as `vault:vN:<base64url>`, once `N`
    /// is the configured version.
    fn raw_signature(&self, signature: &str) -> KmsAeadResult<RawSignature> {
        let encoding_error = |reason: &str| {
            KmsAeadSignatureError::create(
                "SIGNATURE_ENCODING",
                &format!("The Vault Transit signature {reason}"),
            )
        };
        let (version, encoded) = signature
            .strip_prefix("vault:v")
            .and_then(|versioned| versioned.split_once(':'))
            .ok_or_else(|| encoding_error("does not start with vault:vN:"))?;
        if version.parse::<NonZeroU32>().ok() != Some(self.key_version) {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_KEY_MISMATCH",
                "The Vault Transit signature is of another key version than the configured one",
            ));
        }
        let bytes = Base64UrlUnpadded::decode_vec(encoded)
            .map_err(|_| encoding_error("is not base64url without padding"))?;
        RawSignature::new(self.algorithm, bytes)
    }

    /// The verifying key of the configured version in the `keys` response `key`.
    fn verifying_key_from(&self, key: KeyData) -> KmsAeadResult<VerifyingKey> {
        if key.key_type != self.key_type {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                &format!(
                    "The Vault Transit key {} is not of type {}, the type of {}",
                    self.signing_key.key(),
                    self.key_type,
                    self.algorithm
                ),
            ));
        }
        let invalid = |reason: &str| {
            KmsAeadSignatureError::invalid_public_key(&format!("The Vault Transit key {reason}"))
        };
        let public_key = key
            .keys
            .get(&self.key_version.to_string())
            .and_then(|version| version.get("public_key"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| invalid("holds no public key for the configured version"))?;
        match self.algorithm {
            SigningAlgorithm::Ed25519 => {
                let raw = Base64::decode_vec(public_key)
                    .map_err(|_| invalid("holds a public key that is not base64"))?;
                VerifyingKey::from_bytes(self.algorithm, &raw, PublicKeyFormat::Raw)
            }
            SigningAlgorithm::EcdsaP256Sha256 => VerifyingKey::from_bytes(
                self.algorithm,
                public_key.as_bytes(),
                PublicKeyFormat::SpkiPem,
            ),
        }
    }
}

#[derive(Serialize)]
struct SignRequest<'a> {
    input: &'a str,
    key_version: NonZeroU32,
    hash_algorithm: &'a str,
    marshaling_algorithm: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    prehashed: Option<bool>,
}

#[derive(Deserialize)]
struct SignData {
    signature: String,
}

impl KmsSigningProvider for HcVaultTransitSigningProvider {
    fn signing_key(&self) -> &SigningKeyRef {
        &self.signing_key
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
        spans::in_span(kms::sign_span(&self.signing_key), async {
            input.ensure_algorithm(&self.signing_key, self.algorithm)?;
            let request = self.sign_request(&input)?;

            let body = kms::timed("sign", self.signing_key.provider(), async {
                self.transport
                    .post(&self.sign_uri, request)
                    .await
                    .map_err(KmsAeadError::into_signature_error)
            })
            .await?;
            let response: TransitResponse<SignData> =
                parse_vault_response(&body).map_err(KmsAeadError::into_signature_error)?;
            self.raw_signature(&response.data.signature)
        })
        .await
    }

    async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
        spans::in_span(kms::public_key_span(&self.signing_key), async {
            let body = kms::timed("public_key", self.signing_key.provider(), async {
                self.transport
                    .get(&self.key_uri)
                    .await
                    .map_err(KmsAeadError::into_signature_error)
            })
            .await?;
            let response: TransitResponse<KeyData> =
                parse_vault_response(&body).map_err(KmsAeadError::into_signature_error)?;
            self.verifying_key_from(response.data)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::formats::PublicKeyFormat;
    use crate::signing::{Signer, Verifier, VerifyingKeySet};
    use crate::test_http::{answer_with, ReceivedRequest};
    use crate::test_provider::{
        assert_code, verifying_key_of, Invoice, TestBackend, ED25519_PKCS8_DER, INVOICE_PAYLOAD,
        P256_PKCS8_DER, P256_SIGNATURE,
    };
    use tokio::net::TcpListener;

    const KEY_NAME: &str = "orders";
    const DIGEST: [u8; 32] = [0x5a; 32];
    const PRE_IMAGE: [u8; 46] = [0x11; 46];

    fn key_ref(algorithm: SigningAlgorithm) -> HcVaultTransitSigningKeyRef {
        HcVaultTransitSigningKeyRef::new(KEY_NAME.into(), NonZeroU32::new(2).unwrap(), algorithm)
    }

    fn provider_at(
        address: String,
        namespace: Option<&str>,
        algorithm: SigningAlgorithm,
    ) -> HcVaultTransitSigningProvider {
        let options = HcVaultTransitProviderOptions::new(address)
            .opt_namespace(namespace.map(str::to_string))
            .with_timeout(Duration::from_millis(500));
        HcVaultTransitSigningProvider::with_options(&key_ref(algorithm), options).unwrap()
    }

    /// A provider whose requests go to a local server that answers each of them with `status` and
    /// the JSON `body`, and the requests the server receives.
    async fn provider_answered_with(
        algorithm: SigningAlgorithm,
        status: u16,
        body: String,
    ) -> (
        HcVaultTransitSigningProvider,
        Arc<Mutex<Vec<ReceivedRequest>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = provider_at(
            format!("http://{}", listener.local_addr().unwrap()),
            None,
            algorithm,
        );
        (provider, answer_with(listener, status, body))
    }

    fn offline_provider(algorithm: SigningAlgorithm) -> HcVaultTransitSigningProvider {
        provider_at("https://vault.example.com:8200".into(), None, algorithm)
    }

    fn p256_input() -> SigningInput<'static> {
        SigningInput::EcdsaP256Sha256 {
            pre_image: &PRE_IMAGE,
            digest: &DIGEST,
        }
    }

    fn ed25519_input() -> SigningInput<'static> {
        SigningInput::Ed25519 {
            pre_image: &PRE_IMAGE,
        }
    }

    fn signed_body(signature: &str) -> String {
        format!(r#"{{"data":{{"signature":"{signature}","key_version":2}}}}"#)
    }

    fn jws(bytes: &[u8]) -> String {
        Base64UrlUnpadded::encode_string(bytes)
    }

    #[test]
    fn the_key_is_named_by_its_address_namespace_mount_name_and_version() {
        let provider = provider_at(
            "https://vault.example.com:8200/".into(),
            Some("/tenant-a/"),
            SigningAlgorithm::Ed25519,
        );

        assert_eq!(
            *provider.signing_key(),
            SigningKeyRef::new(
                KmsProvider::HcVaultTransit,
                "https://vault.example.com:8200/tenant-a/transit/keys/orders/v2"
            )
        );
    }

    #[tokio::test]
    async fn ed25519_sends_the_pre_image_and_p256_the_prehashed_digest_for_the_configured_version()
    {
        for (algorithm, input, signed_bytes, prehashed) in [
            (
                SigningAlgorithm::Ed25519,
                ed25519_input(),
                PRE_IMAGE.as_slice(),
                None,
            ),
            (
                SigningAlgorithm::EcdsaP256Sha256,
                p256_input(),
                DIGEST.as_slice(),
                Some(true),
            ),
        ] {
            let (provider, requests) = provider_answered_with(
                algorithm,
                200,
                signed_body(&format!("vault:v2:{}", jws(&[7; 64]))),
            )
            .await;

            provider.sign(input).await.unwrap();

            let requests = requests.lock().unwrap();
            let [request] = requests.as_slice() else {
                panic!("{algorithm}: {} requests", requests.len());
            };
            assert!(
                request.head.starts_with("POST /v1/transit/sign/orders "),
                "{}",
                request.head
            );
            let mut expected = serde_json::json!({
                "input": Base64::encode_string(signed_bytes),
                "key_version": 2,
                "hash_algorithm": "sha2-256",
                "marshaling_algorithm": "jws",
            });
            if let Some(prehashed) = prehashed {
                expected["prehashed"] = prehashed.into();
            }
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&request.body).unwrap(),
                expected,
                "{algorithm}"
            );
        }
    }

    #[tokio::test]
    async fn a_signature_of_the_configured_version_is_the_raw_signature() {
        let raw = hex::decode(P256_SIGNATURE).unwrap();
        let (provider, _) = provider_answered_with(
            SigningAlgorithm::EcdsaP256Sha256,
            200,
            signed_body(&format!("vault:v2:{}", jws(&raw))),
        )
        .await;

        let signature = provider.sign(p256_input()).await.unwrap();

        assert_eq!(signature.value(), raw);
    }

    #[test]
    fn a_signature_of_another_version_or_in_another_encoding_is_refused() {
        let provider = offline_provider(SigningAlgorithm::Ed25519);
        let signature = jws(&[7; 64]);
        for (text, code) in [
            (format!("vault:v3:{signature}"), "SIGNING_KEY_MISMATCH"),
            (format!("vault:v0:{signature}"), "SIGNING_KEY_MISMATCH"),
            (format!("vault:2:{signature}"), "SIGNATURE_ENCODING"),
            (signature.clone(), "SIGNATURE_ENCODING"),
            // Standard base64 with padding, where the JWS marshaling writes base64url.
            (
                format!("vault:v2:{}", Base64::encode_string(&[0xfb; 64])),
                "SIGNATURE_ENCODING",
            ),
            (format!("vault:v2:{}", jws(&[7; 63])), "SIGNATURE_ENCODING"),
        ] {
            assert_code(provider.raw_signature(&text), code);
        }
    }

    fn keys_body(key_type: &str, version_2_public_key: &str) -> String {
        serde_json::json!({
            "data": {
                "type": key_type,
                "keys": {
                    "1": { "public_key": "AAAA", "name": key_type },
                    "2": { "public_key": version_2_public_key, "name": key_type },
                },
            }
        })
        .to_string()
    }

    #[tokio::test]
    async fn the_public_key_of_the_configured_version_is_the_verifying_key() {
        for (pkcs8_der, algorithm, key_type, format) in [
            (
                ED25519_PKCS8_DER,
                SigningAlgorithm::Ed25519,
                "ed25519",
                PublicKeyFormat::Raw,
            ),
            (
                P256_PKCS8_DER,
                SigningAlgorithm::EcdsaP256Sha256,
                "ecdsa-p256",
                PublicKeyFormat::SpkiPem,
            ),
        ] {
            let expected = verifying_key_of(pkcs8_der);
            // Vault writes an Ed25519 public key as base64 and an ECDSA one as PEM.
            let encoded = expected.encode(format).unwrap();
            let public_key = match format {
                PublicKeyFormat::Raw => Base64::encode_string(&encoded),
                _ => String::from_utf8(encoded).unwrap(),
            };
            let (provider, requests) =
                provider_answered_with(algorithm, 200, keys_body(key_type, &public_key)).await;

            let key = provider.verifying_key().await.unwrap();

            assert_eq!(key, expected, "{algorithm}");
            assert!(
                requests.lock().unwrap()[0]
                    .head
                    .starts_with("GET /v1/transit/keys/orders "),
                "{}",
                requests.lock().unwrap()[0].head
            );
        }
    }

    #[tokio::test]
    async fn a_key_of_another_type_or_without_the_version_is_refused() {
        for (body, code) in [
            (
                r#"{"data":{"type":"aes256-gcm96","keys":{"1":1700000000,"2":1700000001}}}"#
                    .to_string(),
                "SIGNING_ALGORITHM_MISMATCH",
            ),
            (
                keys_body("ecdsa-p256", "AAAA"),
                "SIGNING_ALGORITHM_MISMATCH",
            ),
            (
                r#"{"data":{"type":"ed25519","keys":{"1":{"public_key":"AAAA"}}}}"#.to_string(),
                "INVALID_PUBLIC_KEY",
            ),
            (keys_body("ed25519", "not base64!"), "INVALID_PUBLIC_KEY"),
        ] {
            let (provider, _) = provider_answered_with(SigningAlgorithm::Ed25519, 200, body).await;

            assert_code(provider.verifying_key().await, code);
        }
    }

    #[tokio::test]
    async fn a_refusal_is_a_signature_error_and_a_busy_server_a_network_error() {
        let (denied, _) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            403,
            r#"{"errors":["permission denied"]}"#.to_string(),
        )
        .await;
        let (sealed, _) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            503,
            r#"{"errors":["Vault is sealed"]}"#.to_string(),
        )
        .await;

        assert_code(denied.sign(ed25519_input()).await, "VAULT_STATUS_403");
        let sealed = sealed.sign(ed25519_input()).await.unwrap_err();
        assert!(
            matches!(&sealed, KmsAeadError::NetworkError(_)),
            "{sealed:?}"
        );
        assert_eq!(sealed.code(), "VAULT_STATUS_503");
    }

    #[tokio::test]
    async fn an_input_of_another_algorithm_is_refused_before_any_request() {
        let (provider, requests) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            200,
            signed_body(&format!("vault:v2:{}", jws(&[7; 64]))),
        )
        .await;

        assert_code(
            provider.sign(p256_input()).await,
            "SIGNING_ALGORITHM_MISMATCH",
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    /// Transit keys on the server in `VAULT_ADDR`, which `VAULT_TOKEN` may sign with and read:
    /// `VAULT_TRANSIT_SIGNING_KEY_ED25519` of type `ed25519` and `VAULT_TRANSIT_SIGNING_KEY_P256`
    /// of type `ecdsa-p256`, each at version 1.
    fn live_provider(algorithm: SigningAlgorithm) -> HcVaultTransitSigningProvider {
        let variable = match algorithm {
            SigningAlgorithm::Ed25519 => "VAULT_TRANSIT_SIGNING_KEY_ED25519",
            SigningAlgorithm::EcdsaP256Sha256 => "VAULT_TRANSIT_SIGNING_KEY_P256",
        };
        HcVaultTransitSigningProvider::new(&HcVaultTransitSigningKeyRef::new(
            std::env::var(variable)
                .unwrap_or_else(|_| panic!("{variable} must name a Transit key")),
            NonZeroU32::MIN,
            algorithm,
        ))
        .unwrap()
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn live_keys_sign_values_that_verify_without_the_kms() -> KmsAeadResult<()> {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let signer = Signer::<_, TestBackend>::new(live_provider(algorithm)).await?;
            let verifier = Verifier::<TestBackend>::new(VerifyingKeySet::new([signer
                .verifying_key()
                .clone()])?)?;
            let invoice = Invoice(INVOICE_PAYLOAD.to_vec());

            let signature = signer.sign(&invoice).await?;

            assert_eq!(
                verifier.verify(&invoice, &signature)?,
                signer.verifying_key(),
                "{algorithm}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn live_key_of_another_type_than_configured_is_refused() {
        let key_name = std::env::var("VAULT_TRANSIT_SIGNING_KEY_ED25519")
            .expect("VAULT_TRANSIT_SIGNING_KEY_ED25519 must name a Transit key");
        let provider = HcVaultTransitSigningProvider::new(&HcVaultTransitSigningKeyRef::new(
            key_name,
            NonZeroU32::MIN,
            SigningAlgorithm::EcdsaP256Sha256,
        ))
        .unwrap();

        assert_code(provider.verifying_key().await, "SIGNING_ALGORITHM_MISMATCH");
    }
}
