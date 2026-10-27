use aws_sdk_kms::operation::get_public_key::GetPublicKeyOutput;
use aws_sdk_kms::operation::sign::builders::SignFluentBuilder;
use aws_sdk_kms::operation::sign::SignOutput;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{KeySpec, MessageType, SigningAlgorithmSpec};
use rsb_derive::Builder;

use crate::errors::{KmsAeadError, KmsAeadSignatureError, KmsAeadSystemError};
use crate::formats::PublicKeyFormat;
use crate::signing::{
    KmsSigningProvider, RawSignature, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
};
use crate::spans::{self, kms};
use crate::{KmsAeadResult, KmsProvider};

/// An AWS KMS asymmetric key that signs.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsKmsSigningKeyRef {
    /// The AWS account that owns the key, used to build its ARN.
    pub account_id: String,
    /// A key id or key ARN, never an alias: an alias that moves to another key would sign with a
    /// key the signature's id does not name. Outside the `aws` partition, such as in GovCloud or
    /// China, give the full ARN, since a key id becomes an `arn:aws:` ARN.
    pub key_id: String,
    /// The region of the key. Without one, [`AwsKmsSigningProvider::new`] takes the region of the
    /// AWS configuration it loads.
    pub aws_region: Option<aws_sdk_kms::config::Region>,
    /// [`Ed25519`](SigningAlgorithm::Ed25519) for an `ECC_NIST_EDWARDS25519` key,
    /// [`EcdsaP256Sha256`](SigningAlgorithm::EcdsaP256Sha256) for `ECC_NIST_P256`.
    pub algorithm: SigningAlgorithm,
}

impl AwsKmsSigningKeyRef {
    /// The ARN of the key: `key_id` itself when it is an ARN already, and a key ARN for a key id.
    /// Without a region it is `key_id` unchanged.
    fn to_key_arn(&self) -> String {
        match &self.aws_region {
            Some(region) if !self.key_id.starts_with("arn:") => format!(
                "arn:aws:kms:{region}:{}:key/{}",
                self.account_id, self.key_id
            ),
            _ => self.key_id.clone(),
        }
    }

    /// Whether `key_id` names an alias, as an alias name or an alias ARN.
    fn is_alias(&self) -> bool {
        self.key_id.starts_with("alias/")
            || (self.key_id.starts_with("arn:") && self.key_id.contains(":alias/"))
    }

    /// The key spec of a key that signs with [`algorithm`](Self::algorithm).
    fn key_spec(&self) -> KeySpec {
        match self.algorithm {
            SigningAlgorithm::Ed25519 => KeySpec::EccNistEdwards25519,
            SigningAlgorithm::EcdsaP256Sha256 => KeySpec::EccNistP256,
        }
    }
}

/// Signs with an AWS KMS asymmetric key.
///
/// The Ed25519 pre-image goes to `Sign` as a `RAW` message with `ED25519_SHA_512`, and a P-256
/// signer sends the SHA-256 of the pre-image as a `DIGEST` with `ECDSA_SHA_256`. AWS KMS returns a
/// P-256 signature in DER, which is converted to `r || s`. A response that names another key
/// than the configured one is `SIGNING_KEY_MISMATCH`.
///
/// An error AWS KMS returned keeps its AWS error code, and the error kinds split into network and
/// signature errors as [`AwsKmsProvider`](super::AwsKmsProvider)'s split into network and
/// encryption errors.
///
/// The principal needs `kms:Sign` and `kms:GetPublicKey` on the key.
pub struct AwsKmsSigningProvider {
    client: aws_sdk_kms::Client,
    signing_key: SigningKeyRef,
    algorithm: SigningAlgorithm,
    key_spec: KeySpec,
}

impl AwsKmsSigningProvider {
    /// A provider for the key at `key_ref`, with the AWS configuration from the environment.
    ///
    /// It sends no request, so missing credentials or an unreachable endpoint fail the first
    /// `Signer::new`.
    ///
    /// # Errors
    ///
    /// `AWS_SIGNING_KEY_ALIAS` when `key_id` is an alias name, `alias/…`, or an alias ARN.
    pub async fn new(key_ref: &AwsKmsSigningKeyRef) -> KmsAeadResult<Self> {
        let shared_config = aws_config::load_from_env().await;
        let effective_key_ref = if key_ref.aws_region.is_none() {
            key_ref
                .clone()
                .opt_aws_region(shared_config.region().cloned())
        } else {
            key_ref.clone()
        };
        Self::with_client(&effective_key_ref, aws_sdk_kms::Client::new(&shared_config))
    }

    /// As [`new`](Self::new), with `client`.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub fn with_client(
        key_ref: &AwsKmsSigningKeyRef,
        client: aws_sdk_kms::Client,
    ) -> KmsAeadResult<Self> {
        if key_ref.is_alias() {
            return Err(KmsAeadSystemError::create(
                "AWS_SIGNING_KEY_ALIAS",
                "An AWS signing key is named by its key id or key ARN, never by an alias: an alias \
                 that moves to another key would sign with a key the signature's id does not name",
            ));
        }
        Ok(Self {
            client,
            signing_key: SigningKeyRef::new(KmsProvider::Aws, key_ref.to_key_arn()),
            algorithm: key_ref.algorithm,
            key_spec: key_ref.key_spec(),
        })
    }

    /// `Sign` with the configured key: the pre-image as a `RAW` message for Ed25519, the digest
    /// as a `DIGEST` for P-256. Returns the algorithm the response must name.
    fn sign_request(&self, input: &SigningInput<'_>) -> (SignFluentBuilder, SigningAlgorithmSpec) {
        let (message, message_type, algorithm) = match *input {
            SigningInput::Ed25519 { pre_image } => (
                pre_image,
                MessageType::Raw,
                SigningAlgorithmSpec::Ed25519Sha512,
            ),
            SigningInput::EcdsaP256Sha256 { digest, .. } => (
                digest.as_slice(),
                MessageType::Digest,
                SigningAlgorithmSpec::EcdsaSha256,
            ),
        };
        let request = self
            .client
            .sign()
            .key_id(self.signing_key.key())
            .message(Blob::new(message))
            .message_type(message_type)
            .signing_algorithm(algorithm.clone());
        (request, algorithm)
    }

    /// The raw signature in a `Sign` response, once it names the configured key and the algorithm
    /// the request named.
    fn raw_signature(
        &self,
        response: SignOutput,
        input: &SigningInput<'_>,
        requested: &SigningAlgorithmSpec,
    ) -> KmsAeadResult<RawSignature> {
        self.ensure_key(response.key_id())?;
        if response.signing_algorithm() != Some(requested) {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                "The AWS KMS response names another signing algorithm than the request",
            ));
        }
        let signature = response.signature().ok_or_else(|| {
            KmsAeadSignatureError::create(
                "SIGNATURE_ENCODING",
                "The AWS KMS response holds no signature",
            )
        })?;
        match input {
            SigningInput::Ed25519 { .. } => {
                RawSignature::new(input.algorithm(), signature.as_ref().to_vec())
            }
            SigningInput::EcdsaP256Sha256 { .. } => {
                RawSignature::from_ecdsa_p256_der(signature.as_ref())
            }
        }
    }

    /// The verifying key in a `GetPublicKey` response, once it names the configured key and is of
    /// the configured key spec.
    fn verifying_key_from(&self, response: GetPublicKeyOutput) -> KmsAeadResult<VerifyingKey> {
        self.ensure_key(response.key_id())?;
        if response.key_spec() != Some(&self.key_spec) {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                &format!(
                    "The AWS KMS key {} is not of {}, the key spec of {}",
                    self.signing_key.key(),
                    self.key_spec,
                    self.algorithm
                ),
            ));
        }
        let public_key = response.public_key().ok_or_else(|| {
            KmsAeadSignatureError::invalid_public_key("The AWS KMS response holds no public key")
        })?;
        VerifyingKey::from_bytes(
            self.algorithm,
            public_key.as_ref(),
            PublicKeyFormat::SpkiDer,
        )
    }

    /// Refuses a response whose `KeyId` is not the configured key. A key configured by its key
    /// id, with no region to build the ARN from, matches the key ARN that names it.
    fn ensure_key(&self, response_key_id: Option<&str>) -> KmsAeadResult<()> {
        let configured = self.signing_key.key();
        let names_configured_key = response_key_id.is_some_and(|response| {
            response == configured
                || (!configured.starts_with("arn:")
                    && response
                        .rsplit_once(":key/")
                        .is_some_and(|(_, key_id)| key_id == configured))
        });
        if names_configured_key {
            Ok(())
        } else {
            Err(KmsAeadSignatureError::create(
                "SIGNING_KEY_MISMATCH",
                "The AWS KMS response names another key than the configured one",
            ))
        }
    }
}

impl KmsSigningProvider for AwsKmsSigningProvider {
    fn signing_key(&self) -> &SigningKeyRef {
        &self.signing_key
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
        spans::in_span(kms::sign_span(&self.signing_key), async {
            input.ensure_algorithm(&self.signing_key, self.algorithm)?;
            let (request, requested) = self.sign_request(&input);

            let response = kms::timed("sign", self.signing_key.provider(), async {
                request
                    .send()
                    .await
                    .map_err(|error| KmsAeadError::from_aws_sdk_error(error).into_signature_error())
            })
            .await?;
            self.raw_signature(response, &input, &requested)
        })
        .await
    }

    async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
        spans::in_span(kms::public_key_span(&self.signing_key), async {
            let response = kms::timed("public_key", self.signing_key.provider(), async {
                self.client
                    .get_public_key()
                    .key_id(self.signing_key.key())
                    .send()
                    .await
                    .map_err(|error| KmsAeadError::from_aws_sdk_error(error).into_signature_error())
            })
            .await?;
            self.verifying_key_from(response)
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{Signer, Verifier, VerifyingKeySet};
    use crate::test_http::{answer_with, ReceivedRequest};
    use crate::test_provider::{
        assert_code, verifying_key_of, Invoice, TestBackend, ED25519_PKCS8_DER, INVOICE_PAYLOAD,
        P256_PKCS8_DER, P256_SIGNATURE, P256_SIGNATURE_DER,
    };
    use aws_sdk_kms::config::retry::RetryConfig;
    use aws_sdk_kms::config::{Credentials, Region};
    use base64ct::{Base64, Encoding};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    const REGION: &str = "eu-west-1";
    const ACCOUNT_ID: &str = "123456789012";
    const KEY_ID: &str = "1234abcd-12ab-34cd-56ef-1234567890ab";
    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    const OTHER_KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:123456789012:key/ffffffff-12ab-34cd-56ef-1234567890ab";
    const DIGEST: [u8; 32] = [0x5a; 32];
    const PRE_IMAGE: [u8; 46] = [0x11; 46];

    fn key_ref(key_id: &str, algorithm: SigningAlgorithm) -> AwsKmsSigningKeyRef {
        AwsKmsSigningKeyRef::new(ACCOUNT_ID.into(), key_id.into(), algorithm)
            .with_aws_region(Region::new(REGION))
    }

    fn provider_with(
        key_ref: &AwsKmsSigningKeyRef,
        config: aws_sdk_kms::config::Builder,
    ) -> KmsAeadResult<AwsKmsSigningProvider> {
        let config = config
            .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
            .build();
        AwsKmsSigningProvider::with_client(key_ref, aws_sdk_kms::Client::from_conf(config))
    }

    fn offline_provider(algorithm: SigningAlgorithm) -> AwsKmsSigningProvider {
        provider_with(&key_ref(KEY_ID, algorithm), aws_sdk_kms::Config::builder()).unwrap()
    }

    /// A provider whose requests go to a local server that answers each of them with `status` and
    /// the JSON `body`, and the requests the server receives.
    async fn provider_answered_with(
        algorithm: SigningAlgorithm,
        status: u16,
        body: String,
    ) -> (AwsKmsSigningProvider, Arc<Mutex<Vec<ReceivedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = answer_with(listener, status, body);
        let provider = provider_with(
            &key_ref(KEY_ID, algorithm),
            aws_sdk_kms::Config::builder()
                .endpoint_url(endpoint)
                .region(Region::new(REGION))
                .credentials_provider(Credentials::new("AKID", "SECRET", None, None, "test"))
                .retry_config(RetryConfig::disabled()),
        )
        .unwrap();
        (provider, requests)
    }

    fn base64(bytes: &[u8]) -> String {
        Base64::encode_string(bytes)
    }

    fn signed_body(key_arn: &str, signature: &[u8], signing_algorithm: &str) -> String {
        format!(
            r#"{{"KeyId":"{key_arn}","Signature":"{}","SigningAlgorithm":"{signing_algorithm}"}}"#,
            base64(signature)
        )
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

    fn request_body(requests: &Mutex<Vec<ReceivedRequest>>) -> serde_json::Value {
        let requests = requests.lock().unwrap();
        let [request] = requests.as_slice() else {
            panic!("{} requests", requests.len());
        };
        serde_json::from_slice(&request.body).unwrap()
    }

    #[test]
    fn an_alias_is_refused_and_a_key_id_or_arn_is_named_by_its_arn() {
        for alias in [
            "alias/signing",
            "arn:aws:kms:eu-west-1:123456789012:alias/signing",
        ] {
            let result = provider_with(
                &key_ref(alias, SigningAlgorithm::Ed25519),
                aws_sdk_kms::Config::builder(),
            );
            assert!(
                matches!(&result, Err(KmsAeadError::SystemError(error))
                    if error.public.code == "AWS_SIGNING_KEY_ALIAS"),
                "{alias}: {:?}",
                result.err()
            );
        }

        assert_eq!(
            offline_provider(SigningAlgorithm::Ed25519).signing_key(),
            &SigningKeyRef::new(KmsProvider::Aws, KEY_ARN)
        );
        let arn = provider_with(
            &key_ref(OTHER_KEY_ARN, SigningAlgorithm::Ed25519),
            aws_sdk_kms::Config::builder(),
        )
        .unwrap();
        assert_eq!(arn.signing_key().key(), OTHER_KEY_ARN);
    }

    #[test]
    fn ed25519_sends_a_raw_message_and_p256_a_digest() {
        let ed25519 = offline_provider(SigningAlgorithm::Ed25519);
        let p256 = offline_provider(SigningAlgorithm::EcdsaP256Sha256);

        let (ed25519, _) = ed25519.sign_request(&ed25519_input());
        let (p256, _) = p256.sign_request(&p256_input());

        assert_eq!(ed25519.get_key_id().as_deref(), Some(KEY_ARN));
        assert_eq!(
            ed25519.get_message().as_ref().map(Blob::as_ref),
            Some(PRE_IMAGE.as_slice())
        );
        assert_eq!(ed25519.get_message_type(), &Some(MessageType::Raw));
        assert_eq!(
            ed25519.get_signing_algorithm(),
            &Some(SigningAlgorithmSpec::Ed25519Sha512)
        );
        assert_eq!(p256.get_key_id().as_deref(), Some(KEY_ARN));
        assert_eq!(
            p256.get_message().as_ref().map(Blob::as_ref),
            Some(DIGEST.as_slice())
        );
        assert_eq!(p256.get_message_type(), &Some(MessageType::Digest));
        assert_eq!(
            p256.get_signing_algorithm(),
            &Some(SigningAlgorithmSpec::EcdsaSha256)
        );
    }

    #[tokio::test]
    async fn a_signature_of_the_configured_key_is_converted_to_the_raw_form() -> KmsAeadResult<()> {
        let (provider, requests) = provider_answered_with(
            SigningAlgorithm::EcdsaP256Sha256,
            200,
            signed_body(
                KEY_ARN,
                &hex::decode(P256_SIGNATURE_DER).unwrap(),
                "ECDSA_SHA_256",
            ),
        )
        .await;

        let signature = provider.sign(p256_input()).await?;

        assert_eq!(hex::encode(signature.value()), P256_SIGNATURE);
        let body = request_body(&requests);
        assert_eq!(body["KeyId"], KEY_ARN);
        assert_eq!(body["Message"], base64(&DIGEST));
        assert_eq!(body["MessageType"], "DIGEST");
        assert_eq!(body["SigningAlgorithm"], "ECDSA_SHA_256");
        Ok(())
    }

    #[tokio::test]
    async fn a_response_for_another_key_or_algorithm_is_refused() {
        for (body, code) in [
            (
                signed_body(OTHER_KEY_ARN, &[7; 64], "ED25519_SHA_512"),
                "SIGNING_KEY_MISMATCH",
            ),
            (
                r#"{"Signature":"BwcH","SigningAlgorithm":"ED25519_SHA_512"}"#.to_string(),
                "SIGNING_KEY_MISMATCH",
            ),
            (
                signed_body(KEY_ARN, &[7; 64], "ED25519_PH_SHA_512"),
                "SIGNING_ALGORITHM_MISMATCH",
            ),
        ] {
            let (provider, _) = provider_answered_with(SigningAlgorithm::Ed25519, 200, body).await;

            assert_code(provider.sign(ed25519_input()).await, code);
        }
    }

    #[tokio::test]
    async fn a_signature_in_another_encoding_is_refused() {
        for (algorithm, input, signature, signing_algorithm) in [
            (
                SigningAlgorithm::EcdsaP256Sha256,
                p256_input(),
                hex::decode(P256_SIGNATURE).unwrap(),
                "ECDSA_SHA_256",
            ),
            (
                SigningAlgorithm::Ed25519,
                ed25519_input(),
                vec![7; 63],
                "ED25519_SHA_512",
            ),
        ] {
            let (provider, _) = provider_answered_with(
                algorithm,
                200,
                signed_body(KEY_ARN, &signature, signing_algorithm),
            )
            .await;

            assert_code(provider.sign(input).await, "SIGNATURE_ENCODING");
        }
    }

    fn public_key_body(key: &VerifyingKey, key_spec: &str) -> String {
        format!(
            r#"{{"KeyId":"{KEY_ARN}","PublicKey":"{}","KeySpec":"{key_spec}","KeyUsage":"SIGN_VERIFY"}}"#,
            base64(&key.encode(PublicKeyFormat::SpkiDer).unwrap())
        )
    }

    #[tokio::test]
    async fn the_der_public_key_of_the_configured_key_is_the_verifying_key() -> KmsAeadResult<()> {
        for (pkcs8_der, algorithm, key_spec) in [
            (
                ED25519_PKCS8_DER,
                SigningAlgorithm::Ed25519,
                "ECC_NIST_EDWARDS25519",
            ),
            (
                P256_PKCS8_DER,
                SigningAlgorithm::EcdsaP256Sha256,
                "ECC_NIST_P256",
            ),
        ] {
            let expected = verifying_key_of(pkcs8_der);
            let (provider, requests) =
                provider_answered_with(algorithm, 200, public_key_body(&expected, key_spec)).await;

            let key = provider.verifying_key().await?;

            assert_eq!(key, expected);
            assert_eq!(request_body(&requests)["KeyId"], KEY_ARN);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_public_key_of_another_key_spec_or_key_is_refused() {
        let p256 = verifying_key_of(P256_PKCS8_DER);
        let other_key = public_key_body(&p256, "ECC_NIST_P256").replace(KEY_ARN, OTHER_KEY_ARN);
        for (body, code) in [
            (
                public_key_body(&p256, "ECC_NIST_P384"),
                "SIGNING_ALGORITHM_MISMATCH",
            ),
            (other_key, "SIGNING_KEY_MISMATCH"),
        ] {
            let (provider, _) =
                provider_answered_with(SigningAlgorithm::EcdsaP256Sha256, 200, body).await;

            assert_code(provider.verifying_key().await, code);
        }
    }

    #[tokio::test]
    async fn a_refusal_is_a_signature_error_with_the_aws_code_and_throttling_stays_a_network_error()
    {
        let (denied, _) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            400,
            r#"{"__type":"AccessDeniedException","message":"not allowed"}"#.to_string(),
        )
        .await;
        let (throttled, _) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            400,
            r#"{"__type":"ThrottlingException","message":"slow down"}"#.to_string(),
        )
        .await;

        let denied = denied.sign(ed25519_input()).await.unwrap_err();
        let throttled = throttled.sign(ed25519_input()).await.unwrap_err();

        assert!(
            matches!(&denied, KmsAeadError::SignatureError(error)
                if error.public.code == "AccessDeniedException" && error.root_cause.is_some()),
            "{denied:?}"
        );
        assert!(
            matches!(&throttled, KmsAeadError::NetworkError(_)),
            "{throttled:?}"
        );
    }

    #[tokio::test]
    async fn an_input_of_another_algorithm_is_refused_before_any_request() {
        let (provider, requests) = provider_answered_with(
            SigningAlgorithm::Ed25519,
            200,
            signed_body(KEY_ARN, &[7; 64], "ED25519_SHA_512"),
        )
        .await;

        assert_code(
            provider.sign(p256_input()).await,
            "SIGNING_ALGORITHM_MISMATCH",
        );
        assert!(requests.lock().unwrap().is_empty());
    }

    /// The keys of the live tests, which the principal may sign with and read the public key of:
    /// `KMS_SIGNING_KEY_ID_ED25519` of `ECC_NIST_EDWARDS25519` and `KMS_SIGNING_KEY_ID_P256` of
    /// `ECC_NIST_P256`, by key id or key ARN.
    fn live_key_ref(algorithm: SigningAlgorithm) -> AwsKmsSigningKeyRef {
        let key_id = match algorithm {
            SigningAlgorithm::Ed25519 => "KMS_SIGNING_KEY_ID_ED25519",
            SigningAlgorithm::EcdsaP256Sha256 => "KMS_SIGNING_KEY_ID_P256",
        };
        AwsKmsSigningKeyRef::new(
            std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set"),
            std::env::var(key_id).unwrap_or_else(|_| panic!("{key_id} is set")),
            algorithm,
        )
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_keys_sign_values_that_verify_without_the_kms() -> KmsAeadResult<()> {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let provider = AwsKmsSigningProvider::new(&live_key_ref(algorithm)).await?;
            let signer = Signer::<_, TestBackend>::new(provider).await?;
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
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_key_of_another_algorithm_than_configured_is_refused() -> KmsAeadResult<()> {
        let mut key_ref = live_key_ref(SigningAlgorithm::Ed25519);
        key_ref.algorithm = SigningAlgorithm::EcdsaP256Sha256;
        let provider = AwsKmsSigningProvider::new(&key_ref).await?;

        assert_code(provider.verifying_key().await, "SIGNING_ALGORITHM_MISMATCH");
        Ok(())
    }
}
