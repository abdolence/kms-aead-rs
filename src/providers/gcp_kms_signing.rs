use std::num::NonZeroU32;

use gcloud_sdk::google::cloud::kms::v1::crypto_key_version::CryptoKeyVersionAlgorithm;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::{
    digest, AsymmetricSignRequest, AsymmetricSignResponse, Digest, GetPublicKeyRequest, PublicKey,
};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};
use rsb_derive::Builder;

use super::gcp_kms_encryption::{cloud_kms_client, request_with_routing_header};
use crate::errors::{KmsAeadError, KmsAeadSignatureError};
use crate::formats::PublicKeyFormat;
use crate::signing::{
    KmsSigningProvider, RawSignature, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
};
use crate::spans::{self, kms};
use crate::{KmsAeadResult, KmsProvider};

/// A Google Cloud KMS CryptoKeyVersion that signs.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct GcpKmsSigningKeyRef {
    /// The project that holds the key ring.
    pub google_project_id: String,
    /// The location of the key ring, such as `global` or `europe-west1`.
    pub location: String,
    /// The key ring that holds the key.
    pub key_ring: String,
    /// The CryptoKey name.
    pub key: String,
    /// The CryptoKeyVersion, the `N` of `cryptoKeyVersions/N`. Asymmetric keys have no primary
    /// version, so a signer names one.
    pub version: NonZeroU32,
    /// [`Ed25519`](SigningAlgorithm::Ed25519) for an `EC_SIGN_ED25519` version,
    /// [`EcdsaP256Sha256`](SigningAlgorithm::EcdsaP256Sha256) for `EC_SIGN_P256_SHA256`.
    pub algorithm: SigningAlgorithm,
}

impl GcpKmsSigningKeyRef {
    /// The resource name of the CryptoKeyVersion.
    fn to_google_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}/cryptoKeyVersions/{}",
            self.google_project_id, self.location, self.key_ring, self.key, self.version
        )
    }

    /// The Cloud KMS algorithm of a version that signs with [`algorithm`](Self::algorithm).
    fn google_algorithm(&self) -> CryptoKeyVersionAlgorithm {
        match self.algorithm {
            SigningAlgorithm::Ed25519 => CryptoKeyVersionAlgorithm::EcSignEd25519,
            SigningAlgorithm::EcdsaP256Sha256 => CryptoKeyVersionAlgorithm::EcSignP256Sha256,
        }
    }
}

/// Signs with one CryptoKeyVersion of Google Cloud KMS.
///
/// The Ed25519 pre-image goes to `AsymmetricSign` as `data` and a P-256 signer sends the SHA-256
/// of the pre-image as `digest`, each with its CRC32C checksum. Cloud KMS returns a P-256
/// signature in DER, which is converted to `r || s`. A response whose checksums fail is a
/// `SIGNATURE_ENCODING` error, and one that names another CryptoKeyVersion
/// `SIGNING_KEY_MISMATCH`.
///
/// The code of a failed KMS call is the gRPC status code. The statuses that
/// [`GcpKmsProvider`](super::GcpKmsProvider) returns as a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError) are one here too, and any other
/// code, such as `PermissionDenied` or `NotFound`, is a
/// [`SignatureError`](crate::errors::KmsAeadError::SignatureError).
///
/// The principal needs `cloudkms.cryptoKeyVersions.useToSign` and
/// `cloudkms.cryptoKeyVersions.viewPublicKey`, as in `roles/cloudkms.signerVerifier`.
#[derive(Clone)]
pub struct GcpKmsSigningProvider {
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    signing_key: SigningKeyRef,
    algorithm: SigningAlgorithm,
    expected_algorithm: CryptoKeyVersionAlgorithm,
}

impl GcpKmsSigningProvider {
    /// A provider for the version at `key_ref`, with a Cloud KMS client authenticated with the
    /// application default credentials. It sends no request.
    ///
    /// # Errors
    ///
    /// A [`SystemError`](crate::errors::KmsAeadError::SystemError) when the client cannot be
    /// built, such as when no credentials are found.
    pub async fn new(key_ref: &GcpKmsSigningKeyRef) -> KmsAeadResult<Self> {
        Ok(Self::with_client(key_ref, cloud_kms_client().await?))
    }

    /// A provider for the version at `key_ref` that sends its requests with `client`.
    pub fn with_client(
        key_ref: &GcpKmsSigningKeyRef,
        client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    ) -> Self {
        Self {
            client,
            signing_key: SigningKeyRef::new(KmsProvider::Gcp, key_ref.to_google_ref()),
            algorithm: key_ref.algorithm,
            expected_algorithm: key_ref.google_algorithm(),
        }
    }
}

/// `AsymmetricSign` for the CryptoKeyVersion `name`: the pre-image as `data` for Ed25519 and the
/// digest for P-256, each with its CRC32C checksum.
fn sign_request(
    name: &str,
    input: &SigningInput<'_>,
) -> KmsAeadResult<gcloud_sdk::tonic::Request<AsymmetricSignRequest>> {
    let message = match input {
        SigningInput::Ed25519 { pre_image } => AsymmetricSignRequest {
            name: name.to_string(),
            data: pre_image.to_vec(),
            data_crc32c: Some(crc32c_checksum(pre_image)),
            ..Default::default()
        },
        SigningInput::EcdsaP256Sha256 { digest, .. } => AsymmetricSignRequest {
            name: name.to_string(),
            digest: Some(Digest {
                digest: Some(digest::Digest::Sha256(digest.to_vec())),
            }),
            digest_crc32c: Some(crc32c_checksum(digest.as_slice())),
            ..Default::default()
        },
    };
    request_with_routing_header(message, name, "SIGN_KEY")
}

/// The CRC32C of `bytes` as the `int64` field of Cloud KMS messages.
fn crc32c_checksum(bytes: &[u8]) -> i64 {
    i64::from(crc32c::crc32c(bytes))
}

/// The raw signature of a response to the request for `input`, once the response names the
/// CryptoKeyVersion `name`, Cloud KMS verified the checksum of the input and the signature
/// matches its checksum.
fn raw_signature(
    response: AsymmetricSignResponse,
    name: &str,
    input: &SigningInput<'_>,
) -> KmsAeadResult<RawSignature> {
    if response.name != name {
        return Err(KmsAeadSignatureError::create(
            "SIGNING_KEY_MISMATCH",
            "The Cloud KMS response names another CryptoKeyVersion than the configured one",
        ));
    }
    let input_verified = match input {
        SigningInput::Ed25519 { .. } => response.verified_data_crc32c,
        SigningInput::EcdsaP256Sha256 { .. } => response.verified_digest_crc32c,
    };
    if !input_verified {
        return Err(KmsAeadSignatureError::create(
            "SIGNATURE_ENCODING",
            "Cloud KMS did not verify the CRC32C checksum of the request",
        ));
    }
    if response.signature_crc32c != Some(crc32c_checksum(&response.signature)) {
        return Err(KmsAeadSignatureError::create(
            "SIGNATURE_ENCODING",
            "The CRC32C checksum of the Cloud KMS signature is missing or does not match",
        ));
    }
    match input {
        SigningInput::Ed25519 { .. } => RawSignature::new(input.algorithm(), response.signature),
        SigningInput::EcdsaP256Sha256 { .. } => {
            RawSignature::from_ecdsa_p256_der(&response.signature)
        }
    }
}

/// The verifying key of a `GetPublicKey` response for the CryptoKeyVersion `name`, which the
/// response must name and which must be of `expected`'s algorithm.
fn verifying_key(
    public_key: PublicKey,
    name: &str,
    algorithm: SigningAlgorithm,
    expected: CryptoKeyVersionAlgorithm,
) -> KmsAeadResult<VerifyingKey> {
    if public_key.name != name {
        return Err(KmsAeadSignatureError::create(
            "SIGNING_KEY_MISMATCH",
            "The Cloud KMS response names another CryptoKeyVersion than the configured one",
        ));
    }
    if public_key.algorithm != i32::from(expected) {
        return Err(KmsAeadSignatureError::create(
            "SIGNING_ALGORITHM_MISMATCH",
            &format!(
                "The CryptoKeyVersion {name} is not of {}, the algorithm of {algorithm}",
                expected.as_str_name()
            ),
        ));
    }
    VerifyingKey::from_bytes(
        algorithm,
        public_key.pem.as_bytes(),
        PublicKeyFormat::SpkiPem,
    )
}

impl KmsSigningProvider for GcpKmsSigningProvider {
    fn signing_key(&self) -> &SigningKeyRef {
        &self.signing_key
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
        spans::in_span(kms::sign_span(&self.signing_key), async {
            input.ensure_algorithm(&self.signing_key, self.algorithm)?;
            let request = sign_request(self.signing_key.key(), &input)
                .map_err(KmsAeadError::into_signature_error)?;

            let response = kms::timed("sign", self.signing_key.provider(), async {
                self.client
                    .get()
                    .asymmetric_sign(request)
                    .await
                    .map_err(|status| KmsAeadError::from_gcp_status(status).into_signature_error())
            })
            .await?;
            raw_signature(response.into_inner(), self.signing_key.key(), &input)
        })
        .await
    }

    async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
        spans::in_span(kms::public_key_span(&self.signing_key), async {
            let request = request_with_routing_header(
                GetPublicKeyRequest {
                    name: self.signing_key.key().to_string(),
                    ..Default::default()
                },
                self.signing_key.key(),
                "GET_PUBLIC_KEY",
            )
            .map_err(KmsAeadError::into_signature_error)?;

            let response = kms::timed("public_key", self.signing_key.provider(), async {
                self.client
                    .get()
                    .get_public_key(request)
                    .await
                    .map_err(|status| KmsAeadError::from_gcp_status(status).into_signature_error())
            })
            .await?;
            verifying_key(
                response.into_inner(),
                self.signing_key.key(),
                self.algorithm,
                self.expected_algorithm,
            )
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::{Signer, Verifier, VerifyingKeySet};
    use crate::test_provider::{
        assert_code, verifying_key_of, Invoice, TestBackend, ED25519_PKCS8_DER, INVOICE_PAYLOAD,
        P256_PKCS8_DER, P256_SIGNATURE, P256_SIGNATURE_DER,
    };
    use gcloud_sdk::tonic::{Code, Status};

    const VERSION_NAME: &str = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/3";
    const OTHER_VERSION_NAME: &str = "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/4";
    const DIGEST: [u8; 32] = [0x5a; 32];
    const PRE_IMAGE: [u8; 46] = [0x11; 46];

    fn key_ref(algorithm: SigningAlgorithm) -> GcpKmsSigningKeyRef {
        GcpKmsSigningKeyRef::new(
            "my-project".into(),
            "global".into(),
            "my-ring".into(),
            "my-key".into(),
            NonZeroU32::new(3).unwrap(),
            algorithm,
        )
    }

    fn ed25519_input() -> SigningInput<'static> {
        SigningInput::Ed25519 {
            pre_image: &PRE_IMAGE,
        }
    }

    fn p256_input() -> SigningInput<'static> {
        SigningInput::EcdsaP256Sha256 {
            pre_image: &PRE_IMAGE,
            digest: &DIGEST,
        }
    }

    /// What Cloud KMS answers to `AsymmetricSign` with `signature`: the checksums verified and
    /// the signature's own checksum.
    fn signed(signature: Vec<u8>) -> AsymmetricSignResponse {
        AsymmetricSignResponse {
            signature_crc32c: Some(crc32c_checksum(&signature)),
            signature,
            verified_digest_crc32c: true,
            verified_data_crc32c: true,
            name: VERSION_NAME.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_key_version_is_named_by_its_resource_name() {
        assert_eq!(
            key_ref(SigningAlgorithm::Ed25519).to_google_ref(),
            VERSION_NAME
        );
    }

    #[test]
    fn ed25519_sends_the_pre_image_and_p256_sends_the_digest_each_with_its_checksum(
    ) -> KmsAeadResult<()> {
        let ed25519 = sign_request(VERSION_NAME, &ed25519_input())?;
        let p256 = sign_request(VERSION_NAME, &p256_input())?;

        assert_eq!(
            ed25519.get_ref(),
            &AsymmetricSignRequest {
                name: VERSION_NAME.to_string(),
                data: PRE_IMAGE.to_vec(),
                data_crc32c: Some(i64::from(crc32c::crc32c(&PRE_IMAGE))),
                ..Default::default()
            }
        );
        assert_eq!(
            p256.get_ref(),
            &AsymmetricSignRequest {
                name: VERSION_NAME.to_string(),
                digest: Some(Digest {
                    digest: Some(digest::Digest::Sha256(DIGEST.to_vec()))
                }),
                digest_crc32c: Some(i64::from(crc32c::crc32c(&DIGEST))),
                ..Default::default()
            }
        );
        assert_eq!(
            p256.metadata().get("x-goog-request-params").unwrap(),
            format!("name={VERSION_NAME}").as_str()
        );
        Ok(())
    }

    #[test]
    fn a_checked_response_is_the_raw_signature() -> KmsAeadResult<()> {
        let ed25519 = raw_signature(signed(vec![7; 64]), VERSION_NAME, &ed25519_input())?;
        let p256 = raw_signature(
            signed(hex::decode(P256_SIGNATURE_DER).unwrap()),
            VERSION_NAME,
            &p256_input(),
        )?;

        assert_eq!(ed25519.value(), [7; 64]);
        assert_eq!(hex::encode(p256.value()), P256_SIGNATURE);
        Ok(())
    }

    #[test]
    fn a_response_for_another_version_is_a_key_mismatch() {
        let response = AsymmetricSignResponse {
            name: OTHER_VERSION_NAME.to_string(),
            ..signed(vec![7; 64])
        };

        assert_code(
            raw_signature(response, VERSION_NAME, &ed25519_input()),
            "SIGNING_KEY_MISMATCH",
        );
    }

    #[test]
    fn a_checksum_that_failed_is_an_encoding_error() {
        let unverified_data = AsymmetricSignResponse {
            verified_data_crc32c: false,
            ..signed(vec![7; 64])
        };
        let unverified_digest = AsymmetricSignResponse {
            verified_digest_crc32c: false,
            ..signed(hex::decode(P256_SIGNATURE_DER).unwrap())
        };
        let altered_signature = AsymmetricSignResponse {
            signature_crc32c: Some(0),
            ..signed(vec![7; 64])
        };
        let unchecked_signature = AsymmetricSignResponse {
            signature_crc32c: None,
            ..signed(vec![7; 64])
        };

        for (response, input) in [
            (unverified_data, ed25519_input()),
            (unverified_digest, p256_input()),
            (altered_signature, ed25519_input()),
            (unchecked_signature, ed25519_input()),
        ] {
            assert_code(
                raw_signature(response, VERSION_NAME, &input),
                "SIGNATURE_ENCODING",
            );
        }
    }

    #[test]
    fn a_signature_in_another_encoding_is_refused() {
        // The P-256 signature in raw form where Cloud KMS returns DER, and an Ed25519 signature
        // of the wrong length.
        for (signature, input) in [
            (hex::decode(P256_SIGNATURE).unwrap(), p256_input()),
            (vec![7; 63], ed25519_input()),
        ] {
            assert_code(
                raw_signature(signed(signature), VERSION_NAME, &input),
                "SIGNATURE_ENCODING",
            );
        }
    }

    fn public_key_of(key: &VerifyingKey, algorithm: CryptoKeyVersionAlgorithm) -> PublicKey {
        let pem = String::from_utf8(key.encode(PublicKeyFormat::SpkiPem).unwrap()).unwrap();
        PublicKey {
            pem,
            algorithm: algorithm.into(),
            name: VERSION_NAME.to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn the_pem_of_the_response_is_the_verifying_key() -> KmsAeadResult<()> {
        for (pkcs8_der, algorithm, google) in [
            (
                ED25519_PKCS8_DER,
                SigningAlgorithm::Ed25519,
                CryptoKeyVersionAlgorithm::EcSignEd25519,
            ),
            (
                P256_PKCS8_DER,
                SigningAlgorithm::EcdsaP256Sha256,
                CryptoKeyVersionAlgorithm::EcSignP256Sha256,
            ),
        ] {
            let expected = verifying_key_of(pkcs8_der);

            let key = verifying_key(
                public_key_of(&expected, google),
                VERSION_NAME,
                algorithm,
                google,
            )?;

            assert_eq!(key, expected);
        }
        Ok(())
    }

    #[test]
    fn a_public_key_without_the_configured_version_name_or_algorithm_or_pem_is_refused() {
        let p256 = verifying_key_of(P256_PKCS8_DER);
        let call = |public_key: PublicKey| {
            verifying_key(
                public_key,
                VERSION_NAME,
                SigningAlgorithm::EcdsaP256Sha256,
                CryptoKeyVersionAlgorithm::EcSignP256Sha256,
            )
        };

        assert_code(
            call(public_key_of(
                &p256,
                CryptoKeyVersionAlgorithm::EcSignP384Sha384,
            )),
            "SIGNING_ALGORITHM_MISMATCH",
        );
        assert_code(
            call(PublicKey {
                name: OTHER_VERSION_NAME.to_string(),
                ..public_key_of(&p256, CryptoKeyVersionAlgorithm::EcSignP256Sha256)
            }),
            "SIGNING_KEY_MISMATCH",
        );
        assert_code(
            call(PublicKey {
                name: String::new(),
                ..public_key_of(&p256, CryptoKeyVersionAlgorithm::EcSignP256Sha256)
            }),
            "SIGNING_KEY_MISMATCH",
        );
        assert_code(
            call(PublicKey {
                pem: "not a PEM".to_string(),
                ..public_key_of(&p256, CryptoKeyVersionAlgorithm::EcSignP256Sha256)
            }),
            "INVALID_PUBLIC_KEY",
        );
    }

    #[test]
    fn a_status_is_a_network_error_when_a_retry_may_clear_it_and_a_signature_error_otherwise() {
        let unavailable = KmsAeadError::from_gcp_status(Status::new(Code::Unavailable, ""))
            .into_signature_error();
        let denied = KmsAeadError::from_gcp_status(Status::new(Code::PermissionDenied, ""))
            .into_signature_error();

        assert!(matches!(unavailable, KmsAeadError::NetworkError(_)));
        assert!(
            matches!(&denied, KmsAeadError::SignatureError(error)
                if error.public.code == "PermissionDenied"),
            "{denied:?}"
        );
    }

    /// The CryptoKeys of the live tests, in the project, location and key ring that the
    /// encryption tests configure, each at version 1: `KMS_SIGNING_KEY_ED25519` of
    /// `EC_SIGN_ED25519` and `KMS_SIGNING_KEY_P256` of `EC_SIGN_P256_SHA256`.
    fn live_key_ref(algorithm: SigningAlgorithm) -> GcpKmsSigningKeyRef {
        let key = match algorithm {
            SigningAlgorithm::Ed25519 => "KMS_SIGNING_KEY_ED25519",
            SigningAlgorithm::EcdsaP256Sha256 => "KMS_SIGNING_KEY_P256",
        };
        GcpKmsSigningKeyRef::new(
            std::env::var("PROJECT_ID").expect("PROJECT_ID is set"),
            std::env::var("PROJECT_LOCATION").expect("PROJECT_LOCATION is set"),
            std::env::var("KMS_KEY_RING").expect("KMS_KEY_RING is set"),
            std::env::var(key).unwrap_or_else(|_| panic!("{key} is set")),
            NonZeroU32::MIN,
            algorithm,
        )
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_keys_sign_values_that_verify_without_the_kms() -> KmsAeadResult<()> {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let provider = GcpKmsSigningProvider::new(&live_key_ref(algorithm)).await?;
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
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_public_key_response_names_the_configured_version_and_is_the_verifying_key(
    ) -> KmsAeadResult<()> {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let key_ref = live_key_ref(algorithm);
            let name = key_ref.to_google_ref();
            let provider = GcpKmsSigningProvider::new(&key_ref).await?;
            let request = request_with_routing_header(
                GetPublicKeyRequest {
                    name: name.clone(),
                    ..Default::default()
                },
                &name,
                "GET_PUBLIC_KEY",
            )?;

            let response = provider
                .client
                .get()
                .get_public_key(request)
                .await
                .map_err(KmsAeadError::from_gcp_status)?
                .into_inner();

            assert_eq!(response.name, name, "{algorithm}");
            assert_eq!(
                VerifyingKey::from_bytes(
                    algorithm,
                    response.pem.as_bytes(),
                    PublicKeyFormat::SpkiPem
                )?,
                provider.verifying_key().await?,
                "{algorithm}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_key_of_another_algorithm_than_configured_is_refused() -> KmsAeadResult<()> {
        let mut key_ref = live_key_ref(SigningAlgorithm::Ed25519);
        key_ref.algorithm = SigningAlgorithm::EcdsaP256Sha256;
        let provider = GcpKmsSigningProvider::new(&key_ref).await?;

        assert_code(provider.verifying_key().await, "SIGNING_ALGORITHM_MISMATCH");
        Ok(())
    }
}
