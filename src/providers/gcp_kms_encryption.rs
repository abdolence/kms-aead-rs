use rsb_derive::*;

use super::kms_key_version::read_kek_version;
use super::KmsKeyVersion;
use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::formats::asymmetric::PublicKeyEncryptedDek;
use crate::formats::PublicKeyFormat;
use crate::spans::{self, kms};
use crate::*;
use gcloud_sdk::google::cloud::kms::v1::crypto_key_version::CryptoKeyVersionAlgorithm;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::*;
use gcloud_sdk::proto_ext::kms::*;
use gcloud_sdk::*;
use tracing::*;

use secret_vault_value::SecretValue;
use tonic::metadata::MetadataValue;

/// A Google Cloud KMS CryptoKey that encrypts data encryption keys.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct GcpKmsKeyRef {
    /// The project that holds the key ring.
    pub google_project_id: String,
    /// The location of the key ring, such as `global` or `europe-west1`.
    pub location: String,
    /// The key ring that holds the key.
    pub key_ring: String,
    /// The CryptoKey name.
    pub key: String,
}

impl GcpKmsKeyRef {
    fn to_google_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.google_project_id, self.location, self.key_ring, self.key
        )
    }

    fn to_location_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}",
            self.google_project_id, self.location
        )
    }
}

/// The request with the routing header Cloud KMS expects for `resource`, failing with
/// `error_code` when `resource` cannot be a header value.
pub(super) fn request_with_routing_header<T>(
    message: T,
    resource: &str,
    error_code: &str,
) -> KmsAeadResult<tonic::Request<T>> {
    let mut request = tonic::Request::new(message);
    let routing = MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={resource}"))
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                error_code,
                format!("Unable to create request metadata: {e:?}").as_str(),
            )
        })?;
    request
        .metadata_mut()
        .insert("x-goog-request-params", routing);
    Ok(request)
}

/// The `N` of the `…/cryptoKeyVersions/N` name that Cloud KMS returns from encrypt for `key`: the
/// version that encrypted, which can be the previous primary version while a change of primary
/// propagates. Decrypt addresses the CryptoKey, and Cloud KMS finds the version in its ciphertext.
fn crypto_key_version(key: &str, name: &str) -> KmsAeadResult<KmsKeyVersion> {
    let version = name
        .strip_prefix(key)
        .and_then(|version_path| version_path.strip_prefix("/cryptoKeyVersions/"))
        .ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_KEY_VERSION",
                "The name is not a CryptoKeyVersion of the configured key",
            )
        })?;
    read_kek_version(version.as_bytes())
}

/// Encrypts under the primary version of the CryptoKey `key`.
fn encrypt_request(
    key: &str,
    dek: &DataEncryptionKey,
) -> KmsAeadResult<tonic::Request<EncryptRequest>> {
    request_with_routing_header(
        EncryptRequest {
            name: key.to_string(),
            plaintext: SecretValue::new(dek.value().ref_sensitive_value().clone()),
            ..Default::default()
        },
        key,
        "ENCRYPT_KEY",
    )
}

/// Names the CryptoKey `key`, so that Cloud KMS refuses a key encrypted under another one.
fn decrypt_request(
    key: &str,
    encrypted_dek: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<tonic::Request<DecryptRequest>> {
    request_with_routing_header(
        DecryptRequest {
            name: key.to_string(),
            ciphertext: encrypted_dek.value().to_vec(),
            ..Default::default()
        },
        key,
        "DECRYPT_KEY",
    )
}

/// The name of the CryptoKeyVersion `kek_version` of the CryptoKey `key`.
fn crypto_key_version_name(key: &str, kek_version: &KmsKeyVersion) -> String {
    format!("{key}/cryptoKeyVersions/{kek_version}")
}

/// Decrypts `block`, a DEK a public key encrypted, with the CryptoKeyVersion `kek_version` of the
/// CryptoKey `key`: an asymmetric key has no primary version, so the request names the version.
fn asymmetric_decrypt_request(
    key: &str,
    kek_version: &KmsKeyVersion,
    block: &[u8],
) -> KmsAeadResult<tonic::Request<AsymmetricDecryptRequest>> {
    let name = crypto_key_version_name(key, kek_version);
    request_with_routing_header(
        AsymmetricDecryptRequest {
            name: name.clone(),
            ciphertext: block.to_vec(),
            ..Default::default()
        },
        &name,
        "DECRYPT_KEY",
    )
}

/// A Cloud KMS client authenticated with the application default credentials.
pub(super) async fn cloud_kms_client(
) -> KmsAeadResult<GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>> {
    GoogleApi::from_function(
        KeyManagementServiceClient::new,
        "https://cloudkms.googleapis.com",
        None,
    )
    .await
    .map_err(KmsAeadError::from_gcp_error)
}

/// Options for [`GcpKmsProvider`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct GcpKmsProviderOptions {
    /// Generates data encryption keys with Cloud KMS `GenerateRandomBytes` at the HSM protection
    /// level instead of the backend's CSPRNG, at the cost of one more KMS request per key.
    /// [`DEFAULT_USE_KMS_RANDOM_GEN`](Self::DEFAULT_USE_KMS_RANDOM_GEN) by default.
    #[default = "Self::DEFAULT_USE_KMS_RANDOM_GEN"]
    pub use_kms_random_gen: bool,
}

impl GcpKmsProviderOptions {
    /// The default [`use_kms_random_gen`](Self::use_kms_random_gen): `false`, the backend's
    /// CSPRNG generates the keys.
    pub const DEFAULT_USE_KMS_RANDOM_GEN: bool = false;
}

/// Encrypts and decrypts data encryption keys with a Google Cloud KMS CryptoKey.
///
/// The code of a failed KMS call is the gRPC status code. `Unavailable`, `DeadlineExceeded`,
/// `ResourceExhausted`, `Aborted`, `Internal`, `Unknown` and `Cancelled` are a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError), any other code, such as
/// `PermissionDenied` or `NotFound`, an
/// [`EncryptionError`](crate::errors::KmsAeadError::EncryptionError).
#[derive(Clone)]
pub struct GcpKmsProvider {
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    options: GcpKmsProviderOptions,
    kek: KekRef,
    // `projects/<project>/locations/<location>`, the resource `GenerateRandomBytes` names.
    location: String,
}

impl GcpKmsProvider {
    /// A provider for the key at `kms_key_ref`, with the default options and a Cloud KMS client
    /// authenticated with the application default credentials.
    ///
    /// # Errors
    ///
    /// A [`SystemError`](crate::errors::KmsAeadError::SystemError) when the client cannot be
    /// built, such as when no credentials are found.
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, GcpKmsProviderOptions::new()).await
    }
    /// As [`new`](Self::new), with `options`.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub async fn with_options(
        kms_key_ref: &GcpKmsKeyRef,
        options: GcpKmsProviderOptions,
    ) -> KmsAeadResult<Self> {
        Ok(Self::with_client(
            kms_key_ref,
            options,
            cloud_kms_client().await?,
        ))
    }
    /// The public key of the CryptoKeyVersion `kek_version` of an asymmetric KEK, a key of
    /// purpose `ASYMMETRIC_DECRYPT`, from `GetPublicKey` with
    /// `cloudkms.cryptoKeyVersions.viewPublicKey`: for the administration, which hands it to the
    /// producers. The version is the one the response names.
    ///
    /// # Errors
    ///
    /// The KMS's errors, and `ASYMMETRIC_KEK_PUBLIC_KEY` when the version's algorithm is not
    /// `RSA_DECRYPT_OAEP_2048_SHA256`, `RSA_DECRYPT_OAEP_3072_SHA256` or
    /// `RSA_DECRYPT_OAEP_4096_SHA256`.
    pub async fn public_key(
        &self,
        kek_version: &KmsKeyVersion,
    ) -> KmsAeadResult<AsymmetricKekPublicKey> {
        spans::in_span(kms::kek_public_key_span(&self.kek), async {
            kms::record_kek_version(kek_version.as_str());
            let name = crypto_key_version_name(self.kek.key(), kek_version);
            let request = request_with_routing_header(
                GetPublicKeyRequest {
                    name: name.clone(),
                    ..Default::default()
                },
                &name,
                "GET_PUBLIC_KEY",
            )?;
            let response = kms::timed("public_key", self.kek.provider(), async {
                self.client
                    .get()
                    .get_public_key(request)
                    .await
                    .map_err(KmsAeadError::from_gcp_status)
            })
            .await?;
            Self::kek_public_key(&self.kek, response.into_inner())
        })
        .await
    }

    /// The public key of a `GetPublicKey` response for a version of `kek`: the version comes from
    /// the response's `name`, and the algorithm must be an RSA-OAEP decryption with SHA-256.
    fn kek_public_key(
        kek: &KekRef,
        public_key: PublicKey,
    ) -> KmsAeadResult<AsymmetricKekPublicKey> {
        let kek_version = crypto_key_version(kek.key(), &public_key.name).map_err(|_| {
            KmsAeadSystemError::asymmetric_public_key(
                "The Cloud KMS response names no CryptoKeyVersion of the configured key",
            )
        })?;
        let algorithm = CryptoKeyVersionAlgorithm::try_from(public_key.algorithm).ok();
        match algorithm {
            Some(
                CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha256
                | CryptoKeyVersionAlgorithm::RsaDecryptOaep3072Sha256
                | CryptoKeyVersionAlgorithm::RsaDecryptOaep4096Sha256,
            ) => AsymmetricKekPublicKey::new(
                kek.clone(),
                Some(kek_version),
                AsymmetricKekAlgorithm::RsaOaepSha256,
                public_key.pem.into_bytes(),
                PublicKeyFormat::SpkiPem,
            ),
            _ => Err(KmsAeadSystemError::asymmetric_public_key(&format!(
                "The CryptoKeyVersion {} is of {}, not of RSA_DECRYPT_OAEP_2048_SHA256, \
                 RSA_DECRYPT_OAEP_3072_SHA256 or RSA_DECRYPT_OAEP_4096_SHA256",
                public_key.name,
                algorithm.map_or("an unknown algorithm", |algorithm| algorithm.as_str_name())
            ))),
        }
    }

    /// The DEK `encrypted_dek` holds, decrypted by its CryptoKeyVersion, in the span of the caller.
    async fn asymmetric_decrypt(
        &self,
        encrypted_dek: PublicKeyEncryptedDek<'_>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let (kek_version, block) = encrypted_dek.into_versioned_block()?;
        kms::record_kek_version(kek_version.as_str());
        let request = asymmetric_decrypt_request(self.kek.key(), &kek_version, block)?;
        let response = kms::timed("decrypt_dek", self.kek.provider(), async {
            self.client
                .get()
                .asymmetric_decrypt(request)
                .await
                .map_err(KmsAeadError::from_gcp_status)
        })
        .await?;
        Ok(DataEncryptionKey::from(SecretValue::new(
            response.into_inner().plaintext,
        )))
    }

    /// A provider for the key at `kms_key_ref` that sends its requests with `client`.
    pub fn with_client(
        kms_key_ref: &GcpKmsKeyRef,
        options: GcpKmsProviderOptions,
        client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    ) -> Self {
        Self {
            client,
            options,
            kek: KekRef::new(KmsProvider::Gcp, kms_key_ref.to_google_ref()),
            location: kms_key_ref.to_location_ref(),
        }
    }
}

impl KmsAeadEncryptionProvider for GcpKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(&self.kek), async {
            let encrypt_request = encrypt_request(self.kek.key(), dek)?;

            let encrypt_response = kms::timed("encrypt_dek", self.kek.provider(), async {
                self.client
                    .get()
                    .encrypt(encrypt_request)
                    .await
                    .map_err(KmsAeadError::from_gcp_status)
            })
            .await?;
            let EncryptResponse {
                name, ciphertext, ..
            } = encrypt_response.into_inner();

            let encrypted_dek = EncryptedDataEncryptionKey::new(ciphertext);
            match crypto_key_version(self.kek.key(), &name) {
                Ok(kek_version) => {
                    kms::record_kek_version(kek_version.as_str());
                    Ok(encrypted_dek.with_kek_version(kek_version))
                }
                Err(error) => {
                    warn!(name, %error, "No key version in the GCP KMS encrypt response");
                    Ok(encrypted_dek)
                }
            }
        })
        .await
    }

    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        if !self.options.use_kms_random_gen {
            return Ok(None);
        }
        let span = kms::random_span(self.kek.provider(), Some(&self.location), len);
        spans::in_span(span, async {
            let length_bytes = i32::try_from(len).map_err(|_| {
                KmsAeadEncryptionError::create(
                    "INVALID_KEY_LENGTH",
                    &format!("GCP KMS cannot generate {len} random bytes in one request"),
                )
            })?;
            let request = request_with_routing_header(
                GenerateRandomBytesRequest {
                    location: self.location.clone(),
                    length_bytes,
                    protection_level: ProtectionLevel::Hsm.into(),
                },
                &self.location,
                "RANDOM_GENERATOR",
            )?;

            let response = kms::timed("random", self.kek.provider(), async {
                self.client
                    .get()
                    .generate_random_bytes(request)
                    .await
                    .map_err(KmsAeadError::from_gcp_status)
            })
            .await?;
            Ok(Some(SecretValue::new(response.into_inner().data)))
        })
        .await
    }
}

impl KmsAeadDecryptionProvider for GcpKmsProvider {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::decrypt_span(&self.kek), async {
            if let Some(public_key_dek) = PublicKeyEncryptedDek::read(encrypted_dek.value()) {
                return self.asymmetric_decrypt(public_key_dek?).await;
            }
            let decrypt_request = decrypt_request(self.kek.key(), encrypted_dek)?;
            let decrypt_response = kms::timed("decrypt_dek", self.kek.provider(), async {
                self.client
                    .get()
                    .decrypt(decrypt_request)
                    .await
                    .map_err(KmsAeadError::from_gcp_status)
            })
            .await?;

            Ok(DataEncryptionKey::from(
                decrypt_response.into_inner().plaintext,
            ))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gcloud_sdk::tonic::codegen::Bytes;
    use gcloud_sdk::tonic::metadata::MetadataMap;
    use gcloud_sdk::tonic::{Code, Status};

    use crate::formats::Envelope;
    use crate::test_provider::{RsaOaepSuite, TestBackend, TinkEnvelope};

    const KEY_NAME: &str =
        "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key";
    const KEY_MARKER: &str = "data-key-marker-value-of-32bytes";

    #[test]
    fn decrypt_names_the_configured_kek() -> KmsAeadResult<()> {
        let key_ref = GcpKmsKeyRef::new(
            "my-project".into(),
            "global".into(),
            "my-ring".into(),
            "my-key".into(),
        );

        let request = decrypt_request(
            &key_ref.to_google_ref(),
            &EncryptedDataEncryptionKey::new(b"encrypted-dek".to_vec()),
        )?;

        assert_eq!(request.get_ref().name, KEY_NAME);
        assert_eq!(request.get_ref().ciphertext, b"encrypted-dek");
        assert_eq!(
            request.metadata().get("x-goog-request-params").unwrap(),
            format!("name={KEY_NAME}").as_str()
        );
        Ok(())
    }

    #[test]
    fn requests_name_the_key_and_carry_no_additional_authenticated_data() -> KmsAeadResult<()> {
        let dek = DataEncryptionKey::from(SecretValue::from(KEY_MARKER));

        let encrypt = encrypt_request(KEY_NAME, &dek)?;
        let decrypt = decrypt_request(
            KEY_NAME,
            &EncryptedDataEncryptionKey::new(b"encrypted-dek".to_vec()),
        )?;

        assert_eq!(
            encrypt.get_ref(),
            &EncryptRequest {
                name: KEY_NAME.to_string(),
                plaintext: SecretValue::from(KEY_MARKER),
                ..Default::default()
            }
        );
        assert_eq!(
            encrypt.metadata().get("x-goog-request-params").unwrap(),
            format!("name={KEY_NAME}").as_str()
        );
        assert!(decrypt.get_ref().additional_authenticated_data.is_empty());
        Ok(())
    }

    #[test]
    fn an_asymmetric_decryption_names_the_crypto_key_version_of_the_encrypted_dek(
    ) -> KmsAeadResult<()> {
        let version_name = format!("{KEY_NAME}/cryptoKeyVersions/3");

        let request = asymmetric_decrypt_request(
            KEY_NAME,
            &KmsKeyVersion::try_from("3".to_string())?,
            b"block",
        )?;

        assert_eq!(
            request.get_ref(),
            &AsymmetricDecryptRequest {
                name: version_name.clone(),
                ciphertext: b"block".to_vec(),
                ..Default::default()
            }
        );
        assert_eq!(
            request.metadata().get("x-goog-request-params").unwrap(),
            format!("name={version_name}").as_str()
        );
        Ok(())
    }

    #[test]
    fn a_public_key_takes_its_version_from_the_response() -> KmsAeadResult<()> {
        let kek = KekRef::new(KmsProvider::Gcp, KEY_NAME);

        let public_key = GcpKmsProvider::kek_public_key(
            &kek,
            PublicKey {
                pem: RsaOaepSuite::of_bits(2048).spki_pem(),
                algorithm: CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha256.into(),
                name: format!("{KEY_NAME}/cryptoKeyVersions/4"),
                ..Default::default()
            },
        )?;

        assert_eq!(public_key.kek(), &kek);
        assert_eq!(
            public_key.kek_version(),
            Some(&KmsKeyVersion::try_from("4".to_string())?)
        );
        Ok(())
    }

    #[test]
    fn a_public_key_of_another_algorithm_or_key_is_refused() {
        let kek = KekRef::new(KmsProvider::Gcp, KEY_NAME);
        let other_key = KEY_NAME.replace("my-key", "other-key");
        for (algorithm, key) in [
            (
                CryptoKeyVersionAlgorithm::RsaDecryptOaep4096Sha512,
                KEY_NAME,
            ),
            (CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha1, KEY_NAME),
            (CryptoKeyVersionAlgorithm::RsaSignPss2048Sha256, KEY_NAME),
            (
                CryptoKeyVersionAlgorithm::RsaDecryptOaep2048Sha256,
                other_key.as_str(),
            ),
        ] {
            let result = GcpKmsProvider::kek_public_key(
                &kek,
                PublicKey {
                    pem: RsaOaepSuite::of_bits(2048).spki_pem(),
                    algorithm: algorithm.into(),
                    name: format!("{key}/cryptoKeyVersions/4"),
                    ..Default::default()
                },
            );
            assert!(
                matches!(&result, Err(error) if error.code() == "ASYMMETRIC_KEK_PUBLIC_KEY"),
                "{algorithm:?} {key}: {result:?}"
            );
        }
    }

    #[test]
    fn transient_statuses_are_network_errors_with_their_code() {
        for code in [
            Code::Unavailable,
            Code::DeadlineExceeded,
            Code::ResourceExhausted,
            Code::Aborted,
            Code::Internal,
            Code::Unknown,
            Code::Cancelled,
        ] {
            let error = KmsAeadError::from_gcp_status(Status::new(code, "try again later"));

            assert!(
                matches!(&error, KmsAeadError::NetworkError(_)),
                "{code:?}: {error:?}"
            );
            assert_eq!(error.code(), format!("{code:?}"));
        }
    }

    #[test]
    fn refused_requests_are_encryption_errors_with_their_code() {
        for code in [
            Code::PermissionDenied,
            Code::Unauthenticated,
            Code::NotFound,
            Code::InvalidArgument,
            Code::FailedPrecondition,
            Code::OutOfRange,
            Code::Unimplemented,
            Code::AlreadyExists,
            Code::DataLoss,
        ] {
            let error = KmsAeadError::from_gcp_status(Status::new(code, "refused"));

            assert!(
                matches!(&error, KmsAeadError::EncryptionError(_)),
                "{code:?}: {error:?}"
            );
            assert_eq!(error.code(), format!("{code:?}"));
        }
    }

    #[test]
    fn a_client_error_is_a_system_error_with_its_kind() {
        let error = KmsAeadError::from_gcp_error(gcloud_sdk::error::Error::from(
            gcloud_sdk::error::ErrorKind::CryptoProviderMissing,
        ));

        assert!(
            matches!(&error, KmsAeadError::SystemError(error)
                if error.public.code == "CryptoProviderMissing" && error.root_cause.is_some()),
            "{error:?}"
        );
    }

    #[test]
    fn provider_errors_carry_no_key_material() {
        let mut metadata = MetadataMap::new();
        metadata.insert("x-echo", KEY_MARKER.parse().unwrap());
        let status = Status::with_details_and_metadata(
            Code::Internal,
            "internal error",
            Bytes::from_static(KEY_MARKER.as_bytes()),
            metadata,
        );

        let error = KmsAeadError::from_gcp_status(status);

        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(KEY_MARKER), "{text}");
        }
    }

    #[test]
    fn key_version_is_read_from_the_crypto_key_version_name_of_the_configured_key(
    ) -> KmsAeadResult<()> {
        assert_eq!(
            crypto_key_version(
                KEY_NAME,
                "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/18"
            )?,
            KmsKeyVersion::try_from("18".to_string())?
        );
        assert!(crypto_key_version(
            KEY_NAME,
            "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/other-key/cryptoKeyVersions/18"
        )
        .is_err());
        Ok(())
    }

    /// `KmsEnvelopeAead` on the Cloud KMS key the live tests configure, which stays enabled while
    /// these exist: Tink 1.16.1 for Python, as `tests/tink_interop.py` writes them, and for
    /// ChaCha20-Poly1305, which Tink for Python lacks, Tink 1.24.0 for Java with
    /// `KmsEnvelopeAead.create(ChaCha20Poly1305Parameters.create(), …)`.
    const TINK_ENVELOPES: &[TinkEnvelope] = &[
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes128Gcm,
            aad: "orders/gcp/aes-128-gcm",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000640a25006b8d8e5ae13bbecda31384f3912487db6049ae2ead7c2bdedf73642e92e5256921d3f393123b00eaf42f63b959f2daa01603f521ae30cad418c20f4896b3102137c302bdaa57f2b7901fad92cd0f1d4ee87d821e97b852055d7f40d3925e42dcdc69eb3595e65bbccc71c225c9a11c7340db7416aab3a8aee6f165728ec168b60319f84473b0bbcbfc16f52a825c865fa31f",
        },
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes256Gcm,
            aad: "orders/gcp/aes-256-gcm",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000740a25006b8d8e5ab00c118c3b606a67e34d0f7137963ae14dae0cc70cfbb9fe97e86871e0166ff8124b00eaf42f6318880810c8a2cdb5f89e59b5f6d45b8ca2dc3533159eee2360b087938fdea20aa6971e65f4d94d5879fc9b793564402be5a1918a28adde7568d1a26d797f62c33458ac7839e2fba14afad173bcffd7fbf750cd2ab4d3cddfdc2e8d3051677d0aa452474215f065eb815d35760a533c66f96460b129fd28",
        },
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            aad: "orders/gcp/aes-256-gcm-siv",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000740a25006b8d8e5ac7c2bc09ab2b5f509988c24f4bf9a74199a28059b772359f0ef1fac1e20d762b124b00eaf42f630f94956b28e0f36bfe1d46f1b6ea46adbd81af73033d37a2abdb95238ac727b6cae2dbc44f13f245d9d1155d91435651babc20456b017c30bba280ddf49d9907084e8d7994a397e0d6c67197693d0da56d6deb66b627088e5b2a762854373f88cfa319cd61277c1e5c4fef16a30e2862bc36e62d7aad4d",
        },
        TinkEnvelope {
            algorithm: AeadAlgorithm::ChaCha20Poly1305,
            aad: "orders/gcp/chacha20-poly1305",
            plain_text: "sealed by Tink Java 1.24.0",
            value: "000000740a25006b8d8e5aa71290d3f41610c57a8eb343729c94e910e4b043b215195740b7f36897844f01124b00eaf42f63d18c7beacf3d46a38d13240bea3bc0c92f8280c0268c6156c749e91e736428b592e54d4448b6fbb0dd7e7be925fe9c91cf36fa2d38ae78027bc339d2b20088548f026bda2290b19a7120c26f0a32aad89f56e5d59252d5d774f8c5cea4228e13cd52c2f3249161da2e702b30169e7094bb842ca26a064dc6b5a179c6",
        },
    ];

    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_encrypt_reports_the_crypto_key_version_that_encrypted() -> KmsAeadResult<()> {
        let provider = GcpKmsProvider::new(&live_key_ref()).await?;

        let encrypted_dek = provider
            .encrypt_data_encryption_key(&DataEncryptionKey::from(SecretValue::from(KEY_MARKER)))
            .await?;

        let kek_version = encrypted_dek.kek_version();
        assert!(
            kek_version.is_some_and(|kek_version| kek_version
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit())),
            "{kek_version:?}"
        );
        Ok(())
    }

    /// Decrypts the values of the algorithms the test backend implements: every one but
    /// AES-256-GCM-SIV on ring.
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_key_decrypts_tink_envelopes() -> KmsAeadResult<()> {
        let key_ref = live_key_ref();
        for tink in TINK_ENVELOPES {
            let envelope = match KmsAeadEnvelope::<_, TestBackend>::with_options(
                GcpKmsProvider::new(&key_ref).await?,
                KmsAeadEnvelopeOptions::new().with_algorithm(tink.algorithm),
            ) {
                Err(KmsAeadError::UnsupportedAlgorithm(_)) => continue,
                envelope => envelope?,
            };
            let value =
                Encrypted::<SecretValue, Envelope>::try_from(hex::decode(tink.value).unwrap())?;

            let decrypted = envelope.decrypt(tink.aad.as_bytes(), &value).await?;

            assert_eq!(
                decrypted,
                SecretValue::from(tink.plain_text),
                "{:?}",
                tink.algorithm
            );
        }
        Ok(())
    }

    /// The asymmetric KEK of the live tests, `KMS_DECRYPT_KEY_RSA`: a CryptoKey of purpose
    /// `ASYMMETRIC_DECRYPT` and algorithm `RSA_DECRYPT_OAEP_3072_SHA256` in the project, location
    /// and key ring of the other live keys, read at version 1.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    fn live_rsa_key_ref() -> (GcpKmsKeyRef, KmsKeyVersion) {
        (
            GcpKmsKeyRef::new(
                std::env::var("PROJECT_ID").expect("PROJECT_ID is set"),
                std::env::var("PROJECT_LOCATION").expect("PROJECT_LOCATION is set"),
                std::env::var("KMS_KEY_RING").expect("KMS_KEY_RING is set"),
                std::env::var("KMS_DECRYPT_KEY_RSA").expect("KMS_DECRYPT_KEY_RSA is set"),
            ),
            KmsKeyVersion::try_from("1".to_string()).expect("1 is a key version"),
        )
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_key_decrypts_what_its_public_key_encrypts() -> KmsAeadResult<()> {
        use crate::providers::PublicKeyKekProvider;
        use crate::test_provider::RsaTestBackend;
        let (key_ref, kek_version) = live_rsa_key_ref();
        let reader = GcpKmsProvider::new(&key_ref).await?;

        let public_key = reader.public_key(&kek_version).await?;
        let producer = KmsAeadEnvelope::<_, RsaTestBackend>::new(PublicKeyKekProvider::<
            RsaTestBackend,
        >::new(public_key)?)?;
        let reader = KmsAeadEnvelope::<_, RsaTestBackend>::new(reader)?;
        let encrypted: Encrypted<SecretValue, Envelope> = producer
            .encrypt(b"orders/gcp/rsa", &SecretValue::from(KEY_MARKER))
            .await?;

        assert_eq!(
            producer.provider().public_key().kek(),
            reader.provider().kek()
        );
        assert_eq!(
            producer.provider().public_key().kek_version(),
            Some(&kek_version)
        );
        assert_eq!(
            reader
                .decrypt::<SecretValue>(b"orders/gcp/rsa", &encrypted)
                .await?,
            SecretValue::from(KEY_MARKER)
        );
        Ok(())
    }

    /// The administration's re-encryption decrypts through Cloud KMS and encrypts again locally.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_administration_reencrypts_a_value_the_readers_decrypt() -> KmsAeadResult<()> {
        use crate::providers::AsymmetricKekProvider;
        use crate::test_provider::RsaTestBackend;
        let (key_ref, kek_version) = live_rsa_key_ref();
        let reader = GcpKmsProvider::new(&key_ref).await?;
        let administration = KmsAeadEnvelope::<_, RsaTestBackend>::new(AsymmetricKekProvider::<
            RsaTestBackend,
            _,
        >::new(
            reader.public_key(&kek_version).await?,
            reader.clone(),
        )?)?;
        let reader = KmsAeadEnvelope::<_, RsaTestBackend>::new(reader)?;
        let encrypted: Encrypted<SecretValue, Envelope> = administration
            .encrypt(b"orders/gcp/rsa", &SecretValue::from(KEY_MARKER))
            .await?;

        let reencrypted = administration.reencrypt_dek(&encrypted).await?;

        assert_ne!(reencrypted.separate()?.1, encrypted.separate()?.1);
        assert_eq!(
            reader
                .decrypt::<SecretValue>(b"orders/gcp/rsa", &reencrypted)
                .await?,
            SecretValue::from(KEY_MARKER)
        );
        Ok(())
    }

    /// A block of another key under the live key's version is refused by Cloud KMS, with the code
    /// the book names for it.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_key_refuses_a_block_of_another_key() -> KmsAeadResult<()> {
        use crate::providers::{LocalAsymmetricKmsProvider, LocalKekId, PublicKeyKekProvider};
        use crate::test_provider::RsaTestBackend;
        let (key_ref, kek_version) = live_rsa_key_ref();
        let reader = GcpKmsProvider::new(&key_ref).await?;
        let another_key = LocalAsymmetricKmsProvider::<RsaTestBackend>::ephemeral(
            LocalKekId::try_from("another".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
        )?;
        let impostor = PublicKeyKekProvider::<RsaTestBackend>::new(AsymmetricKekPublicKey::new(
            reader.kek().clone(),
            Some(kek_version),
            AsymmetricKekAlgorithm::RsaOaepSha256,
            another_key.public_key(None)?.spki_der().to_vec(),
            PublicKeyFormat::SpkiDer,
        )?)?;
        let encrypted_dek = impostor
            .encrypt_data_encryption_key(&DataEncryptionKey::from(SecretValue::from(KEY_MARKER)))
            .await?;

        let result = reader.decrypt_data_encryption_key(&encrypted_dek).await;

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "InvalidArgument"),
            "{result:?}"
        );
        Ok(())
    }

    fn live_key_ref() -> GcpKmsKeyRef {
        GcpKmsKeyRef::new(
            std::env::var("PROJECT_ID").expect("PROJECT_ID is set"),
            std::env::var("PROJECT_LOCATION").expect("PROJECT_LOCATION is set"),
            std::env::var("KMS_KEY_RING").expect("KMS_KEY_RING is set"),
            std::env::var("KMS_KEY").expect("KMS_KEY is set"),
        )
    }

    // Encrypted from `test-secret` with AAD `test-aad` by kms-aead 0.28.1 and 0.29, under their
    // default ChaCha20-Poly1305 and the GCP key that the live tests configure. That key stays
    // enabled while these exist.
    #[cfg(feature = "legacy-formats")]
    const ENVELOPE_FROM_0_28_1: &str = "00000000000000720a25006b8d8e5a0486811990a63e61e59cb77be2d4807ee94aa937eb475793b6ff9cd40f06ee1e124900eaf42f6345696c4e0bed89fb241b2478c8fd3f402e2e63ec5ca95764623f36b3f8f08fbb232c99d5cb0b589c08937f279791f80dd948e5b51869556073caba2d16e85c91ba683c373719274ce985c3799cc100de5f539b0b9983475ea80b45d76133cf1103dcec14f33fd2eb793f95";
    #[cfg(feature = "legacy-formats")]
    const ENVELOPE_FROM_0_29: &str = "0102313800720a25006b8d8e5a8e86a5a08f5e037793f8ef10fa761a405a1b7671502bde6bd99bd94c5bfdeea0124900eaf42f63f2b2bfd2be52a7ba228358efc9ce15c6b1add6c4425e405ef132335b8295daf42a74967f32aa8f02a314ce02c443548ea267bfa6edc17d7cfa69d90364fe040b71513c40a0234d736eb30b4b9de8963886967adda827b982dbe37531904f4b534269e8d548446a3ccd021a";

    #[tokio::test]
    #[cfg(feature = "legacy-formats")]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn live_key_decrypts_and_upgrades_stored_envelopes() -> KmsAeadResult<()> {
        let encryption = KmsAeadEnvelope::<_, TestBackend>::with_options(
            GcpKmsProvider::new(&live_key_ref()).await?,
            KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
        )?;
        for stored in [ENVELOPE_FROM_0_28_1, ENVELOPE_FROM_0_29] {
            let stored =
                Encrypted::<SecretValue, Envelope>::try_from(hex::decode(stored).unwrap())?;

            let decrypted = encryption.decrypt(b"test-aad", &stored).await?;
            let upgraded = encryption
                .upgrade_legacy_value(b"test-aad", &stored)
                .await?;

            assert_eq!(decrypted, SecretValue::from("test-secret"));
            let upgraded = upgraded.expect("a legacy value is upgraded");
            assert_eq!(upgraded.value()[0], 0x00);
            assert_eq!(
                encryption.decrypt(b"test-aad", &upgraded).await?,
                SecretValue::from("test-secret")
            );
            assert!(encryption
                .upgrade_legacy_value(b"test-aad", &upgraded)
                .await?
                .is_none());
        }
        Ok(())
    }
}
