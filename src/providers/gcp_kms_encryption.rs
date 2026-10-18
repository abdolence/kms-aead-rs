use rsb_derive::*;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::spans::{self, kms};
use crate::*;
use async_trait::async_trait;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::*;
use gcloud_sdk::proto_ext::kms::*;
use gcloud_sdk::*;
use tracing::*;

use secret_vault_value::SecretValue;
use tonic::metadata::MetadataValue;

/// A Google Cloud KMS CryptoKey that wraps data encryption keys.
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
fn routed<T>(message: T, resource: &str, error_code: &str) -> KmsAeadResult<tonic::Request<T>> {
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

/// The `N` of the `…/cryptoKeyVersions/N` name that Cloud KMS returns from encrypt for `key`,
/// for the span only: decrypt addresses the CryptoKey, and Cloud KMS finds the version in its
/// ciphertext.
fn crypto_key_version<'n>(key: &str, name: &'n str) -> Option<&'n str> {
    name.strip_prefix(key)?.strip_prefix("/cryptoKeyVersions/")
}

/// Wraps under the primary version of the CryptoKey `key`.
fn encrypt_request(
    key: &str,
    encryption_key: &DataEncryptionKey,
) -> KmsAeadResult<tonic::Request<EncryptRequest>> {
    routed(
        EncryptRequest {
            name: key.to_string(),
            plaintext: SecretValue::new(encryption_key.value().ref_sensitive_value().clone()),
            ..Default::default()
        },
        key,
        "ENCRYPT_KEY",
    )
}

/// Names the CryptoKey `key`, so that Cloud KMS refuses a key wrapped under another one.
fn decrypt_request(
    key: &str,
    encrypted_key: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<tonic::Request<DecryptRequest>> {
    routed(
        DecryptRequest {
            name: key.to_string(),
            ciphertext: encrypted_key.value().clone(),
            ..Default::default()
        },
        key,
        "DECRYPT_KEY",
    )
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

/// Wraps and unwraps data encryption keys with a Google Cloud KMS CryptoKey.
///
/// A failed KMS call is a [`NetworkError`](crate::errors::KmsAeadError::NetworkError) whose code
/// is the gRPC status code, such as `PermissionDenied` or `NotFound`.
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
        let client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await
            .map_err(KmsAeadError::from_gcp_error)?;

        Ok(Self::with_client(kms_key_ref, options, client))
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
            kek: KekRef::new(KekProvider::Gcp, kms_key_ref.to_google_ref()),
            location: kms_key_ref.to_location_ref(),
        }
    }
}

#[async_trait]
impl KmsAeadEncryptionProvider for GcpKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::wrap_span(&self.kek), async {
            let encrypt_request = encrypt_request(self.kek.key(), encryption_key)?;

            let encrypt_response = kms::timed(self.client.get().encrypt(encrypt_request))
                .await
                .map_err(KmsAeadError::from_gcp_status)?;
            let EncryptResponse {
                name, ciphertext, ..
            } = encrypt_response.into_inner();

            match crypto_key_version(self.kek.key(), &name) {
                Some(key_version) => kms::record_key_version(key_version),
                None => warn!(name, "No key version in the GCP KMS encrypt response"),
            }
            Ok(EncryptedDataEncryptionKey::new(ciphertext))
        })
        .await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::unwrap_span(&self.kek), async {
            let decrypt_request = decrypt_request(self.kek.key(), encrypted_key)?;
            let decrypt_response = kms::timed(self.client.get().decrypt(decrypt_request))
                .await
                .map_err(KmsAeadError::from_gcp_status)?;

            Ok(DataEncryptionKey::from(
                decrypt_response.into_inner().plaintext,
            ))
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
            let request = routed(
                GenerateRandomBytesRequest {
                    location: self.location.clone(),
                    length_bytes,
                    protection_level: ProtectionLevel::Hsm.into(),
                },
                &self.location,
                "RANDOM_GENERATOR",
            )?;

            let response = kms::timed(self.client.get().generate_random_bytes(request))
                .await
                .map_err(KmsAeadError::from_gcp_status)?;
            Ok(Some(SecretValue::new(response.into_inner().data)))
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

    use crate::test_provider::{TestBackend, TinkEnvelope};

    const KEY_NAME: &str =
        "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key";
    const KEY_MARKER: &str = "data-key-marker-value-of-32bytes";

    #[test]
    fn unwrap_names_the_configured_kek() -> KmsAeadResult<()> {
        let key_ref = GcpKmsKeyRef::new(
            "my-project".into(),
            "global".into(),
            "my-ring".into(),
            "my-key".into(),
        );

        let request = decrypt_request(
            &key_ref.to_google_ref(),
            &EncryptedDataEncryptionKey::new(b"wrapped".to_vec()),
        )?;

        assert_eq!(request.get_ref().name, KEY_NAME);
        assert_eq!(request.get_ref().ciphertext, b"wrapped");
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
            &EncryptedDataEncryptionKey::new(b"wrapped".to_vec()),
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
    fn a_status_is_a_network_error_with_its_code() {
        let error = KmsAeadError::from_gcp_status(Status::permission_denied(
            "Permission 'cloudkms.cryptoKeyVersions.useToDecrypt' denied",
        ));

        assert!(
            matches!(&error, KmsAeadError::NetworkError(error) if error.public.code == "PermissionDenied"),
            "{error:?}"
        );
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
    fn key_version_is_read_from_the_crypto_key_version_name_of_the_configured_key() {
        assert_eq!(
            crypto_key_version(
                KEY_NAME,
                "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/my-key/cryptoKeyVersions/18"
            ),
            Some("18")
        );
        assert_eq!(
            crypto_key_version(
                KEY_NAME,
                "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/other-key/cryptoKeyVersions/18"
            ),
            None
        );
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
            let value = CipherTextWithEncryptedKey::from(hex::decode(tink.value).unwrap());

            let decrypted = envelope.decrypt_value(tink.aad.as_bytes(), &value).await?;

            assert_eq!(
                decrypted,
                SecretValue::from(tink.plain_text),
                "{:?}",
                tink.algorithm
            );
        }
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
            let stored = CipherTextWithEncryptedKey::from(hex::decode(stored).unwrap());

            let decrypted = encryption.decrypt_value(b"test-aad", &stored).await?;
            let upgraded = encryption
                .upgrade_legacy_value(b"test-aad", &stored)
                .await?;

            assert_eq!(decrypted, SecretValue::from("test-secret"));
            let upgraded = upgraded.expect("a legacy value is upgraded");
            assert_eq!(upgraded.value()[0], 0x00);
            assert_eq!(
                encryption.decrypt_value(b"test-aad", &upgraded).await?,
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
