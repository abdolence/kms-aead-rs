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

/// A Google Cloud KMS CryptoKey that wraps data encryption keys. Available with the
/// `gcp-kms-encryption-base` feature.
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

/// The request with the routing header Cloud KMS expects for `resource`.
fn routed<T>(message: T, resource: &str) -> KmsAeadResult<tonic::Request<T>> {
    let mut request = tonic::Request::new(message);
    let routing = MetadataValue::<tonic::metadata::Ascii>::try_from(format!("name={resource}"))
        .map_err(|e| {
            KmsAeadEncryptionError::create(
                "DECRYPT_KEY",
                format!("Unable to create request metadata: {e:?}").as_str(),
            )
        })?;
    request
        .metadata_mut()
        .insert("x-goog-request-params", routing);
    Ok(request)
}

// The `N` of the `…/cryptoKeyVersions/N` name that GCP KMS returns from encrypt for `key`. It is
// recorded for audit only: decrypt addresses the CryptoKey, and GCP finds the version in the
// wrapped key.
fn crypto_key_version(key: &str, name: &str) -> Option<KmsKeyVersion> {
    let version = name
        .strip_prefix(key)?
        .strip_prefix("/cryptoKeyVersions/")?;
    KmsKeyVersion::try_from(version.to_string()).ok()
}

/// Names the CryptoKey `key`, so that Cloud KMS refuses a key wrapped under another one.
fn decrypt_request(
    key: &str,
    encrypted_key: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<tonic::Request<DecryptRequest>> {
    routed(
        DecryptRequest {
            name: key.to_string(),
            ciphertext: encrypted_key.wrapped().to_vec(),
            ..Default::default()
        },
        key,
    )
}

/// Options for [`GcpKmsProvider`].
#[derive(Debug, Clone, Builder)]
pub struct GcpKmsProviderOptions {
    /// Generates data encryption keys with Cloud KMS `GenerateRandomBytes` at the HSM protection
    /// level instead of the backend's CSPRNG, at the cost of one more KMS request per key. Off by
    /// default.
    #[default = "false"]
    pub use_kms_random_gen: bool,
}

/// Wraps and unwraps data encryption keys with a Google Cloud KMS CryptoKey. Available with the
/// `gcp-kms-encryption-base` feature.
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
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        if binding.is_some() {
            return Err(KmsAeadEncryptionError::create(
                "DEK_BINDING_UNSUPPORTED",
                "This provider does not bind wrapped keys yet",
            ));
        }
        spans::in_span(kms::wrap_span(&self.kek), async {
            let encrypt_request = routed(
                EncryptRequest {
                    name: self.kek.key().to_string(),
                    plaintext: SecretValue::new(
                        encryption_key.value().ref_sensitive_value().clone(),
                    ),
                    ..Default::default()
                },
                self.kek.key(),
            )?;

            let encrypt_response = kms::timed(self.client.get().encrypt(encrypt_request))
                .await
                .map_err(KmsAeadError::from_gcp_status)?;
            let EncryptResponse {
                name, ciphertext, ..
            } = encrypt_response.into_inner();

            let key_version = crypto_key_version(self.kek.key(), &name);
            if key_version.is_none() {
                warn!(name, "No key version in the GCP KMS encrypt response");
            }

            let encrypted_key = EncryptedDataEncryptionKey::new(ciphertext, key_version);
            kms::record_wrap(&encrypted_key);
            Ok(encrypted_key)
        })
        .await
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        if binding.is_some() {
            return Err(KmsAeadEncryptionError::create(
                "DEK_BINDING_UNSUPPORTED",
                "This provider does not bind wrapped keys yet",
            ));
        }
        let span = kms::unwrap_span(&self.kek, encrypted_key.key_version());
        spans::in_span(span, async {
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
    use rvstruct::ValueStruct;

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
            &EncryptedDataEncryptionKey::new(b"wrapped".to_vec(), None),
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
            Some(KmsKeyVersion::try_from("18".to_string()).unwrap())
        );
        assert_eq!(
            crypto_key_version(
                KEY_NAME,
                "projects/my-project/locations/global/keyRings/my-ring/cryptoKeys/other-key/cryptoKeyVersions/18"
            ),
            None
        );
    }

    // Encrypted from `test-secret` with AAD `test-aad` by kms-aead 0.28.1 and by layout v1, with
    // the GCP key that the live test configures. That key stays enabled while these exist.
    #[cfg(feature = "legacy-formats")]
    const ENVELOPE_FROM_0_28_1: &str = "00000000000000720a25006b8d8e5a0486811990a63e61e59cb77be2d4807ee94aa937eb475793b6ff9cd40f06ee1e124900eaf42f6345696c4e0bed89fb241b2478c8fd3f402e2e63ec5ca95764623f36b3f8f08fbb232c99d5cb0b589c08937f279791f80dd948e5b51869556073caba2d16e85c91ba683c373719274ce985c3799cc100de5f539b0b9983475ea80b45d76133cf1103dcec14f33fd2eb793f95";
    const ENVELOPE_V1: &str = "0102313800720a25006b8d8e5a8e86a5a08f5e037793f8ef10fa761a405a1b7671502bde6bd99bd94c5bfdeea0124900eaf42f63f2b2bfd2be52a7ba228358efc9ce15c6b1add6c4425e405ef132335b8295daf42a74967f32aa8f02a314ce02c443548ea267bfa6edc17d7cfa69d90364fe040b71513c40a0234d736eb30b4b9de8963886967adda827b982dbe37531904f4b534269e8d548446a3ccd021a";

    #[test]
    fn envelope_v1_from_a_live_key_splits_into_key_version_and_wrapped_key() {
        let (v1_cipher_text, v1_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_V1).unwrap())
                .separate()
                .unwrap();

        assert_eq!(
            v1_dek.key_version(),
            Some(&KmsKeyVersion::try_from("18".to_string()).unwrap())
        );
        assert_eq!(v1_dek.wrapped().len(), 114);
        // Nonce, the 11 bytes of `test-secret` and the tag.
        assert_eq!(v1_cipher_text.value().len(), 12 + 11 + 16);
    }

    #[cfg(feature = "legacy-formats")]
    #[test]
    fn envelope_from_0_28_1_splits_into_a_wrapped_key_without_key_version() {
        let (legacy_cipher_text, legacy_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_FROM_0_28_1).unwrap())
                .separate()
                .unwrap();

        assert_eq!(legacy_dek.key_version(), None);
        assert_eq!(legacy_dek.wrapped().len(), 114);
        assert_eq!(legacy_cipher_text.value().len(), 12 + 11 + 16);
    }

    #[cfg(feature = "legacy-formats")]
    #[test]
    fn wrapped_key_stored_by_0_28_1_reads_as_a_bare_wrapped_key() {
        let (_, legacy_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_FROM_0_28_1).unwrap())
                .separate()
                .unwrap();

        assert_eq!(
            EncryptedDataEncryptionKey::try_from(legacy_dek.wrapped()).unwrap(),
            legacy_dek
        );
        assert_eq!(
            EncryptedDataEncryptionKey::try_from_hex_string(&hex::encode(legacy_dek.wrapped()))
                .unwrap(),
            legacy_dek
        );
    }

    #[tokio::test]
    #[cfg(feature = "ring")]
    #[cfg_attr(not(feature = "ci-gcp"), ignore)]
    async fn live_key_decrypts_stored_envelopes() -> KmsAeadResult<()> {
        let key_ref = GcpKmsKeyRef::new(
            std::env::var("PROJECT_ID").expect("PROJECT_ID is set"),
            std::env::var("PROJECT_LOCATION").expect("PROJECT_LOCATION is set"),
            std::env::var("KMS_KEY_RING").expect("KMS_KEY_RING is set"),
            std::env::var("KMS_KEY").expect("KMS_KEY is set"),
        );
        let encryption =
            KmsAeadEnvelope::new(GcpKmsProvider::new(&key_ref).await?, AeadBackend::Ring)?;
        let envelopes = [
            #[cfg(feature = "legacy-formats")]
            ENVELOPE_FROM_0_28_1,
            ENVELOPE_V1,
        ];
        for envelope in envelopes {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope).unwrap());
            let secret = encryption.decrypt_value(b"test-aad", &envelope).await?;
            assert_eq!(secret, SecretValue::from("test-secret"));
        }
        Ok(())
    }
}
