use rsb_derive::*;

use crate::*;
use async_trait::async_trait;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::*;
use gcloud_sdk::proto_ext::kms::*;
use gcloud_sdk::*;
use tracing::*;

use crate::ring_encryption::RingAeadEncryption;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use tonic::metadata::MetadataValue;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct GcpKmsKeyRef {
    pub google_project_id: String,
    pub location: String,
    pub key_ring: String,
    pub key: String,
}

impl GcpKmsKeyRef {
    fn to_google_ref(&self) -> String {
        format!(
            "projects/{}/locations/{}/keyRings/{}/cryptoKeys/{}",
            self.google_project_id, self.location, self.key_ring, self.key
        )
    }
}

#[derive(Debug, Clone, Builder)]
pub struct GcpKmsProviderOptions {
    #[default = "false"]
    pub use_kms_random_gen: bool,
}

pub struct GcpKmsProvider {
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    gcp_key_ref: GcpKmsKeyRef,
    options: GcpKmsProviderOptions,
}

impl GcpKmsProvider {
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, GcpKmsProviderOptions::new()).await
    }
    pub async fn with_options(
        kms_key_ref: &GcpKmsKeyRef,
        options: GcpKmsProviderOptions,
    ) -> KmsAeadResult<Self> {
        debug!(
            "Initialising Google KMS envelope encryption for {}",
            kms_key_ref.to_google_ref()
        );

        let client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>> =
            GoogleApi::from_function(
                KeyManagementServiceClient::new,
                "https://cloudkms.googleapis.com",
                None,
            )
            .await?;

        Ok(Self {
            gcp_key_ref: kms_key_ref.clone(),
            client,
            options,
        })
    }
}

#[async_trait]
impl KmsAeadRingEncryptionProvider for GcpKmsProvider {
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let mut encrypt_request = tonic::Request::new(EncryptRequest {
            name: self.gcp_key_ref.to_google_ref(),
            plaintext: secret_vault_value::SecretValue::new(
                hex::encode(encryption_key.value().ref_sensitive_value().as_slice()).into_bytes(),
            ),
            ..Default::default()
        });

        encrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                self.gcp_key_ref.to_google_ref()
            ))
            .unwrap(),
        );

        let encrypt_response = self.client.get().encrypt(encrypt_request).await?;

        Ok(EncryptedDataEncryptionKey::from(
            encrypt_response.into_inner().ciphertext,
        ))
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let mut decrypt_request = tonic::Request::new(DecryptRequest {
            name: self.gcp_key_ref.to_google_ref(),
            ciphertext: encrypted_key.value().clone(),
            ..Default::default()
        });

        decrypt_request.metadata_mut().insert(
            "x-goog-request-params",
            MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                "name={}",
                self.gcp_key_ref.to_google_ref()
            ))
            .unwrap(),
        );

        let decrypt_response = self.client.get().decrypt(decrypt_request).await?;

        Ok(DataEncryptionKey::from(
            secret_vault_value::SecretValue::new(
                hex::decode(
                    decrypt_response
                        .into_inner()
                        .plaintext
                        .ref_sensitive_value(),
                )
                .unwrap(),
            ),
        ))
    }

    async fn generate_encryption_key(
        &self,
        aead_encryption: &RingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey> {
        if self.options.use_kms_random_gen {
            let gcp_global_location = format!(
                "projects/{}/locations/{}",
                self.gcp_key_ref.google_project_id, self.gcp_key_ref.location
            );

            let mut gen_random_bytes_req = tonic::Request::new(GenerateRandomBytesRequest {
                location: gcp_global_location.clone(),
                length_bytes: aead_encryption.algo.key_len() as i32,
                protection_level: ProtectionLevel::Hsm.into(),
            });

            gen_random_bytes_req.metadata_mut().insert(
                "x-goog-request-params",
                MetadataValue::<tonic::metadata::Ascii>::try_from(format!(
                    "name={gcp_global_location}"
                ))
                .unwrap(),
            );

            let gen_random_bytes_resp = self
                .client
                .get()
                .generate_random_bytes(gen_random_bytes_req)
                .await?;
            Ok(DataEncryptionKey::from(SecretValue::from(
                gen_random_bytes_resp.into_inner().data,
            )))
        } else {
            aead_encryption.generate_data_encryption_key()
        }
    }
}
