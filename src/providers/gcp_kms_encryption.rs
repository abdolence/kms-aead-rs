use rsb_derive::*;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use gcloud_sdk::google::cloud::kms::v1::key_management_service_client::KeyManagementServiceClient;
use gcloud_sdk::google::cloud::kms::v1::*;
use gcloud_sdk::proto_ext::kms::*;
use gcloud_sdk::*;
use tracing::*;

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

pub struct GcpKmsProvider {
    client: GoogleApi<KeyManagementServiceClient<GoogleAuthMiddleware>>,
    gcp_key_ref: GcpKmsKeyRef,
}

impl GcpKmsProvider {
    pub async fn new(kms_key_ref: &GcpKmsKeyRef) -> KmsAeadResult<Self> {
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
            .await
            .map_err(|e| KmsAeadError::from(e))?;

        Ok(Self {
            gcp_key_ref: kms_key_ref.clone(),
            client,
        })
    }
}

#[async_trait]
impl KmsAeadRingEncryptionProvider for GcpKmsProvider {
    async fn encrypt_session_key(
        &self,
        session_key: SecretValue,
    ) -> KmsAeadResult<EncryptedSessionKey> {
        let mut encrypt_request = tonic::Request::new(EncryptRequest {
            name: self.gcp_key_ref.to_google_ref(),
            plaintext: secret_vault_value::SecretValue::new(
                hex::encode(session_key.ref_sensitive_value().as_slice()).into_bytes(),
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

        let encrypt_response = self
            .client
            .get()
            .encrypt(encrypt_request)
            .await
            .map_err(|e| KmsAeadError::from(e))?;

        Ok(EncryptedSessionKey(secret_vault_value::SecretValue::new(
            encrypt_response.into_inner().ciphertext,
        )))
    }

    async fn decrypt_session_key(
        &self,
        encrypted_session_secret: &EncryptedSessionKey,
    ) -> KmsAeadResult<SecretValue> {
        let mut decrypt_request = tonic::Request::new(DecryptRequest {
            name: self.gcp_key_ref.to_google_ref(),
            ciphertext: encrypted_session_secret
                .value()
                .ref_sensitive_value()
                .clone(),
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

        let decrypt_response = self
            .client
            .get()
            .decrypt(decrypt_request)
            .await
            .map_err(|e| KmsAeadError::from(e))?;

        Ok(secret_vault_value::SecretValue::new(
            hex::decode(
                decrypt_response
                    .into_inner()
                    .plaintext
                    .ref_sensitive_value(),
            )
            .unwrap(),
        ))
    }
}
