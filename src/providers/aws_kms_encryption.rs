use rsb_derive::*;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use aws_sdk_kms::types::Blob;
use tracing::*;

use crate::ring_encryption::KmsAeadRingAeadEncryption;
use crate::ring_envelope_encryption::KmsAeadRingEncryptionProvider;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsKmsKeyRef {
    pub account_id: String,
    pub key_id: String,
    pub aws_region: Option<aws_sdk_kms::Region>,
}

impl AwsKmsKeyRef {
    pub fn to_key_arn(&self) -> String {
        self.aws_region
            .as_ref()
            .map(|region| {
                format!(
                    "arn:aws:kms:{}:{}:key/{}",
                    region, self.account_id, self.key_id
                )
            })
            .unwrap_or_else(|| self.key_id.clone())
    }
}

#[derive(Debug, Clone, Builder)]
pub struct AwsKmsProviderOptions {
    #[default = "false"]
    pub use_kms_random_gen: bool,
}

pub struct AwsKmsProvider {
    aws_key_ref: AwsKmsKeyRef,
    client: aws_sdk_kms::Client,
    options: AwsKmsProviderOptions,
}

impl AwsKmsProvider {
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, AwsKmsProviderOptions::new()).await
    }

    pub async fn with_options(
        kms_key_ref: &AwsKmsKeyRef,
        options: AwsKmsProviderOptions,
    ) -> KmsAeadResult<Self> {
        debug!(
            "Initialising AWS KMS envelope encryption for {}",
            kms_key_ref.to_key_arn()
        );

        let shared_config = aws_config::load_from_env().await;

        let effective_kms_ref = if kms_key_ref.aws_region.is_none() {
            kms_key_ref
                .clone()
                .opt_aws_region(shared_config.region().cloned())
        } else {
            kms_key_ref.clone()
        };

        let client = aws_sdk_kms::Client::new(&shared_config);

        Ok(Self {
            aws_key_ref: effective_kms_ref,
            client,
            options,
        })
    }
}

#[async_trait]
impl KmsAeadRingEncryptionProvider for AwsKmsProvider {
    async fn encrypt_session_key(
        &self,
        session_key: SecretValue,
    ) -> KmsAeadResult<EncryptedSessionKey> {
        match self
            .client
            .encrypt()
            .set_key_id(Some(self.aws_key_ref.to_key_arn()))
            .set_plaintext(Some(Blob::new(
                hex::encode(session_key.ref_sensitive_value().as_slice()).into_bytes(),
            )))
            .send()
            .await
        {
            Ok(encrypt_response) => {
                if let Some(blob) = encrypt_response.ciphertext_blob {
                    Ok(EncryptedSessionKey(secret_vault_value::SecretValue::new(
                        blob.into_inner(),
                    )))
                } else {
                    error!(
                        "Unable to encrypt DEK with AWS KMS {}: Didn't receive any blob.",
                        self.aws_key_ref.to_key_arn()
                    );
                    return Err(KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
                        KmsAeadErrorPublicGenericDetails::new("AWS_ERROR".into()),
                        format!(
                            "AWS error {:?}. No encrypted blob received.",
                            self.aws_key_ref.to_key_arn()
                        ),
                    )));
                }
            }
            Err(err) => {
                error!(
                    "Unable to encrypt DEK with AWS KMS {}: {}.",
                    self.aws_key_ref.to_key_arn(),
                    err
                );
                return Err(KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
                    KmsAeadErrorPublicGenericDetails::new("AWS_ERROR".into()),
                    format!("AWS error {:?}: {}", self.aws_key_ref.to_key_arn(), err),
                )));
            }
        }
    }

    async fn decrypt_session_key(
        &self,
        encrypted_session_secret: &EncryptedSessionKey,
    ) -> KmsAeadResult<SecretValue> {
        let decrypt_response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(
                encrypted_session_secret
                    .value()
                    .ref_sensitive_value()
                    .as_slice(),
            ))
            .send()
            .await?;

        if let Some(plaintext) = decrypt_response.plaintext {
            Ok(secret_vault_value::SecretValue::new(
                hex::decode(plaintext.into_inner()).unwrap(),
            ))
        } else {
            Err(KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
                KmsAeadErrorPublicGenericDetails::new("AWS_ERROR".into()),
                format!(
                    "AWS error {:?}: No plaintext received",
                    self.aws_key_ref.to_key_arn()
                ),
            )))
        }
    }

    async fn generate_secure_key(
        &self,
        aead_encryption: &KmsAeadRingAeadEncryption,
    ) -> KmsAeadResult<SecretValue> {
        if self.options.use_kms_random_gen {
            let resp = self
                .client
                .generate_random()
                .number_of_bytes(aead_encryption.algo.key_len() as i32)
                .send()
                .await?;
            let random_bytes_blob = resp.plaintext.ok_or_else(|| {
                KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
                    KmsAeadErrorPublicGenericDetails::new("AWS_ERROR".into()),
                    format!(
                        "AWS error {:?}. No secure random bytes received.",
                        self.aws_key_ref.to_key_arn()
                    ),
                ))
            })?;

            Ok(SecretValue::from(random_bytes_blob.into_inner()))
        } else {
            aead_encryption.generate_session_key()
        }
    }
}
