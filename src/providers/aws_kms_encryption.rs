use rsb_derive::*;

use crate::errors::*;
use crate::*;
use async_trait::async_trait;
use aws_sdk_kms::primitives::Blob;
use tracing::*;

use crate::ring_encryption::RingAeadEncryption;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsKmsKeyRef {
    pub account_id: String,
    pub key_id: String,
    pub aws_region: Option<aws_sdk_kms::config::Region>,
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
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match self
            .client
            .encrypt()
            .set_key_id(Some(self.aws_key_ref.to_key_arn()))
            .set_plaintext(Some(Blob::new(
                encryption_key.value().ref_sensitive_value().as_slice(),
            )))
            .send()
            .await
        {
            Ok(encrypt_response) => {
                if let Some(blob) = encrypt_response.ciphertext_blob {
                    Ok(EncryptedDataEncryptionKey::new(blob.into_inner(), None))
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

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let decrypt_response = self
            .client
            .decrypt()
            .ciphertext_blob(Blob::new(encrypted_key.wrapped()))
            .send()
            .await?;

        if let Some(plaintext) = decrypt_response.plaintext {
            Ok(DataEncryptionKey::from(
                secret_vault_value::SecretValue::new(plaintext.into_inner()),
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

    async fn generate_encryption_key(
        &self,
        aead_encryption: &RingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey> {
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

            Ok(DataEncryptionKey::from(SecretValue::from(
                random_bytes_blob.into_inner(),
            )))
        } else {
            aead_encryption.generate_data_encryption_key()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Encrypted from `test-secret` with AAD `test-aad` by kms-aead 0.28.1 and by layout v1, with
    // the AWS key that the live test configures. That key stays enabled while these exist.
    const ENVELOPE_FROM_0_28_1: &str = "00000000000000b801020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f9016d64cc226f7525698a42aa79440d72eb0000007e307c06092a864886f70d010706a06f306d020100306806092a864886f70d010701301e060960864801650304012e3011040c0197410ab39e7f2e03fcb949020110803b199d4e5e7f622192544e6afd92c61bf191d969c8e2bd79558786d3adf0453ebe0883967e7031d5c67d4dbebddd4f05aeca971b7636dbde5946860e8b8069a47514d7c98af6d41f881e50d921ed7eb7568617f632b87134c3d01dc25b292fb39badbe";
    const ENVELOPE_V1: &str = "010000b801020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f901328f5ffd046ddc430b18ba1d85738d440000007e307c06092a864886f70d010706a06f306d020100306806092a864886f70d010701301e060960864801650304012e3011040c2fb61160bcd48c2e564c02d5020110803b5d02b9463971cf911780d692666861a56101335c3d3d047dad9187a4dd15295189e5489017cb4c745c93064abfe217335d46e0cd8f6da27c8997e5ec392560da00e258e81877a60cc0e2a1d06cedfaef2b10d45bb80fda1cb2b81a5f038b24e8c607";

    #[test]
    fn envelopes_from_a_live_key_split_into_key_version_and_wrapped_key() {
        let (legacy_cipher_text, legacy_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_FROM_0_28_1).unwrap())
                .separate()
                .unwrap();
        let (v1_cipher_text, v1_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_V1).unwrap())
                .separate()
                .unwrap();

        assert_eq!(legacy_dek.key_version(), None);
        assert_eq!(legacy_dek.wrapped().len(), 184);
        assert_eq!(v1_dek.key_version(), None);
        assert_eq!(v1_dek.wrapped().len(), 184);
        // Nonce, the 11 bytes of `test-secret` and the tag.
        assert_eq!(legacy_cipher_text.value().len(), 12 + 11 + 16);
        assert_eq!(v1_cipher_text.value().len(), 12 + 11 + 16);
    }

    #[test]
    fn wrapped_key_stored_by_0_28_1_reads_as_a_bare_wrapped_key() {
        let (_, legacy_dek) =
            CipherTextWithEncryptedKey::from(hex::decode(ENVELOPE_FROM_0_28_1).unwrap())
                .separate()
                .unwrap();

        assert_eq!(
            EncryptedDataEncryptionKey::try_from_bytes(legacy_dek.wrapped()).unwrap(),
            legacy_dek
        );
        assert_eq!(
            EncryptedDataEncryptionKey::try_from_hex_string(&hex::encode(legacy_dek.wrapped()))
                .unwrap(),
            legacy_dek
        );
    }

    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_key_decrypts_envelopes_from_0_28_1_and_v1() -> KmsAeadResult<()> {
        let key_ref = AwsKmsKeyRef::new(
            std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set"),
            std::env::var("KMS_KEY_ID").expect("KMS_KEY_ID is set"),
        );
        let encryption =
            KmsAeadRingEnvelopeEncryption::new(AwsKmsProvider::new(&key_ref).await?).await?;
        for envelope in [ENVELOPE_FROM_0_28_1, ENVELOPE_V1] {
            let envelope = CipherTextWithEncryptedKey::from(hex::decode(envelope).unwrap());
            let secret = encryption.decrypt_value(&"test-aad", &envelope).await?;
            assert_eq!(secret, SecretValue::from("test-secret"));
        }
        Ok(())
    }
}
