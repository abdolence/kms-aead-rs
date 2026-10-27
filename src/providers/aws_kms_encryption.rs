use rsb_derive::*;

use crate::errors::*;
use crate::formats::asymmetric::PublicKeyEncryptedDek;
use crate::formats::PublicKeyFormat;
use crate::spans::{self, kms};
use crate::*;
use aws_sdk_kms::operation::decrypt::builders::DecryptFluentBuilder;
use aws_sdk_kms::operation::encrypt::builders::EncryptFluentBuilder;
use aws_sdk_kms::operation::get_public_key::GetPublicKeyOutput;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::{EncryptionAlgorithmSpec, KeyUsageType};

use secret_vault_value::SecretValue;

/// An AWS KMS key that encrypts data encryption keys.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AwsKmsKeyRef {
    /// The AWS account that owns the key, used to build its ARN.
    pub account_id: String,
    /// The key as AWS KMS accepts it: a key id, a key ARN, an alias name such as
    /// `alias/orders`, or an alias ARN.
    ///
    /// A decryption names the configured key. Configure the key ARN rather than an alias: a key
    /// encrypted under an alias that later moves to another key fails to decrypt with
    /// `IncorrectKeyException`. Outside the `aws` partition, such as in GovCloud or China, give
    /// the full ARN, since a key id or an alias name becomes an `arn:aws:` ARN.
    pub key_id: String,
    /// The region of the key. Without one, [`AwsKmsProvider::new`] takes the region of the AWS
    /// configuration it loads.
    pub aws_region: Option<aws_sdk_kms::config::Region>,
}

impl AwsKmsKeyRef {
    /// The ARN of the key: `key_id` itself when it is an ARN already, an alias ARN for an alias
    /// name, and a key ARN for a key id. Without a region it is `key_id` unchanged.
    pub fn to_key_arn(&self) -> String {
        match &self.aws_region {
            _ if self.key_id.starts_with("arn:") => self.key_id.clone(),
            Some(region) if self.key_id.starts_with("alias/") => {
                format!("arn:aws:kms:{region}:{}:{}", self.account_id, self.key_id)
            }
            Some(region) => format!(
                "arn:aws:kms:{region}:{}:key/{}",
                self.account_id, self.key_id
            ),
            None => self.key_id.clone(),
        }
    }
}

/// Options for [`AwsKmsProvider`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct AwsKmsProviderOptions {
    /// Generates data encryption keys with AWS KMS `GenerateRandom` instead of the backend's
    /// CSPRNG, at the cost of one more KMS request per key.
    /// [`DEFAULT_USE_KMS_RANDOM_GEN`](Self::DEFAULT_USE_KMS_RANDOM_GEN) by default.
    #[default = "Self::DEFAULT_USE_KMS_RANDOM_GEN"]
    pub use_kms_random_gen: bool,
}

impl AwsKmsProviderOptions {
    /// The default [`use_kms_random_gen`](Self::use_kms_random_gen): `false`, the backend's
    /// CSPRNG generates the keys.
    pub const DEFAULT_USE_KMS_RANDOM_GEN: bool = false;
}

/// Encrypts and decrypts data encryption keys with an AWS KMS key.
///
/// An error AWS KMS returned keeps its AWS error code, such as `IncorrectKeyException` or
/// `NotFoundException`, and the message AWS KMS returned. `ThrottlingException`,
/// `KMSInternalException`, `DependencyTimeoutException`, `KeyUnavailableException` and any 5xx or
/// 429 status are a [`NetworkError`](crate::errors::KmsAeadError::NetworkError), and so are a
/// timeout, a connection failure and a response the SDK could not read. Any other error, such as
/// `AccessDeniedException` or a request that could not be built or signed, is an
/// [`EncryptionError`](crate::errors::KmsAeadError::EncryptionError) whose root cause is the SDK
/// error.
///
/// With an `RSA_*` key of usage `ENCRYPT_DECRYPT` it also decrypts an encrypted DEK that a
/// producer encrypted with the key's public half, which [`public_key`](Self::public_key) returns.
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    options: AwsKmsProviderOptions,
    kek: KekRef,
}

impl AwsKmsProvider {
    /// A provider for the key at `kms_key_ref`, with the default options and the AWS
    /// configuration from the environment.
    ///
    /// It sends no request, so missing credentials or an unreachable endpoint fail the first
    /// encryption or decryption.
    ///
    /// # Errors
    ///
    /// None: it returns `Ok` for every key reference.
    pub async fn new(kms_key_ref: &AwsKmsKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, AwsKmsProviderOptions::new()).await
    }

    /// As [`new`](Self::new), with `options`.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new).
    pub async fn with_options(
        kms_key_ref: &AwsKmsKeyRef,
        options: AwsKmsProviderOptions,
    ) -> KmsAeadResult<Self> {
        let shared_config = aws_config::load_from_env().await;

        let effective_kms_ref = if kms_key_ref.aws_region.is_none() {
            kms_key_ref
                .clone()
                .opt_aws_region(shared_config.region().cloned())
        } else {
            kms_key_ref.clone()
        };

        Ok(Self::with_client(
            &effective_kms_ref,
            aws_sdk_kms::Client::new(&shared_config),
            options,
        ))
    }

    fn with_client(
        kms_key_ref: &AwsKmsKeyRef,
        client: aws_sdk_kms::Client,
        options: AwsKmsProviderOptions,
    ) -> Self {
        Self {
            client,
            options,
            kek: KekRef::new(KmsProvider::Aws, kms_key_ref.to_key_arn()),
        }
    }

    /// Encrypts under the configured key.
    fn encrypt_request(&self, dek: &DataEncryptionKey) -> EncryptFluentBuilder {
        self.client
            .encrypt()
            .key_id(self.kek.key())
            .plaintext(Blob::new(dek.value().ref_sensitive_value().as_slice()))
    }

    /// Names the configured key: without it AWS KMS decrypts under whichever key the blob names,
    /// for any key the principal may decrypt with.
    fn decrypt_request(&self, encrypted_dek: &EncryptedDataEncryptionKey) -> DecryptFluentBuilder {
        self.client
            .decrypt()
            .key_id(self.kek.key())
            .ciphertext_blob(Blob::new(encrypted_dek.value()))
    }

    /// As `decrypt_request`, for `block`, a DEK a public key encrypted: AWS KMS requires the
    /// algorithm for an asymmetric key and has no default for it.
    fn asymmetric_decrypt_request(&self, block: &[u8]) -> DecryptFluentBuilder {
        self.client
            .decrypt()
            .key_id(self.kek.key())
            .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
            .ciphertext_blob(Blob::new(block))
    }

    /// The public key of a `GetPublicKey` response for the configured key: it must be a key of
    /// usage `ENCRYPT_DECRYPT` that decrypts with RSAES-OAEP and SHA-256.
    fn kek_public_key(
        &self,
        response: GetPublicKeyOutput,
    ) -> KmsAeadResult<AsymmetricKekPublicKey> {
        let refuse = |reason: &str| {
            KmsAeadSystemError::asymmetric_public_key(&format!(
                "The AWS KMS key {} {reason}",
                self.kek.key()
            ))
        };
        if response.key_usage() != Some(&KeyUsageType::EncryptDecrypt) {
            return Err(refuse("is not of usage ENCRYPT_DECRYPT"));
        }
        if !response
            .encryption_algorithms()
            .contains(&EncryptionAlgorithmSpec::RsaesOaepSha256)
        {
            return Err(refuse("does not decrypt with RSAES_OAEP_SHA_256"));
        }
        let public_key = response
            .public_key
            .ok_or_else(|| refuse("holds no public key"))?;
        AsymmetricKekPublicKey::new(
            self.kek.clone(),
            None,
            AsymmetricKekAlgorithm::RsaOaepSha256,
            public_key.into_inner(),
            PublicKeyFormat::SpkiDer,
        )
    }

    /// The public key of the configured asymmetric KEK, a key of usage `ENCRYPT_DECRYPT`, from
    /// `GetPublicKey` with `kms:GetPublicKey`: for the administration, which hands it to the
    /// producers. AWS KMS keys have no versions, so the key carries none.
    ///
    /// # Errors
    ///
    /// The KMS's errors, and `ASYMMETRIC_KEK_PUBLIC_KEY` when the key's `KeyUsage` is not
    /// `ENCRYPT_DECRYPT` or `RSAES_OAEP_SHA_256` is not among its `EncryptionAlgorithms`.
    pub async fn public_key(&self) -> KmsAeadResult<AsymmetricKekPublicKey> {
        spans::in_span(kms::kek_public_key_span(&self.kek), async {
            let response = kms::timed("public_key", self.kek.provider(), async {
                self.client
                    .get_public_key()
                    .key_id(self.kek.key())
                    .send()
                    .await
                    .map_err(KmsAeadError::from_aws_sdk_error)
            })
            .await?;
            self.kek_public_key(response)
        })
        .await
    }
}

impl KmsAeadEncryptionProvider for AwsKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(&self.kek), async {
            let encrypt_response = kms::timed("encrypt_dek", self.kek.provider(), async {
                self.encrypt_request(dek)
                    .send()
                    .await
                    .map_err(KmsAeadError::from_aws_sdk_error)
            })
            .await?;
            match encrypt_response.ciphertext_blob {
                // The response names no key material, so the KEK version is unknown.
                Some(blob) => Ok(EncryptedDataEncryptionKey::new(blob.into_inner())),
                None => Err(KmsAeadEncryptionError::create(
                    "AWS_ERROR",
                    &format!(
                        "AWS error {:?}. No encrypted blob received.",
                        self.kek.key()
                    ),
                )),
            }
        })
        .await
    }

    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        if !self.options.use_kms_random_gen {
            return Ok(None);
        }
        spans::in_span(kms::random_span(self.kek.provider(), None, len), async {
            let number_of_bytes = i32::try_from(len).map_err(|_| {
                KmsAeadEncryptionError::create(
                    "INVALID_KEY_LENGTH",
                    &format!("AWS KMS cannot generate {len} random bytes in one request"),
                )
            })?;
            let response = kms::timed("random", self.kek.provider(), async {
                self.client
                    .generate_random()
                    .number_of_bytes(number_of_bytes)
                    .send()
                    .await
                    .map_err(KmsAeadError::from_aws_sdk_error)
            })
            .await?;
            let random_bytes = response.plaintext.ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "AWS_ERROR",
                    &format!(
                        "AWS error {:?}. No secure random bytes received.",
                        self.kek.key()
                    ),
                )
            })?;
            Ok(Some(SecretValue::new(random_bytes.into_inner())))
        })
        .await
    }
}

impl KmsAeadDecryptionProvider for AwsKmsProvider {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::decrypt_span(&self.kek), async {
            let request = match PublicKeyEncryptedDek::read(encrypted_dek.value()) {
                Some(public_key_dek) => {
                    self.asymmetric_decrypt_request(public_key_dek?.into_unversioned_block()?)
                }
                None => self.decrypt_request(encrypted_dek),
            };
            let decrypt_response = kms::timed("decrypt_dek", self.kek.provider(), async {
                request
                    .send()
                    .await
                    .map_err(KmsAeadError::from_aws_sdk_error)
            })
            .await?;

            match decrypt_response.plaintext {
                Some(plaintext) => Ok(DataEncryptionKey::from(SecretValue::new(
                    plaintext.into_inner(),
                ))),
                None => Err(KmsAeadEncryptionError::create(
                    "AWS_ERROR",
                    &format!("AWS error {:?}: No plaintext received", self.kek.key()),
                )),
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_http::{answer_with, ReceivedRequest};
    use aws_sdk_kms::config::http::HttpResponse;
    use aws_sdk_kms::config::retry::RetryConfig;
    use aws_sdk_kms::config::{Credentials, Region};
    use aws_sdk_kms::error::{ConnectorError, ErrorMetadata, SdkError};
    use aws_sdk_kms::operation::decrypt::DecryptError;
    use aws_sdk_kms::types::error::IncorrectKeyException;
    use base64ct::{Base64, Encoding};
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;

    use crate::formats::Envelope;
    use crate::test_provider::{
        public_key_encrypted_dek, RsaOaepSuite, TestBackend, TinkEnvelope, ENCRYPTED_BLOCK,
    };

    const REGION: &str = "eu-west-1";
    const ACCOUNT_ID: &str = "123456789012";
    const KEY_ID: &str = "1234abcd-12ab-34cd-56ef-1234567890ab";
    const KEY_ARN: &str =
        "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab";
    /// The base64 of a data encryption key in a Decrypt response body.
    const PLAINTEXT_MARKER: &str = "cGxhaW50ZXh0LWRhdGEta2V5LW1hcmtlcg==";
    const DATA_KEY: &[u8; 32] = b"data-key-marker-value-of-32bytes";

    fn provider_for(key_id: &str, config: aws_sdk_kms::config::Builder) -> AwsKmsProvider {
        let key_ref = AwsKmsKeyRef::new(ACCOUNT_ID.into(), key_id.into())
            .with_aws_region(Region::new(REGION));
        let config = config
            .behavior_version(aws_sdk_kms::config::BehaviorVersion::latest())
            .build();
        AwsKmsProvider::with_client(
            &key_ref,
            aws_sdk_kms::Client::from_conf(config),
            AwsKmsProviderOptions::new(),
        )
    }

    fn offline_provider() -> AwsKmsProvider {
        provider_for(KEY_ID, aws_sdk_kms::Config::builder())
    }

    fn decrypt_key_id(configured_key_id: &str) -> Option<String> {
        provider_for(configured_key_id, aws_sdk_kms::Config::builder())
            .decrypt_request(&EncryptedDataEncryptionKey::new(b"encrypted-dek".to_vec()))
            .get_key_id()
            .clone()
    }

    /// A provider whose requests go to a local server that answers each of them with `status`
    /// and the JSON `body`, and the requests the server receives.
    async fn provider_recording(
        status: u16,
        body: &str,
    ) -> (AwsKmsProvider, Arc<Mutex<Vec<ReceivedRequest>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let requests = answer_with(listener, status, body.to_string());
        let provider = provider_for(
            KEY_ID,
            aws_sdk_kms::Config::builder()
                .endpoint_url(endpoint)
                .region(Region::new(REGION))
                .credentials_provider(Credentials::new("AKID", "SECRET", None, None, "test"))
                .retry_config(RetryConfig::disabled()),
        );
        (provider, requests)
    }

    async fn provider_answered_with(status: u16, body: &str) -> AwsKmsProvider {
        provider_recording(status, body).await.0
    }

    fn response_with_body(status: u16, body: &str) -> HttpResponse {
        HttpResponse::new(status.try_into().unwrap(), body.to_string().into())
    }

    const INCORRECT_KEY_MESSAGE: &str =
        "The key ID in the request does not identify a CMK that can perform this operation.";

    fn incorrect_key_exception() -> DecryptError {
        DecryptError::IncorrectKeyException(
            IncorrectKeyException::builder()
                .message(INCORRECT_KEY_MESSAGE)
                .meta(
                    ErrorMetadata::builder()
                        .code("IncorrectKeyException")
                        .message(INCORRECT_KEY_MESSAGE)
                        .build(),
                )
                .build(),
        )
    }

    fn request_body(request: &ReceivedRequest) -> serde_json::Value {
        serde_json::from_slice(&request.body).unwrap()
    }

    #[tokio::test]
    async fn an_asymmetric_decryption_names_the_key_the_algorithm_and_the_block(
    ) -> KmsAeadResult<()> {
        let (provider, requests) = provider_recording(
            200,
            &format!(
                r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{}","EncryptionAlgorithm":"RSAES_OAEP_SHA_256"}}"#,
                Base64::encode_string(DATA_KEY)
            ),
        )
        .await;

        let dek = provider
            .decrypt_data_encryption_key(&public_key_encrypted_dek(b"", None)?)
            .await?;

        assert_eq!(dek.value().ref_sensitive_value().as_slice(), DATA_KEY);
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].head.contains("TrentService.Decrypt"),
            "{}",
            requests[0].head
        );
        assert_eq!(
            request_body(&requests[0]),
            serde_json::json!({
                "KeyId": KEY_ARN,
                "EncryptionAlgorithm": "RSAES_OAEP_SHA_256",
                "CiphertextBlob": Base64::encode_string(&ENCRYPTED_BLOCK),
            })
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_asymmetric_header_that_names_a_kek_id_or_a_version_is_refused_before_any_request(
    ) -> KmsAeadResult<()> {
        for (kek_id, kek_version) in [(&b"orders"[..], None), (b"", Some("3"))] {
            let (provider, requests) = provider_recording(200, "{}").await;

            let result = provider
                .decrypt_data_encryption_key(&public_key_encrypted_dek(kek_id, kek_version)?)
                .await;

            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "ASYMMETRIC_ENCRYPTED_DEK_FORMAT"),
                "{result:?}"
            );
            assert!(requests.lock().unwrap().is_empty());
        }
        Ok(())
    }

    fn public_key_response(
        key_usage: KeyUsageType,
        encryption_algorithms: &[EncryptionAlgorithmSpec],
    ) -> GetPublicKeyOutput {
        GetPublicKeyOutput::builder()
            .public_key(Blob::new(RsaOaepSuite::of_bits(2048).spki_der()))
            .key_usage(key_usage)
            .set_encryption_algorithms(Some(encryption_algorithms.to_vec()))
            .build()
    }

    #[tokio::test]
    async fn a_public_key_is_the_configured_keys_without_a_version() -> KmsAeadResult<()> {
        let (provider, requests) = provider_recording(
            200,
            &format!(
                r#"{{"KeyId":"{KEY_ARN}","KeyUsage":"ENCRYPT_DECRYPT","KeySpec":"RSA_2048","PublicKey":"{}","EncryptionAlgorithms":["RSAES_OAEP_SHA_1","RSAES_OAEP_SHA_256"]}}"#,
                Base64::encode_string(&RsaOaepSuite::of_bits(2048).spki_der())
            ),
        )
        .await;

        let public_key = provider.public_key().await?;

        assert_eq!(public_key.kek(), provider.kek());
        assert_eq!(public_key.kek_version(), None);
        assert_eq!(
            public_key.spki_der(),
            RsaOaepSuite::of_bits(2048).spki_der()
        );
        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0].head.contains("TrentService.GetPublicKey"),
            "{}",
            requests[0].head
        );
        assert_eq!(
            request_body(&requests[0]),
            serde_json::json!({ "KeyId": KEY_ARN })
        );
        Ok(())
    }

    #[test]
    fn a_public_key_of_another_usage_or_algorithm_is_refused() {
        let provider = offline_provider();
        for response in [
            public_key_response(
                KeyUsageType::SignVerify,
                &[EncryptionAlgorithmSpec::RsaesOaepSha256],
            ),
            public_key_response(
                KeyUsageType::EncryptDecrypt,
                &[EncryptionAlgorithmSpec::RsaesOaepSha1],
            ),
            public_key_response(KeyUsageType::EncryptDecrypt, &[]),
        ] {
            let result = provider.kek_public_key(response.clone());

            assert!(
                matches!(&result, Err(error) if error.code() == "ASYMMETRIC_KEK_PUBLIC_KEY"),
                "{response:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_public_key_response_without_a_key_is_refused_as_a_public_key() {
        let response = GetPublicKeyOutput::builder()
            .key_usage(KeyUsageType::EncryptDecrypt)
            .encryption_algorithms(EncryptionAlgorithmSpec::RsaesOaepSha256)
            .build();

        let result = offline_provider().kek_public_key(response);

        assert!(
            matches!(&result, Err(error) if error.code() == "ASYMMETRIC_KEK_PUBLIC_KEY"),
            "{result:?}"
        );
    }

    #[test]
    fn decrypt_names_the_configured_kek() {
        let provider = offline_provider();

        let request =
            provider.decrypt_request(&EncryptedDataEncryptionKey::new(b"encrypted-dek".to_vec()));

        assert_eq!(request.get_key_id().as_deref(), Some(KEY_ARN));
        assert_eq!(
            request.get_ciphertext_blob().as_ref().map(Blob::as_ref),
            Some(b"encrypted-dek".as_slice())
        );
        assert_eq!(*provider.kek(), KekRef::new(KmsProvider::Aws, KEY_ARN));
    }

    #[test]
    fn requests_name_the_key_and_carry_no_encryption_context() {
        let provider = offline_provider();
        let dek = DataEncryptionKey::from(SecretValue::new(DATA_KEY.to_vec()));

        let encrypt = provider.encrypt_request(&dek);
        let decrypt =
            provider.decrypt_request(&EncryptedDataEncryptionKey::new(b"encrypted-dek".to_vec()));

        assert_eq!(encrypt.get_key_id().as_deref(), Some(KEY_ARN));
        assert_eq!(
            encrypt.get_plaintext().as_ref().map(Blob::as_ref),
            Some(DATA_KEY.as_slice())
        );
        assert_eq!(encrypt.get_encryption_context(), &None);
        assert_eq!(decrypt.get_encryption_context(), &None);
    }

    #[test]
    fn decrypt_names_a_configured_key_id_by_its_key_arn() {
        assert_eq!(decrypt_key_id(KEY_ID).as_deref(), Some(KEY_ARN));
    }

    #[test]
    fn decrypt_names_a_configured_key_arn_as_it_is() {
        let key_arn = "arn:aws:kms:us-east-2:210987654321:key/1234abcd-12ab-34cd-56ef-1234567890ab";
        assert_eq!(decrypt_key_id(key_arn).as_deref(), Some(key_arn));
    }

    #[test]
    fn decrypt_names_a_configured_alias_name_by_its_alias_arn() {
        assert_eq!(
            decrypt_key_id("alias/orders").as_deref(),
            Some("arn:aws:kms:eu-west-1:123456789012:alias/orders")
        );
    }

    #[test]
    fn decrypt_names_a_configured_alias_arn_as_it_is() {
        let alias_arn = "arn:aws:kms:us-east-2:210987654321:alias/orders";
        assert_eq!(decrypt_key_id(alias_arn).as_deref(), Some(alias_arn));
    }

    #[tokio::test]
    async fn an_encryption_refused_by_kms_keeps_the_service_code_and_message() {
        let provider = provider_answered_with(
            400,
            r#"{"__type":"NotFoundException","message":"Key 'orders' does not exist"}"#,
        )
        .await;

        let error = provider
            .encrypt_data_encryption_key(&DataEncryptionKey::from(SecretValue::new(vec![0x42; 32])))
            .await
            .unwrap_err();

        let KmsAeadError::EncryptionError(error) = error else {
            panic!("expected an encryption error, got {error:?}");
        };
        assert_eq!(error.public.code, "NotFoundException");
        assert!(
            error.message.contains("Key 'orders' does not exist"),
            "{}",
            error.message
        );
        assert!(error.root_cause.is_some());
    }

    #[test]
    fn a_service_error_keeps_the_service_code_and_error() {
        let error = KmsAeadError::from_aws_sdk_error(SdkError::service_error(
            incorrect_key_exception(),
            response_with_body(400, r#"{"__type":"IncorrectKeyException"}"#),
        ));

        let KmsAeadError::EncryptionError(error) = error else {
            panic!("expected an encryption error, got {error:?}");
        };
        assert_eq!(error.public.code, "IncorrectKeyException");
        assert!(
            error.message.contains(INCORRECT_KEY_MESSAGE),
            "{}",
            error.message
        );
        let root_cause = error.root_cause.expect("the service error is kept");
        assert!(root_cause
            .downcast_ref::<DecryptError>()
            .is_some_and(DecryptError::is_incorrect_key_exception));
    }

    #[tokio::test]
    async fn throttling_and_unavailable_service_errors_are_network_errors() {
        let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; 32]));
        for (status, code) in [
            (400, "ThrottlingException"),
            (400, "KMSInternalException"),
            (400, "DependencyTimeoutException"),
            (400, "KeyUnavailableException"),
            (503, "ServiceUnavailableException"),
        ] {
            let provider = provider_answered_with(
                status,
                &format!(r#"{{"__type":"{code}","message":"try again later"}}"#),
            )
            .await;

            let error = provider
                .encrypt_data_encryption_key(&dek)
                .await
                .unwrap_err();

            assert!(
                matches!(&error, KmsAeadError::NetworkError(_)),
                "{code}: {error:?}"
            );
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn transport_failures_are_network_errors() {
        let errors = [
            SdkError::<DecryptError, HttpResponse>::timeout_error("connect timed out"),
            SdkError::dispatch_failure(ConnectorError::io("connection reset".into())),
            SdkError::response_error("the body ended early", response_with_body(200, "{")),
        ];

        for sdk_error in errors {
            let code = sdk_error.to_string();
            let error = KmsAeadError::from_aws_sdk_error(sdk_error);

            assert!(matches!(&error, KmsAeadError::NetworkError(_)), "{error:?}");
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn requests_that_cannot_be_built_or_sent_are_encryption_errors() {
        let errors = [
            SdkError::<DecryptError, HttpResponse>::construction_failure("no key id"),
            SdkError::dispatch_failure(ConnectorError::user("invalid endpoint".into())),
        ];

        for sdk_error in errors {
            let code = sdk_error.to_string();
            let error = KmsAeadError::from_aws_sdk_error(sdk_error);

            assert!(
                matches!(&error, KmsAeadError::EncryptionError(error) if error.root_cause.is_some()),
                "{error:?}"
            );
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn provider_errors_carry_no_key_material() {
        let body = format!(r#"{{"KeyId":"{KEY_ARN}","Plaintext":"{PLAINTEXT_MARKER}"}}"#);
        let errors = [
            // A successful decryption whose body failed to parse.
            KmsAeadError::from_aws_sdk_error(
                SdkError::<DecryptError, HttpResponse>::response_error(
                    "failed to parse the response",
                    response_with_body(200, &body),
                ),
            ),
            KmsAeadError::from_aws_sdk_error(SdkError::service_error(
                incorrect_key_exception(),
                response_with_body(400, &body),
            )),
        ];

        for error in errors {
            for text in [format!("{error}"), format!("{error:?}")] {
                assert!(!text.contains(PLAINTEXT_MARKER), "{text}");
            }
        }
    }

    /// Tink 1.16.1 for Python, `KmsEnvelopeAead` on the AWS key the live tests configure, which
    /// stays enabled while these exist; `tests/tink_interop.py` writes them.
    const TINK_ENVELOPES: &[TinkEnvelope] = &[
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes128Gcm,
            aad: "orders/aws/aes-128-gcm",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000aa01020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f901d4e770136e2cd7b89c2359c808aef01800000070306e06092a864886f70d010706a061305f020100305a06092a864886f70d010701301e060960864801650304012e3011040cc2369d5a5fcb48672876a33e020110802d54365e9dddb00e682312c83705ece381ab479a9ed00702dbe49848d0402bd7919b29de2ee4a183a15913b11f5e99c0b3b17910209e6aac4c0119fd2b43a813cf3a49a08a8870957b406b818df41d946d416d6037527ab00ef596c389b14b",
        },
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes256Gcm,
            aad: "orders/aws/aes-256-gcm",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000ba01020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f901daab91f1efca5ecdfc32d1a4afd1b5c400000080307e06092a864886f70d010706a071306f020100306a06092a864886f70d010701301e060960864801650304012e3011040c5a77f0b4ca9335fcc70cd08a020110803df618fb2f75d06206bc4a85f3a78b81475195779392e7aa4da51dd11c40a38f4ffd7af4a1f2987b8f6594c44775d39bc68311ecdca1681f586a2271cc46259fb02152553b45eda34fbcdd65e3d986a06e8079223c6feca1af6d6455de05be6887754b61a009110102439707d1e5d8",
        },
        TinkEnvelope {
            algorithm: AeadAlgorithm::Aes256GcmSiv,
            aad: "orders/aws/aes-256-gcm-siv",
            plain_text: "sealed by Tink 1.16.1",
            value: "000000ba01020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f90103876be1d3aad7a662cab60fc762652600000080307e06092a864886f70d010706a071306f020100306a06092a864886f70d010701301e060960864801650304012e3011040ce0b11d0d01bb2c290edf5779020110803de712e319619be931e6d5f9ca826e88695152d7547b42cba5975506760e3662515f9e710ec6f8a0e0dcd689dd99c5e26ffa09b1c93f4a1ab04998e80e1813414dea869d3dc65a4770456707fd3e2d5644559561e3a5057e73a14c341444a435004f3cc875fc51fef29476d42152f3",
        },
    ];

    fn live_key_ref() -> AwsKmsKeyRef {
        AwsKmsKeyRef::new(
            std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set"),
            std::env::var("KMS_KEY_ID").expect("KMS_KEY_ID is set"),
        )
    }

    /// The asymmetric KEK of the live tests, `KMS_KEY_ID_RSA`: a key of spec `RSA_3072` and usage
    /// `ENCRYPT_DECRYPT` in the account of the other live keys.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_key_decrypts_what_its_public_key_encrypts() -> KmsAeadResult<()> {
        use crate::providers::PublicKeyKekProvider;
        use crate::test_provider::RsaTestBackend;
        let reader = AwsKmsProvider::new(&AwsKmsKeyRef::new(
            std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set"),
            std::env::var("KMS_KEY_ID_RSA").expect("KMS_KEY_ID_RSA is set"),
        ))
        .await?;

        let public_key = reader.public_key().await?;
        let producer = KmsAeadEnvelope::<_, RsaTestBackend>::new(PublicKeyKekProvider::<
            RsaTestBackend,
        >::new(public_key)?)?;
        let reader = KmsAeadEnvelope::<_, RsaTestBackend>::new(reader)?;
        let encrypted: Encrypted<SecretValue, Envelope> = producer
            .encrypt(
                b"orders/aws/rsa",
                &SecretValue::from("encrypted by a producer"),
            )
            .await?;

        assert_eq!(
            producer.provider().public_key().kek(),
            reader.provider().kek()
        );
        assert_eq!(producer.provider().public_key().kek_version(), None);
        assert_eq!(
            reader
                .decrypt::<SecretValue>(b"orders/aws/rsa", &encrypted)
                .await?,
            SecretValue::from("encrypted by a producer")
        );
        Ok(())
    }

    /// A block encrypted with the public key of another key is refused by AWS KMS with one of the
    /// two codes the book names for it.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_key_refuses_a_block_of_another_key() -> KmsAeadResult<()> {
        use crate::providers::{LocalAsymmetricKmsProvider, LocalKekId, PublicKeyKekProvider};
        use crate::test_provider::RsaTestBackend;
        let reader = AwsKmsProvider::new(&AwsKmsKeyRef::new(
            std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set"),
            std::env::var("KMS_KEY_ID_RSA").expect("KMS_KEY_ID_RSA is set"),
        ))
        .await?;
        let another_key = LocalAsymmetricKmsProvider::<RsaTestBackend>::ephemeral(
            LocalKekId::try_from("another".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
        )?;
        let impostor = PublicKeyKekProvider::<RsaTestBackend>::new(AsymmetricKekPublicKey::new(
            reader.kek().clone(),
            None,
            AsymmetricKekAlgorithm::RsaOaepSha256,
            another_key.public_key(None)?.spki_der().to_vec(),
            PublicKeyFormat::SpkiDer,
        )?)?;
        let encrypted_dek = impostor
            .encrypt_data_encryption_key(&DataEncryptionKey::from(SecretValue::new(vec![0x42; 32])))
            .await?;

        let result = reader.decrypt_data_encryption_key(&encrypted_dek).await;

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if ["IncorrectKeyException", "InvalidCiphertextException"]
                    .contains(&error.public.code.as_str())),
            "{result:?}"
        );
        Ok(())
    }

    /// Decrypts the values of the algorithms the test backend implements: every one but
    /// AES-256-GCM-SIV on ring.
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_key_decrypts_tink_envelopes() -> KmsAeadResult<()> {
        let key_ref = live_key_ref();
        for tink in TINK_ENVELOPES {
            let envelope = match KmsAeadEnvelope::<_, TestBackend>::with_options(
                AwsKmsProvider::new(&key_ref).await?,
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

    // Encrypted from `test-secret` with AAD `test-aad` by kms-aead 0.28.1 and 0.29, under their
    // default ChaCha20-Poly1305 and the AWS key that the live tests configure. That key stays
    // enabled while these exist.
    #[cfg(feature = "legacy-formats")]
    const ENVELOPE_FROM_0_28_1: &str = "00000000000000b801020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f9016d64cc226f7525698a42aa79440d72eb0000007e307c06092a864886f70d010706a06f306d020100306806092a864886f70d010701301e060960864801650304012e3011040c0197410ab39e7f2e03fcb949020110803b199d4e5e7f622192544e6afd92c61bf191d969c8e2bd79558786d3adf0453ebe0883967e7031d5c67d4dbebddd4f05aeca971b7636dbde5946860e8b8069a47514d7c98af6d41f881e50d921ed7eb7568617f632b87134c3d01dc25b292fb39badbe";
    #[cfg(feature = "legacy-formats")]
    const ENVELOPE_FROM_0_29: &str = "010000b801020200789693b39039bcbc820ade874e0d635e726f1ce1ac65f509186e2dfaabdaaf32f901328f5ffd046ddc430b18ba1d85738d440000007e307c06092a864886f70d010706a06f306d020100306806092a864886f70d010701301e060960864801650304012e3011040c2fb61160bcd48c2e564c02d5020110803b5d02b9463971cf911780d692666861a56101335c3d3d047dad9187a4dd15295189e5489017cb4c745c93064abfe217335d46e0cd8f6da27c8997e5ec392560da00e258e81877a60cc0e2a1d06cedfaef2b10d45bb80fda1cb2b81a5f038b24e8c607";

    #[tokio::test]
    #[cfg(feature = "legacy-formats")]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    #[expect(deprecated, reason = "tests the deprecated upgrade")]
    async fn live_key_decrypts_and_upgrades_stored_envelopes() -> KmsAeadResult<()> {
        let encryption = KmsAeadEnvelope::<_, TestBackend>::with_options(
            AwsKmsProvider::new(&live_key_ref()).await?,
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

    /// Needs a second key in the account, named by `KMS_SECOND_KEY_ID`, that the test principal
    /// may encrypt and decrypt with; passes without running when the variable is unset.
    #[tokio::test]
    #[cfg_attr(not(feature = "ci-aws"), ignore)]
    async fn live_decryption_of_a_dek_encrypted_under_another_kek_fails() -> KmsAeadResult<()> {
        let Ok(second_key_id) = std::env::var("KMS_SECOND_KEY_ID") else {
            return Ok(());
        };
        let account_id = std::env::var("ACCOUNT_ID").expect("ACCOUNT_ID is set");
        let configured = AwsKmsKeyRef::new(
            account_id.clone(),
            std::env::var("KMS_KEY_ID").expect("KMS_KEY_ID is set"),
        );
        let other = AwsKmsKeyRef::new(account_id, second_key_id);
        let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; 32]));
        let encrypted_under_other = AwsKmsProvider::new(&other)
            .await?
            .encrypt_data_encryption_key(&dek)
            .await?;

        let result = AwsKmsProvider::new(&configured)
            .await?
            .decrypt_data_encryption_key(&encrypted_under_other)
            .await;

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "IncorrectKeyException"),
            "{:?}",
            result.err()
        );
        Ok(())
    }
}
