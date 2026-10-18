//! The Azure provider against canned Key Vault responses.

use azure_core::http::headers::{self, Headers};
use azure_core::http::{
    AsyncRawResponse, ClientOptions, HttpClient, Request, RetryOptions, StatusCode, Transport,
};
use azure_security_keyvault_keys::models::EncryptionAlgorithm;
use azure_security_keyvault_keys::KeyClientOptions;
use kms_aead::errors::KmsAeadError;
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions};
use kms_aead::*;
use std::sync::{Arc, Mutex};

mod common;
use common::FixedTokenCredential;

const VAULT_URL: &str = "https://test-vault.vault.azure.net";
const KEY_NAME: &str = "dek-wrapping-key";
const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";
const LEAK_MARKER: &str = "body-marker-that-must-not-leak";

/// Answers every request with one canned response and keeps the URL of each request.
#[derive(Debug)]
struct CannedHttpClient {
    status: StatusCode,
    body: String,
    urls: Mutex<Vec<String>>,
}

impl CannedHttpClient {
    fn new(status: StatusCode, body: String) -> Self {
        Self {
            status,
            body,
            urls: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for CannedHttpClient {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        self.urls.lock().unwrap().push(request.url().to_string());
        let mut headers = Headers::new();
        headers.insert(headers::CONTENT_TYPE, "application/json");
        Ok(AsyncRawResponse::from_bytes(
            self.status,
            headers,
            self.body.clone().into_bytes(),
        ))
    }
}

fn options_over(status: StatusCode, body: String) -> AzureKmsProviderOptions {
    options_with(Arc::new(CannedHttpClient::new(status, body)))
}

fn options_with(http_client: Arc<CannedHttpClient>) -> AzureKmsProviderOptions {
    common::install_crypto_provider();
    AzureKmsProviderOptions::new().with_client_options(KeyClientOptions {
        client_options: ClientOptions {
            transport: Some(Transport::new(http_client)),
            retry: RetryOptions::none(),
            ..Default::default()
        },
        ..Default::default()
    })
}

fn provider_over(status: StatusCode, body: String) -> AzureKmsProvider {
    AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
        options_over(status, body),
        Arc::new(FixedTokenCredential),
    )
    .unwrap()
}

fn key_version() -> KmsKeyVersion {
    KmsKeyVersion::try_from(KEY_VERSION.to_string()).unwrap()
}

fn data_encryption_key() -> DataEncryptionKey {
    DataEncryptionKey::from(secret_vault_value::SecretValue::new(vec![7u8; 32]))
}

#[tokio::test]
async fn unwrap_names_the_configured_kek() {
    let http_client = Arc::new(CannedHttpClient::new(
        StatusCode::Ok,
        format!(
            r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
            azure_core::base64::encode_url_safe([7u8; 32])
        ),
    ));
    let provider = AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
        options_with(http_client.clone()),
        Arc::new(FixedTokenCredential),
    )
    .unwrap();

    provider
        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
            b"wrapped".to_vec(),
            Some(key_version()),
        ))
        .await
        .unwrap();

    let urls = http_client.urls.lock().unwrap();
    assert!(
        urls.iter().all(|url| url.starts_with(&format!(
            "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}/unwrapkey?"
        ))),
        "{urls:?}"
    );
    assert!(!urls.is_empty());
    assert_eq!(
        provider.kek(),
        KekRef::new(KekProvider::Azure, format!("{VAULT_URL}/keys/{KEY_NAME}"))
    );
}

#[tokio::test]
async fn provider_errors_carry_no_key_material() {
    let key_marker = azure_core::base64::encode_url_safe(LEAK_MARKER);
    let encrypted_key = EncryptedDataEncryptionKey::new(b"wrapped".to_vec(), Some(key_version()));
    let responses = [
        // A successful unwrap whose body is not the expected model.
        (StatusCode::Ok, format!(r#"{{"value": ["{key_marker}"]}}"#)),
        (StatusCode::Ok, format!(r#"{{"value": "{key_marker}""#)),
        (
            StatusCode::InternalServerError,
            format!(r#"{{"value": "{key_marker}"}}"#),
        ),
    ];

    for (status, body) in responses {
        let err = provider_over(status, body)
            .decrypt_data_encryption_key(&encrypted_key)
            .await
            .unwrap_err();

        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains(&key_marker), "{status}: {text}");
        }
    }
}

#[tokio::test]
async fn wrap_with_the_latest_key_version_records_the_version_from_kid() {
    let wrapped = b"wrapped-data-encryption-key".to_vec();
    let body = format!(
        r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
        azure_core::base64::encode_url_safe(&wrapped)
    );

    let encrypted_key = provider_over(StatusCode::Ok, body)
        .encrypt_data_encryption_key(&data_encryption_key())
        .await
        .unwrap();

    assert_eq!(
        encrypted_key,
        EncryptedDataEncryptionKey::new(wrapped, Some(key_version()))
    );
}

#[tokio::test]
async fn wrapped_key_read_back_from_hex_keeps_its_key_version() {
    let body = format!(
        r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
        azure_core::base64::encode_url_safe(b"wrapped-data-encryption-key")
    );
    let encrypted_key = provider_over(StatusCode::Ok, body)
        .encrypt_data_encryption_key(&data_encryption_key())
        .await
        .unwrap();

    let read_back =
        EncryptedDataEncryptionKey::try_from_hex_string(&encrypted_key.to_hex_string().unwrap())
            .unwrap();

    assert_eq!(read_back.key_version(), Some(&key_version()));
    assert_eq!(read_back, encrypted_key);
}

#[tokio::test]
async fn encrypted_key_without_a_key_version_is_rejected_before_any_request() {
    // A request would be answered with 200 and an unwrapped key, so an error here can only
    // come from the encrypted key.
    let provider = provider_over(
        StatusCode::Ok,
        format!(r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "AAAA"}}"#),
    );

    let err = provider
        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(b"wrapped".to_vec(), None))
        .await
        .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "AZURE_KEY_VERSION_MISSING"),
        "{err:?}"
    );
}

#[tokio::test]
async fn error_response_body_is_absent_from_errors() {
    // A body that is not an Azure error envelope is copied into the SDK error.
    let body = format!(r#"{{"value": "{LEAK_MARKER}"}}"#);
    let err = provider_over(StatusCode::Forbidden, body)
        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
            b"wrapped".to_vec(),
            Some(key_version()),
        ))
        .await
        .unwrap_err();

    assert!(matches!(err, KmsAeadError::EncryptionError(_)));
    assert!(!err.to_string().contains(LEAK_MARKER), "{err}");
    assert!(!format!("{err:?}").contains(LEAK_MARKER), "{err:?}");
}

#[tokio::test]
async fn server_errors_and_throttling_are_network_errors() {
    for status in [StatusCode::ServiceUnavailable, StatusCode::TooManyRequests] {
        let err = provider_over(
            status,
            r#"{"error": {"code": "Throttled", "message": "Try later"}}"#.into(),
        )
        .encrypt_data_encryption_key(&data_encryption_key())
        .await
        .unwrap_err();

        assert!(
            matches!(err, KmsAeadError::NetworkError(_)),
            "{status}: {err:?}"
        );
    }
}

#[tokio::test]
async fn client_errors_keep_the_key_vault_error_code() {
    let err = provider_over(
        StatusCode::Forbidden,
        r#"{"error": {"code": "Forbidden", "message": "The user does not have keys wrapKey permission"}}"#
            .into(),
    )
    .encrypt_data_encryption_key(&data_encryption_key())
    .await
    .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "Forbidden"),
        "{err:?}"
    );
}

#[test]
fn insecure_or_unknown_wrap_algorithms_are_rejected() {
    for algorithm in [
        EncryptionAlgorithm::Rsa1_5,
        EncryptionAlgorithm::UnknownValue("RSA-OAEP-512".into()),
    ] {
        let result = AzureKmsProvider::with_options(
            &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
            options_over(StatusCode::Ok, String::new()).with_algorithm(algorithm.clone()),
            Arc::new(FixedTokenCredential),
        );

        assert!(
            matches!(&result, Err(KmsAeadError::SystemError(e)) if e.public.code == "AZURE_WRAP_ALGORITHM"),
            "{algorithm:?}"
        );
    }
}

#[test]
fn vault_url_without_a_scheme_is_a_configuration_error() {
    let result = AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new("test-vault.vault.azure.net".into(), KEY_NAME.into()),
        options_over(StatusCode::Ok, String::new()),
        Arc::new(FixedTokenCredential),
    );

    assert!(
        matches!(&result, Err(KmsAeadError::SystemError(e)) if e.public.code == "AZURE_VAULT_URL"),
        "{:?}",
        result.err()
    );
}
