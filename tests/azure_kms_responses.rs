//! The Azure provider against canned Key Vault responses.

use azure_core::http::headers::{self, Headers};
use azure_core::http::{
    AsyncRawResponse, Body, ClientOptions, HttpClient, Request, RetryOptions, StatusCode, Transport,
};
use azure_security_keyvault_keys::models::EncryptionAlgorithm;
use azure_security_keyvault_keys::KeyClientOptions;
use kms_aead::errors::KmsAeadError;
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions, KekVersion};
use kms_aead::*;
use std::sync::{Arc, Mutex, PoisonError};

mod common;
use common::{Backend, FixedTokenCredential};

const VAULT_URL: &str = "https://test-vault.vault.azure.net";
const KEY_NAME: &str = "dek-encrypting-key";
const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";
const LEAK_MARKER: &str = "body-marker-that-must-not-leak";

/// Answers every request with one canned response and keeps the URL and the body of each
/// request.
#[derive(Debug)]
struct CannedHttpClient {
    status: StatusCode,
    body: String,
    urls: Mutex<Vec<String>>,
    request_bodies: Mutex<Vec<Vec<u8>>>,
}

impl CannedHttpClient {
    fn new(status: StatusCode, body: String) -> Self {
        Self {
            status,
            body,
            urls: Mutex::new(Vec::new()),
            request_bodies: Mutex::new(Vec::new()),
        }
    }
}

/// Key Vault's challenge to a request that carries no token, such as the first request of a
/// client, which the SDK sends without its body.
const CHALLENGE: &str = r#"Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net""#;

#[async_trait::async_trait]
impl HttpClient for CannedHttpClient {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        self.urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.url().to_string());
        let mut headers = Headers::new();
        match request.body() {
            Body::Bytes(body) if !body.is_empty() => {
                self.request_bodies
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(body.to_vec());
            }
            _ => {
                headers.insert(headers::WWW_AUTHENTICATE, CHALLENGE);
                return Ok(AsyncRawResponse::from_bytes(
                    StatusCode::Unauthorized,
                    headers,
                    Vec::new(),
                ));
            }
        }
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

fn provider_over(status: StatusCode, body: String) -> KmsAeadResult<AzureKmsProvider> {
    AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
        options_over(status, body),
        Arc::new(FixedTokenCredential),
    )
}

/// `wrapped` in the layout of the provider's encrypted keys, after the key version `KEY_VERSION`:
/// `[0x01][k: u8][key version: k][encrypted DEK]`.
fn encrypted_key(wrapped: &[u8]) -> EncryptedDataEncryptionKey {
    let key_version = KEY_VERSION.as_bytes();
    let header = [
        0x01,
        u8::try_from(key_version.len()).expect("KEY_VERSION is 32 characters"),
    ];
    EncryptedDataEncryptionKey::new([&header[..], key_version, wrapped].concat())
}

fn data_encryption_key() -> DataEncryptionKey {
    DataEncryptionKey::from(secret_vault_value::SecretValue::new(vec![7u8; 32]))
}

#[tokio::test]
async fn decrypt_names_the_configured_kek() -> KmsAeadResult<()> {
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
    )?;

    provider
        .decrypt_data_encryption_key(&encrypted_key(b"wrapped"))
        .await?;

    let urls = http_client.urls.lock().unwrap();
    assert!(
        urls.iter().all(|url| url.starts_with(&format!(
            "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}/unwrapkey?"
        ))),
        "{urls:?}"
    );
    assert!(!urls.is_empty());
    assert_eq!(
        *provider.kek(),
        KekRef::new(KekProvider::Azure, format!("{VAULT_URL}/keys/{KEY_NAME}"))
    );
    Ok(())
}

#[tokio::test]
async fn provider_errors_carry_no_key_material() -> KmsAeadResult<()> {
    let key_marker = azure_core::base64::encode_url_safe(LEAK_MARKER);
    let encrypted_dek = encrypted_key(b"wrapped");
    let responses = [
        // A successful decryption whose body is not the expected model.
        (StatusCode::Ok, format!(r#"{{"value": ["{key_marker}"]}}"#)),
        (StatusCode::Ok, format!(r#"{{"value": "{key_marker}""#)),
        (
            StatusCode::InternalServerError,
            format!(r#"{{"value": "{key_marker}"}}"#),
        ),
    ];

    for (status, body) in responses {
        let err = provider_over(status, body)?
            .decrypt_data_encryption_key(&encrypted_dek)
            .await
            .unwrap_err();

        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains(&key_marker), "{status}: {text}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn encryption_with_the_latest_key_version_carries_the_version_from_kid() -> KmsAeadResult<()>
{
    let wrapped = b"wrapped-data-encryption-key".to_vec();
    let body = format!(
        r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
        azure_core::base64::encode_url_safe(&wrapped)
    );

    let dek_encryption = provider_over(StatusCode::Ok, body)?
        .encrypt_data_encryption_key(&data_encryption_key())
        .await?;

    assert_eq!(
        dek_encryption,
        DekEncryption {
            encrypted_dek: self::encrypted_key(&wrapped),
            kek_version: Some(KekVersion::try_from(KEY_VERSION.to_string())?),
        }
    );
    Ok(())
}

#[tokio::test]
async fn key_vault_encrypts_the_raw_key() -> Result<(), Box<dyn std::error::Error>> {
    for algorithm in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm] {
        let http_client = Arc::new(CannedHttpClient::new(
            StatusCode::Ok,
            format!(
                r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "d3JhcHBlZA"}}"#
            ),
        ));
        let provider = AzureKmsProvider::with_options(
            &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
            options_with(http_client.clone()),
            Arc::new(FixedTokenCredential),
        )?;
        let envelope = KmsAeadEnvelope::<_, Backend>::with_options(
            provider,
            KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
        )?;

        let (dek, _) = envelope.generate_encrypted_dek().await?;

        let request_bodies = http_client.request_bodies.lock().unwrap();
        let [request_body] = request_bodies.as_slice() else {
            panic!("{algorithm}: {} requests", request_bodies.len());
        };
        let parameters: serde_json::Value = serde_json::from_slice(request_body)?;
        let wrapped = azure_core::base64::decode_url_safe(
            parameters["value"]
                .as_str()
                .ok_or("no value in the encryption request")?,
        )?;
        assert_eq!(wrapped.len(), algorithm.key_len(), "{algorithm}");
        assert_eq!(wrapped, *dek.value().ref_sensitive_value(), "{algorithm}");
    }
    Ok(())
}

#[tokio::test]
async fn encrypted_key_outside_the_layout_is_rejected_before_any_request() -> KmsAeadResult<()> {
    // A request would be answered with 200 and a decrypted key, so an error here can only
    // come from the encrypted key.
    let provider = provider_over(
        StatusCode::Ok,
        format!(r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "AAAA"}}"#),
    )?;

    let err = provider
        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(b"wrapped".to_vec()))
        .await
        .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "AZURE_ENCRYPTED_DEK_FORMAT"),
        "{err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn error_response_body_is_absent_from_errors() -> KmsAeadResult<()> {
    // A body that is not an Azure error envelope is copied into the SDK error.
    let body = format!(r#"{{"value": "{LEAK_MARKER}"}}"#);
    let err = provider_over(StatusCode::Forbidden, body)?
        .decrypt_data_encryption_key(&encrypted_key(b"wrapped"))
        .await
        .unwrap_err();

    assert!(matches!(err, KmsAeadError::EncryptionError(_)));
    assert!(!err.to_string().contains(LEAK_MARKER), "{err}");
    assert!(!format!("{err:?}").contains(LEAK_MARKER), "{err:?}");
    Ok(())
}

#[tokio::test]
async fn server_errors_and_throttling_are_network_errors() -> KmsAeadResult<()> {
    for status in [StatusCode::ServiceUnavailable, StatusCode::TooManyRequests] {
        let err = provider_over(
            status,
            r#"{"error": {"code": "Throttled", "message": "Try later"}}"#.into(),
        )?
        .encrypt_data_encryption_key(&data_encryption_key())
        .await
        .unwrap_err();

        assert!(
            matches!(err, KmsAeadError::NetworkError(_)),
            "{status}: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn client_errors_keep_the_key_vault_error_code() -> KmsAeadResult<()> {
    let err = provider_over(
        StatusCode::Forbidden,
        r#"{"error": {"code": "Forbidden", "message": "The user does not have keys wrapKey permission"}}"#
            .into(),
    )?
    .encrypt_data_encryption_key(&data_encryption_key())
    .await
    .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "Forbidden"),
        "{err:?}"
    );
    Ok(())
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
