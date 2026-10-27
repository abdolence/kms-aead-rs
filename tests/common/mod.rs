#![allow(
    dead_code,
    reason = "each test target that includes this module uses some of it"
)]

use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::http::headers::{self, Headers};
use azure_core::http::{AsyncRawResponse, Body, HttpClient, Request, StatusCode};
use azure_core::time::{Duration, OffsetDateTime};
use std::sync::{Mutex, PoisonError};

/// The backend the tests encrypt with: the first one the build has.
#[cfg(feature = "ring")]
pub type Backend = kms_aead::backends::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
pub type Backend = kms_aead::backends::AwsLc;
#[cfg(all(
    not(feature = "ring"),
    not(feature = "aws-lc-rs"),
    feature = "rustcrypto"
))]
pub type Backend = kms_aead::backends::RustCrypto;

/// The backend that encrypts under a public key, which ring cannot.
#[cfg(feature = "aws-lc-rs")]
pub type RsaBackend = kms_aead::backends::AwsLc;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "rustcrypto"))]
pub type RsaBackend = kms_aead::backends::RustCrypto;

/// Hands out the same bearer token for every request, for servers that accept any token.
#[derive(Debug)]
pub struct FixedTokenCredential;

#[async_trait::async_trait]
impl TokenCredential for FixedTokenCredential {
    async fn get_token(
        &self,
        _scopes: &[&str],
        _options: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        Ok(AccessToken::new(
            "fixed-token",
            OffsetDateTime::now_utc() + Duration::hours(1),
        ))
    }
}

/// With `azure-kms-encryption-tls-no-provider` the application installs the rustls crypto
/// provider; an install that finds one already installed changes nothing.
pub fn install_crypto_provider() {
    #[cfg(feature = "azure-kms-encryption-tls-no-provider")]
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Key Vault's challenge to a request that carries no token, such as the first request of a
/// client.
const KEY_VAULT_CHALLENGE: &str = r#"Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net""#;

/// Answers every request that carries a token with one canned response and keeps the URL of each
/// request and the body of each request that has one. A request without a token is answered with
/// Key Vault's challenge, as the SDK expects before it sends its token.
#[derive(Debug)]
pub struct CannedHttpClient {
    status: StatusCode,
    body: String,
    pub urls: Mutex<Vec<String>>,
    pub request_bodies: Mutex<Vec<Vec<u8>>>,
}

impl CannedHttpClient {
    pub fn new(status: StatusCode, body: String) -> Self {
        Self {
            status,
            body,
            urls: Mutex::new(Vec::new()),
            request_bodies: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for CannedHttpClient {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        self.urls
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(request.url().to_string());
        let mut headers = Headers::new();
        if request
            .headers()
            .get_optional_str(&headers::AUTHORIZATION)
            .is_none()
        {
            headers.insert(headers::WWW_AUTHENTICATE, KEY_VAULT_CHALLENGE);
            return Ok(AsyncRawResponse::from_bytes(
                StatusCode::Unauthorized,
                headers,
                Vec::new(),
            ));
        }
        if let Body::Bytes(body) = request.body() {
            if !body.is_empty() {
                self.request_bodies
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(body.to_vec());
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
