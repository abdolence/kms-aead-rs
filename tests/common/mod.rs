use azure_core::credentials::{AccessToken, TokenCredential, TokenRequestOptions};
use azure_core::time::{Duration, OffsetDateTime};

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
