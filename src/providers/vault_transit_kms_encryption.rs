use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use hyper::{Method, Request, StatusCode, Uri};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use rsb_derive::Builder;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::CertificateDer;
use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use tracing::*;

use crate::errors::*;
use crate::ring_encryption::RingAeadEncryption;
use crate::*;

const VAULT_TOKEN_HEADER: &str = "x-vault-token";
const VAULT_NAMESPACE_HEADER: &str = "x-vault-namespace";
/// Vault Agent and Vault Proxy refuse requests without it when `require_request_header` is set.
const VAULT_REQUEST_HEADER: &str = "x-vault-request";
/// A Transit response carries one wrapped or unwrapped data key, so a response this large is not
/// one and is not buffered.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// Characters a path segment keeps as they are: the RFC 3986 unreserved set.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A Vault token: non-empty visible ASCII, zeroized on drop, shown as `***` by `Debug`.
#[derive(Debug, Clone)]
pub struct VaultTransitToken(SecretValue);

impl TryFrom<SecretValue> for VaultTransitToken {
    type Error = KmsAeadError;

    fn try_from(token: SecretValue) -> Result<Self, Self::Error> {
        let bytes = token.ref_sensitive_value();
        if !bytes.is_empty() && bytes.iter().all(u8::is_ascii_graphic) {
            Ok(Self(token))
        } else {
            Err(KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "A Vault token must be a non-empty string of visible ASCII characters",
            ))
        }
    }
}

impl VaultTransitToken {
    /// The HTTP stack copies the value into buffers this crate cannot zeroize. Marking it
    /// sensitive keeps it out of the `Debug` output of the request headers.
    fn header_value(&self) -> HeaderValue {
        let mut value = HeaderValue::from_bytes(self.0.ref_sensitive_value())
            .expect("a token holds visible ASCII only, which is always a valid header value");
        value.set_sensitive(true);
        value
    }
}

/// A key of the Vault Transit secrets engine.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct VaultTransitKeyRef {
    pub key_name: String,

    /// Mount path of the Transit secrets engine.
    #[default = "\"transit\".into()"]
    pub mount: String,
}

/// Options for [`VaultTransitProvider`].
#[derive(Debug, Clone, Builder)]
pub struct VaultTransitProviderOptions {
    /// Address of the Vault server, such as `https://vault.example.com:8200`.
    pub address: String,

    /// Token sent with every request. Without one the requests carry no token, which is what a
    /// Vault Agent or Vault Proxy with `use_auto_auth_token` expects.
    pub token: Option<VaultTransitToken>,

    /// Vault Enterprise namespace the mount belongs to.
    pub namespace: Option<String>,

    /// PEM file with CA certificates to trust besides the ones of the selected root store, for a
    /// server whose certificate comes from a private CA.
    pub ca_certificate: Option<PathBuf>,

    /// Time limit for one request, from opening the connection to receiving the last byte of the
    /// response.
    #[default = "Duration::from_secs(60)"]
    pub timeout: Duration,
}

impl VaultTransitProviderOptions {
    /// Options from the variables the Vault CLI reads: `VAULT_ADDR` (required), `VAULT_TOKEN`,
    /// `VAULT_NAMESPACE` and `VAULT_CACERT`. An empty variable counts as unset.
    pub fn from_env() -> KmsAeadResult<Self> {
        let address = env_var("VAULT_ADDR")?.ok_or_else(|| {
            KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "VAULT_ADDR must be set to the address of the Vault server",
            )
        })?;
        let token = env_var("VAULT_TOKEN")?
            .map(|token| VaultTransitToken::try_from(SecretValue::from(token)))
            .transpose()?;

        Ok(Self::new(address)
            .opt_token(token)
            .opt_namespace(env_var("VAULT_NAMESPACE")?)
            .opt_ca_certificate(env_var("VAULT_CACERT")?.map(PathBuf::from)))
    }
}

/// Wraps and unwraps data encryption keys with a key of the Vault Transit secrets engine.
///
/// The encrypted data encryption key is the Transit ciphertext, such as `vault:v1:...`. It names
/// the key version, so it still decrypts after the key is rotated.
#[derive(Clone)]
pub struct VaultTransitProvider {
    http_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    encrypt_uri: Uri,
    decrypt_uri: Uri,
    token: Option<VaultTransitToken>,
    namespace: Option<HeaderValue>,
    timeout: Duration,
}

impl VaultTransitProvider {
    /// A provider with the options from [`VaultTransitProviderOptions::from_env`].
    pub fn new(key_ref: &VaultTransitKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(key_ref, VaultTransitProviderOptions::from_env()?)
    }

    /// Fails on an invalid address, mount, key name, namespace or timeout, an unreadable CA
    /// certificate file, or no CA certificate to trust at all. It sends no request, so a wrong
    /// token or an unreachable server fail the first encryption.
    pub fn with_options(
        key_ref: &VaultTransitKeyRef,
        options: VaultTransitProviderOptions,
    ) -> KmsAeadResult<Self> {
        if options.timeout.is_zero() {
            return Err(KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "The Vault request timeout must be greater than zero",
            ));
        }
        let key_endpoint = |operation: &str| -> KmsAeadResult<Uri> {
            let uri = format!(
                "{}/v1/{}/{operation}/{}",
                vault_api_base(&options.address)?,
                encoded_vault_path("mount", key_ref.mount.trim_matches('/'))?,
                encoded_vault_path("key_name", &key_ref.key_name)?
            );
            Uri::try_from(uri.as_str()).map_err(|e| {
                KmsAeadSystemError::create(
                    "VAULT_INVALID_OPTIONS",
                    &format!("`{uri}` is not a valid Vault request URI: {e}"),
                )
            })
        };
        let namespace = options
            .namespace
            .as_deref()
            .map(|namespace| {
                HeaderValue::from_str(namespace).map_err(|_| {
                    KmsAeadSystemError::create(
                        "VAULT_INVALID_OPTIONS",
                        &format!("`{namespace}` is not a valid Vault namespace"),
                    )
                })
            })
            .transpose()?;
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(tls_config(options.ca_certificate.as_deref())?)
            .https_or_http()
            .enable_http1()
            .build();

        debug!(
            mount = %key_ref.mount,
            key_name = %key_ref.key_name,
            "Initialising Vault Transit envelope encryption"
        );

        Ok(Self {
            http_client: Client::builder(TokioExecutor::new()).build(connector),
            encrypt_uri: key_endpoint("encrypt")?,
            decrypt_uri: key_endpoint("decrypt")?,
            token: options.token,
            namespace,
            timeout: options.timeout,
        })
    }

    async fn post(&self, uri: &Uri, body: Vec<u8>) -> KmsAeadResult<Bytes> {
        let mut request = Request::new(Full::new(Bytes::from(body)));
        *request.method_mut() = Method::POST;
        *request.uri_mut() = uri.clone();
        let headers = request.headers_mut();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert(
            HeaderName::from_static(VAULT_REQUEST_HEADER),
            HeaderValue::from_static("true"),
        );
        if let Some(token) = &self.token {
            headers.insert(
                HeaderName::from_static(VAULT_TOKEN_HEADER),
                token.header_value(),
            );
        }
        if let Some(namespace) = &self.namespace {
            headers.insert(
                HeaderName::from_static(VAULT_NAMESPACE_HEADER),
                namespace.clone(),
            );
        }

        trace!(%uri, "Sending Vault Transit request");
        let exchange = async {
            let response = self.http_client.request(request).await?;
            let status = response.status();
            // The body buffer belongs to the HTTP stack and is freed without being zeroized.
            let body = Limited::new(response.into_body(), MAX_RESPONSE_SIZE)
                .collect()
                .await
                .map_err(|e| {
                    if e.is::<LengthLimitError>() {
                        KmsAeadEncryptionError::create(
                            "VAULT_RESPONSE_TOO_LARGE",
                            &format!("The Vault response is larger than {MAX_RESPONSE_SIZE} bytes"),
                        )
                    } else {
                        KmsAeadError::NetworkError(KmsAeadNetworkError::with_error_chain(
                            "VAULT_HTTP",
                            "Unable to receive the Vault response",
                            e.as_ref(),
                        ))
                    }
                })?
                .to_bytes();
            Ok::<_, KmsAeadError>((status, body))
        };
        let (status, body) = tokio::time::timeout(self.timeout, exchange)
            .await
            .map_err(|_| {
                KmsAeadNetworkError::create(
                    "VAULT_TIMEOUT",
                    &format!("No complete Vault response within {:?}", self.timeout),
                )
            })??;

        if status.is_success() {
            return Ok(body);
        }

        let errors = match serde_json::from_slice::<VaultErrorResponse>(&body) {
            Ok(response) => format!("{:?}", response.errors),
            // The parse error is dropped because serde_json may quote the body in it.
            Err(_) => "the body is not a Vault error response".to_string(),
        };
        let code = format!("VAULT_STATUS_{}", status.as_u16());
        let message = format!("Vault returned {status} for {}: {errors}", uri.path());
        // A sealed or overloaded server answers 5xx or 429 and may serve the same request later;
        // any other status will not change on a retry.
        if status.is_server_error() || status == StatusCode::TOO_MANY_REQUESTS {
            Err(KmsAeadNetworkError::create(&code, &message))
        } else {
            Err(KmsAeadEncryptionError::create(&code, &message))
        }
    }
}

#[async_trait]
impl KmsAeadRingEncryptionProvider for VaultTransitProvider {
    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let plaintext = encryption_key.value().as_sensitive_base64_str();
        // The request buffer belongs to the HTTP stack and is freed without being zeroized.
        let request = serde_json::to_vec(&EncryptRequest {
            plaintext: &plaintext,
        })
        .map_err(|e| KmsAeadSystemError::create("VAULT_REQUEST", &e.to_string()))?;

        let body = self.post(&self.encrypt_uri, request).await?;
        let response: TransitResponse<EncryptData> = parse_response(&body)?;
        Ok(EncryptedDataEncryptionKey(
            response.data.ciphertext.into_bytes(),
        ))
    }

    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let ciphertext = std::str::from_utf8(encrypted_key.value()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "VAULT_CIPHERTEXT",
                "The encrypted data encryption key is not a Vault Transit ciphertext",
            )
        })?;
        let request = serde_json::to_vec(&DecryptRequest { ciphertext })
            .map_err(|e| KmsAeadSystemError::create("VAULT_REQUEST", &e.to_string()))?;

        let body = self.post(&self.decrypt_uri, request).await?;
        let response: TransitResponse<DecryptData> = parse_response(&body)?;
        // The decode error is dropped because it names a byte of the key and its offset.
        let plaintext = SecretValue::from_base64_str(response.data.plaintext).map_err(|_| {
            KmsAeadEncryptionError::create(
                "VAULT_RESPONSE",
                "The Vault Transit plaintext is not valid base64",
            )
        })?;
        Ok(DataEncryptionKey(plaintext))
    }

    async fn generate_encryption_key(
        &self,
        aead_encryption: &RingAeadEncryption,
    ) -> KmsAeadResult<DataEncryptionKey> {
        aead_encryption.generate_data_encryption_key()
    }
}

#[derive(Serialize)]
struct EncryptRequest<'a> {
    plaintext: &'a str,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext: &'a str,
}

#[derive(Deserialize)]
struct TransitResponse<D> {
    data: D,
}

#[derive(Deserialize)]
struct EncryptData {
    ciphertext: String,
}

#[derive(Deserialize)]
struct DecryptData {
    plaintext: String,
}

/// The body of a failed Vault request.
#[derive(Deserialize)]
struct VaultErrorResponse {
    #[serde(default)]
    errors: Vec<String>,
}

/// serde_json quotes the offending value in its messages, and in a decrypt response that value
/// can be the data key itself, so only the category and position are kept.
fn parse_response<'a, T: Deserialize<'a>>(body: &'a [u8]) -> KmsAeadResult<T> {
    serde_json::from_slice(body).map_err(|e| {
        KmsAeadEncryptionError::create(
            "VAULT_RESPONSE",
            &format!(
                "Unable to parse the Vault Transit response: {:?} error at line {} column {}",
                e.classify(),
                e.line(),
                e.column()
            ),
        )
    })
}

/// The value of an environment variable, `None` when it is unset or empty.
fn env_var(name: &str) -> KmsAeadResult<Option<String>> {
    match std::env::var(name) {
        Ok(value) if value.is_empty() => Ok(None),
        Ok(value) => Ok(Some(value)),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err(KmsAeadSystemError::create(
            "VAULT_INVALID_OPTIONS",
            &format!("{name} is not valid Unicode"),
        )),
    }
}

/// `scheme://authority` of a Vault address, followed by its path when Vault is served under a
/// path prefix.
fn vault_api_base(address: &str) -> KmsAeadResult<String> {
    let invalid = |reason: String| {
        KmsAeadSystemError::create(
            "VAULT_INVALID_OPTIONS",
            &format!("`{address}` is not a valid Vault address: {reason}"),
        )
    };
    let uri = address.parse::<Uri>().map_err(|e| invalid(e.to_string()))?;
    match (uri.scheme_str(), uri.authority(), uri.query()) {
        (Some(scheme @ ("http" | "https")), Some(authority), None) => Ok(format!(
            "{scheme}://{authority}{}",
            uri.path().trim_end_matches('/')
        )),
        _ => Err(invalid(
            "expected http:// or https://, a host and no query".into(),
        )),
    }
}

/// Percent-encodes each `/`-separated segment of a path inside Vault, so a name can neither add
/// a query nor reach outside the mount.
fn encoded_vault_path(field: &str, path: &str) -> KmsAeadResult<String> {
    path.split('/')
        .map(|segment| match segment {
            "" | "." | ".." => Err(KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                &format!("`{path}` is not a valid Vault {field}: its segments must not be empty, `.` or `..`"),
            )),
            segment => Ok(utf8_percent_encode(segment, PATH_SEGMENT).to_string()),
        })
        .collect::<KmsAeadResult<Vec<_>>>()
        .map(|segments| segments.join("/"))
}

/// The roots of the selected root store plus the CA certificates in `ca_certificate`, with the
/// selected crypto provider. The provider is passed to this config only and never installed as
/// the process default, which stays the application's choice.
fn tls_config(ca_certificate: Option<&Path>) -> KmsAeadResult<rustls::ClientConfig> {
    let roots = trusted_roots(selected_root_store(), ca_certificate)?;

    #[cfg(feature = "vault-transit-kms-encryption-tls-aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "vault-transit-kms-encryption-tls-ring")]
    let provider = rustls::crypto::ring::default_provider();

    let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .map_err(|e| KmsAeadSystemError::create("VAULT_TLS", &e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(config)
}

fn selected_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    #[cfg(feature = "vault-transit-kms-encryption-tls-roots")]
    {
        let system_certificates = rustls_native_certs::load_native_certs();
        for error in &system_certificates.errors {
            warn!(%error, "Unable to load a system CA certificate");
        }
        roots.add_parsable_certificates(system_certificates.certs);
    }
    #[cfg(feature = "vault-transit-kms-encryption-tls-webpki")]
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// `roots` plus the CA certificates in `ca_certificate`; fails when the result trusts no CA.
fn trusted_roots(
    mut roots: rustls::RootCertStore,
    ca_certificate: Option<&Path>,
) -> KmsAeadResult<rustls::RootCertStore> {
    if let Some(path) = ca_certificate {
        let certificates = CertificateDer::pem_file_iter(path)
            .and_then(|certificates| certificates.collect::<Result<Vec<_>, _>>())
            .map_err(|e| {
                KmsAeadSystemError::create(
                    "VAULT_INVALID_OPTIONS",
                    &format!(
                        "Unable to read PEM certificates from {}: {e}",
                        path.display()
                    ),
                )
            })?;
        let (added, ignored) = roots.add_parsable_certificates(certificates);
        if added == 0 || ignored > 0 {
            return Err(KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                &format!(
                    "{} must hold CA certificates only: {added} usable, {ignored} not",
                    path.display()
                ),
            ));
        }
    }
    // With system roots on a host that has none installed, such as a distroless image, every
    // request would fail later with an unknown issuer.
    if roots.is_empty() {
        return Err(KmsAeadSystemError::create(
            "VAULT_INVALID_OPTIONS",
            "No CA certificates to trust: the system has none and no CA certificate file is set",
        ));
    }
    Ok(roots)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const TOKEN: &str = "hvs.token-marker-value";
    const DATA_KEY: &str = "data-key-marker-value-of-32bytes";
    const TEST_KEY: &str = "orders";

    /// Ends a test whose request would otherwise hang, so a missing timeout fails the test.
    const TEST_GUARD: Duration = Duration::from_secs(5);

    fn local_provider(listener: &TcpListener) -> VaultTransitProvider {
        let address = format!("http://{}", listener.local_addr().unwrap());
        let token = VaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();
        let options = VaultTransitProviderOptions::new(address)
            .with_token(token)
            .with_timeout(Duration::from_millis(200));
        VaultTransitProvider::with_options(&VaultTransitKeyRef::new(TEST_KEY.into()), options)
            .unwrap()
    }

    /// Answers every request on `listener` with `status` and `body`.
    fn answer_with(listener: TcpListener, status: StatusCode, body: String) {
        tokio::spawn(async move {
            loop {
                let (mut connection, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                let mut buffer = [0u8; 1024];
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let read = connection.read(&mut buffer).await.unwrap();
                    request.extend_from_slice(&buffer[..read]);
                }
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                connection.write_all(response.as_bytes()).await.unwrap();
            }
        });
    }

    fn data_key() -> DataEncryptionKey {
        DataEncryptionKey(SecretValue::from(DATA_KEY))
    }

    fn error_code(error: &KmsAeadError) -> &str {
        match error {
            KmsAeadError::SystemError(error) => &error.public.code,
            KmsAeadError::NetworkError(error) => &error.public.code,
            KmsAeadError::EncryptionError(error) => &error.public.code,
        }
    }

    fn assert_no_secrets(error: &KmsAeadError) {
        let data_key_base64 = data_key().value().as_sensitive_base64_str();
        for text in [format!("{error}"), format!("{error:?}")] {
            assert!(!text.contains(TOKEN), "{text}");
            assert!(!text.contains(DATA_KEY), "{text}");
            assert!(!text.contains(data_key_base64.as_str()), "{text}");
        }
    }

    #[tokio::test]
    async fn unanswered_request_times_out_as_network_error() {
        // The listener is never accepted from: the kernel completes the connection and the
        // request is written, but no response ever comes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);

        let result = tokio::time::timeout(
            TEST_GUARD,
            provider.encrypt_data_encryption_key(&data_key()),
        )
        .await
        .expect("the request must end before the test guard");

        let Err(error) = result else {
            panic!("an unanswered request is not an encrypted key");
        };
        assert!(matches!(error, KmsAeadError::NetworkError(_)));
        assert_eq!(error_code(&error), "VAULT_TIMEOUT");
    }

    #[tokio::test]
    async fn forbidden_response_is_not_quoted_in_error() {
        // A proxy in front of Vault may answer with a page that echoes the request.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        let data_key_base64 = data_key().value().as_sensitive_base64_str();
        answer_with(
            listener,
            StatusCode::FORBIDDEN,
            format!("denied {TOKEN} {DATA_KEY} {}", data_key_base64.as_str()),
        );

        let Err(error) = provider.encrypt_data_encryption_key(&data_key()).await else {
            panic!("a 403 is not an encrypted key");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_eq!(error_code(&error), "VAULT_STATUS_403");
        assert_no_secrets(&error);
    }

    #[test]
    fn token_is_not_shown_by_debug() {
        let token = VaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();

        assert!(!format!("{token:?}").contains(TOKEN));
    }

    #[test]
    fn root_store_without_certificates_is_rejected() {
        let Err(error) = trusted_roots(rustls::RootCertStore::empty(), None) else {
            panic!("a root store without certificates trusts no Vault server");
        };

        assert!(matches!(error, KmsAeadError::SystemError(_)));
        assert_eq!(error_code(&error), "VAULT_INVALID_OPTIONS");
    }

    #[tokio::test]
    async fn unparseable_decrypt_response_is_not_quoted_in_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        answer_with(
            listener,
            StatusCode::OK,
            format!(r#"{{"data":"{DATA_KEY}"}}"#),
        );

        let Err(error) = provider
            .decrypt_data_encryption_key(&EncryptedDataEncryptionKey(b"vault:v1:wrapped".into()))
            .await
        else {
            panic!("a string is not a Transit decrypt response");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_no_secrets(&error);
    }

    /// Runs against the Vault server in `VAULT_ADDR`, with a Transit key named `VAULT_TRANSIT_KEY`
    /// that `VAULT_TOKEN` may encrypt with, decrypt with and rotate.
    fn live_provider() -> VaultTransitProvider {
        let key_name =
            std::env::var("VAULT_TRANSIT_KEY").expect("VAULT_TRANSIT_KEY must name a Transit key");
        VaultTransitProvider::new(&VaultTransitKeyRef::new(key_name)).unwrap()
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn envelope_round_trip_survives_key_rotation() {
        let provider = live_provider();
        let rotate_uri = Uri::try_from(
            provider
                .encrypt_uri
                .to_string()
                .replace("/encrypt/", "/keys/")
                + "/rotate",
        )
        .unwrap();
        let encryption = KmsAeadRingEnvelopeEncryption::new(provider.clone())
            .await
            .unwrap();
        let aad = "orders-aad".to_string();
        let secret = SecretValue::from("order-secret");

        let cipher_text = encryption.encrypt_value(&aad, &secret).await.unwrap();
        assert_eq!(
            encryption.decrypt_value(&aad, &cipher_text).await.unwrap(),
            secret
        );

        provider.post(&rotate_uri, Vec::new()).await.unwrap();

        assert_eq!(
            encryption.decrypt_value(&aad, &cipher_text).await.unwrap(),
            secret
        );
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn invalid_token_is_rejected() {
        let key_name = std::env::var("VAULT_TRANSIT_KEY").unwrap();
        let token = VaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();
        let options = VaultTransitProviderOptions::from_env()
            .unwrap()
            .with_token(token);
        let provider =
            VaultTransitProvider::with_options(&VaultTransitKeyRef::new(key_name), options)
                .unwrap();

        let Err(error) = provider.encrypt_data_encryption_key(&data_key()).await else {
            panic!("an invalid token must not encrypt");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_no_secrets(&error);
    }
}
