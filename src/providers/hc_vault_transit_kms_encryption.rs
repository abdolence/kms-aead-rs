use std::net::IpAddr;
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
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};
use tracing::*;

use crate::errors::*;
use crate::spans::{self, kms};
use crate::*;

const VAULT_TOKEN_HEADER: &str = "x-vault-token";
const VAULT_NAMESPACE_HEADER: &str = "x-vault-namespace";
/// Vault Agent and Vault Proxy refuse requests without it when `require_request_header` is set.
const VAULT_REQUEST_HEADER: &str = "x-vault-request";
/// A Transit response carries one wrapped or unwrapped data key, so a response this large is not
/// one and is not buffered.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;
/// The longest Vault error text quoted into an error. A misbehaving proxy may echo the request
/// or other data into `errors`, so only a short prefix of the first one is kept.
const MAX_VAULT_ERROR_CHARS: usize = 256;

/// Characters a path segment keeps as they are: the RFC 3986 unreserved set.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

/// A Vault token: non-empty visible ASCII, zeroized on drop, shown as `***` by `Debug`.
#[derive(Debug, Clone)]
pub struct HcVaultTransitToken(SecretValue);

impl TryFrom<SecretValue> for HcVaultTransitToken {
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

impl HcVaultTransitToken {
    /// The HTTP stack copies the value into buffers this crate cannot zeroize. Marking it
    /// sensitive keeps it out of the `Debug` output of the request headers.
    fn header_value(&self) -> KmsAeadResult<HeaderValue> {
        let mut value = HeaderValue::from_bytes(self.0.ref_sensitive_value()).map_err(|_| {
            KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "The Vault token is not a valid header value",
            )
        })?;
        value.set_sensitive(true);
        Ok(value)
    }
}

/// A key of the HashiCorp Vault Transit secrets engine.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct HcVaultTransitKeyRef {
    /// The name of the Transit key.
    pub key_name: String,

    /// Mount path of the Transit secrets engine.
    #[default = "\"transit\".into()"]
    pub mount: String,
}

/// Options for [`HcVaultTransitProvider`].
#[derive(Debug, Clone, Builder)]
pub struct HcVaultTransitProviderOptions {
    /// Address of the Vault server, such as `https://vault.example.com:8200`.
    pub address: String,

    /// Token sent with every request. Without one the requests carry no token, which is what a
    /// Vault Agent or Vault Proxy with `use_auto_auth_token` expects.
    pub token: Option<HcVaultTransitToken>,

    /// Vault Enterprise namespace the mount belongs to.
    pub namespace: Option<String>,

    /// PEM file with CA certificates to trust besides the ones of the selected root store, for a
    /// server whose certificate comes from a private CA. The file adds to the root store and does
    /// not replace it, unlike `VAULT_CACERT` in the Vault CLI, so a server with a certificate from
    /// any public CA in the root store is trusted as well.
    pub ca_certificate: Option<PathBuf>,

    /// Time limit for one request, from opening the connection to receiving the last byte of the
    /// response.
    #[default = "Duration::from_secs(60)"]
    pub timeout: Duration,
}

impl HcVaultTransitProviderOptions {
    /// Options from the variables the Vault CLI reads: `VAULT_ADDR` (required), `VAULT_TOKEN`,
    /// `VAULT_NAMESPACE` and `VAULT_CACERT`. An empty variable counts as unset.
    ///
    /// # Errors
    ///
    /// `VAULT_INVALID_OPTIONS` when `VAULT_ADDR` is unset, a variable is not valid Unicode, or
    /// the token is not visible ASCII.
    pub fn from_env() -> KmsAeadResult<Self> {
        let address = env_var("VAULT_ADDR")?.ok_or_else(|| {
            KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "VAULT_ADDR must be set to the address of the Vault server",
            )
        })?;
        let token = env_var("VAULT_TOKEN")?
            .map(|token| HcVaultTransitToken::try_from(SecretValue::from(token)))
            .transpose()?;

        Ok(Self::new(address)
            .opt_token(token)
            .opt_namespace(env_var("VAULT_NAMESPACE")?)
            .opt_ca_certificate(env_var("VAULT_CACERT")?.map(PathBuf::from)))
    }
}

/// Wraps and unwraps data encryption keys with a key of the HashiCorp Vault Transit secrets
/// engine. Available with the `hashicorp-vault-transit-kms-encryption-base` feature and one TLS
/// root store and one crypto provider feature.
///
/// A response with an error status is `VAULT_STATUS_<status>`: a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError) for a server error or a rate
/// limit, an [`EncryptionError`](crate::errors::KmsAeadError::EncryptionError) otherwise.
/// `VAULT_HTTP` and `VAULT_TIMEOUT` are network errors for a request that got no complete
/// response, and `VAULT_RESPONSE`, `VAULT_RESPONSE_TOO_LARGE` and `VAULT_CIPHERTEXT` encryption
/// errors for a response or an encrypted key that cannot be read.
///
/// The encrypted data encryption key is the Transit ciphertext, such as `vault:v1:...`. It names
/// the key version, so it still decrypts after the key is rotated. That version is also recorded
/// as the [`KmsKeyVersion`], for audit only: decrypt sends the ciphertext and never the recorded
/// version.
#[derive(Clone)]
pub struct HcVaultTransitProvider {
    http_client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    encrypt_uri: Uri,
    decrypt_uri: Uri,
    token: Option<HcVaultTransitToken>,
    namespace: Option<HeaderValue>,
    timeout: Duration,
    kek: KekRef,
}

impl HcVaultTransitProvider {
    /// A provider with the options from [`HcVaultTransitProviderOptions::from_env`].
    ///
    /// # Errors
    ///
    /// As [`HcVaultTransitProviderOptions::from_env`] and [`with_options`](Self::with_options).
    pub fn new(key_ref: &HcVaultTransitKeyRef) -> KmsAeadResult<Self> {
        Self::with_options(key_ref, HcVaultTransitProviderOptions::from_env()?)
    }

    /// A provider for the key at `key_ref` with `options`. It sends no request, so a wrong token
    /// or an unreachable server fail the first encryption.
    ///
    /// # Errors
    ///
    /// `VAULT_INVALID_OPTIONS` on an invalid address, mount, key name, namespace or timeout, an
    /// unreadable CA certificate file, or no CA certificate to trust at all, and `VAULT_TLS` when
    /// the TLS configuration cannot be built.
    pub fn with_options(
        key_ref: &HcVaultTransitKeyRef,
        options: HcVaultTransitProviderOptions,
    ) -> KmsAeadResult<Self> {
        if options.timeout.is_zero() {
            return Err(KmsAeadSystemError::create(
                "VAULT_INVALID_OPTIONS",
                "The Vault request timeout must be greater than zero",
            ));
        }
        let address = vault_address(&options.address)?;
        if is_plain_http_to_another_host(&address) {
            warn!(
                %address,
                "The Vault address uses plain HTTP to another host, so the token and the data keys cross the network unencrypted"
            );
        }
        let key_endpoint = |operation: &str| -> KmsAeadResult<Uri> {
            let uri = format!(
                "{}/v1/{}/{operation}/{}",
                address.to_string().trim_end_matches('/'),
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

        Ok(Self {
            http_client: Client::builder(TokioExecutor::new()).build(connector),
            encrypt_uri: key_endpoint("encrypt")?,
            decrypt_uri: key_endpoint("decrypt")?,
            token: options.token,
            namespace,
            timeout: options.timeout,
            kek: Self::kek_ref(&address, options.namespace.as_deref(), key_ref),
        })
    }

    /// `<address>/<namespace>/<mount>/keys/<name>`, without the namespace segment when none is
    /// set. The address and the namespace are part of it because the same mount and key name
    /// exist on every Vault server and in every Enterprise namespace, and a cache keyed by the
    /// KEK must never serve one tenant's data key to another.
    fn kek_ref(address: &Uri, namespace: Option<&str>, key_ref: &HcVaultTransitKeyRef) -> KekRef {
        let address = address.to_string();
        let namespace = namespace
            .map(|namespace| namespace.trim_matches('/'))
            .filter(|namespace| !namespace.is_empty());
        let mount = key_ref.mount.trim_matches('/');
        let key = match namespace {
            Some(namespace) => format!(
                "{}/{namespace}/{mount}/keys/{}",
                address.trim_end_matches('/'),
                key_ref.key_name
            ),
            None => format!(
                "{}/{mount}/keys/{}",
                address.trim_end_matches('/'),
                key_ref.key_name
            ),
        };
        KekRef::new(KekProvider::HcVaultTransit, key)
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
                token.header_value()?,
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
            let response = self
                .http_client
                .request(request)
                .await
                .map_err(KmsAeadError::from_vault_http_error)?;
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
            Ok(response) => response.first_error_prefix(),
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
impl KmsAeadEncryptionProvider for HcVaultTransitProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        encryption_key: &DataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::wrap_span(&self.kek), async {
            let plaintext = encryption_key.value().as_sensitive_base64_str();
            let associated_data = binding.map(associated_data);
            // The request buffer belongs to the HTTP stack and is freed without being zeroized.
            let request = serde_json::to_vec(&EncryptRequest {
                plaintext: &plaintext,
                associated_data: associated_data.as_deref(),
            })
            .map_err(|e| KmsAeadSystemError::create("VAULT_REQUEST", &e.to_string()))?;

            let body = kms::timed(self.post(&self.encrypt_uri, request)).await?;
            let response: TransitResponse<EncryptData> = parse_response(&body)?;
            response.check_binding(binding)?;
            let ciphertext = response.data.ciphertext;
            let key_version = transit_key_version(&ciphertext);
            let encrypted_key =
                EncryptedDataEncryptionKey::new(ciphertext.into_bytes(), key_version);
            kms::record_wrap(&encrypted_key);
            Ok(encrypted_key)
        })
        .await
    }

    /// The request URL names the configured key, so that Vault refuses a ciphertext of another
    /// key.
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_key: &EncryptedDataEncryptionKey,
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let span = kms::unwrap_span(&self.kek, encrypted_key.key_version());
        spans::in_span(span, async {
            let ciphertext = std::str::from_utf8(encrypted_key.wrapped()).map_err(|_| {
                KmsAeadEncryptionError::create(
                    "VAULT_CIPHERTEXT",
                    "The encrypted data encryption key is not a Vault Transit ciphertext",
                )
            })?;
            let associated_data = binding.map(associated_data);
            let request = serde_json::to_vec(&DecryptRequest {
                ciphertext,
                associated_data: associated_data.as_deref(),
            })
            .map_err(|e| KmsAeadSystemError::create("VAULT_REQUEST", &e.to_string()))?;

            let body = kms::timed(self.post(&self.decrypt_uri, request)).await?;
            let response: TransitResponse<DecryptData> = parse_response(&body)?;
            response.check_binding(binding)?;
            // The decode error is dropped because it names a byte of the key and its offset.
            let plaintext =
                SecretValue::from_base64_str(response.data.plaintext).map_err(|_| {
                    KmsAeadEncryptionError::create(
                        "VAULT_RESPONSE",
                        "The Vault Transit plaintext is not valid base64",
                    )
                })?;
            Ok(DataEncryptionKey::from(plaintext))
        })
        .await
    }
}

/// The Transit `associated_data` of `binding`: its bytes in base64.
fn associated_data(binding: &DekBinding) -> String {
    SecretValue::from(binding.as_str())
        .as_sensitive_base64_str()
        .to_string()
}

/// Without a binding the body has no `associated_data` key, so that an unbound wrap or unwrap
/// works on a Vault that does not know the field.
#[derive(Serialize)]
struct EncryptRequest<'a> {
    plaintext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
}

#[derive(Serialize)]
struct DecryptRequest<'a> {
    ciphertext: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    associated_data: Option<&'a str>,
}

#[derive(Deserialize)]
struct TransitResponse<D> {
    data: D,
    #[serde(default)]
    warnings: Option<Vec<String>>,
}

impl<D> TransitResponse<D> {
    /// A Vault that does not know `associated_data` ignores it and names it in a warning. The
    /// call then fails, so that a bound wrap or unwrap never succeeds unbound.
    fn check_binding(&self, binding: Option<&DekBinding>) -> KmsAeadResult<()> {
        let ignored = binding.is_some()
            && self
                .warnings
                .iter()
                .flatten()
                .any(|warning| warning.contains("associated_data"));
        if ignored {
            Err(KmsAeadEncryptionError::create(
                "VAULT_BINDING_IGNORED",
                "Vault ignored the associated data of a bound key, which needs Vault 1.13 or later and an AEAD Transit key type",
            ))
        } else {
            Ok(())
        }
    }
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

impl VaultErrorResponse {
    /// At most [`MAX_VAULT_ERROR_CHARS`] characters of the first error, quoted.
    fn first_error_prefix(&self) -> String {
        let first_error = self.errors.first().map(String::as_str).unwrap_or_default();
        format!(
            "{:?}",
            first_error
                .chars()
                .take(MAX_VAULT_ERROR_CHARS)
                .collect::<String>()
        )
    }
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

/// The `N` of the `vault:vN:` prefix of a Transit ciphertext. It is recorded for audit only:
/// Vault reads the version from its own ciphertext at decrypt.
fn transit_key_version(ciphertext: &str) -> Option<KmsKeyVersion> {
    match ciphertext
        .strip_prefix("vault:v")
        .and_then(|rest| rest.split_once(':'))
        .map(|(version, _)| KmsKeyVersion::try_from(version.to_string()))
    {
        Some(Ok(version)) => Some(version),
        _ => {
            warn!("No key version in the Vault Transit ciphertext");
            None
        }
    }
}

/// Whether requests to `address` carry the token and the data keys in plain text off this host:
/// an `http` address whose host is not `localhost` or a loopback IP address.
fn is_plain_http_to_another_host(address: &Uri) -> bool {
    let host = address.host().unwrap_or_default();
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    address.scheme_str() == Some("http") && !is_loopback
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

/// A Vault address: an `http` or `https` URI with a host and no query. Its text without the
/// trailing `/` is the API base, which keeps the path of a Vault served under a path prefix.
fn vault_address(address: &str) -> KmsAeadResult<Uri> {
    let invalid = |reason: String| {
        KmsAeadSystemError::create(
            "VAULT_INVALID_OPTIONS",
            &format!("`{address}` is not a valid Vault address: {reason}"),
        )
    };
    let uri = address.parse::<Uri>().map_err(|e| invalid(e.to_string()))?;
    match (uri.scheme_str(), uri.authority(), uri.query()) {
        (Some("http" | "https"), Some(_), None) => Ok(uri),
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

    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs")]
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-tls-ring")]
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
    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-tls-roots")]
    {
        let system_certificates = rustls_native_certs::load_native_certs();
        for error in &system_certificates.errors {
            warn!(%error, "Unable to load a system CA certificate");
        }
        roots.add_parsable_certificates(system_certificates.certs);
    }
    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-tls-webpki")]
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    roots
}

/// `roots` plus the CA certificates in `ca_certificate`, which add to the roots and never replace
/// them; fails when the result trusts no CA.
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
    use crate::test_http::answer_with;
    use crate::test_provider::TEST_BACKEND;
    use tokio::net::TcpListener;

    const TOKEN: &str = "hvs.token-marker-value";
    const DATA_KEY: &str = "data-key-marker-value-of-32bytes";
    const TEST_KEY: &str = "orders";
    const WRAPPED_KEY: &str = "vault:v1:wrapped";

    /// Ends a test whose request would otherwise hang, so a missing timeout fails the test.
    const TEST_GUARD: Duration = Duration::from_secs(5);

    fn local_provider(listener: &TcpListener) -> HcVaultTransitProvider {
        let address = format!("http://{}", listener.local_addr().unwrap());
        let token = HcVaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();
        let options = HcVaultTransitProviderOptions::new(address)
            .with_token(token)
            .with_timeout(Duration::from_millis(200));
        HcVaultTransitProvider::with_options(&HcVaultTransitKeyRef::new(TEST_KEY.into()), options)
            .unwrap()
    }

    fn data_key() -> DataEncryptionKey {
        DataEncryptionKey::from(SecretValue::from(DATA_KEY))
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
    async fn unwrap_names_the_configured_kek() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let provider = local_provider(&listener);
        let data_key_base64 = data_key().value().as_sensitive_base64_str();
        let requests = answer_with(
            listener,
            200,
            format!(
                r#"{{"data":{{"plaintext":"{}"}}}}"#,
                data_key_base64.as_str()
            ),
        );

        provider
            .decrypt_data_encryption_key(
                &EncryptedDataEncryptionKey::new(b"vault:v1:wrapped".into(), None),
                None,
            )
            .await
            .unwrap();

        let requests = requests.lock().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(
            requests[0]
                .head
                .starts_with(&format!("POST /v1/transit/decrypt/{TEST_KEY} ")),
            "{}",
            requests[0].head
        );
        assert_eq!(
            provider.kek().key(),
            format!("http://{address}/transit/keys/{TEST_KEY}")
        );
    }

    /// A body that answers both a Transit encrypt and a Transit decrypt.
    fn success_body(extra_fields: &str) -> String {
        format!(
            r#"{{"data":{{"ciphertext":"{WRAPPED_KEY}","plaintext":"{}"}}{extra_fields}}}"#,
            data_key().value().as_sensitive_base64_str().as_str()
        )
    }

    /// The JSON bodies of a wrap and an unwrap with `binding`.
    async fn wrap_and_unwrap_bodies(
        binding: Option<&DekBinding>,
    ) -> KmsAeadResult<Vec<serde_json::Value>> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        let requests = answer_with(listener, 200, success_body(""));

        let wrapped = provider
            .encrypt_data_encryption_key(&data_key(), binding)
            .await?;
        provider
            .decrypt_data_encryption_key(&wrapped, binding)
            .await?;

        let requests = requests.lock().unwrap();
        Ok(requests
            .iter()
            .map(|request| serde_json::from_slice(&request.body).unwrap())
            .collect())
    }

    #[tokio::test]
    async fn wrap_and_unwrap_carry_the_binding() -> KmsAeadResult<()> {
        let binding = DekBinding::try_from("tenant-42/3".to_string())?;

        let bodies = wrap_and_unwrap_bodies(Some(&binding)).await?;

        assert_eq!(bodies.len(), 2);
        for body in bodies {
            assert_eq!(body["associated_data"], "dGVuYW50LTQyLzM=", "{body}");
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_unbound_wrap_builds_the_0_29_request() -> KmsAeadResult<()> {
        let bodies = wrap_and_unwrap_bodies(None).await?;

        assert_eq!(
            bodies,
            [
                serde_json::json!({
                    "plaintext": data_key().value().as_sensitive_base64_str().as_str()
                }),
                serde_json::json!({ "ciphertext": WRAPPED_KEY }),
            ]
        );
        Ok(())
    }

    #[tokio::test]
    async fn an_ignored_associated_data_warning_fails_the_call() -> KmsAeadResult<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        answer_with(
            listener,
            200,
            success_body(
                r#","warnings":["Endpoint ignored these unrecognized parameters: [associated_data]"]"#,
            ),
        );
        let binding = DekBinding::try_from("tenant-42/3".to_string())?;

        let wrapped = provider
            .encrypt_data_encryption_key(&data_key(), Some(&binding))
            .await;
        let unwrapped = provider
            .decrypt_data_encryption_key(
                &EncryptedDataEncryptionKey::new(WRAPPED_KEY.into(), None),
                Some(&binding),
            )
            .await;

        assert!(
            matches!(&wrapped, Err(e) if e.code() == "VAULT_BINDING_IGNORED"),
            "{wrapped:?}"
        );
        assert!(
            matches!(&unwrapped, Err(e) if e.code() == "VAULT_BINDING_IGNORED"),
            "{:?}",
            unwrapped.err()
        );
        Ok(())
    }

    fn kek_of(address: &str, namespace: Option<&str>) -> KekRef {
        let options = HcVaultTransitProviderOptions::new(address.into())
            .opt_namespace(namespace.map(str::to_string));
        HcVaultTransitProvider::with_options(&HcVaultTransitKeyRef::new(TEST_KEY.into()), options)
            .unwrap()
            .kek()
            .clone()
    }

    #[test]
    fn kek_names_the_address_the_namespace_and_the_key() {
        assert_eq!(
            kek_of("https://vault.example.com:8200/", Some("/tenant-a/")),
            KekRef::new(
                KekProvider::HcVaultTransit,
                format!("https://vault.example.com:8200/tenant-a/transit/keys/{TEST_KEY}")
            )
        );
        assert_eq!(
            kek_of("https://vault.example.com:8200", None).key(),
            format!("https://vault.example.com:8200/transit/keys/{TEST_KEY}")
        );
    }

    #[test]
    fn keks_differ_across_namespaces_and_addresses() {
        let address = "https://vault.example.com:8200";
        assert_ne!(
            kek_of(address, Some("tenant-a")),
            kek_of(address, Some("tenant-b"))
        );
        assert_ne!(kek_of(address, None), kek_of(address, Some("tenant-a")));
        assert_ne!(
            kek_of(address, None),
            kek_of("https://vault.example.org:8200", None)
        );
    }

    #[tokio::test]
    async fn an_unreachable_server_is_a_network_error() {
        // A port that was just freed refuses the connection.
        let address = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap();
        let options = HcVaultTransitProviderOptions::new(format!("http://{address}"))
            .with_timeout(Duration::from_secs(2));
        let provider = HcVaultTransitProvider::with_options(
            &HcVaultTransitKeyRef::new(TEST_KEY.into()),
            options,
        )
        .unwrap();

        let Err(error) = provider
            .encrypt_data_encryption_key(&data_key(), None)
            .await
        else {
            panic!("a refused connection is not an encrypted key");
        };

        assert!(matches!(error, KmsAeadError::NetworkError(_)), "{error:?}");
        assert_eq!(error.code(), "VAULT_HTTP");
    }

    #[tokio::test]
    async fn unanswered_request_times_out_as_network_error() {
        // The listener is never accepted from: the kernel completes the connection and the
        // request is written, but no response ever comes.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);

        let result = tokio::time::timeout(
            TEST_GUARD,
            provider.encrypt_data_encryption_key(&data_key(), None),
        )
        .await
        .expect("the request must end before the test guard");

        let Err(error) = result else {
            panic!("an unanswered request is not an encrypted key");
        };
        assert!(matches!(error, KmsAeadError::NetworkError(_)));
        assert_eq!(error.code(), "VAULT_TIMEOUT");
    }

    #[tokio::test]
    async fn forbidden_response_is_not_quoted_in_error() {
        // A proxy in front of Vault may answer with a page that echoes the request.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        let data_key_base64 = data_key().value().as_sensitive_base64_str();
        answer_with(
            listener,
            403,
            format!("denied {TOKEN} {DATA_KEY} {}", data_key_base64.as_str()),
        );

        let Err(error) = provider
            .encrypt_data_encryption_key(&data_key(), None)
            .await
        else {
            panic!("a 403 is not an encrypted key");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_eq!(error.code(), "VAULT_STATUS_403");
        assert_no_secrets(&error);
    }

    #[test]
    fn token_is_not_shown_by_debug() {
        let token = HcVaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();

        assert!(!format!("{token:?}").contains(TOKEN));
    }

    #[test]
    fn root_store_without_certificates_is_rejected() {
        let Err(error) = trusted_roots(rustls::RootCertStore::empty(), None) else {
            panic!("a root store without certificates trusts no Vault server");
        };

        assert!(matches!(error, KmsAeadError::SystemError(_)));
        assert_eq!(error.code(), "VAULT_INVALID_OPTIONS");
    }

    #[tokio::test]
    async fn unparseable_decrypt_response_is_not_quoted_in_error() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        answer_with(listener, 200, format!(r#"{{"data":"{DATA_KEY}"}}"#));

        let Err(error) = provider
            .decrypt_data_encryption_key(
                &EncryptedDataEncryptionKey::new(b"vault:v1:wrapped".into(), None),
                None,
            )
            .await
        else {
            panic!("a string is not a Transit decrypt response");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_no_secrets(&error);
    }

    #[tokio::test]
    async fn vault_errors_are_cut_to_first_error_prefix() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let provider = local_provider(&listener);
        // Multi-byte characters put the cut inside a character unless it is made on a char
        // boundary.
        let echoed = format!("{}{DATA_KEY}", "é".repeat(MAX_VAULT_ERROR_CHARS));
        let body = serde_json::json!({ "errors": [echoed, DATA_KEY] }).to_string();
        answer_with(listener, 400, body);

        let Err(error) = provider
            .encrypt_data_encryption_key(&data_key(), None)
            .await
        else {
            panic!("a 400 is not an encrypted key");
        };

        assert_eq!(error.code(), "VAULT_STATUS_400");
        assert_no_secrets(&error);
        assert!(format!("{error}").chars().count() < 2 * MAX_VAULT_ERROR_CHARS);
    }

    #[test]
    fn key_version_is_read_from_the_transit_ciphertext() {
        assert_eq!(
            transit_key_version("vault:v3:AbCd+/ef=="),
            Some(KmsKeyVersion::try_from("3".to_string()).unwrap())
        );
        for malformed in [
            "vault:3:AbCd",
            "vault:v:AbCd",
            "vault:v3",
            "AbCd",
            "vault:v3-x:AbCd",
        ] {
            assert_eq!(transit_key_version(malformed), None, "{malformed}");
        }
    }

    #[test]
    fn only_plain_http_to_another_host_is_flagged() {
        for (address, flagged) in [
            ("http://vault.example.com:8200", true),
            ("http://10.0.0.5:8200", true),
            ("http://127.0.0.1:8200", false),
            ("http://127.1.2.3:8200", false),
            ("http://[::1]:8200", false),
            ("http://LocalHost:8200", false),
            ("https://vault.example.com:8200", false),
        ] {
            let address = vault_address(address).unwrap();
            assert_eq!(
                is_plain_http_to_another_host(&address),
                flagged,
                "{address}"
            );
        }
    }

    /// Runs against the Vault server in `VAULT_ADDR`, with a Transit key named `VAULT_TRANSIT_KEY`
    /// that `VAULT_TOKEN` may encrypt with, decrypt with and rotate.
    fn live_provider() -> HcVaultTransitProvider {
        let key_name =
            std::env::var("VAULT_TRANSIT_KEY").expect("VAULT_TRANSIT_KEY must name a Transit key");
        HcVaultTransitProvider::new(&HcVaultTransitKeyRef::new(key_name)).unwrap()
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
        let encryption = KmsAeadEnvelope::new(provider.clone(), TEST_BACKEND).unwrap();
        let aad = "orders-aad".to_string();
        let secret = SecretValue::from("order-secret");

        let key_version = |cipher_text: &CipherTextWithEncryptedKey| {
            let (_, encrypted_dek) = cipher_text.separate().unwrap();
            encrypted_dek.key_version().map(KmsKeyVersion::to_string)
        };

        let before_rotation = encryption
            .encrypt_value(aad.as_bytes(), &secret)
            .await
            .unwrap();
        provider.post(&rotate_uri, Vec::new()).await.unwrap();
        let after_rotation = encryption
            .encrypt_value(aad.as_bytes(), &secret)
            .await
            .unwrap();

        assert_eq!(key_version(&before_rotation).as_deref(), Some("1"));
        assert_eq!(key_version(&after_rotation).as_deref(), Some("2"));
        for cipher_text in [before_rotation, after_rotation] {
            assert_eq!(
                encryption
                    .decrypt_value(aad.as_bytes(), &cipher_text)
                    .await
                    .unwrap(),
                secret
            );
        }
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn live_unwrap_with_another_binding_fails() -> KmsAeadResult<()> {
        let provider = live_provider();
        let binding = DekBinding::try_from("tenant-42/1".to_string())?;
        let wrapped = provider
            .encrypt_data_encryption_key(&data_key(), Some(&binding))
            .await?;

        let unwrapped = provider
            .decrypt_data_encryption_key(&wrapped, Some(&binding))
            .await?;
        let result = provider
            .decrypt_data_encryption_key(
                &wrapped,
                Some(&DekBinding::try_from("tenant-42/2".to_string())?),
            )
            .await;

        println!(
            "Vault refused another binding with {:?}",
            result.as_ref().err().map(KmsAeadError::code)
        );
        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(e)) if e.public.code == "VAULT_STATUS_400"),
            "{:?}",
            result.err()
        );
        assert_eq!(unwrapped.value(), data_key().value());
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs a Vault server with the Transit secrets engine"]
    async fn invalid_token_is_rejected() {
        let key_name = std::env::var("VAULT_TRANSIT_KEY").unwrap();
        let token = HcVaultTransitToken::try_from(SecretValue::from(TOKEN)).unwrap();
        let options = HcVaultTransitProviderOptions::from_env()
            .unwrap()
            .with_token(token);
        let provider =
            HcVaultTransitProvider::with_options(&HcVaultTransitKeyRef::new(key_name), options)
                .unwrap();

        let Err(error) = provider
            .encrypt_data_encryption_key(&data_key(), None)
            .await
        else {
            panic!("an invalid token must not encrypt");
        };

        assert!(matches!(error, KmsAeadError::EncryptionError(_)));
        assert_no_secrets(&error);
    }
}
