use rsb_derive::Builder;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::time::SystemTimeError;

pub type BoxedError = Box<dyn std::error::Error + Send + Sync>;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub enum KmsAeadError {
    SystemError(KmsAeadSystemError),
    NetworkError(KmsAeadNetworkError),
    EncryptionError(KmsAeadEncryptionError),
}

impl Display for KmsAeadError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match *self {
            KmsAeadError::SystemError(ref err) => err.fmt(f),
            KmsAeadError::NetworkError(ref err) => err.fmt(f),
            KmsAeadError::EncryptionError(ref err) => err.fmt(f),
        }
    }
}

impl std::error::Error for KmsAeadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match *self {
            KmsAeadError::SystemError(ref err) => Some(err),
            KmsAeadError::NetworkError(ref err) => Some(err),
            KmsAeadError::EncryptionError(ref err) => Some(err),
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KmsAeadErrorPublicGenericDetails {
    pub code: String,
}

#[derive(Debug, Builder)]
pub struct KmsAeadSystemError {
    pub public: KmsAeadErrorPublicGenericDetails,
    pub message: String,
    pub root_cause: Option<BoxedError>,
}

impl Display for KmsAeadSystemError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "KmsAead system/internal error: {:?} / {}",
            self.public, self.message
        )
    }
}

impl KmsAeadSystemError {
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::SystemError(KmsAeadSystemError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }
}

impl std::error::Error for KmsAeadSystemError {}

#[derive(Debug, Eq, PartialEq, Clone, Builder)]
pub struct KmsAeadNetworkError {
    pub public: KmsAeadErrorPublicGenericDetails,
    pub message: String,
}

impl Display for KmsAeadNetworkError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Network error: {:?} / {}", self.public, self.message)
    }
}

impl KmsAeadNetworkError {
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::NetworkError(KmsAeadNetworkError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }

    /// For an error whose message and source chain carry no secret. The chain goes into the
    /// message, since the top-level message of an HTTP error rarely says what failed.
    #[cfg(feature = "vault-transit-kms-encryption-base")]
    pub(crate) fn with_error_chain(code: &str, context: &str, e: &(dyn Error + 'static)) -> Self {
        let mut message = format!("{context}: {e}");
        let mut source = e.source();
        while let Some(cause) = source {
            message.push_str(&format!(": {cause}"));
            source = cause.source();
        }
        KmsAeadNetworkError::new(KmsAeadErrorPublicGenericDetails::new(code.into()), message)
    }
}

impl std::error::Error for KmsAeadNetworkError {}

#[derive(Debug, Builder)]
pub struct KmsAeadEncryptionError {
    pub public: KmsAeadErrorPublicGenericDetails,
    pub message: String,
    pub root_cause: Option<BoxedError>,
}

impl KmsAeadEncryptionError {
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }
}

impl Display for KmsAeadEncryptionError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "KmsAead encryption error: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for KmsAeadEncryptionError {}

impl From<SystemTimeError> for KmsAeadError {
    fn from(e: SystemTimeError) -> Self {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new("SYSTEM_TIME_ERROR".to_string()),
                format!("System time error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(feature = "gcp")]
impl From<gcloud_sdk::error::Error> for KmsAeadError {
    fn from(e: gcloud_sdk::error::Error) -> Self {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new(format!("{:?}", e.kind())),
                format!("GCloud system error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(feature = "gcp")]
impl From<gcloud_sdk::tonic::Status> for KmsAeadError {
    fn from(status: gcloud_sdk::tonic::Status) -> Self {
        KmsAeadError::NetworkError(KmsAeadNetworkError::new(
            KmsAeadErrorPublicGenericDetails::new(format!("{:?}", status.code())),
            format!("{status}"),
        ))
    }
}

#[cfg(feature = "aws")]
impl<E: Display + Error + Sync + Send + 'static, R: std::fmt::Debug + Sync + Send + 'static>
    From<aws_sdk_kms::error::SdkError<E, R>> for KmsAeadError
{
    fn from(e: aws_sdk_kms::error::SdkError<E, R>) -> Self {
        KmsAeadError::EncryptionError(
            KmsAeadEncryptionError::new(
                KmsAeadErrorPublicGenericDetails::new(format!("{e}")),
                format!("AWS KMS error: {e}"),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(feature = "vault-transit-kms-encryption-base")]
impl From<hyper_util::client::legacy::Error> for KmsAeadError {
    fn from(e: hyper_util::client::legacy::Error) -> Self {
        KmsAeadError::NetworkError(KmsAeadNetworkError::with_error_chain(
            "VAULT_HTTP",
            "Unable to send the Vault request",
            &e,
        ))
    }
}

#[cfg(feature = "azure-kms-encryption-base")]
impl From<azure_core::Error> for KmsAeadError {
    /// A 5xx or 429 response is a retryable network error; any other HTTP error keeps Key
    /// Vault's error code and the message of its error envelope. Nothing else from a response
    /// body is kept: for a body that is not an Azure error envelope the SDK copies the whole
    /// body into the error, and an unwrap response body holds the data encryption key. A
    /// response parse error keeps no message or root cause for the same reason.
    fn from(e: azure_core::Error) -> Self {
        use azure_core::error::ErrorKind;
        match e.kind() {
            ErrorKind::HttpResponse {
                status,
                error_code,
                raw_response,
            } => {
                let code = error_code
                    .clone()
                    .unwrap_or_else(|| format!("AZURE_STATUS_{}", u16::from(*status)));
                let envelope_message = raw_response
                    .as_ref()
                    .and_then(|response| {
                        azure_core::json::from_json::<_, azure_core::error::ErrorResponse>(
                            response.body(),
                        )
                        .ok()
                    })
                    .and_then(|response| response.error)
                    .and_then(|detail| detail.message);
                let message = match envelope_message {
                    Some(message) => format!("Azure Key Vault returned {status}: {message}"),
                    None => format!("Azure Key Vault returned {status}"),
                };
                if status.is_server_error()
                    || *status == azure_core::http::StatusCode::TooManyRequests
                {
                    KmsAeadNetworkError::create(&code, &message)
                } else {
                    KmsAeadEncryptionError::create(&code, &message)
                }
            }
            ErrorKind::DataConversion => KmsAeadEncryptionError::create(
                &format!("{}", e.kind()),
                "Unable to parse the Azure Key Vault response",
            ),
            ErrorKind::Connection | ErrorKind::Io => KmsAeadNetworkError::create(
                &format!("{}", e.kind()),
                &format!("Azure Key Vault network error: {e}"),
            ),
            _ => KmsAeadError::EncryptionError(
                KmsAeadEncryptionError::new(
                    KmsAeadErrorPublicGenericDetails::new(format!("{}", e.kind())),
                    format!("Azure Key Vault error: {e}"),
                )
                .with_root_cause(Box::new(e)),
            ),
        }
    }
}
