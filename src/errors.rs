//! The error type of every fallible operation, [`KmsAeadError`].
//!
//! Each error carries a code in [`KmsAeadErrorPublicGenericDetails::code`]: one of the crate's
//! own codes, such as `INVALID_KEY_LENGTH` or `DECRYPT`, or the error code a KMS returned, such as
//! AWS's `IncorrectKeyException` or `VAULT_STATUS_403` for an HTTP status from Vault.

use rsb_derive::Builder;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::sync::Arc;
use std::time::SystemTimeError;

use crate::AeadAlgorithm;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Every error of the crate. No variant carries plaintext, key material in any form, AAD content
/// or cipher text bytes, in `Display` or in `Debug`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsAeadError {
    /// The configuration or the environment: invalid provider options, a KMS client that cannot
    /// be built, or a system clock error.
    SystemError(KmsAeadSystemError),
    /// A KMS that could not be reached or did not answer in time, a server error or a rate limit
    /// from Azure Key Vault or Vault, and every gRPC status from Google Cloud KMS.
    NetworkError(KmsAeadNetworkError),
    /// Encrypting, decrypting, wrapping or unwrapping failed, or a stored value could not be
    /// read. Includes every AWS KMS error, and the requests Azure Key Vault and Vault refused.
    EncryptionError(KmsAeadEncryptionError),
    /// The backend does not implement the algorithm. Returned by constructors only.
    UnsupportedAlgorithm(KmsAeadUnsupportedAlgorithmError),
    /// A stored value in a layout that only the `legacy-formats` feature reads.
    LegacyFormat(KmsAeadLegacyFormatError),
}

impl KmsAeadError {
    /// The value of the `error_code` span field.
    pub(crate) fn code(&self) -> &str {
        match self {
            KmsAeadError::SystemError(err) => &err.public.code,
            KmsAeadError::NetworkError(err) => &err.public.code,
            KmsAeadError::EncryptionError(err) => &err.public.code,
            KmsAeadError::UnsupportedAlgorithm(err) => &err.public.code,
            KmsAeadError::LegacyFormat(err) => &err.public.code,
        }
    }

    #[cfg(feature = "gcp")]
    pub(crate) fn from_gcp_error(e: gcloud_sdk::error::Error) -> Self {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new(format!("{:?}", e.kind())),
                format!("GCloud system error: {e}"),
            )
            .with_root_cause(Arc::new(e)),
        )
    }

    #[cfg(feature = "gcp")]
    pub(crate) fn from_gcp_status(status: gcloud_sdk::tonic::Status) -> Self {
        KmsAeadNetworkError::create(&format!("{:?}", status.code()), &format!("{status}"))
    }

    /// A service error keeps the code the service returned, such as `IncorrectKeyException`, and
    /// the modelled service error as the root cause. No variant keeps the raw response: the body
    /// of a response that failed to parse can be a successful unwrap, which holds the data
    /// encryption key.
    #[cfg(feature = "aws-kms-encryption")]
    pub(crate) fn from_aws_sdk_error<E, R>(e: aws_sdk_kms::error::SdkError<E, R>) -> Self
    where
        E: aws_sdk_kms::error::ProvideErrorMetadata + Error + Send + Sync + 'static,
        R: std::fmt::Debug + Send + Sync + 'static,
    {
        use aws_sdk_kms::error::SdkError;
        let (code, message, root_cause): (String, String, Option<Arc<dyn Error + Send + Sync>>) =
            match e {
                SdkError::ServiceError(context) => {
                    let service_error = context.into_err();
                    let code = service_error
                        .code()
                        .map_or_else(|| "service error".to_string(), str::to_string);
                    let message = match service_error.message() {
                        Some(message) => format!("AWS KMS returned {code}: {message}"),
                        None => format!("AWS KMS returned {code}"),
                    };
                    (code, message, Some(Arc::new(service_error)))
                }
                SdkError::ResponseError(_) => (e.to_string(), format!("AWS KMS error: {e}"), None),
                other => (
                    other.to_string(),
                    format!("AWS KMS error: {other}"),
                    Some(Arc::new(other)),
                ),
            };
        KmsAeadError::EncryptionError(KmsAeadEncryptionError {
            public: KmsAeadErrorPublicGenericDetails::new(code),
            message,
            root_cause,
        })
    }

    #[cfg(feature = "vault-transit-kms-encryption-base")]
    pub(crate) fn from_vault_http_error(e: hyper_util::client::legacy::Error) -> Self {
        KmsAeadError::NetworkError(KmsAeadNetworkError::with_error_chain(
            "VAULT_HTTP",
            "Unable to send the Vault request",
            &e,
        ))
    }

    /// A 5xx or 429 response is a retryable network error; any other HTTP error keeps Key
    /// Vault's error code and the message of its error envelope. Nothing else from a response
    /// body is kept: for a body that is not an Azure error envelope the SDK copies the whole
    /// body into the error, and an unwrap response body holds the data encryption key. A
    /// response parse error keeps no message or root cause for the same reason.
    #[cfg(feature = "azure-kms-encryption-base")]
    pub(crate) fn from_azure_error(e: azure_core::Error) -> Self {
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
                .with_root_cause(Arc::new(e)),
            ),
        }
    }
}

impl Display for KmsAeadError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            KmsAeadError::SystemError(err) => err.fmt(f),
            KmsAeadError::NetworkError(err) => err.fmt(f),
            KmsAeadError::EncryptionError(err) => err.fmt(f),
            KmsAeadError::UnsupportedAlgorithm(err) => err.fmt(f),
            KmsAeadError::LegacyFormat(err) => err.fmt(f),
        }
    }
}

impl std::error::Error for KmsAeadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KmsAeadError::SystemError(err) => Some(err),
            KmsAeadError::NetworkError(err) => Some(err),
            KmsAeadError::EncryptionError(err) => Some(err),
            KmsAeadError::UnsupportedAlgorithm(err) => Some(err),
            KmsAeadError::LegacyFormat(err) => Some(err),
        }
    }
}

/// The part of an error that is safe to return to an application's own callers.
#[derive(Debug, Eq, PartialEq, Clone, Builder)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct KmsAeadErrorPublicGenericDetails {
    /// A code a caller can match on: one of the crate's codes or the code a KMS returned.
    pub code: String,
}

/// See [`KmsAeadError::SystemError`].
#[derive(Debug, Clone, Builder)]
pub struct KmsAeadSystemError {
    /// The error code.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// What failed, for a person reading logs.
    pub message: String,
    /// The error of the library that failed, when there is one.
    pub root_cause: Option<Arc<dyn Error + Send + Sync>>,
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
    /// A [`KmsAeadError::SystemError`] with `code` and `message` and no root cause.
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::SystemError(KmsAeadSystemError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }
}

impl std::error::Error for KmsAeadSystemError {}

/// See [`KmsAeadError::NetworkError`].
#[derive(Debug, Eq, PartialEq, Clone, Builder)]
pub struct KmsAeadNetworkError {
    /// The error code.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// What failed, for a person reading logs.
    pub message: String,
}

impl Display for KmsAeadNetworkError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Network error: {:?} / {}", self.public, self.message)
    }
}

impl KmsAeadNetworkError {
    /// A [`KmsAeadError::NetworkError`] with `code` and `message`.
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

/// See [`KmsAeadError::EncryptionError`].
#[derive(Debug, Clone, Builder)]
pub struct KmsAeadEncryptionError {
    /// The error code.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// What failed, for a person reading logs.
    pub message: String,
    /// The error of the library or the KMS that failed, when there is one.
    pub root_cause: Option<Arc<dyn Error + Send + Sync>>,
}

impl KmsAeadEncryptionError {
    /// A [`KmsAeadError::EncryptionError`] with `code` and `message` and no root cause.
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::EncryptionError(KmsAeadEncryptionError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }

    /// `INVALID_KEY_LENGTH`: a key of `len` bytes given to `algorithm`, which takes `key_len`.
    pub(crate) fn invalid_key_length(
        len: usize,
        algorithm: impl Display,
        key_len: usize,
    ) -> KmsAeadError {
        Self::create(
            "INVALID_KEY_LENGTH",
            &format!("A key of {len} bytes does not fit {algorithm}, which takes {key_len} bytes"),
        )
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

/// See [`KmsAeadError::UnsupportedAlgorithm`]. Its code is `UNSUPPORTED_ALGORITHM`.
#[derive(Debug, Clone, PartialEq, Eq, Builder)]
#[non_exhaustive]
pub struct KmsAeadUnsupportedAlgorithmError {
    /// The error code, `UNSUPPORTED_ALGORITHM`.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// The algorithm the backend does not implement.
    pub algorithm: AeadAlgorithm,
    /// Names the backend.
    pub message: String,
}

impl KmsAeadUnsupportedAlgorithmError {
    pub(crate) fn create(algorithm: AeadAlgorithm, backend: &str) -> KmsAeadError {
        KmsAeadError::UnsupportedAlgorithm(KmsAeadUnsupportedAlgorithmError::new(
            KmsAeadErrorPublicGenericDetails::new("UNSUPPORTED_ALGORITHM".to_string()),
            algorithm,
            format!("The {backend} backend does not implement {algorithm}"),
        ))
    }
}

impl Display for KmsAeadUnsupportedAlgorithmError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "KmsAead unsupported algorithm: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for KmsAeadUnsupportedAlgorithmError {}

/// See [`KmsAeadError::LegacyFormat`]. Its code is `LEGACY_FORMAT`.
#[derive(Debug, Clone, PartialEq, Eq, Builder)]
#[non_exhaustive]
pub struct KmsAeadLegacyFormatError {
    /// The error code, `LEGACY_FORMAT`.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// The layout of the stored value.
    pub format: KmsAeadLegacyFormat,
    /// Names the feature that reads the layout.
    pub message: String,
}

impl Display for KmsAeadLegacyFormatError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "KmsAead legacy format: {:?} / {}",
            self.public, self.message
        )
    }
}

impl std::error::Error for KmsAeadLegacyFormatError {}

/// A layout written by kms-aead 0.28.1 and earlier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmsAeadLegacyFormat {
    /// `CipherTextWithEncryptedKey` written up to 0.28.1.
    LengthPrefixedEnvelope,
    /// `EncryptedDataEncryptionKey` stored as the bare wrapped key, up to 0.28.1.
    BareEncryptedKey,
}

impl From<SystemTimeError> for KmsAeadError {
    fn from(e: SystemTimeError) -> Self {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new("SYSTEM_TIME_ERROR".to_string()),
                format!("System time error: {e}"),
            )
            .with_root_cause(Arc::new(e)),
        )
    }
}
