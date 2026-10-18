//! The error type of every fallible operation, [`KmsAeadError`].
//!
//! Each error carries a code, which [`KmsAeadError::code`] returns: one of the crate's own codes,
//! such as `INVALID_KEY_LENGTH` or `DECRYPT`, or the error code a KMS returned, such as AWS's
//! `IncorrectKeyException` or `VAULT_STATUS_403` for an HTTP status from Vault.

use rsb_derive::Builder;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;
use std::sync::Arc;

use crate::AeadAlgorithm;

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Every error of the crate. No variant carries plaintext, key material in any form, AAD content
/// or cipher text bytes, in `Display` or in `Debug`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsAeadError {
    /// The configuration or the environment: invalid provider options or a KMS client that
    /// cannot be built.
    SystemError(KmsAeadSystemError),
    /// A KMS that could not be reached or did not answer in time, a server error or a rate limit
    /// from Azure Key Vault or Vault, and every gRPC status from Google Cloud KMS.
    NetworkError(KmsAeadNetworkError),
    /// Encrypting or decrypting a value or a DEK failed, or a stored value could not be
    /// read. Includes every AWS KMS error, and the requests Azure Key Vault and Vault refused.
    EncryptionError(KmsAeadEncryptionError),
    /// The backend does not implement the algorithm. Returned by constructors only.
    UnsupportedAlgorithm(KmsAeadUnsupportedAlgorithmError),
    /// A stored value in a layout written by 0.29 or earlier, which only the `legacy-formats`
    /// feature reads.
    LegacyFormat(KmsAeadLegacyFormatError),
}

impl KmsAeadError {
    /// The code to match on: one of the crate's codes, such as `DECRYPT`, or the code the KMS
    /// returned, such as `IncorrectKeyException`. It is the value of the `error_code` span field.
    pub fn code(&self) -> &str {
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
    /// of a response that failed to parse can be a successful decryption, which holds the data
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

    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
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
    /// body into the error, and a decryption response body holds the data encryption key. A
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

/// The root cause of the inner error, when there is one. The inner error is not a link of the
/// chain: its `Display` is this error's.
impl std::error::Error for KmsAeadError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KmsAeadError::SystemError(err) => err.source(),
            KmsAeadError::NetworkError(err) => err.source(),
            KmsAeadError::EncryptionError(err) => err.source(),
            KmsAeadError::UnsupportedAlgorithm(err) => err.source(),
            KmsAeadError::LegacyFormat(err) => err.source(),
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

/// The root cause, when there is one.
impl std::error::Error for KmsAeadSystemError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.root_cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}

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
    #[cfg(feature = "hashicorp-vault-transit-kms-encryption-base")]
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

    /// `INVALID_PLAINTEXT`: a plaintext that does not convert to or from `T`, for `reason`, which
    /// never quotes the plaintext.
    pub(crate) fn invalid_plaintext<T>(reason: impl Display) -> KmsAeadError {
        Self::create(
            "INVALID_PLAINTEXT",
            &format!(
                "The plaintext does not convert to or from {}: {reason}",
                std::any::type_name::<T>()
            ),
        )
    }

    /// `INVALID_HEX`: hex that does not decode into `subject`, for the reason in `error` but
    /// without the character that is not a hex digit, which may be a byte of a value stored in
    /// plain text.
    pub(crate) fn invalid_hex(subject: &str, error: hex::FromHexError) -> KmsAeadError {
        let reason = match error {
            hex::FromHexError::InvalidHexCharacter { index, .. } => {
                format!("the character at position {index} is not a hex digit")
            }
            other => other.to_string(),
        };
        Self::create("INVALID_HEX", &format!("{subject} is not hex: {reason}"))
    }

    /// `INVALID_PLAINTEXT` for the JSON of `T`, with serde_json's category and position of
    /// `error`, never its message, which quotes the input.
    #[cfg(feature = "serde-json")]
    pub(crate) fn invalid_json<T>(error: &serde_json::Error) -> KmsAeadError {
        Self::invalid_plaintext::<T>(format_args!(
            "{:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
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

/// The root cause, when there is one.
impl std::error::Error for KmsAeadEncryptionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.root_cause
            .as_deref()
            .map(|cause| cause as &(dyn Error + 'static))
    }
}

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

impl KmsAeadLegacyFormatError {
    /// The message names the layout and the feature, never the bytes read.
    pub(crate) fn create(format: KmsAeadLegacyFormat) -> KmsAeadError {
        let message = match format {
            KmsAeadLegacyFormat::EnvelopeV1 => {
                "The cipher text is in the envelope layout v1 of kms-aead 0.29. It is read as an \
                 Encrypted value and decrypted only with the deprecated legacy-formats feature, \
                 and Encrypted::separate never reads it"
            }
            KmsAeadLegacyFormat::LengthPrefixedEnvelope => {
                "The cipher text is in the length-prefixed layout written by kms-aead 0.28.1 and \
                 earlier. It is read as an Encrypted value and decrypted only with the deprecated \
                 legacy-formats feature, and Encrypted::separate never reads it"
            }
            KmsAeadLegacyFormat::EncryptedKeyV1 => {
                "The encrypted key is in the encrypted key layout of kms-aead 0.29, which only the \
                 deprecated legacy-formats feature reads"
            }
            KmsAeadLegacyFormat::RawEncryptedDek => {
                "The encrypted DEK holds the raw key, as kms-aead 0.29 and earlier encrypted every \
                 key, not a serialised Tink key. Only the deprecated legacy-formats feature reads \
                 it"
            }
        };
        KmsAeadError::LegacyFormat(KmsAeadLegacyFormatError::new(
            KmsAeadErrorPublicGenericDetails::new("LEGACY_FORMAT".to_string()),
            format,
            message.to_string(),
        ))
    }
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

/// A layout written by kms-aead 0.29 or earlier. The formats chapter of the book shows the bytes
/// of each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KmsAeadLegacyFormat {
    /// An [`Envelope`](crate::formats::Envelope) value in the envelope layout v1 of 0.29,
    /// starting with `0x01`.
    EnvelopeV1,
    /// An [`Envelope`](crate::formats::Envelope) value with the length prefix written up to
    /// 0.28.1, starting with four zero bytes.
    LengthPrefixedEnvelope,
    /// Stored `EncryptedDataEncryptionKey` bytes in the encrypted key layout of 0.29, starting
    /// with `0xFF 0x01`.
    EncryptedKeyV1,
    /// An encrypted DEK that decrypts to the raw key, as 0.29 and earlier encrypted every key,
    /// rather than to a serialised Tink key. The values of 32-bit targets before 0.24.0, whose
    /// framing is Tink's, fail with it too.
    RawEncryptedDek,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_root_cause_is_the_source() {
        let root_cause = || Arc::new(std::io::Error::other("connection reset"));
        let errors = [
            KmsAeadError::EncryptionError(
                KmsAeadEncryptionError::new(
                    KmsAeadErrorPublicGenericDetails::new("ENCRYPT".to_string()),
                    "Unable to encrypt".to_string(),
                )
                .with_root_cause(root_cause()),
            ),
            KmsAeadError::SystemError(
                KmsAeadSystemError::new(
                    KmsAeadErrorPublicGenericDetails::new("AZURE_VAULT_URL".to_string()),
                    "Invalid vault URL".to_string(),
                )
                .with_root_cause(root_cause()),
            ),
        ];

        for error in errors {
            assert!(
                error
                    .source()
                    .is_some_and(|source| source.is::<std::io::Error>()),
                "{error:?}"
            );
        }
    }
}
