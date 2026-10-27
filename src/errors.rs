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

#[cfg(feature = "stream")]
use crate::AeadAlgorithm;
use crate::BackendAlgorithm;

use serde::{Deserialize, Serialize};

/// Every error of the crate. No variant carries plaintext, key material in any form, AAD content
/// or cipher text bytes, in `Display` or in `Debug`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KmsAeadError {
    /// The configuration or the environment: invalid provider options or a KMS client that
    /// cannot be built.
    SystemError(KmsAeadSystemError),
    /// A KMS that could not be reached, did not answer in time, failed on its side or limited
    /// the rate of requests. The same call may succeed later, so a caller may retry it, with a
    /// backoff.
    NetworkError(KmsAeadNetworkError),
    /// Encrypting or decrypting a value or a DEK failed, a stored value could not be read, or a
    /// KMS refused the request: a denied permission, a key that does not exist or is disabled,
    /// an invalid request or encrypted DEK. The same call fails the same way again, so a caller
    /// should not retry it.
    EncryptionError(KmsAeadEncryptionError),
    /// The backend does not implement the algorithm. Returned by constructors only.
    UnsupportedAlgorithm(KmsAeadUnsupportedAlgorithmError),
    /// A stored value in a layout written by 0.29 or earlier, which only the `legacy-formats`
    /// feature reads. The envelope's [`reencrypt_dek`](crate::KmsAeadEnvelope::reencrypt_dek) and
    /// [`reencrypt_encrypted_dek`](crate::KmsAeadEnvelope::reencrypt_encrypted_dek) return it with
    /// the feature too: the upgrades rewrite such a value.
    LegacyFormat(KmsAeadLegacyFormatError),
    /// A signature could not be made, read or verified, a public key or a key set could not be
    /// read, or a KMS refused a sign or public-key request. The same call fails the same way
    /// again, so a caller should not retry it; a verifier's `SIGNING_KEY_UNKNOWN` clears once its
    /// key set is refreshed.
    SignatureError(KmsAeadSignatureError),
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
            KmsAeadError::SignatureError(err) => &err.public.code,
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

    /// A status that a retry may clear is a network error; one about the request, the key or the
    /// caller's permissions is an encryption error. Google's client libraries retry Cloud KMS
    /// calls on `Unavailable` and `DeadlineExceeded` only; the other network codes are the ones
    /// gRPC defines as transient or server-side.
    #[cfg(feature = "gcp")]
    pub(crate) fn from_gcp_status(status: gcloud_sdk::tonic::Status) -> Self {
        use gcloud_sdk::tonic::Code;
        let code = format!("{:?}", status.code());
        let message = format!("{status}");
        match status.code() {
            Code::Unavailable
            | Code::DeadlineExceeded
            | Code::ResourceExhausted
            | Code::Aborted
            | Code::Internal
            | Code::Unknown
            | Code::Cancelled => KmsAeadNetworkError::create(&code, &message),
            Code::PermissionDenied
            | Code::Unauthenticated
            | Code::NotFound
            | Code::InvalidArgument
            | Code::FailedPrecondition
            | Code::OutOfRange
            | Code::Unimplemented
            | Code::AlreadyExists
            | Code::DataLoss
            | Code::Ok => KmsAeadEncryptionError::create(&code, &message),
        }
    }

    /// A service error keeps the code the service returned, such as `IncorrectKeyException`, and
    /// the modelled service error as the root cause. No variant keeps the raw response: the body
    /// of a response that failed to parse can be a successful decryption, which holds the data
    /// encryption key.
    ///
    /// The network errors are the failures the SDK's own retry classifiers treat as transient: a
    /// timeout, an I/O or timeout failure of the connector, a response that could not be read,
    /// AWS KMS's throttling and internal error codes, and a 5xx or 429 status. Everything else,
    /// a request that could not be built or signed included, is an encryption error.
    #[cfg(feature = "aws-kms-encryption")]
    pub(crate) fn from_aws_sdk_error<E>(
        e: aws_sdk_kms::error::SdkError<E, aws_sdk_kms::config::http::HttpResponse>,
    ) -> Self
    where
        E: aws_sdk_kms::error::ProvideErrorMetadata + Error + Send + Sync + 'static,
    {
        use aws_sdk_kms::error::SdkError;
        let transport_failure = match &e {
            SdkError::TimeoutError(_) => true,
            SdkError::DispatchFailure(failure) => failure.is_io() || failure.is_timeout(),
            _ => false,
        };
        match e {
            SdkError::ServiceError(context) => {
                let status = context.raw().status();
                let service_error = context.into_err();
                let code = service_error
                    .code()
                    .map_or_else(|| "service error".to_string(), str::to_string);
                let message = match service_error.message() {
                    Some(message) => format!("AWS KMS returned {code}: {message}"),
                    None => format!("AWS KMS returned {code}"),
                };
                if AWS_KMS_RETRYABLE_ERROR_CODES.contains(&code.as_str())
                    || status.is_server_error()
                    || status.as_u16() == 429
                {
                    KmsAeadNetworkError::create(&code, &message)
                } else {
                    KmsAeadError::EncryptionError(
                        KmsAeadEncryptionError::new(
                            KmsAeadErrorPublicGenericDetails::new(code),
                            message,
                        )
                        .with_root_cause(Arc::new(service_error)),
                    )
                }
            }
            SdkError::ResponseError(_) => {
                KmsAeadNetworkError::create(&e.to_string(), &format!("AWS KMS error: {e}"))
            }
            transport if transport_failure => {
                KmsAeadError::NetworkError(KmsAeadNetworkError::with_error_chain(
                    &transport.to_string(),
                    "AWS KMS error",
                    &transport,
                ))
            }
            other => KmsAeadError::EncryptionError(
                KmsAeadEncryptionError::new(
                    KmsAeadErrorPublicGenericDetails::new(other.to_string()),
                    format!("AWS KMS error: {other}"),
                )
                .with_root_cause(Arc::new(other)),
            ),
        }
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

    /// A KMS refusal of a sign or public-key request as a signature error: the
    /// [`EncryptionError`](Self::EncryptionError) that the encryption providers' error mappings
    /// return becomes a [`SignatureError`](Self::SignatureError) with the same code, message and
    /// root cause. Every other variant is returned as it is, so that a network error stays
    /// retryable.
    #[cfg(any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ))]
    pub(crate) fn into_signature_error(self) -> Self {
        match self {
            KmsAeadError::EncryptionError(error) => KmsAeadError::SignatureError(
                KmsAeadSignatureError::new(error.public, error.message)
                    .opt_root_cause(error.root_cause),
            ),
            other => other,
        }
    }
}

/// The AWS KMS error codes of a request that may succeed later: throttling, an internal error, a
/// custom key store that did not answer in time, and a key that is temporarily unavailable.
#[cfg(feature = "aws-kms-encryption")]
const AWS_KMS_RETRYABLE_ERROR_CODES: &[&str] = &[
    "ThrottlingException",
    "KMSInternalException",
    "DependencyTimeoutException",
    "KeyUnavailableException",
];

impl Display for KmsAeadError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        match self {
            KmsAeadError::SystemError(err) => err.fmt(f),
            KmsAeadError::NetworkError(err) => err.fmt(f),
            KmsAeadError::EncryptionError(err) => err.fmt(f),
            KmsAeadError::UnsupportedAlgorithm(err) => err.fmt(f),
            KmsAeadError::LegacyFormat(err) => err.fmt(f),
            KmsAeadError::SignatureError(err) => err.fmt(f),
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
            KmsAeadError::SignatureError(err) => err.source(),
        }
    }
}

/// The part of an error that is safe to return to an application's own callers.
#[derive(Debug, Eq, PartialEq, Clone, Builder, Serialize, Deserialize)]
#[non_exhaustive]
pub struct KmsAeadErrorPublicGenericDetails {
    /// A code a caller can match on: one of the crate's codes or the code a KMS returned.
    pub code: String,
}

/// See [`KmsAeadError::SystemError`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
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

    /// `ASYMMETRIC_KEK_PUBLIC_KEY`: bytes, a document or a KMS key that are not the public half of
    /// an asymmetric KEK, for `reason`, which never quotes the bytes.
    pub(crate) fn asymmetric_public_key(reason: &str) -> KmsAeadError {
        Self::create("ASYMMETRIC_KEK_PUBLIC_KEY", reason)
    }

    /// `ASYMMETRIC_KEK_PRIVATE_KEY`: bytes that are not the private key of a local asymmetric KEK,
    /// for `reason`, which never quotes the bytes.
    pub(crate) fn asymmetric_private_key(reason: &str) -> KmsAeadError {
        Self::create("ASYMMETRIC_KEK_PRIVATE_KEY", reason)
    }

    /// `ASYMMETRIC_KEK_MISMATCH`: a public key of another KEK than the one it is used with, for
    /// `reason`.
    pub(crate) fn asymmetric_kek_mismatch(reason: &str) -> KmsAeadError {
        Self::create("ASYMMETRIC_KEK_MISMATCH", reason)
    }

    /// `STREAM_IO`: the source or the sink a streamed value was read from or written to failed,
    /// as `context` names it, with `error` as the root cause. The error is the caller's I/O, never
    /// the value's, so its message is kept.
    #[cfg(feature = "stream")]
    pub(crate) fn stream_io(context: &str, error: Arc<dyn Error + Send + Sync>) -> KmsAeadError {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new("STREAM_IO".to_string()),
                format!("{context}: {error}"),
            )
            .with_root_cause(error),
        )
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
#[non_exhaustive]
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
    #[cfg(any(
        feature = "hashicorp-vault-transit-kms-encryption-base",
        feature = "aws-kms-encryption"
    ))]
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
#[non_exhaustive]
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

    /// `ASYMMETRIC_ENCRYPTED_DEK_FORMAT`: an encrypted DEK a public key encrypted whose header the
    /// reading provider refuses before any KMS call, for `reason`, which never quotes the bytes.
    pub(crate) fn asymmetric_encrypted_dek_format(reason: &str) -> KmsAeadError {
        Self::create("ASYMMETRIC_ENCRYPTED_DEK_FORMAT", reason)
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

    /// `INVALID_MAC_FORMAT` for a value of `len` bytes that is not `layout`.
    pub(crate) fn invalid_mac_format(len: usize, layout: &str) -> KmsAeadError {
        Self::create(
            "INVALID_MAC_FORMAT",
            &format!("A value of {len} bytes is not {layout}"),
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

    /// `INVALID_PLAINTEXT` for the JSON of `T`, with serde_json's category of `error`, never its
    /// message, which quotes the input, nor its position, which gives away the length of the
    /// values before it.
    pub(crate) fn invalid_json<T>(error: &serde_json::Error) -> KmsAeadError {
        Self::invalid_plaintext::<T>(json_error_category(error.classify()))
    }

    /// `INVALID_PAYLOAD` for the JSON of `T`, with serde_json's category of `error` only, as
    /// [`invalid_json`](Self::invalid_json).
    pub(crate) fn invalid_json_payload<T>(error: &serde_json::Error) -> KmsAeadError {
        Self::create(
            "INVALID_PAYLOAD",
            &format!(
                "The payload does not convert to or from {}: {}",
                std::any::type_name::<T>(),
                json_error_category(error.classify())
            ),
        )
    }

    /// `STREAM_ALGORITHM`: a cipher or key version of `algorithm` asked to encrypt or decrypt a
    /// streamed value, which is AES-256-GCM only.
    #[cfg(feature = "stream")]
    pub(crate) fn stream_algorithm(algorithm: AeadAlgorithm) -> KmsAeadError {
        Self::create(
            "STREAM_ALGORITHM",
            &format!("A streamed value is encrypted with aes-256-gcm only, not {algorithm}"),
        )
    }

    /// `STREAM_LENGTH`: a stored length, the bytes given for a chunk read plan, or a source that ends, where
    /// the layout of a streamed value refuses them, for `reason`, which names no length of the
    /// value: the length is the plaintext's.
    #[cfg(feature = "stream")]
    pub(crate) fn stream_length(reason: &str) -> KmsAeadError {
        Self::create("STREAM_LENGTH", reason)
    }

    /// `STREAM_KEY_COMMITMENT`: the key commitment in a streamed value's header is not the one
    /// the DEK, the salt and the AAD derive.
    #[cfg(feature = "stream")]
    pub(crate) fn stream_key_commitment() -> KmsAeadError {
        Self::create(
            "STREAM_KEY_COMMITMENT",
            "The key commitment of the streamed value is not the one its DEK, salt and AAD derive",
        )
    }

    /// `STREAM_RANGE`: a plaintext range or a chunk index outside a streamed value, for `reason`.
    #[cfg(feature = "stream")]
    pub(crate) fn stream_range(reason: &str) -> KmsAeadError {
        Self::create("STREAM_RANGE", reason)
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

/// See [`KmsAeadError::SignatureError`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KmsAeadSignatureError {
    /// The error code.
    pub public: KmsAeadErrorPublicGenericDetails,
    /// What failed, for a person reading logs.
    pub message: String,
    /// The error of the library or the KMS that failed, when there is one.
    pub root_cause: Option<Arc<dyn Error + Send + Sync>>,
}

impl KmsAeadSignatureError {
    /// A [`KmsAeadError::SignatureError`] with `code` and `message` and no root cause.
    pub fn create(code: &str, message: &str) -> KmsAeadError {
        KmsAeadError::SignatureError(KmsAeadSignatureError::new(
            KmsAeadErrorPublicGenericDetails::new(code.to_string()),
            message.to_string(),
        ))
    }

    /// `INVALID_PUBLIC_KEY` with `message`, which never quotes the key bytes.
    pub(crate) fn invalid_public_key(message: &str) -> KmsAeadError {
        Self::create("INVALID_PUBLIC_KEY", message)
    }

    /// `INVALID_SIGNATURE_FORMAT` for a value of `len` bytes that is not `layout`.
    pub(crate) fn invalid_format(len: usize, layout: &str) -> KmsAeadError {
        Self::create(
            "INVALID_SIGNATURE_FORMAT",
            &format!("A value of {len} bytes is not {layout}"),
        )
    }
}

impl Display for KmsAeadSignatureError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(
            f,
            "KmsAead signature error: {:?} / {}",
            self.public, self.message
        )
    }
}

/// The root cause, when there is one.
impl std::error::Error for KmsAeadSignatureError {
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
    /// The algorithm the backend does not implement. An `AeadAlgorithm` in 0.30.
    pub algorithm: BackendAlgorithm,
    /// Names the backend.
    pub message: String,
}

impl KmsAeadUnsupportedAlgorithmError {
    pub(crate) fn create(algorithm: impl Into<BackendAlgorithm>, backend: &str) -> KmsAeadError {
        let algorithm = algorithm.into();
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
    /// Names the feature that reads the layout or, from a re-encryption, the calls that rewrite it.
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
            KmsAeadLegacyFormat::EncryptedDekV1 => {
                "The encrypted DEK is in the encrypted DEK layout v1 of kms-aead 0.29, which \
                 only the deprecated legacy-formats feature reads"
            }
            KmsAeadLegacyFormat::RawEncryptedDek => {
                "The encrypted DEK holds the raw key, as kms-aead 0.29 and earlier encrypted every \
                 key, not a serialised Tink key. Only the deprecated legacy-formats feature reads \
                 it"
            }
        };
        Self::error(format, message)
    }

    /// The error of a re-encryption, which reads no layout of 0.29 or earlier, with or without
    /// `legacy-formats`, so the message names the calls that rewrite the layout instead of the
    /// feature.
    pub(crate) fn refused_by_reencryption(format: KmsAeadLegacyFormat) -> KmsAeadError {
        Self::error(
            format,
            "The value or its encrypted DEK is in a layout of kms-aead 0.29 or earlier, which \
             re-encryption never reads, with or without the legacy-formats feature. \
             upgrade_legacy_value and upgrade_legacy_encrypted_dek of that feature rewrite it in \
             Tink's format, under the KEK's current version",
        )
    }

    fn error(format: KmsAeadLegacyFormat, message: &str) -> KmsAeadError {
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
    /// Stored `EncryptedDataEncryptionKey` bytes in the encrypted DEK layout v1 of 0.29, starting
    /// with `0xFF 0x01`.
    EncryptedDekV1,
    /// An encrypted DEK that decrypts to the raw key, as 0.29 and earlier encrypted every key,
    /// rather than to a serialised Tink key. The values of 32-bit targets before 0.24.0, whose
    /// framing is Tink's, fail with it too.
    RawEncryptedDek,
}

/// In what way a serde_json error of `category` failed, without serde_json's message, which quotes
/// the input, and without its line and column, which are byte offsets into the input.
pub(crate) fn json_error_category(category: serde_json::error::Category) -> String {
    format!("{category:?} error")
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

    #[cfg(any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ))]
    #[test]
    fn a_refusal_becomes_a_signature_error_and_a_network_error_stays() {
        let refusal = KmsAeadError::EncryptionError(
            KmsAeadEncryptionError::new(
                KmsAeadErrorPublicGenericDetails::new("PermissionDenied".to_string()),
                "denied".to_string(),
            )
            .with_root_cause(Arc::new(std::io::Error::other("denied"))),
        );
        let network = KmsAeadNetworkError::create("Unavailable", "try again");

        let refusal = refusal.into_signature_error();
        let network = network.into_signature_error();

        assert!(
            matches!(&refusal, KmsAeadError::SignatureError(error)
                if error.public.code == "PermissionDenied" && error.root_cause.is_some()),
            "{refusal:?}"
        );
        assert!(
            matches!(network, KmsAeadError::NetworkError(_)),
            "{network:?}"
        );
    }
}
