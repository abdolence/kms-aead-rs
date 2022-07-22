use rsb_derive::Builder;
use std::error::Error;
use std::fmt::Display;
use std::fmt::Formatter;

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

#[derive(Debug, PartialEq, Clone, Builder)]
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

impl std::error::Error for KmsAeadSystemError {}

#[derive(Debug, PartialEq, Clone, Builder)]
pub struct KmsAeadNetworkError {
    pub public: KmsAeadErrorPublicGenericDetails,
    pub message: String,
}

impl Display for KmsAeadNetworkError {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "Network error: {:?} / {}", self.public, self.message)
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

#[cfg(feature = "gcp")]
impl From<gcloud_sdk::error::Error> for KmsAeadError {
    fn from(e: gcloud_sdk::error::Error) -> Self {
        KmsAeadError::SystemError(
            KmsAeadSystemError::new(
                KmsAeadErrorPublicGenericDetails::new(format!("{:?}", e.kind())),
                format!("GCloud system error: {}", e),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}

#[cfg(feature = "gcp")]
impl From<tonic::Status> for KmsAeadError {
    fn from(status: tonic::Status) -> Self {
        KmsAeadError::NetworkError(KmsAeadNetworkError::new(
            KmsAeadErrorPublicGenericDetails::new(format!("{:?}", status.code())),
            format!("{}", status),
        ))
    }
}

#[cfg(feature = "aws")]
impl<E: Display + Error + Sync + Send + 'static> From<aws_sdk_kms::types::SdkError<E>>
    for KmsAeadError
{
    fn from(e: aws_sdk_kms::types::SdkError<E>) -> Self {
        KmsAeadError::EncryptionError(
            KmsAeadEncryptionError::new(
                KmsAeadErrorPublicGenericDetails::new(format!("{}", e)),
                format!("AWS KMS error: {}", e),
            )
            .with_root_cause(Box::new(e)),
        )
    }
}
