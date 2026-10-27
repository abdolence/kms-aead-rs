use std::fs::File;
use std::io::Read;
use std::path::Path;

use secret_vault_value::SecretValue;

use crate::errors::{KmsAeadError, KmsAeadSystemError};

/// The most bytes read from a local key file or variable, the one cap of every local key of the
/// two crates: room for a PEM private key, small enough that a wrong path is refused before its
/// content is read into memory.
pub(crate) const LOCAL_KEY_MAX_LEN: usize = 32 * 1024;

/// Why the bytes of a local key could not be read, before any decoding. Each loader maps it to
/// its own codes. The messages name the origin, never the content.
#[derive(Debug)]
pub(crate) enum LocalKeySourceError {
    /// A file that cannot be opened or read or is not a regular file, or an unset variable.
    Unavailable(String),
    /// More than [`LOCAL_KEY_MAX_LEN`] bytes.
    TooLarge(String),
}

impl LocalKeySourceError {
    /// The system error of a loader whose codes for the two cases are `unavailable` and
    /// `too_large`.
    pub(crate) fn into_error(self, unavailable: &str, too_large: &str) -> KmsAeadError {
        match self {
            LocalKeySourceError::Unavailable(message) => {
                KmsAeadSystemError::create(unavailable, &message)
            }
            LocalKeySourceError::TooLarge(message) => {
                KmsAeadSystemError::create(too_large, &message)
            }
        }
    }
}

/// The bytes of the file at `path`, described as `origin` in errors. A symbolic link is
/// followed. The opened file must be a regular file of at most [`LOCAL_KEY_MAX_LEN`] bytes, both
/// checked on the opened file before it is read, so a file swapped in after the open is never
/// read. Opening a FIFO blocks until a writer opens it.
pub(crate) fn read_local_key_file(
    path: &Path,
    origin: &str,
) -> Result<SecretValue, LocalKeySourceError> {
    let unreadable = |error: std::io::Error| {
        LocalKeySourceError::Unavailable(format!("Unable to read {origin}: {error}"))
    };
    let file = File::open(path).map_err(unreadable)?;
    let metadata = file.metadata().map_err(unreadable)?;
    if !metadata.is_file() {
        return Err(LocalKeySourceError::Unavailable(format!(
            "{origin} is not a regular file"
        )));
    }
    let len = usize::try_from(metadata.len())
        .ok()
        .filter(|len| *len <= LOCAL_KEY_MAX_LEN)
        .ok_or_else(|| {
            LocalKeySourceError::TooLarge(format!(
                "{origin} is larger than {LOCAL_KEY_MAX_LEN} bytes"
            ))
        })?;
    let mut content = SecretValue::new(Vec::with_capacity(len));
    // Reading at most the length the file had when opened keeps the buffer from growing, which
    // would leave a copy of the key in freed memory.
    file.take(metadata.len())
        .read_to_end(content.ref_sensitive_value_mut())
        .map_err(unreadable)?;
    Ok(content)
}

/// The bytes of the environment variable `variable`, described as `origin` in errors, at most
/// [`LOCAL_KEY_MAX_LEN`] of them.
pub(crate) fn read_local_key_env(
    variable: &str,
    origin: &str,
) -> Result<SecretValue, LocalKeySourceError> {
    let value = std::env::var_os(variable)
        .ok_or_else(|| LocalKeySourceError::Unavailable(format!("{origin} is not set")))?;
    let content = SecretValue::new(value.into_encoded_bytes());
    if content.ref_sensitive_value().len() > LOCAL_KEY_MAX_LEN {
        return Err(LocalKeySourceError::TooLarge(format!(
            "{origin} is larger than {LOCAL_KEY_MAX_LEN} bytes"
        )));
    }
    Ok(content)
}

/// The bytes the standard base64 in `encoded` holds, trailing whitespace allowed, or `None` when
/// it is not standard base64. Every copy of the text is zeroised: `encoded` on drop, and the
/// trimmed copy by `from_base64_str`.
pub(crate) fn decode_local_key_base64(encoded: SecretValue) -> Option<SecretValue> {
    let text = encoded.sensitive_value_to_str().ok()?;
    SecretValue::from_base64_str(text.trim_end().to_string()).ok()
}
