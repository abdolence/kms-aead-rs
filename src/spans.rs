//! The span and field names of every kms-aead operation. Dashboards and trace queries depend on
//! them, so a name changes only in a breaking release.
//!
//! Every span opens at `DEBUG` with all its fields declared, records a field once its value is
//! known, and leaves a value nobody reported unrecorded. No field carries plaintext, key
//! material in any form, AAD content, cipher text bytes, or the length of a value or of its AAD.

use std::fmt::Display;
use std::future::Future;

use tracing::{debug_span, field, Instrument, Span};

use crate::KmsAeadResult;

const PROVIDER: &str = "/kms_aead/provider";
const KEY: &str = "/kms_aead/key";
const KEY_VERSION: &str = "/kms_aead/key_version";
const RESPONSE_TIME: &str = "/kms_aead/response_time";
const LEN: &str = "/kms_aead/len";
const MODE: &str = "/kms_aead/mode";
const ALGORITHM: &str = "/kms_aead/algorithm";
const BACKEND: &str = "/kms_aead/backend";
const DEK_CACHE: &str = "/kms_aead/dek_cache";
const FORMAT: &str = "/kms_aead/format";
const PURPOSE: &str = "/kms_aead/purpose";
const FROM_FORMAT: &str = "/kms_aead/from_format";
const TO_FORMAT: &str = "/kms_aead/to_format";
const ERROR_CODE: &str = "/kms_aead/error_code";

/// The `dek_cache` value of every envelope call: the per-call envelope has no unwrap cache.
const DEK_CACHE_DISABLED: &str = "disabled";

/// The spans of the calls to a KMS, which the providers open.
#[cfg_attr(
    not(any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "vault-transit-kms-encryption-base"
    )),
    allow(dead_code, reason = "no KMS provider is compiled into this build")
)]
pub(crate) mod kms {
    use std::future::Future;
    use std::time::Instant;

    use tracing::{debug_span, field, Span};

    use super::{ERROR_CODE, KEY, KEY_VERSION, LEN, PROVIDER, RESPONSE_TIME};
    use crate::{EncryptedDataEncryptionKey, KekProvider, KekRef, KmsKeyVersion};

    /// `KMS wrap`, around a provider's `encrypt_data_encryption_key`.
    pub(crate) fn wrap(kek: &KekRef) -> Span {
        debug_span!(
            "KMS wrap",
            { PROVIDER } = kek.provider().name(),
            { KEY } = kek.key(),
            { KEY_VERSION } = field::Empty,
            { RESPONSE_TIME } = field::Empty,
            { ERROR_CODE } = field::Empty,
        )
    }

    /// `KMS unwrap`, around a provider's `decrypt_data_encryption_key`, with the key version the
    /// encrypted key records.
    pub(crate) fn unwrap(kek: &KekRef, key_version: Option<&KmsKeyVersion>) -> Span {
        let span = debug_span!(
            "KMS unwrap",
            { PROVIDER } = kek.provider().name(),
            { KEY } = kek.key(),
            { KEY_VERSION } = field::Empty,
            { RESPONSE_TIME } = field::Empty,
            { ERROR_CODE } = field::Empty,
        );
        if let Some(key_version) = key_version {
            span.record(KEY_VERSION, key_version.as_str());
        }
        span
    }

    /// `KMS random`, around a call to a KMS generator. `key` is what the request names, if
    /// anything.
    #[cfg_attr(
        not(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption")),
        allow(
            dead_code,
            reason = "only the GCP and AWS providers call a KMS generator"
        )
    )]
    pub(crate) fn random(provider: &KekProvider, key: Option<&str>, len: usize) -> Span {
        let span = debug_span!(
            "KMS random",
            { PROVIDER } = provider.name(),
            { KEY } = field::Empty,
            { LEN } = len,
            { RESPONSE_TIME } = field::Empty,
            { ERROR_CODE } = field::Empty,
        );
        if let Some(key) = key {
            span.record(KEY, key);
        }
        span
    }

    /// Records on the current KMS span the key version that wrapped `encrypted_key`, when the
    /// KMS reported one.
    pub(crate) fn record_wrap(encrypted_key: &EncryptedDataEncryptionKey) {
        if let Some(key_version) = encrypted_key.key_version() {
            Span::current().record(KEY_VERSION, key_version.as_str());
        }
    }

    /// Sends a KMS request and records on the current span how long it took, in milliseconds.
    pub(crate) async fn timed<T>(request: impl Future<Output = T>) -> T {
        let started = Instant::now();
        let response = request.await;
        let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        Span::current().record(RESPONSE_TIME, elapsed);
        response
    }
}

/// `KMS AEAD encrypt`, around the envelope's encrypt calls. `mode` is `per_call` for
/// `encrypt_value` and `caller_dek` for the calls that take a key.
pub(crate) fn aead_encrypt(mode: &str, algorithm: impl Display, backend: &str) -> Span {
    debug_span!(
        "KMS AEAD encrypt",
        { MODE } = mode,
        { ALGORITHM } = %algorithm,
        { BACKEND } = backend,
        { DEK_CACHE } = DEK_CACHE_DISABLED,
        { ERROR_CODE } = field::Empty,
    )
}

/// `KMS AEAD decrypt`, around the envelope's decrypt calls, with the layout of the stored value
/// for a call that reads one: `envelope_v1` or `envelope_legacy`.
pub(crate) fn aead_decrypt(
    mode: &str,
    algorithm: impl Display,
    backend: &str,
    format: Option<&str>,
) -> Span {
    let span = debug_span!(
        "KMS AEAD decrypt",
        { MODE } = mode,
        { ALGORITHM } = %algorithm,
        { BACKEND } = backend,
        { DEK_CACHE } = DEK_CACHE_DISABLED,
        { FORMAT } = field::Empty,
        { ERROR_CODE } = field::Empty,
    );
    if let Some(format) = format {
        span.record(FORMAT, format);
    }
    span
}

/// `KMS AEAD generate DEK`, around the envelope's key generation. `purpose` is `randomized` or
/// `deterministic`.
pub(crate) fn generate_dek(purpose: &str, algorithm: impl Display, backend: &str) -> Span {
    debug_span!(
        "KMS AEAD generate DEK",
        { PURPOSE } = purpose,
        { ALGORITHM } = %algorithm,
        { BACKEND } = backend,
        { ERROR_CODE } = field::Empty,
    )
}

/// `KMS AEAD decrypt DEK`, around the envelope's unwrap of a deterministic key.
#[allow(dead_code, reason = "opened only with the deterministic feature")]
pub(crate) fn decrypt_dek(purpose: &str, algorithm: impl Display) -> Span {
    debug_span!(
        "KMS AEAD decrypt DEK",
        { PURPOSE } = purpose,
        { ALGORITHM } = %algorithm,
        { DEK_CACHE } = DEK_CACHE_DISABLED,
        { ERROR_CODE } = field::Empty,
    )
}

/// `KMS AEAD upgrade`, around the upgrade of a stored value from a legacy layout. The formats
/// are `envelope_legacy`, `envelope_v1`, `encrypted_key_bare` and `encrypted_key_v1`; the one it
/// is upgraded to is recorded with [`record_upgraded_format`] only when the input was not current
/// already.
#[allow(dead_code, reason = "opened only with the legacy-formats feature")]
pub(crate) fn upgrade(from_format: &str) -> Span {
    debug_span!(
        "KMS AEAD upgrade",
        { FROM_FORMAT } = from_format,
        { TO_FORMAT } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

#[allow(dead_code, reason = "recorded only with the legacy-formats feature")]
pub(crate) fn record_upgraded_format(to_format: &str) {
    Span::current().record(TO_FORMAT, to_format);
}

/// Runs `operation` inside `span`, without holding the span entered across an `.await`, and
/// records the code of the error it returns.
pub(crate) async fn in_span<T>(
    span: Span,
    operation: impl Future<Output = KmsAeadResult<T>>,
) -> KmsAeadResult<T> {
    let result = operation.instrument(span.clone()).await;
    if let Err(error) = &result {
        span.record(ERROR_CODE, error.code());
    }
    result
}
