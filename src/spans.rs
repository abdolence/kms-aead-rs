//! The span and field names of every kms-aead operation. Dashboards and trace queries depend on
//! them, so a name changes only in a breaking release.
//!
//! Every span opens at `DEBUG` with all its fields declared, records a field once its value is
//! known, and leaves a value nobody reported unrecorded. No field carries plaintext, key
//! material in any form, AAD content, cipher text bytes, or the length of a value or of its AAD.

use std::fmt::Display;
use std::future::Future;

use tracing::{debug_span, field, Instrument, Span};

use crate::cache::{DekCache, DekCacheOutcome};
use crate::KmsAeadResult;

const MODE: &str = "/kms_aead/mode";
const ALGORITHM: &str = "/kms_aead/algorithm";
const BACKEND: &str = "/kms_aead/backend";
const DEK_CACHE: &str = "/kms_aead/dek_cache";
const FORMAT: &str = "/kms_aead/format";
const PURPOSE: &str = "/kms_aead/purpose";
const ERROR_CODE: &str = "/kms_aead/error_code";
#[cfg(feature = "legacy-formats")]
const FROM_FORMAT: &str = "/kms_aead/from_format";
#[cfg(feature = "legacy-formats")]
const TO_FORMAT: &str = "/kms_aead/to_format";

/// The `dek_cache` value of a call that unwraps through the provider although the envelope has
/// a cache.
#[cfg(feature = "deterministic")]
const DEK_CACHE_BYPASSED: &str = "bypassed";

/// The spans of the calls to a KMS, which the providers open.
pub(crate) mod kms {
    use std::future::Future;
    use std::time::Instant;

    use tracing::{debug_span, field, Span};

    use super::ERROR_CODE;
    use crate::{EncryptedDataEncryptionKey, KekRef, KmsKeyVersion};

    const PROVIDER: &str = "/kms_aead/provider";
    const KEY: &str = "/kms_aead/key";
    const KEY_VERSION: &str = "/kms_aead/key_version";
    const KEY_VERSIONS: &str = "/kms_aead/key_versions";
    const RESPONSE_TIME: &str = "/kms_aead/response_time";
    #[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
    const LEN: &str = "/kms_aead/len";

    /// `KMS wrap`, around a provider's `encrypt_data_encryption_key`.
    pub(crate) fn wrap_span(kek: &KekRef) -> Span {
        debug_span!(
            "KMS wrap",
            { PROVIDER } = %kek.provider(),
            { KEY } = kek.key(),
            { KEY_VERSION } = field::Empty,
            { RESPONSE_TIME } = field::Empty,
            { ERROR_CODE } = field::Empty,
        )
    }

    /// `KMS unwrap`, around a provider's `decrypt_data_encryption_key`, with the key version the
    /// encrypted key records.
    pub(crate) fn unwrap_span(kek: &KekRef, key_version: Option<&KmsKeyVersion>) -> Span {
        let span = debug_span!(
            "KMS unwrap",
            { PROVIDER } = %kek.provider(),
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
    #[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
    pub(crate) fn random_span(
        provider: &crate::KekProvider,
        key: Option<&str>,
        len: usize,
    ) -> Span {
        let span = debug_span!(
            "KMS random",
            { PROVIDER } = %provider,
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

    /// The `INFO` event of a new local KMS provider: its KEK id and its versions, each with
    /// where it came from, such as `1 (file), 2 (secret)`.
    pub(crate) fn local_kek_loaded(key: &impl std::fmt::Display, versions: &str) {
        tracing::info!(
            { KEY } = %key,
            { KEY_VERSIONS } = versions,
            "A local KEK wraps and unwraps data encryption keys"
        );
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

/// `KMS AEAD encrypt`, around the envelope's encrypt calls. `mode` is `per_call` or
/// `store_less` for `encrypt_value` and `caller_dek` for the calls that take a key.
pub(crate) fn aead_encrypt(
    mode: &str,
    algorithm: impl Display,
    backend: &str,
    dek_cache: &DekCache,
) -> Span {
    let span = debug_span!(
        "KMS AEAD encrypt",
        { MODE } = mode,
        { ALGORITHM } = %algorithm,
        { BACKEND } = %backend,
        { DEK_CACHE } = field::Empty,
        { ERROR_CODE } = field::Empty,
    );
    record_disabled_cache(&span, dek_cache);
    span
}

/// `KMS AEAD decrypt`, around the envelope's decrypt calls, with the layout of the stored value
/// for a call that reads one: `envelope_v1` or `envelope_legacy`.
pub(crate) fn aead_decrypt(
    mode: &str,
    algorithm: impl Display,
    backend: &str,
    dek_cache: &DekCache,
    format: Option<&str>,
) -> Span {
    let span = debug_span!(
        "KMS AEAD decrypt",
        { MODE } = mode,
        { ALGORITHM } = %algorithm,
        { BACKEND } = %backend,
        { DEK_CACHE } = field::Empty,
        { FORMAT } = field::Empty,
        { ERROR_CODE } = field::Empty,
    );
    record_disabled_cache(&span, dek_cache);
    if let Some(format) = format {
        span.record(FORMAT, format);
    }
    span
}

/// Records `dek_cache` as `disabled` for an envelope without a cache. With one, a call records
/// what its lookup found, and a call that looks nothing up leaves the field unrecorded.
fn record_disabled_cache(span: &Span, dek_cache: &DekCache) {
    if !dek_cache.is_enabled() {
        span.record(DEK_CACHE, field::display(DekCacheOutcome::Disabled));
    }
}

/// Records on the current envelope span where the key of the call came from.
pub(crate) fn record_dek_cache(outcome: DekCacheOutcome) {
    Span::current().record(DEK_CACHE, field::display(outcome));
}

/// `KMS AEAD generate DEK`, around the envelope's key generation. `purpose` is `randomized` or
/// `deterministic`.
pub(crate) fn generate_dek(purpose: &str, algorithm: impl Display, backend: &str) -> Span {
    debug_span!(
        "KMS AEAD generate DEK",
        { PURPOSE } = purpose,
        { ALGORITHM } = %algorithm,
        { BACKEND } = %backend,
        { ERROR_CODE } = field::Empty,
    )
}

/// `KMS AEAD decrypt DEK`, around the envelope's unwrap of a key the caller stored, which never
/// goes through the cache. `purpose` is `randomized` or `deterministic`.
#[cfg(feature = "deterministic")]
pub(crate) fn decrypt_dek(purpose: &str, algorithm: impl Display, dek_cache: &DekCache) -> Span {
    let span = debug_span!(
        "KMS AEAD decrypt DEK",
        { PURPOSE } = purpose,
        { ALGORITHM } = %algorithm,
        { DEK_CACHE } = field::Empty,
        { ERROR_CODE } = field::Empty,
    );
    if dek_cache.is_enabled() {
        span.record(DEK_CACHE, DEK_CACHE_BYPASSED);
    } else {
        span.record(DEK_CACHE, field::display(DekCacheOutcome::Disabled));
    }
    span
}

/// Runs `operation`, the re-framing of a stored value, inside a `KMS AEAD upgrade` span.
/// `from_format` is the layout of the stored value, when its first bytes name one, and
/// `to_format` is recorded only when `operation` returns a value in it, not `None` for a value
/// that already was current. The code of the error it returns is recorded too.
#[cfg(feature = "legacy-formats")]
pub(crate) fn upgrade<T>(
    from_format: Option<&str>,
    to_format: &str,
    operation: impl FnOnce() -> KmsAeadResult<Option<T>>,
) -> KmsAeadResult<Option<T>> {
    let span = debug_span!(
        "KMS AEAD upgrade",
        { FROM_FORMAT } = field::Empty,
        { TO_FORMAT } = field::Empty,
        { ERROR_CODE } = field::Empty,
    );
    if let Some(from_format) = from_format {
        span.record(FROM_FORMAT, from_format);
    }
    let result = span.in_scope(operation);
    match &result {
        Ok(Some(_)) => {
            span.record(TO_FORMAT, to_format);
        }
        Ok(None) => {}
        Err(error) => {
            span.record(ERROR_CODE, error.code());
        }
    }
    result
}

/// Runs the synchronous `operation` inside `span`, and records the code of the error it returns.
pub(crate) fn in_scope<T>(
    span: Span,
    operation: impl FnOnce() -> KmsAeadResult<T>,
) -> KmsAeadResult<T> {
    let result = span.in_scope(operation);
    if let Err(error) = &result {
        span.record(ERROR_CODE, error.code());
    }
    result
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
