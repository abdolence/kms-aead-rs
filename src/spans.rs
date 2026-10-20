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

const FIELD_MODE: &str = "/kms_aead/mode";
const FIELD_ALGORITHM: &str = "/kms_aead/algorithm";
const FIELD_BACKEND: &str = "/kms_aead/backend";
const FIELD_DEK_CACHE: &str = "/kms_aead/dek_cache";
const FIELD_PURPOSE: &str = "/kms_aead/purpose";
const FIELD_ERROR_CODE: &str = "/kms_aead/error_code";

/// The `dek_cache` value of a call that decrypts through the provider although the envelope has
/// a cache.
const DEK_CACHE_BYPASSED: &str = "bypassed";

/// The spans of the calls to a KMS, which the providers open.
pub(crate) mod kms {
    use std::future::Future;
    use std::time::Instant;

    use tracing::{debug_span, field, Span};

    use super::FIELD_ERROR_CODE;
    use crate::{KekProvider, KekRef, KmsAeadResult};

    const FIELD_PROVIDER: &str = "/kms_aead/provider";
    const FIELD_KEY: &str = "/kms_aead/key";
    const FIELD_KEK_VERSION: &str = "/kms_aead/kek_version";
    const FIELD_KEK_VERSIONS: &str = "/kms_aead/kek_versions";
    const FIELD_RESPONSE_TIME: &str = "/kms_aead/response_time";
    #[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
    const FIELD_LEN: &str = "/kms_aead/len";

    /// `KMS encrypt DEK`, around a provider's `encrypt_data_encryption_key`.
    pub(crate) fn encrypt_span(kek: &KekRef) -> Span {
        debug_span!(
            "KMS encrypt DEK",
            { FIELD_PROVIDER } = %kek.provider(),
            { FIELD_KEY } = kek.key(),
            { FIELD_KEK_VERSION } = field::Empty,
            { FIELD_RESPONSE_TIME } = field::Empty,
            { FIELD_ERROR_CODE } = field::Empty,
        )
    }

    /// `KMS decrypt DEK`, around a provider's `decrypt_data_encryption_key`.
    pub(crate) fn decrypt_span(kek: &KekRef) -> Span {
        debug_span!(
            "KMS decrypt DEK",
            { FIELD_PROVIDER } = %kek.provider(),
            { FIELD_KEY } = kek.key(),
            { FIELD_KEK_VERSION } = field::Empty,
            { FIELD_RESPONSE_TIME } = field::Empty,
            { FIELD_ERROR_CODE } = field::Empty,
        )
    }

    /// `KMS random`, around a call to a KMS generator. `key` is what the request names, if
    /// anything.
    #[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
    pub(crate) fn random_span(provider: &KekProvider, key: Option<&str>, len: usize) -> Span {
        let span = debug_span!(
            "KMS random",
            { FIELD_PROVIDER } = %provider,
            { FIELD_KEY } = field::Empty,
            { FIELD_LEN } = len,
            { FIELD_RESPONSE_TIME } = field::Empty,
            { FIELD_ERROR_CODE } = field::Empty,
        );
        if let Some(key) = key {
            span.record(FIELD_KEY, key);
        }
        span
    }

    /// The `INFO` event of a new local KMS provider: its KEK id and its versions, each with
    /// where it came from, such as `1 (file), 2 (secret)`.
    pub(crate) fn local_kek_loaded(key: &impl std::fmt::Display, versions: &str) {
        tracing::info!(
            { FIELD_KEY } = %key,
            { FIELD_KEK_VERSIONS } = versions,
            "A local KEK encrypts and decrypts data encryption keys"
        );
    }

    /// Records on the current KMS span the version of the KEK that encrypts or encrypted the DEK:
    /// from the KMS response on encryption, from the encrypted DEK on decryption.
    pub(crate) fn record_kek_version(kek_version: &str) {
        Span::current().record(FIELD_KEK_VERSION, kek_version);
    }

    /// Sends a request to `provider`'s KMS and records how long it took on the current span, in
    /// milliseconds, and with the `opentelemetry` feature in the KMS duration histogram, under
    /// `operation`: `encrypt_dek`, `decrypt_dek` or `random`. `request` maps the KMS's error, so
    /// that the histogram records its code.
    pub(crate) fn timed<'a, T: 'a>(
        operation: &'static str,
        provider: &'a KekProvider,
        request: impl Future<Output = KmsAeadResult<T>> + 'a,
    ) -> impl Future<Output = KmsAeadResult<T>> + 'a {
        // Boxed before the returned future holds it, which keeps the SDK's future type out of the
        // layout of every future that calls a provider. With the AWS SDK's inline, an
        // application's `main` that calls an envelope goes past the compiler's default query
        // depth.
        let request = Box::pin(request);
        async move {
            let started = Instant::now();
            let response = request.await;
            let elapsed = started.elapsed();
            Span::current().record(
                FIELD_RESPONSE_TIME,
                u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX),
            );
            crate::metrics::record_kms_call(operation, provider, elapsed, &response);
            response
        }
    }
}

/// `KMS AEAD encrypt`, around the envelope's encrypt calls. `mode` is `per_call` or
/// `store_less` for `encrypt` and `caller_dek` for the calls that take a key.
pub(crate) fn aead_encrypt(
    mode: &str,
    algorithm: impl Display,
    backend: &str,
    dek_cache: &DekCache,
) -> Span {
    let span = debug_span!(
        "KMS AEAD encrypt",
        { FIELD_MODE } = mode,
        { FIELD_ALGORITHM } = %algorithm,
        { FIELD_BACKEND } = %backend,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    );
    record_disabled_cache(&span, dek_cache);
    span
}

/// `KMS AEAD decrypt`, around the envelope's decrypt calls.
pub(crate) fn aead_decrypt(
    mode: &str,
    algorithm: impl Display,
    backend: &str,
    dek_cache: &DekCache,
) -> Span {
    let span = debug_span!(
        "KMS AEAD decrypt",
        { FIELD_MODE } = mode,
        { FIELD_ALGORITHM } = %algorithm,
        { FIELD_BACKEND } = %backend,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    );
    record_disabled_cache(&span, dek_cache);
    span
}

/// Records `dek_cache` as `disabled` for an envelope without a cache. With one, a call records
/// what its lookup found, and a call that looks nothing up leaves the field unrecorded.
fn record_disabled_cache(span: &Span, dek_cache: &DekCache) {
    if !dek_cache.is_enabled() {
        span.record(FIELD_DEK_CACHE, field::display(DekCacheOutcome::Disabled));
    }
}

/// Records on the current envelope span where the key of the call came from.
pub(crate) fn record_dek_cache(outcome: DekCacheOutcome) {
    Span::current().record(FIELD_DEK_CACHE, field::display(outcome));
}

/// `KMS AEAD beacon`, around the envelope's beacon of a value.
pub(crate) fn beacon(algorithm: impl Display, backend: &str, dek_cache: &DekCache) -> Span {
    let span = debug_span!(
        "KMS AEAD beacon",
        { FIELD_ALGORITHM } = %algorithm,
        { FIELD_BACKEND } = %backend,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    );
    record_disabled_cache(&span, dek_cache);
    span
}

/// `KMS AEAD generate DEK`, around the envelope's key generation. `purpose` is `randomized` or
/// `deterministic`.
pub(crate) fn generate_encrypted_dek(
    purpose: &str,
    algorithm: impl Display,
    backend: &str,
) -> Span {
    debug_span!(
        "KMS AEAD generate DEK",
        { FIELD_PURPOSE } = purpose,
        { FIELD_ALGORITHM } = %algorithm,
        { FIELD_BACKEND } = %backend,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `KMS AEAD decrypt DEK`, around the envelope's decryption of a deterministic key the caller
/// stored, which never goes through the cache.
#[cfg(feature = "deterministic")]
pub(crate) fn decrypt_dek(algorithm: impl Display, dek_cache: &DekCache) -> Span {
    let span = debug_span!(
        "KMS AEAD decrypt DEK",
        { FIELD_PURPOSE } = "deterministic",
        { FIELD_ALGORITHM } = %algorithm,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    );
    record_bypassed_cache(&span, dek_cache);
    span
}

/// `KMS AEAD re-encrypt DEK`, around the envelope's re-encryption of a DEK, which never goes
/// through the cache.
pub(crate) fn reencrypt_dek(dek_cache: &DekCache) -> Span {
    let span = debug_span!(
        "KMS AEAD re-encrypt DEK",
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    );
    record_bypassed_cache(&span, dek_cache);
    span
}

/// Records `dek_cache` as `bypassed` for a call that decrypts through the provider beside an
/// enabled cache, and as `disabled` without one.
fn record_bypassed_cache(span: &Span, dek_cache: &DekCache) {
    if dek_cache.is_enabled() {
        span.record(FIELD_DEK_CACHE, DEK_CACHE_BYPASSED);
    } else {
        span.record(FIELD_DEK_CACHE, field::display(DekCacheOutcome::Disabled));
    }
}

/// Runs the synchronous `operation` inside `span`, and records the code of the error it returns.
pub(crate) fn in_scope<T>(
    span: Span,
    operation: impl FnOnce() -> KmsAeadResult<T>,
) -> KmsAeadResult<T> {
    let result = span.in_scope(operation);
    if let Err(error) = &result {
        span.record(FIELD_ERROR_CODE, error.code());
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
        span.record(FIELD_ERROR_CODE, error.code());
    }
    result
}
