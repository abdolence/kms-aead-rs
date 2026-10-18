//! The span and field names of every keyring operation. Dashboards and trace queries depend on
//! them, so a name changes only in a breaking release.
//!
//! Every span opens at `DEBUG` with all its fields declared, records a field once its value is
//! known, and leaves a value nobody reported unrecorded. kms-aead's spans nest inside them: a
//! `KMS unwrap` under a `Keyring decrypt` on a DEK cache miss, a `KMS wrap` under a
//! `Keyring rotate`. No field carries plaintext, key material in any form, AAD content, cipher
//! text bytes, or the length of a value or of its AAD.

use std::fmt::Display;
use std::future::Future;

use kms_aead::cache::DekCacheOutcome;
use kms_aead::AeadBackend;
use tracing::{debug_span, field, Instrument, Span};

use crate::errors::{KeyringResult, RegressionRule};
use crate::store::StoreKind;
use crate::sweep::SweepReport;
use crate::{KeyId, KeyVersion, KeyringError, KeyringId, Purpose};

const KEYRING: &str = "/kms_aead_keyring/keyring";
const PURPOSE: &str = "/kms_aead_keyring/purpose";
const KEY_ID: &str = "/kms_aead_keyring/key_id";
const ALGORITHM: &str = "/kms_aead_keyring/algorithm";
const BACKEND: &str = "/kms_aead_keyring/backend";
const DEK_CACHE: &str = "/kms_aead_keyring/dek_cache";
const KEY_STATE: &str = "/kms_aead_keyring/key_state";
const RELOAD: &str = "/kms_aead_keyring/reload";
const STORE: &str = "/kms_aead_keyring/store";
const REASON: &str = "/kms_aead_keyring/reason";
const CHANGED: &str = "/kms_aead_keyring/changed";
const REVISION: &str = "/kms_aead_keyring/revision";
const RESPONSE_TIME: &str = "/kms_aead_keyring/response_time";
const FROM_KEY_ID: &str = "/kms_aead_keyring/from_key_id";
const TO_KEY_ID: &str = "/kms_aead_keyring/to_key_id";
const CAS_RETRIES: &str = "/kms_aead_keyring/cas_retries";
const VERSIONS: &str = "/kms_aead_keyring/versions";
const ERROR_CODE: &str = "/kms_aead_keyring/error_code";
const SCANNED: &str = "/kms_aead_keyring/scanned";
const RESEALED: &str = "/kms_aead_keyring/resealed";
const RESEALED_FROM_COMPROMISED: &str = "/kms_aead_keyring/resealed_from_compromised";
const SKIPPED: &str = "/kms_aead_keyring/skipped";
const FAILED: &str = "/kms_aead_keyring/failed";
const RECORD: &str = "/kms_aead_keyring/record";

/// The `dek_cache` value of a call that unwraps through the provider although the keyring has a
/// cache: `rewrap`, and a compromised version read by `decrypt_with_status`.
const DEK_CACHE_BYPASSED: &str = "bypassed";

pub(crate) fn encrypt(keyring: &KeyringId, purpose: Purpose, backend: AeadBackend) -> Span {
    debug_span!(
        "Keyring encrypt",
        { KEYRING } = keyring.as_str(),
        { PURPOSE } = %purpose,
        { KEY_ID } = field::Empty,
        { ALGORITHM } = field::Empty,
        { BACKEND } = %backend,
        { DEK_CACHE } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// `Keyring decrypt`, for the value's key id.
pub(crate) fn decrypt(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring decrypt",
        { KEYRING } = keyring.as_str(),
        { PURPOSE } = %key_id.purpose(),
        { KEY_ID } = %key_id,
        { KEY_STATE } = field::Empty,
        { RELOAD } = field::Empty,
        { DEK_CACHE } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// `Keyring load`, around one store read. `reason` is `open`, `ttl`, `watch`,
/// `unknown_key_id`, `forced` or `admin`.
pub(crate) fn load(keyring: &KeyringId, store: StoreKind, reason: &'static str) -> Span {
    debug_span!(
        "Keyring load",
        { KEYRING } = keyring.as_str(),
        { STORE } = %store,
        { REASON } = reason,
        { CHANGED } = field::Empty,
        { REVISION } = field::Empty,
        { RESPONSE_TIME } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// `Keyring rotate`, for `rotate` and `change_algorithm`.
pub(crate) fn rotate(keyring: &KeyringId, purpose: Purpose) -> Span {
    debug_span!(
        "Keyring rotate",
        { KEYRING } = keyring.as_str(),
        { PURPOSE } = %purpose,
        { FROM_KEY_ID } = field::Empty,
        { TO_KEY_ID } = field::Empty,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn mark_compromised(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring mark compromised",
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        { TO_KEY_ID } = field::Empty,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn retire(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring retire",
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn reinstate(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring reinstate",
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn destroy(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring destroy",
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// `Keyring rewrap`, which unwraps through the provider and never through the DEK cache.
pub(crate) fn rewrap(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring rewrap",
        { KEYRING } = keyring.as_str(),
        { VERSIONS } = field::Empty,
        { DEK_CACHE } = DEK_CACHE_BYPASSED,
        { CAS_RETRIES } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// Runs `operation` inside `span`, without holding the span entered across an `.await`, and
/// records the code of the error it returns.
pub(crate) async fn in_span<T>(
    span: Span,
    operation: impl Future<Output = KeyringResult<T>>,
) -> KeyringResult<T> {
    let result = operation.instrument(span.clone()).await;
    if let Err(error) = &result {
        span.record(ERROR_CODE, error.code());
    }
    result
}

/// Records on the current `Keyring encrypt` span the version that seals.
pub(crate) fn record_sealing_version(version: &KeyVersion) {
    let span = Span::current();
    span.record(KEY_ID, field::display(version.key_id()));
    span.record(ALGORITHM, field::display(version.algorithm()));
}

/// Records on the current `Keyring decrypt` span the state of the version that opens.
pub(crate) fn record_key_state(version: &KeyVersion) {
    let span = Span::current();
    match version.compromised() {
        Some(_) => span.record(KEY_STATE, "compromised"),
        None => span.record(KEY_STATE, field::display(version.state())),
    };
}

/// Records `key_state` as `unknown` on the current span.
pub(crate) fn record_unknown_version() {
    Span::current().record(KEY_STATE, "unknown");
}

/// Records on the current span what an unknown key id caused: `none`, `reloaded` or
/// `rate_limited`.
pub(crate) fn record_reload(reload: &'static str) {
    Span::current().record(RELOAD, reload);
}

/// Records on the current span where the key of the call came from.
pub(crate) fn record_dek_cache(outcome: DekCacheOutcome) {
    Span::current().record(DEK_CACHE, field::display(outcome));
}

/// Records on the current span that the key was unwrapped past the DEK cache.
pub(crate) fn record_dek_cache_bypassed() {
    Span::current().record(DEK_CACHE, DEK_CACHE_BYPASSED);
}

/// Records on the current span the versions of a rotation.
pub(crate) fn record_rotation(previous: Option<KeyId>, current: KeyId) {
    let span = Span::current();
    if let Some(previous) = previous {
        span.record(FROM_KEY_ID, field::display(previous));
    }
    span.record(TO_KEY_ID, field::display(current));
}

/// Records on the current span the conflicts an administrative write retried.
pub(crate) fn record_cas_retries(conflicts: u32) {
    Span::current().record(CAS_RETRIES, conflicts);
}

/// Records on the current span how many versions were wrapped again.
pub(crate) fn record_versions(versions: usize) {
    Span::current().record(VERSIONS, versions);
}

/// Records on the current `Keyring load` span what the read did and the revision it read:
/// `changed` is `true` for a new record taken, `false`, or `regressed` for one refused because
/// it moves backwards.
pub(crate) fn record_load(changed: &'static str, revision: Option<&impl Display>) {
    let span = Span::current();
    span.record(CHANGED, changed);
    if let Some(revision) = revision {
        span.record(REVISION, field::display(revision));
    }
}

/// Sends a store request and records on the current span how long it took, in milliseconds.
pub(crate) async fn timed<T>(request: impl Future<Output = T>) -> T {
    let started = tokio::time::Instant::now();
    let response = request.await;
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Span::current().record(RESPONSE_TIME, elapsed);
    response
}

/// A read of a compromised version under `CompromisedReadPolicy::Allow`.
pub(crate) fn compromised_read_allowed(keyring: &KeyringId, key_id: KeyId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        "Decrypted a value under a compromised key version, as the Allow policy permits"
    );
}

/// A read refused because its version is retired or destroyed: the error says it already, and
/// the event is for an operator watching a sweep.
pub(crate) fn read_refused(keyring: &KeyringId, version: &KeyVersion) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %version.key_id(),
        { KEY_STATE } = %version.state(),
        "Refused a value under a key version that no longer decrypts"
    );
}

/// A reload for an unknown key id refused inside the reload interval.
pub(crate) fn reload_rate_limited(keyring: &KeyringId, key_id: KeyId) {
    tracing::debug!(
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        "Not reloading the keyring record for an unknown key id inside the reload interval"
    );
}

/// A revalidation that failed: the cached record stays in use.
pub(crate) fn revalidation_failed(keyring: &KeyringId, error: &KeyringError) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { ERROR_CODE } = error.event_code(),
        "The keyring record could not be revalidated; the cached record stays in use"
    );
}

/// A record the store no longer holds: the cached record stays in use.
pub(crate) fn record_missing_kept(keyring: &KeyringId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        "The keyring store no longer holds the keyring record; the cached record stays in use"
    );
}

/// A record refused because it moves a version backwards: the detection of a rewritten or
/// restored record.
pub(crate) fn record_regressed(keyring: &KeyringId, rule: RegressionRule) {
    tracing::error!(
        { KEYRING } = keyring.as_str(),
        rule = %rule,
        "Refused a keyring record that moves backwards from the record this process holds"
    );
}

/// A compromised flag written without a rotation, because the new key could not be wrapped.
pub(crate) fn compromised_without_rotation(
    keyring: &KeyringId,
    key_id: KeyId,
    error: &KeyringError,
) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { KEY_ID } = %key_id,
        { ERROR_CODE } = error.event_code(),
        "Flagged the active key version compromised without a new one, since the new key could \
         not be wrapped: nothing encrypts until rotate succeeds"
    );
}

/// The active version of a purpose changed in the cached record, by this process or another.
pub(crate) fn active_version_changed(
    keyring: &KeyringId,
    purpose: Purpose,
    from: Option<KeyId>,
    to: Option<KeyId>,
) {
    tracing::info!(
        { KEYRING } = keyring.as_str(),
        { PURPOSE } = %purpose,
        { FROM_KEY_ID } = from.map(field::display),
        { TO_KEY_ID } = to.map(field::display),
        "The active key version changed"
    );
}

/// A compare-and-swap conflict that the write retries.
pub(crate) fn write_conflict(keyring: &KeyringId, attempt: u32) {
    tracing::debug!(
        { KEYRING } = keyring.as_str(),
        attempt,
        "The keyring record changed during a write; reading it again"
    );
}

/// The store's listener lost its connection.
pub(crate) fn watch_disconnected(keyring: &KeyringId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        "The keyring store's change listener disconnected; the record TTL bounds how late a \
         change is seen until it reconnects"
    );
}

/// The store's listener is connected again.
pub(crate) fn watch_reconnected(keyring: &KeyringId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        "The keyring store's change listener reconnected; revalidating the record"
    );
}

/// The store's listener did not start.
pub(crate) fn watch_failed(keyring: &KeyringId, error: &KeyringError) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { ERROR_CODE } = error.event_code(),
        "The keyring store's change listener did not start: the record TTL alone bounds how late \
         this process sees a change"
    );
}

/// A keyring opened with `bind_keys` off: a writer of its store can bring a leaked key back
/// into use under a new id.
pub(crate) fn keys_unbound(keyring: &KeyringId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        "The keyring's keys are not bound to their key ids at the KMS: its record's integrity \
         rests on the keyring store's access control alone"
    );
}

/// No tokio runtime to run the task that follows the store's signals.
pub(crate) fn watch_without_runtime(keyring: &KeyringId) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        "No tokio runtime runs the call, so the keyring store's change signals are not followed: \
         the record TTL alone bounds how late this process sees a change"
    );
}

/// `Keyring decrypt` for an envelope value, which names no key version: `key_id`, `key_state`
/// and `reload` stay unrecorded.
pub(crate) fn decrypt_envelope(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring decrypt",
        { KEYRING } = keyring.as_str(),
        { PURPOSE } = %Purpose::Randomized,
        { KEY_ID } = field::Empty,
        { KEY_STATE } = field::Empty,
        { RELOAD } = field::Empty,
        { DEK_CACHE } = field::Empty,
        { ERROR_CODE } = field::Empty,
    )
}

/// `Keyring sweep`, whose counts are recorded once the sweep ends.
pub(crate) fn sweep(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring sweep",
        { KEYRING } = keyring.as_str(),
        { SCANNED } = field::Empty,
        { RESEALED } = field::Empty,
        { RESEALED_FROM_COMPROMISED } = field::Empty,
        { SKIPPED } = field::Empty,
        { FAILED } = field::Empty,
    )
}

/// Records the counts of a sweep on its span.
pub(crate) fn record_sweep(span: &Span, report: &SweepReport) {
    span.record(SCANNED, report.scanned);
    span.record(RESEALED, report.resealed);
    span.record(RESEALED_FROM_COMPROMISED, report.resealed_from_compromised);
    span.record(SKIPPED, report.skipped);
    span.record(FAILED, report.failed);
}

/// A record the sweep could not re-seal. The record id is the application's and often an
/// entity id: the sweep's log is read as an administrative log.
pub(crate) fn sweep_failed(keyring: &KeyringId, record: &str, error: &KeyringError) {
    tracing::warn!(
        { KEYRING } = keyring.as_str(),
        { RECORD } = record,
        { ERROR_CODE } = error.event_code(),
        "The sweep could not re-seal a record"
    );
}
