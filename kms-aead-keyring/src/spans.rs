//! The span and field names of every keyring operation. Dashboards and trace queries depend on
//! them, so a name changes only in a breaking release.
//!
//! Every span opens at `DEBUG` with all its fields declared, records a field once its value is
//! known, and leaves a value nobody reported unrecorded. kms-aead's spans nest inside them: a
//! `KMS decrypt DEK` under a `Keyring decrypt` on a DEK cache miss, a `KMS encrypt DEK` under a
//! `Keyring rotate`. No field carries plaintext, key material in any form, AAD content, cipher
//! text bytes, or the length of a value or of its AAD.

use std::fmt::Display;
use std::future::Future;

use kms_aead::cache::DekCacheOutcome;
use tracing::{debug_span, field, Instrument, Span};

use crate::errors::{KeyringResult, RegressionRule};
use crate::store::StoreKind;
use crate::sweep::SweepReport;
use crate::{KeyId, KeyVersion, KeyringError, KeyringId, Purpose};

const FIELD_KEYRING: &str = "/kms_aead_keyring/keyring";
const FIELD_PURPOSE: &str = "/kms_aead_keyring/purpose";
const FIELD_KEY_ID: &str = "/kms_aead_keyring/key_id";
const FIELD_ALGORITHM: &str = "/kms_aead_keyring/algorithm";
const FIELD_BACKEND: &str = "/kms_aead_keyring/backend";
const FIELD_DEK_CACHE: &str = "/kms_aead_keyring/dek_cache";
const FIELD_KEY_STATE: &str = "/kms_aead_keyring/key_state";
const FIELD_RELOAD: &str = "/kms_aead_keyring/reload";
const FIELD_STORE: &str = "/kms_aead_keyring/store";
const FIELD_REASON: &str = "/kms_aead_keyring/reason";
const FIELD_CHANGED: &str = "/kms_aead_keyring/changed";
const FIELD_REVISION: &str = "/kms_aead_keyring/revision";
const FIELD_RESPONSE_TIME: &str = "/kms_aead_keyring/response_time";
const FIELD_FROM_KEY_ID: &str = "/kms_aead_keyring/from_key_id";
const FIELD_TO_KEY_ID: &str = "/kms_aead_keyring/to_key_id";
const FIELD_CAS_RETRIES: &str = "/kms_aead_keyring/cas_retries";
const FIELD_VERSIONS: &str = "/kms_aead_keyring/versions";
const FIELD_ERROR_CODE: &str = "/kms_aead_keyring/error_code";
const FIELD_SCANNED: &str = "/kms_aead_keyring/scanned";
const FIELD_RESEALED: &str = "/kms_aead_keyring/resealed";
const FIELD_RESEALED_FROM_COMPROMISED: &str = "/kms_aead_keyring/resealed_from_compromised";
const FIELD_SKIPPED: &str = "/kms_aead_keyring/skipped";
const FIELD_FAILED: &str = "/kms_aead_keyring/failed";
const FIELD_RECORD: &str = "/kms_aead_keyring/record";

/// The `dek_cache` value of a call that decrypts through the provider although the keyring has a
/// cache: `reencrypt_deks`, a keyset export, and a compromised version read by
/// `decrypt_with_trust`.
const DEK_CACHE_BYPASSED: &str = "bypassed";

/// `Keyring encrypt`, with the name of the keyring's AEAD backend for a randomised call. A
/// deterministic call leaves `backend` unrecorded: AES-SIV runs on RustCrypto whatever the
/// keyring's backend.
pub(crate) fn encrypt(keyring: &KeyringId, purpose: Purpose, backend: Option<&str>) -> Span {
    debug_span!(
        "Keyring encrypt",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %purpose,
        { FIELD_KEY_ID } = field::Empty,
        { FIELD_ALGORITHM } = field::Empty,
        { FIELD_BACKEND } = backend.map(field::display),
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring beacon`, for `beacon` and `beacon_probes`; the key id, algorithm and DEK cache
/// outcome are those of a single beacon.
pub(crate) fn beacon(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring beacon",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = field::Empty,
        { FIELD_ALGORITHM } = field::Empty,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring decrypt`, for the value's key id, of `purpose`.
pub(crate) fn decrypt(keyring: &KeyringId, purpose: Purpose, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring decrypt",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %purpose,
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_KEY_STATE } = field::Empty,
        { FIELD_RELOAD } = field::Empty,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring load`, around one store read. `reason` is `open`, `ttl`, `watch`,
/// `unknown_key_id`, `forced`, `export` or `admin`.
pub(crate) fn load(keyring: &KeyringId, store: StoreKind, reason: LoadReason) -> Span {
    debug_span!(
        "Keyring load",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_STORE } = %store,
        { FIELD_REASON } = reason.as_str(),
        { FIELD_CHANGED } = field::Empty,
        { FIELD_REVISION } = field::Empty,
        { FIELD_RESPONSE_TIME } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring export`, for a keyset of `purpose`.
pub(crate) fn export(keyring: &KeyringId, purpose: Purpose) -> Span {
    debug_span!(
        "Keyring export",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %purpose,
        { FIELD_VERSIONS } = field::Empty,
        { FIELD_DEK_CACHE } = DEK_CACHE_BYPASSED,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring rotate`, for `rotate` and `change_algorithm`, which record the staged version as
/// `to_key_id`.
pub(crate) fn rotate(keyring: &KeyringId, purpose: Purpose) -> Span {
    debug_span!(
        "Keyring rotate",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %purpose,
        { FIELD_FROM_KEY_ID } = field::Empty,
        { FIELD_TO_KEY_ID } = field::Empty,
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring promote`, for the pending version `key_id`.
pub(crate) fn promote(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring promote",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_FROM_KEY_ID } = field::Empty,
        { FIELD_TO_KEY_ID } = field::Empty,
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn mark_compromised(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring mark compromised",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_TO_KEY_ID } = field::Empty,
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn retire(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring retire",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn reinstate(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring reinstate",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

pub(crate) fn destroy(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring destroy",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring destroy all versions`.
pub(crate) fn destroy_all_versions(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring destroy all versions",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring re-encrypt DEKs`, which decrypts through the provider and never through the DEK cache.
pub(crate) fn reencrypt_deks(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring re-encrypt DEKs",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_VERSIONS } = field::Empty,
        { FIELD_DEK_CACHE } = DEK_CACHE_BYPASSED,
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
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
        span.record(FIELD_ERROR_CODE, error.code());
    }
    result
}

/// Records on the current `Keyring encrypt` span the version that seals.
pub(crate) fn record_sealing_version(version: &KeyVersion) {
    let span = Span::current();
    span.record(FIELD_KEY_ID, field::display(version.id().as_u32()));
    span.record(FIELD_ALGORITHM, field::display(version.algorithm()));
}

/// Records on the current `Keyring decrypt` span the state of the version that opens.
pub(crate) fn record_key_state(version: &KeyVersion) {
    let span = Span::current();
    match version.compromised() {
        Some(_) => span.record(FIELD_KEY_STATE, "compromised"),
        None => span.record(FIELD_KEY_STATE, field::display(version.state())),
    };
}

/// Records `key_state` as `unknown` on the current span.
pub(crate) fn record_unknown_version() {
    Span::current().record(FIELD_KEY_STATE, "unknown");
}

/// Records on the current span what an unknown key id caused: `none`, `reloaded` or
/// `rate_limited`.
pub(crate) fn record_reload(reload: Reload) {
    Span::current().record(FIELD_RELOAD, reload.as_str());
}

/// Records on the current span where the key of the call came from.
pub(crate) fn record_dek_cache(outcome: DekCacheOutcome) {
    Span::current().record(FIELD_DEK_CACHE, field::display(outcome));
}

/// Records on the current span that the key was decrypted past the DEK cache.
pub(crate) fn record_dek_cache_bypassed() {
    Span::current().record(FIELD_DEK_CACHE, DEK_CACHE_BYPASSED);
}

/// Records on the current span the versions of a rotation.
pub(crate) fn record_rotation(previous: Option<KeyId>, current: KeyId) {
    let span = Span::current();
    if let Some(previous) = previous {
        span.record(FIELD_FROM_KEY_ID, field::display(previous.as_u32()));
    }
    span.record(FIELD_TO_KEY_ID, field::display(current.as_u32()));
}

/// Records on the current span the conflicts an administrative write retried.
pub(crate) fn record_cas_retries(conflicts: u32) {
    Span::current().record(FIELD_CAS_RETRIES, conflicts);
}

/// Records on the current span how many versions were encrypted again.
pub(crate) fn record_versions(versions: usize) {
    Span::current().record(FIELD_VERSIONS, versions);
}

/// Records on the current `Keyring load` span what the read did and the revision it read:
/// `changed` is `true` for a new record taken, `false`, or `regressed` for one refused because
/// it moves backwards.
pub(crate) fn record_load(changed: LoadChanged, revision: Option<&impl Display>) {
    let span = Span::current();
    span.record(FIELD_CHANGED, changed.as_str());
    if let Some(revision) = revision {
        span.record(FIELD_REVISION, field::display(revision));
    }
}

/// Sends a store request and records on the current span how long it took, in milliseconds.
pub(crate) async fn timed<T>(request: impl Future<Output = T>) -> T {
    let started = tokio::time::Instant::now();
    let response = request.await;
    let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    Span::current().record(FIELD_RESPONSE_TIME, elapsed);
    response
}

/// A read of a compromised version under `CompromisedReadPolicy::Allow`.
pub(crate) fn compromised_read_allowed(keyring: &KeyringId, key_id: KeyId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        "Decrypted a value under a compromised key version, as the Allow policy permits"
    );
}

/// A read refused because its version is retired or destroyed: the error says it already, and
/// the event is for an operator watching a sweep.
pub(crate) fn read_refused(keyring: &KeyringId, version: &KeyVersion) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %version.id().as_u32(),
        { FIELD_KEY_STATE } = %version.state(),
        "Refused a value under a key version that no longer decrypts"
    );
}

/// A reload for an unknown key id refused inside the reload interval.
pub(crate) fn reload_rate_limited(keyring: &KeyringId, key_id: KeyId) {
    tracing::debug!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        "Not reloading the keyring record for an unknown key id inside the reload interval"
    );
}

/// A revalidation that failed: the cached record stays in use.
pub(crate) fn revalidation_failed(keyring: &KeyringId, error: &KeyringError) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_ERROR_CODE } = error.code(),
        "The keyring record could not be revalidated; the cached record stays in use"
    );
}

/// A record the store no longer holds: the cached record stays in use.
pub(crate) fn record_missing_kept(keyring: &KeyringId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        "The keyring store no longer holds the keyring record; the cached record stays in use"
    );
}

/// A record refused because it moves a version backwards: the detection of a rewritten or
/// restored record.
pub(crate) fn record_regressed(keyring: &KeyringId, rule: RegressionRule) {
    tracing::error!(
        { FIELD_KEYRING } = keyring.as_str(),
        rule = %rule,
        "Refused a keyring record that moves backwards from the record this process holds"
    );
}

/// A compromised flag written without a rotation, because the new key could not be encrypted.
pub(crate) fn compromised_without_rotation(
    keyring: &KeyringId,
    key_id: KeyId,
    error: &KeyringError,
) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
        { FIELD_ERROR_CODE } = error.code(),
        "Flagged the active key version compromised without a new one, since the new key could \
         not be encrypted: nothing encrypts until rotate succeeds"
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
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %purpose,
        { FIELD_FROM_KEY_ID } = from.map(|key_id| field::display(key_id.as_u32())),
        { FIELD_TO_KEY_ID } = to.map(|key_id| field::display(key_id.as_u32())),
        "The active key version changed"
    );
}

/// A compare-and-swap conflict that the write retries.
pub(crate) fn write_conflict(keyring: &KeyringId, attempt: u32) {
    tracing::debug!(
        { FIELD_KEYRING } = keyring.as_str(),
        attempt,
        "The keyring record changed during a write; reading it again"
    );
}

/// The store's listener lost its connection.
pub(crate) fn watch_disconnected(keyring: &KeyringId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        "The keyring store's change listener disconnected; the record TTL bounds how late a \
         change is seen until it reconnects"
    );
}

/// The store's listener is connected again.
pub(crate) fn watch_reconnected(keyring: &KeyringId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        "The keyring store's change listener reconnected; revalidating the record"
    );
}

/// The store's listener did not start.
pub(crate) fn watch_failed(keyring: &KeyringId, error: &KeyringError) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_ERROR_CODE } = error.code(),
        "The keyring store's change listener did not start: the record TTL alone bounds how late \
         this process sees a change"
    );
}

/// No tokio runtime to run the task that follows the store's signals.
pub(crate) fn watch_without_runtime(keyring: &KeyringId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        "No tokio runtime runs the call, so the keyring store's change signals are not followed: \
         the record TTL alone bounds how late this process sees a change"
    );
}

/// `Keyring decrypt` for an envelope value, which names no key version: `key_id`, `key_state`
/// and `reload` stay unrecorded.
pub(crate) fn decrypt_envelope(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring decrypt",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_PURPOSE } = %Purpose::Randomized,
        { FIELD_KEY_ID } = field::Empty,
        { FIELD_KEY_STATE } = field::Empty,
        { FIELD_RELOAD } = field::Empty,
        { FIELD_DEK_CACHE } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring sweep`, whose counts are recorded once the sweep ends.
pub(crate) fn sweep(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring sweep",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_SCANNED } = field::Empty,
        { FIELD_RESEALED } = field::Empty,
        { FIELD_RESEALED_FROM_COMPROMISED } = field::Empty,
        { FIELD_SKIPPED } = field::Empty,
        { FIELD_FAILED } = field::Empty,
    )
}

/// Records the counts of a sweep on its span.
pub(crate) fn record_sweep(span: &Span, report: &SweepReport) {
    span.record(FIELD_SCANNED, report.scanned);
    span.record(FIELD_RESEALED, report.resealed);
    span.record(
        FIELD_RESEALED_FROM_COMPROMISED,
        report.resealed_from_compromised,
    );
    span.record(FIELD_SKIPPED, report.skipped);
    span.record(FIELD_FAILED, report.failed);
}

/// A record the sweep could not re-seal, by the application's candidate for it, which is often
/// an entity id: the sweep's log is read as an administrative log.
pub(crate) fn sweep_failed(keyring: &KeyringId, candidate: &str, error: &KeyringError) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_RECORD } = %candidate,
        { FIELD_ERROR_CODE } = error.code(),
        "The sweep could not re-seal a record"
    );
}

/// Why the record was read from the store: the `reason` field of `Keyring load`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum LoadReason {
    Open,
    Ttl,
    Watch,
    UnknownKeyId,
    Forced,
    Export,
    Admin,
}

impl LoadReason {
    fn as_str(self) -> &'static str {
        match self {
            LoadReason::Open => "open",
            LoadReason::Ttl => "ttl",
            LoadReason::Watch => "watch",
            LoadReason::UnknownKeyId => "unknown_key_id",
            LoadReason::Forced => "forced",
            LoadReason::Export => "export",
            LoadReason::Admin => "admin",
        }
    }
}

/// What a read did to the cached record: the `changed` field of `Keyring load`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum LoadChanged {
    Taken,
    Unchanged,
    Regressed,
}

impl LoadChanged {
    fn as_str(self) -> &'static str {
        match self {
            LoadChanged::Taken => "true",
            LoadChanged::Unchanged => "false",
            LoadChanged::Regressed => "regressed",
        }
    }
}

/// What an unknown key id caused: the `reload` field of `Keyring decrypt`.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Reload {
    NotNeeded,
    Reloaded,
    RateLimited,
}

impl Reload {
    fn as_str(self) -> &'static str {
        match self {
            Reload::NotNeeded => "none",
            Reload::Reloaded => "reloaded",
            Reload::RateLimited => "rate_limited",
        }
    }
}
