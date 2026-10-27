//! The spans and events of the administrative calls, which the `admin` feature adds.

use tracing::{debug_span, field, Span};

use super::{
    DEK_CACHE_BYPASSED, FIELD_DEK_CACHE, FIELD_ERROR_CODE, FIELD_FROM_KEY_ID, FIELD_KEYRING,
    FIELD_KEY_ID, FIELD_PURPOSE, FIELD_TO_KEY_ID,
};
use crate::{KeyId, KeyringError, KeyringId, Purpose};

const FIELD_CAS_RETRIES: &str = "/kms_aead_keyring/cas_retries";
const FIELD_VERSIONS: &str = "/kms_aead_keyring/versions";

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

/// A `KeyringAdmin` without a record signer over a provider that encrypts with a public key: its
/// records carry no signature, so a holder of the public key can add a version to them.
pub(crate) fn unsigned_admin_over_asymmetric_kek(keyring: &KeyringId) {
    tracing::warn!(
        { FIELD_KEYRING } = keyring.as_str(),
        "Built an administrative handle without a record signer over an asymmetric KEK; the \
         records it writes are unsigned, and a holder of the public key can add a version to them"
    );
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

/// `Keyring shred`.
pub(crate) fn shred(keyring: &KeyringId) -> Span {
    debug_span!(
        "Keyring shred",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_CAS_RETRIES } = field::Empty,
        { FIELD_ERROR_CODE } = field::Empty,
    )
}

/// `Keyring sign record`, around the signing of a record a write is about to store, under the
/// key `key_id` of the admin's record signer.
pub(crate) fn sign_record(keyring: &KeyringId, key_id: KeyId) -> Span {
    debug_span!(
        "Keyring sign record",
        { FIELD_KEYRING } = keyring.as_str(),
        { FIELD_KEY_ID } = %key_id.as_u32(),
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

/// A compare-and-swap conflict that the write retries.
pub(crate) fn write_conflict(keyring: &KeyringId, attempt: u32) {
    tracing::debug!(
        { FIELD_KEYRING } = keyring.as_str(),
        attempt,
        "The keyring record changed during a write; reading it again"
    );
}
