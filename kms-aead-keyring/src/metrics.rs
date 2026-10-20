//! The keyring's measurements, of the `opentelemetry` feature, recorded into kms-aead's
//! instruments with `mode` `keyring` and the keyring's own attributes. A keyring call runs
//! kms-aead's ciphers and never its envelope, so each call is recorded once, here.
//!
//! Without the feature every call here runs the operation it is given and nothing else.

use std::future::Future;

use kms_aead::formats::{Deterministic, Format, Randomized};

use crate::errors::KeyringResult;
use crate::spans::LoadReason;
use crate::store::StoreKind;
use crate::{Encrypted, KeyId, KeyVersion, KeyringId, Purpose};

/// The formats of the values a keyring version seals.
pub(crate) trait VersionedFormat: Format + Sized {
    /// The version `value` is sealed under, and the length of its plaintext: the value's length
    /// less Tink's 5-byte output prefix and the algorithm's own overhead.
    #[cfg_attr(not(feature = "opentelemetry"), allow(dead_code))]
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize);
}

/// The 12-byte nonce and the 16-byte tag of every randomised algorithm.
impl VersionedFormat for Randomized {
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize) {
        let overhead = 5 + 12 + 16;
        (value.key_id(), value.value().len().saturating_sub(overhead))
    }
}

/// The 16-byte synthetic IV of AES-SIV.
impl VersionedFormat for Deterministic {
    fn version_and_plaintext_len<T>(value: &Encrypted<T, Self>) -> (KeyId, usize) {
        let overhead = 5 + 16;
        (value.key_id(), value.value().len().saturating_sub(overhead))
    }
}

/// The `keyring` attribute of one keyring, built once when the keyring is opened so that a call
/// does not copy the id.
#[derive(Debug)]
pub(crate) struct KeyringAttribute {
    #[cfg(feature = "opentelemetry")]
    value: opentelemetry::StringValue,
}

impl KeyringAttribute {
    #[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
    pub(crate) fn new(id: &KeyringId) -> Self {
        Self {
            #[cfg(feature = "opentelemetry")]
            value: std::sync::Arc::<str>::from(id.as_str()).into(),
        }
    }
}

/// One keyring call of `purpose`: what its measurements carry. The call names the version it
/// seals or opens under with [`version`](Self::version) once it has found it.
#[cfg_attr(not(feature = "opentelemetry"), allow(dead_code))]
pub(crate) struct Call<'k> {
    keyring: &'k KeyringAttribute,
    purpose: Purpose,
    backend: &'static str,
    algorithm: std::sync::OnceLock<&'static str>,
}

impl<'k> Call<'k> {
    /// A call on the backend named `backend`: the keyring's for a randomised call, and
    /// `rustcrypto` for a deterministic one, whose AES-SIV runs on RustCrypto whatever the
    /// keyring's backend.
    pub(crate) fn new(
        keyring: &'k KeyringAttribute,
        purpose: Purpose,
        backend: &'static str,
    ) -> Self {
        Self {
            keyring,
            purpose,
            backend,
            algorithm: std::sync::OnceLock::new(),
        }
    }

    /// Names `version`, the version the call seals or opens under.
    #[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
    pub(crate) fn version(&self, version: &KeyVersion) {
        #[cfg(feature = "opentelemetry")]
        if let Some(name) = instruments::algorithm_name(version.algorithm()) {
            let _ = self.algorithm.set(name);
        }
    }
}

/// The backend of every deterministic call: AES-SIV runs on RustCrypto whatever the keyring's
/// backend.
#[cfg(feature = "deterministic")]
pub(crate) const DETERMINISTIC_BACKEND: &str = "rustcrypto";

/// Runs `seal`, a seal of one value, and with the feature records its duration and, when it
/// succeeds, the value and its plaintext bytes under the version it names.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn encrypt<T, F: VersionedFormat>(
    call: &Call<'_>,
    seal: impl Future<Output = KeyringResult<Encrypted<T, F>>>,
) -> KeyringResult<Encrypted<T, F>> {
    #[cfg(feature = "opentelemetry")]
    let started = std::time::Instant::now();
    let result = seal.await;
    #[cfg(feature = "opentelemetry")]
    instruments::record_call(
        call,
        "encrypt",
        started.elapsed(),
        result.as_ref().ok(),
        &result,
    );
    result
}

/// Runs `open`, the opening of `value`, and with the feature records its duration and, when it
/// succeeds, the value and its plaintext bytes under the version `value` names.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn decrypt<T, F: VersionedFormat, R>(
    call: &Call<'_>,
    value: &Encrypted<T, F>,
    open: impl Future<Output = KeyringResult<R>>,
) -> KeyringResult<R> {
    #[cfg(feature = "opentelemetry")]
    let started = std::time::Instant::now();
    let result = open.await;
    #[cfg(feature = "opentelemetry")]
    instruments::record_call(
        call,
        "decrypt",
        started.elapsed(),
        result.is_ok().then_some(value),
        &result,
    );
    result
}

/// Runs `probes`, the deterministic probes of one plaintext, and with the feature records its
/// duration. Probes are not stored, so they count no value.
#[cfg(feature = "deterministic")]
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) async fn probe<R>(
    call: &Call<'_>,
    probes: impl Future<Output = KeyringResult<R>>,
) -> KeyringResult<R> {
    #[cfg(feature = "opentelemetry")]
    let started = std::time::Instant::now();
    let result = probes.await;
    #[cfg(feature = "opentelemetry")]
    instruments::record_call::<(), Deterministic, R>(
        call,
        "probe",
        started.elapsed(),
        None,
        &result,
    );
    result
}

/// With the feature, records one store read of `keyring` for `reason` that took `elapsed`.
#[cfg_attr(not(feature = "opentelemetry"), allow(unused_variables))]
pub(crate) fn record_store_load<T>(
    keyring: &KeyringAttribute,
    store: StoreKind,
    reason: LoadReason,
    elapsed: std::time::Duration,
    result: &KeyringResult<T>,
) {
    #[cfg(feature = "opentelemetry")]
    kms_aead::__instruments::record_store_load(
        &[
            instruments::keyring(keyring),
            opentelemetry::KeyValue::new("store", store.to_string()),
            opentelemetry::KeyValue::new("reason", reason.as_str()),
        ],
        elapsed,
        result.as_ref().err().map(|error| error.code()),
    );
}

#[cfg(feature = "opentelemetry")]
mod instruments {
    use std::time::Duration;

    use kms_aead::__instruments::{
        aead_algorithm_name, deterministic_algorithm_name, record_operation, record_value,
    };
    use opentelemetry::KeyValue;

    use super::{Call, KeyringAttribute, VersionedFormat};
    use crate::errors::KeyringResult;
    use crate::{Encrypted, KeyAlgorithm};

    /// The `mode` of every keyring call, beside the `per_call`, `store_less` and `caller_dek` of
    /// kms-aead's envelope.
    const MODE: &str = "keyring";

    pub(super) fn keyring(keyring: &KeyringAttribute) -> KeyValue {
        KeyValue::new("keyring", keyring.value.clone())
    }

    pub(super) fn algorithm_name(algorithm: KeyAlgorithm) -> Option<&'static str> {
        match algorithm {
            KeyAlgorithm::Randomized(algorithm) => Some(aead_algorithm_name(algorithm)),
            KeyAlgorithm::Deterministic(algorithm) => Some(deterministic_algorithm_name(algorithm)),
            KeyAlgorithm::Beacon(_) => None,
        }
    }

    /// Records the duration of `call`'s `operation`, and `counted`, the value it sealed or
    /// opened, when there is one.
    pub(super) fn record_call<T, F: VersionedFormat, R>(
        call: &Call<'_>,
        operation: &'static str,
        elapsed: Duration,
        counted: Option<&Encrypted<T, F>>,
        result: &KeyringResult<R>,
    ) {
        let algorithm = call.algorithm.get().copied();
        let attributes = [
            KeyValue::new("operation", operation),
            KeyValue::new("mode", MODE),
            KeyValue::new("backend", call.backend),
            keyring(call.keyring),
            KeyValue::new("purpose", call.purpose.as_str()),
            KeyValue::new("algorithm", algorithm.unwrap_or_default()),
        ];
        // A call that failed before it found its version has no algorithm.
        let known = match algorithm {
            Some(_) => &attributes[..],
            None => &attributes[..attributes.len() - 1],
        };
        record_operation(
            known,
            elapsed,
            result.as_ref().err().map(|error| error.code()),
        );
        if let Some(value) = counted {
            let (key_id, plaintext_len) = F::version_and_plaintext_len(value);
            let [operation, mode, backend, keyring, purpose, algorithm] = attributes;
            record_value(
                &[
                    operation,
                    mode,
                    backend,
                    keyring,
                    purpose,
                    algorithm,
                    KeyValue::new("key_id", i64::from(key_id.as_u32())),
                ],
                plaintext_len,
            );
        }
    }
}
