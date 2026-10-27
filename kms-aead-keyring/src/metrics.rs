//! The keyring's calls and store reads in kms-aead's instruments, of the `opentelemetry` feature:
//! `kms_aead.mode` `keyring`, with the keyring's own attributes `kms_aead.keyring` and
//! `kms_aead.purpose`. A keyring call runs kms-aead's ciphers and never its envelope, so each call
//! is recorded once, here.
//!
//! Without the feature nothing here records or reads a clock.

use std::sync::OnceLock;

use kms_aead::AeadAlgorithm;

use crate::{KeyId, KeyVersion, Purpose};

#[cfg(feature = "opentelemetry")]
pub(crate) use recorded::{record_refusal, record_store_load, KeyringAttribute};
#[cfg(not(feature = "opentelemetry"))]
pub(crate) use unrecorded::{record_refusal, record_store_load, KeyringAttribute};

/// The backend of every deterministic call: AES-SIV runs on RustCrypto whatever the keyring's
/// backend.
#[cfg(feature = "deterministic")]
pub(crate) const DETERMINISTIC_BACKEND: &str = "rustcrypto";

/// One keyring call: what its measurements carry. The call names the version it encrypts, decrypts
/// or derives under with [`version`](Self::version) once it has found it.
#[cfg_attr(
    not(feature = "opentelemetry"),
    expect(
        dead_code,
        reason = "only the `opentelemetry` feature records the attributes"
    )
)]
pub(crate) struct KeyringCall<'k> {
    keyring: &'k KeyringAttribute,
    operation: &'static str,
    purpose: Option<Purpose>,
    backend: &'static str,
    algorithm: OnceLock<&'static str>,
    key_id: OnceLock<KeyId>,
}

impl<'k> KeyringCall<'k> {
    /// A call of `operation` on a value of `purpose`, on the backend named `backend`: the
    /// keyring's, or [`DETERMINISTIC_BACKEND`] for a deterministic one.
    pub(crate) fn new(
        keyring: &'k KeyringAttribute,
        operation: &'static str,
        purpose: Purpose,
        backend: &'static str,
    ) -> Self {
        Self {
            keyring,
            operation,
            purpose: Some(purpose),
            backend,
            algorithm: OnceLock::new(),
            key_id: OnceLock::new(),
        }
    }

    /// The decryption of an envelope value under `algorithm` for its migration into the keyring:
    /// a `decrypt` of no purpose and no version.
    pub(crate) fn envelope_migration(
        keyring: &'k KeyringAttribute,
        backend: &'static str,
        algorithm: AeadAlgorithm,
    ) -> Self {
        Self {
            keyring,
            operation: "decrypt",
            purpose: None,
            backend,
            algorithm: OnceLock::from(algorithm.as_str()),
            key_id: OnceLock::new(),
        }
    }

    /// Names `version`, the version the call runs under.
    pub(crate) fn version(&self, version: &KeyVersion) {
        let _ = self.algorithm.set(version.algorithm().as_str());
        let _ = self.key_id.set(version.id());
    }
}

#[cfg(feature = "opentelemetry")]
mod recorded {
    use std::future::Future;
    use std::time::{Duration, Instant};

    use kms_aead::__instruments::{record_operation, Call, Outcome};
    use kms_aead::formats::Format;
    use opentelemetry::KeyValue;

    use super::KeyringCall;
    use crate::errors::KeyringResult;
    use crate::spans::LoadReason;
    use crate::store::StoreKind;
    use crate::{Encrypted, KeyringError, KeyringId};

    const MODE: &str = "keyring";
    const KEYRING: &str = "kms_aead.keyring";
    const PURPOSE: &str = "kms_aead.purpose";
    const STORE: &str = "kms_aead.store";
    const REASON: &str = "kms_aead.reason";

    /// The `kms_aead.keyring` attribute of one keyring, built once when the keyring is opened so
    /// that a call does not copy the id.
    #[derive(Debug)]
    pub(crate) struct KeyringAttribute(KeyValue);

    impl KeyringAttribute {
        pub(crate) fn new(id: &KeyringId) -> Self {
            Self(KeyValue::new(
                KEYRING,
                std::sync::Arc::<str>::from(id.as_str()),
            ))
        }
    }

    impl KeyringCall<'_> {
        /// Runs `encrypt` and records the call, with the plaintext size of the value it encrypts.
        pub(crate) async fn encrypted<T, F: Format>(
            &self,
            encrypt: impl Future<Output = KeyringResult<Encrypted<T, F>>>,
        ) -> KeyringResult<Encrypted<T, F>> {
            let started = Instant::now();
            let encrypted = encrypt.await;
            self.record(started.elapsed(), &encrypted, |encrypted| {
                Outcome::value(encrypted, self.key_id.get().copied())
            });
            encrypted
        }

        /// Runs `decrypt`, the decryption of `value`, and records the call, with `value`'s
        /// plaintext size.
        pub(crate) async fn decrypted<T, F: Format, R>(
            &self,
            value: &Encrypted<T, F>,
            decrypt: impl Future<Output = KeyringResult<R>>,
        ) -> KeyringResult<R> {
            let started = Instant::now();
            let decrypted = decrypt.await;
            self.record(started.elapsed(), &decrypted, |_| {
                Outcome::value(value, self.key_id.get().copied())
            });
            decrypted
        }

        /// Runs `operation` and records the call, which holds no value to count.
        pub(crate) async fn timed<R>(
            &self,
            operation: impl Future<Output = KeyringResult<R>>,
        ) -> KeyringResult<R> {
            let started = Instant::now();
            let result = operation.await;
            self.record(started.elapsed(), &result, |_| Outcome::Succeeded);
            result
        }

        fn record<'a, R>(
            &self,
            elapsed: Duration,
            result: &'a KeyringResult<R>,
            succeeded: impl FnOnce(&'a R) -> Outcome<'a>,
        ) {
            let outcome = match result {
                Ok(value) => succeeded(value),
                Err(error) => Outcome::Failed {
                    error_type: error.code(),
                },
            };
            let call = Call {
                operation: self.operation,
                mode: MODE,
                backend: self.backend,
                algorithm: self.algorithm.get().copied(),
            };
            let purpose = self
                .purpose
                .map(|purpose| KeyValue::new(PURPOSE, purpose.as_str()));
            record_operation(
                &call,
                std::iter::once(self.keyring.0.clone()).chain(purpose),
                elapsed,
                outcome,
            );
        }
    }

    /// Counts one record of `keyring` refused because of its signature, with the refusal's
    /// `code`.
    pub(crate) fn record_refusal(keyring: &KeyringAttribute, code: &str) {
        kms_aead::__instruments::record_refusal([keyring.0.clone()], code);
    }

    /// Records one read of `keyring`'s record from `store` for `reason` that took `elapsed`.
    pub(crate) fn record_store_load<T>(
        keyring: &KeyringAttribute,
        store: StoreKind,
        reason: LoadReason,
        elapsed: Duration,
        result: &KeyringResult<T>,
    ) {
        kms_aead::__instruments::record_store_load(
            [
                keyring.0.clone(),
                KeyValue::new(STORE, store.to_string()),
                KeyValue::new(REASON, reason.as_str()),
            ],
            elapsed,
            result.as_ref().err().map(KeyringError::code),
        );
    }
}

/// The calls of `recorded` that record nothing, for a build without the feature.
#[cfg(not(feature = "opentelemetry"))]
mod unrecorded {
    use std::future::Future;
    use std::time::Duration;

    use kms_aead::formats::Format;

    use super::KeyringCall;
    use crate::errors::KeyringResult;
    use crate::spans::LoadReason;
    use crate::store::StoreKind;
    use crate::{Encrypted, KeyringId};

    #[derive(Debug)]
    pub(crate) struct KeyringAttribute;

    impl KeyringAttribute {
        pub(crate) fn new(_: &KeyringId) -> Self {
            Self
        }
    }

    impl KeyringCall<'_> {
        pub(crate) async fn encrypted<T, F: Format>(
            &self,
            encrypt: impl Future<Output = KeyringResult<Encrypted<T, F>>>,
        ) -> KeyringResult<Encrypted<T, F>> {
            encrypt.await
        }

        pub(crate) async fn decrypted<T, F: Format, R>(
            &self,
            _: &Encrypted<T, F>,
            decrypt: impl Future<Output = KeyringResult<R>>,
        ) -> KeyringResult<R> {
            decrypt.await
        }

        pub(crate) async fn timed<R>(
            &self,
            operation: impl Future<Output = KeyringResult<R>>,
        ) -> KeyringResult<R> {
            operation.await
        }
    }

    pub(crate) fn record_store_load<T>(
        _: &KeyringAttribute,
        _: StoreKind,
        _: LoadReason,
        _: Duration,
        _: &KeyringResult<T>,
    ) {
    }

    pub(crate) fn record_refusal(_: &KeyringAttribute, _: &str) {}
}
