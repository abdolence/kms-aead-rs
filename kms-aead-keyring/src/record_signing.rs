//! The signature of a keyring record: how a registry verifies the records it reads, and how a
//! `KeyringAdmin` signs the records it writes.

#[cfg(feature = "admin")]
use std::future::Future;

use kms_aead::backends::AeadBackend;
#[cfg(feature = "admin")]
use kms_aead::signing::{KmsSigningProvider, Signature, Signer, VerifyingKey};
use kms_aead::signing::{Verifier, VerifyingKeySet};
#[cfg(feature = "admin")]
use kms_aead::KmsAeadResult;
use kms_aead::KmsProvider;

use crate::errors::{KeyringError, KeyringResult, RecordSignatureInvalidError};
use crate::spans;
use crate::KeyringRecord;

/// How a [`KeyringRegistry`](crate::KeyringRegistry) treats the signatures of the records it
/// reads, at `open`, every revalidation, reload and watch signal, and before every administrative
/// write and export, before any field of the record is used and before any KMS call.
/// [`VerifyIfSigned`](Self::VerifyIfSigned) with no key is the default.
///
/// The verifying keys come from the application's configuration, a JWK Set or the signing KMS
/// key's public key, never from the store or the record.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RecordSignaturePolicy {
    /// A record that carries a signature must verify under the keys, and a record without one is
    /// read as 0.30 reads it. With no key, every signed record is refused, with the cause
    /// `SIGNING_KEY_UNKNOWN`: a reader never accepts a signature it cannot check. A running
    /// process that holds a signed record of a keyring refuses a later unsigned one with
    /// [`KeyringError::RecordSignatureRemoved`] until it restarts.
    VerifyIfSigned(VerifyingKeySet),
    /// Every record must carry a signature that verifies under the keys; a record without one
    /// fails with [`KeyringError::RecordUnsigned`]. The control against a store writer who
    /// strips the signature, for the processes that start after the write.
    Required(VerifyingKeySet),
}

/// [`VerifyIfSigned`](RecordSignaturePolicy::VerifyIfSigned) with no key.
impl Default for RecordSignaturePolicy {
    fn default() -> Self {
        RecordSignaturePolicy::VerifyIfSigned(VerifyingKeySet::default())
    }
}

/// A registry's [`RecordSignaturePolicy`], with its keys parsed on the backend `B` once, when the
/// registry is created.
pub(crate) struct RecordVerifier<B> {
    required: bool,
    /// `None` for a mode with no key, under which every signature is unknown.
    verifier: Option<Verifier<B>>,
}

impl<B: AeadBackend> RecordVerifier<B> {
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] with `INVALID_PUBLIC_KEY` when the backend refuses a key, and with
    /// `EMPTY_KEY_SET` for [`Required`](RecordSignaturePolicy::Required) with no key, which can
    /// only refuse every record.
    pub(crate) fn new(verification: RecordSignaturePolicy) -> KeyringResult<Self> {
        let (required, keys) = match verification {
            RecordSignaturePolicy::VerifyIfSigned(keys) => (false, keys),
            RecordSignaturePolicy::Required(keys) => (true, keys),
        };
        let verifier = if keys.is_empty() && !required {
            None
        } else {
            Some(Verifier::new(keys)?)
        };
        Ok(Self { required, verifier })
    }

    /// Whether `signer` is one of the verifying keys, so that a record signed with it verifies.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] with `SIGNING_KEY_UNKNOWN` when it is not.
    #[cfg(feature = "admin")]
    pub(crate) fn ensure_trusts(&self, signer: &VerifyingKey) -> KeyringResult<()> {
        let trusted = self
            .verifier
            .as_ref()
            .and_then(|verifier| verifier.keys().key_with_id(signer.key_id()))
            == Some(signer);
        if trusted {
            Ok(())
        } else {
            Err(kms_aead::errors::KmsAeadSignatureError::create(
                "SIGNING_KEY_UNKNOWN",
                &format!(
                    "The registry's record verification does not hold the key id {} of the \
                     record signer",
                    signer.key_id().as_u32()
                ),
            )
            .into())
        }
    }

    /// Logs a `WARN` when `record`, just taken, holds a DEK encrypted with a public key and this
    /// verification does not require a signature. A record of an application's own KEK is left
    /// out: this crate cannot tell what its provider's layouts mean.
    pub(crate) fn warn_if_public_key_encrypted(&self, record: &KeyringRecord) {
        if !self.required
            && !matches!(record.kek().provider(), KmsProvider::Other(_))
            && record.holds_public_key_encrypted_dek()
        {
            spans::public_key_encrypted_record_taken(record.id());
        }
    }

    /// Checks the signature of `incoming`, a record of its keyring just read, where the process
    /// holds `held` of the same keyring, or nothing at `open`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordSignatureInvalid`] for a signature that does not verify,
    /// [`KeyringError::RecordUnsigned`] for an unsigned record under `Required`, and
    /// [`KeyringError::RecordSignatureRemoved`] for one under `VerifyIfSigned` where `held` is
    /// signed.
    pub(crate) fn check(
        &self,
        incoming: &KeyringRecord,
        held: Option<&KeyringRecord>,
    ) -> KeyringResult<()> {
        let keyring = incoming.id();
        match incoming.signature() {
            Some(signature) => {
                let verified = match &self.verifier {
                    Some(verifier) => verifier
                        .verify_digest(incoming.canonical_digest(), signature)
                        .map(|_| ()),
                    None => Err(kms_aead::errors::KmsAeadSignatureError::create(
                        "SIGNING_KEY_UNKNOWN",
                        &format!(
                            "No verifying key has the key id {}: the registry holds no key to \
                             verify keyring records with",
                            signature.key_id().as_u32()
                        ),
                    )),
                };
                verified.map_err(|cause| {
                    KeyringError::RecordSignatureInvalid(RecordSignatureInvalidError {
                        keyring: keyring.clone(),
                        cause,
                    })
                })
            }
            None if self.required => Err(KeyringError::RecordUnsigned(keyring.clone())),
            None if held.is_some_and(|held| held.signature().is_some()) => {
                Err(KeyringError::RecordSignatureRemoved(keyring.clone()))
            }
            None => Ok(()),
        }
    }
}

/// Signs records for a `KeyringAdmin`: implemented by [`Signer`] for every signing provider,
/// through [`sign_digest`](Signer::sign_digest), and by an application for a signer of its own.
/// Write `sign_record` as an `async fn`; its future must be `Send`.
#[cfg(feature = "admin")]
pub trait RecordSigner: Send + Sync {
    /// The signature over `record.canonical_digest()`, the SHA-256 of the record's canonical
    /// document, under the record's payload type.
    ///
    /// # Errors
    ///
    /// The signing provider's errors.
    fn sign_record(
        &self,
        record: &KeyringRecord,
    ) -> impl Future<Output = KmsAeadResult<Signature<KeyringRecord>>> + Send;

    /// The public key of the signer, for the registries' key sets, and the key the admin
    /// verifies a new signature under before it writes.
    fn verifying_key(&self) -> &VerifyingKey;
}

#[cfg(feature = "admin")]
impl<P: KmsSigningProvider, B: AeadBackend> RecordSigner for Signer<P, B> {
    async fn sign_record(&self, record: &KeyringRecord) -> KmsAeadResult<Signature<KeyringRecord>> {
        self.sign_digest(record.canonical_digest()).await
    }

    fn verifying_key(&self) -> &VerifyingKey {
        Signer::verifying_key(self)
    }
}

/// The `R` of a `KeyringAdmin` that signs nothing: the default.
#[cfg(feature = "admin")]
#[derive(Debug, Clone, Copy, Default)]
pub struct NoRecordSigner;

/// The `R` of `KeyringAdmin<S, P, B, R>`: [`NoRecordSigner`], or any [`RecordSigner`]. Sealed.
#[cfg(feature = "admin")]
pub trait MaybeRecordSigner: private::Sealed + Send + Sync {}

#[cfg(feature = "admin")]
impl MaybeRecordSigner for NoRecordSigner {}

#[cfg(feature = "admin")]
impl<R: RecordSigner> MaybeRecordSigner for R {}

/// What a write does with the record's signature, through the admin's `R`.
#[cfg(feature = "admin")]
pub(crate) trait RecordSigning: Send + Sync {
    /// The signature of `record`, or `None` for [`NoRecordSigner`].
    fn sign(
        &self,
        record: &KeyringRecord,
    ) -> impl Future<Output = Option<KmsAeadResult<Signature<KeyringRecord>>>> + Send;

    /// The signer's key, or `None` for [`NoRecordSigner`].
    fn signer_key(&self) -> Option<&VerifyingKey>;
}

#[cfg(feature = "admin")]
impl RecordSigning for NoRecordSigner {
    fn sign(
        &self,
        _: &KeyringRecord,
    ) -> impl Future<Output = Option<KmsAeadResult<Signature<KeyringRecord>>>> + Send {
        std::future::ready(None)
    }

    fn signer_key(&self) -> Option<&VerifyingKey> {
        None
    }
}

#[cfg(feature = "admin")]
impl<R: RecordSigner> RecordSigning for R {
    async fn sign(
        &self,
        record: &KeyringRecord,
    ) -> Option<KmsAeadResult<Signature<KeyringRecord>>> {
        Some(self.sign_record(record).await)
    }

    fn signer_key(&self) -> Option<&VerifyingKey> {
        Some(self.verifying_key())
    }
}

#[cfg(feature = "admin")]
impl KeyringRecord {
    /// The record signed by `signer`, or as it is for [`NoRecordSigner`]. The new signature is
    /// verified under the signer's own key on `B` first, so that a signer that returns a
    /// signature of another key, or a damaged one, never reaches the store.
    ///
    /// # Errors
    ///
    /// The signer's errors, and [`KeyringError::RecordSignatureInvalid`] when the signature does
    /// not verify.
    pub(crate) async fn signed_by<B: AeadBackend, R: MaybeRecordSigner>(
        self,
        signer: &R,
    ) -> KeyringResult<Self> {
        let Some(key) = signer.signer_key() else {
            return Ok(self);
        };
        crate::spans::in_span(crate::spans::sign_record(self.id(), key.key_id()), async {
            let Some(signature) = signer.sign(&self).await else {
                return Ok(self);
            };
            let signature = signature?;
            VerifyingKeySet::new([key.clone()])
                .and_then(Verifier::<B>::new)
                .and_then(|verifier| {
                    verifier
                        .verify_digest(self.canonical_digest(), &signature)
                        .map(|_| ())
                })
                .map_err(|cause| {
                    KeyringError::RecordSignatureInvalid(RecordSignatureInvalidError {
                        keyring: self.id().clone(),
                        cause,
                    })
                })?;
            Ok(self.with_signature(signature))
        })
        .await
    }
}

#[cfg(feature = "admin")]
mod private {
    /// Seals [`MaybeRecordSigner`](super::MaybeRecordSigner). Its supertrait is how the crate
    /// reaches a signer through an `R: MaybeRecordSigner` bound, and being crate-private, it
    /// keeps that out of reach of every other crate.
    #[expect(
        private_bounds,
        reason = "a crate-private supertrait is what keeps the signing of a write uncallable \
                  outside the crate"
    )]
    pub trait Sealed: super::RecordSigning {}

    impl Sealed for super::NoRecordSigner {}

    impl<R: super::RecordSigner> Sealed for R {}
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests;
