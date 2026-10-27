use std::marker::PhantomData;

use super::{
    KmsSigningProvider, Signature, Signed, SigningAlgorithm, SigningInput, SigningKeyRef,
    VerifyingKey,
};
use crate::backends::{self, AeadBackend, Sha256Digest};
use crate::errors::KmsAeadSignatureError;
use crate::metrics::{self, Measurement};
use crate::signable::PreImage;
use crate::spans::{self, IntegritySpan};
use crate::{KeyId, KmsAeadResult, Signable, SignableType, SignedPayloadType};

/// Signs values with a signing provider's key, on the backend `B`, which hashes the payload and,
/// for ECDSA, the pre-image. One sign is one provider call: a KMS never sees the payload, only the
/// pre-image or its digest.
///
/// The key id of every signature is the verifying key's, fetched from the provider once when the
/// signer is built: a rotation in the KMS never changes what a running signer signs with, since
/// each provider names one key version. `Send + Sync` when its provider is.
#[derive(Debug)]
pub struct Signer<P, B> {
    provider: P,
    verifying_key: VerifyingKey,
    backend: PhantomData<B>,
}

impl<P: KmsSigningProvider, B: AeadBackend> Signer<P, B> {
    /// A signer on `provider`. Fetches the provider's verifying key once, which fixes the key id of
    /// every signature, and checks that its algorithm is the provider's.
    ///
    /// # Errors
    ///
    /// The provider's errors, and `SIGNING_ALGORITHM_MISMATCH` when the KMS key is not of the
    /// configured algorithm.
    pub async fn new(provider: P) -> KmsAeadResult<Self> {
        let verifying_key = provider.verifying_key().await?;
        if verifying_key.algorithm() != provider.algorithm() {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                &format!(
                    "The signing key {} is a key of {}, not of the configured {}",
                    provider.signing_key(),
                    verifying_key.algorithm(),
                    provider.algorithm()
                ),
            ));
        }
        Ok(Self {
            provider,
            verifying_key,
            backend: PhantomData,
        })
    }

    /// The same signer, writing `key_id` into every signature in place of the derived id, and into
    /// [`verifying_key`](Self::verifying_key), so that the published key carries it.
    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self {
            verifying_key: self.verifying_key.with_key_id(key_id),
            ..self
        }
    }

    /// The key version the provider signs with.
    pub fn signing_key(&self) -> &SigningKeyRef {
        self.provider.signing_key()
    }

    /// The algorithm of the key.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.verifying_key.algorithm()
    }

    /// The public key of the configured version, under the signer's key id, for the published
    /// key set.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Signs `value`: one provider call over the pre-image of `T::PAYLOAD_TYPE` and the SHA-256
    /// of `value.to_payload()`.
    ///
    /// # Errors
    ///
    /// `INVALID_PAYLOAD`, the provider's errors, and `SIGNATURE_ENCODING` or
    /// `SIGNING_KEY_MISMATCH` on a response the provider refuses.
    pub async fn sign<T: Signable>(&self, value: &T) -> KmsAeadResult<Signature<T>> {
        self.measured("sign", T::PAYLOAD_TYPE, async {
            let payload = value.to_payload()?;
            self.sign_payload_digest(T::PAYLOAD_TYPE, &backends::sha256::<B>(&payload)?)
                .await
        })
        .await
    }

    /// [`sign`](Self::sign), joined with the payload.
    ///
    /// # Errors
    ///
    /// As [`sign`](Self::sign).
    pub async fn sign_attached<T: Signable>(&self, value: &T) -> KmsAeadResult<Signed<T>> {
        self.measured("sign", T::PAYLOAD_TYPE, async {
            let payload = value.to_payload()?;
            let signature = self
                .sign_payload_digest(T::PAYLOAD_TYPE, &backends::sha256::<B>(&payload)?)
                .await?;
            Signed::join(&signature, &payload)
        })
        .await
    }

    /// Signs a payload the caller has already hashed: the pre-image of `T::PAYLOAD_TYPE` and
    /// `payload_sha256`. What [`sign`](Self::sign) does after hashing, for a caller that holds the
    /// digest, such as an index of published files or a keyring record's canonical digest.
    ///
    /// # Errors
    ///
    /// The provider's errors, and `SIGNATURE_ENCODING` or `SIGNING_KEY_MISMATCH` on a response
    /// the provider refuses.
    pub async fn sign_digest<T: SignableType>(
        &self,
        payload_sha256: &[u8; 32],
    ) -> KmsAeadResult<Signature<T>> {
        self.measured(
            "sign",
            T::PAYLOAD_TYPE,
            self.sign_payload_digest(T::PAYLOAD_TYPE, payload_sha256),
        )
        .await
    }

    /// Runs `operation` in the `Signature sign` span and records it with `operation_name`.
    async fn measured<R>(
        &self,
        operation_name: &'static str,
        payload_type: SignedPayloadType,
        operation: impl std::future::Future<Output = KmsAeadResult<R>>,
    ) -> KmsAeadResult<R> {
        let measurement = Measurement::start(metrics::Call {
            operation: operation_name,
            mode: "signature",
            backend: B::NAME,
            algorithm: Some(self.algorithm().as_str()),
        });
        let span = spans::signature(
            IntegritySpan::Sign,
            Some(self.algorithm().as_str()),
            B::NAME,
            self.verifying_key.key_id(),
            payload_type,
        );
        let result = spans::in_span(span, operation).await;
        measurement.finished(&result);
        result
    }

    async fn sign_payload_digest<T>(
        &self,
        payload_type: SignedPayloadType,
        payload_sha256: &Sha256Digest,
    ) -> KmsAeadResult<Signature<T>> {
        let pre_image = PreImage::new(payload_type, payload_sha256);
        let pre_image = pre_image.as_bytes();
        let algorithm = self.algorithm();
        let raw = match algorithm {
            SigningAlgorithm::Ed25519 => {
                self.provider
                    .sign(SigningInput::Ed25519 { pre_image })
                    .await?
            }
            SigningAlgorithm::EcdsaP256Sha256 => {
                let digest = backends::sha256::<B>(pre_image)?;
                self.provider
                    .sign(SigningInput::EcdsaP256Sha256 {
                        pre_image,
                        digest: &digest,
                    })
                    .await?
            }
        };
        if raw.value().len() != algorithm.signature_len() {
            return Err(KmsAeadSignatureError::create(
                "SIGNATURE_ENCODING",
                &format!(
                    "The signing key {} returned a signature of {} bytes, not the {} of {algorithm}",
                    self.provider.signing_key(),
                    raw.value().len(),
                    algorithm.signature_len()
                ),
            ));
        }
        Signature::from_raw(self.verifying_key.key_id(), raw.value())
    }
}
