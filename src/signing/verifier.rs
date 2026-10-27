use std::marker::PhantomData;

use super::{Signature, Signed, VerifyingKey, VerifyingKeySet};
use crate::backends::{self, AeadBackend, Sha256Digest};
use crate::errors::KmsAeadSignatureError;
use crate::metrics::{self, Measurement};
use crate::signable::PreImage;
use crate::spans::{self, IntegritySpan};
use crate::{KeyId, KmsAeadResult, Signable, SignableType, SignedPayloadType};

/// Verifies signatures against a key set, on the backend `B`, with no KMS and no secret.
///
/// A signature selects its key by the key id in its prefix, and only that key is tried: an id the
/// set does not hold is refused rather than searched for, since the set is stale or the signer
/// unknown. Neither call reaches a KMS, so a verifier needs no KMS identity.
#[derive(Debug, Clone)]
pub struct Verifier<B> {
    keys: VerifyingKeySet,
    backend: PhantomData<B>,
}

impl<B: AeadBackend> Verifier<B> {
    /// A verifier of `keys`, each parsed on `B` before any value is checked.
    ///
    /// # Errors
    ///
    /// `EMPTY_KEY_SET` for a set without keys, and `INVALID_PUBLIC_KEY` for a point not on the
    /// curve or a key the backend refuses. ring and aws-lc-rs check an Ed25519 point at each
    /// verification instead, where a key off the curve verifies nothing.
    pub fn new(keys: VerifyingKeySet) -> KmsAeadResult<Self> {
        if keys.is_empty() {
            return Err(KmsAeadSignatureError::create(
                "EMPTY_KEY_SET",
                "A verifier needs at least one verifying key",
            ));
        }
        for key in keys.keys() {
            B::check_verifying_key(key.algorithm(), key.public_key()).map_err(|_| {
                KmsAeadSignatureError::invalid_public_key(&format!(
                    "The {} backend refuses the {} key with the key id {}: not a point on \
                         the curve",
                    B::NAME,
                    key.algorithm(),
                    key.key_id().as_u32()
                ))
            })?;
        }
        Ok(Self {
            keys,
            backend: PhantomData,
        })
    }

    /// The keys the verifier trusts.
    pub fn keys(&self) -> &VerifyingKeySet {
        &self.keys
    }

    /// The key of the set that `signature` verifies under for `value`: the one key with the
    /// signature's key id, and no other.
    ///
    /// # Errors
    ///
    /// `SIGNING_KEY_UNKNOWN` when the set has no key with the signature's key id,
    /// `SIGNATURE_INVALID` when that key does not verify it, and `INVALID_PAYLOAD` from
    /// `to_payload`.
    pub fn verify<T: Signable>(
        &self,
        value: &T,
        signature: &Signature<T>,
    ) -> KmsAeadResult<&VerifyingKey> {
        self.measured(signature.key_id(), T::PAYLOAD_TYPE, || {
            let payload = value.to_payload()?;
            self.verify_raw(
                T::PAYLOAD_TYPE,
                &backends::sha256::<B>(&payload)?,
                signature.key_id(),
                signature.raw(),
            )
        })
    }

    /// Verifies the payload of `signed` and decodes it with `from_payload`, in that order: bytes
    /// that did not verify are never parsed.
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify), and `INVALID_PAYLOAD` from `from_payload`.
    pub fn verify_signed<T: Signable>(
        &self,
        signed: &Signed<T>,
    ) -> KmsAeadResult<(T, &VerifyingKey)> {
        self.measured(signed.key_id(), T::PAYLOAD_TYPE, || {
            let payload = signed.unverified_payload();
            let key = self.verify_raw(
                T::PAYLOAD_TYPE,
                &backends::sha256::<B>(payload)?,
                signed.key_id(),
                signed.raw_signature(),
            )?;
            Ok((T::from_payload(payload.to_vec())?, key))
        })
    }

    /// [`verify`](Self::verify) for a caller that holds the SHA-256 of the payload and not the
    /// payload: an index of published files, or a keyring registry with a record's canonical
    /// digest.
    ///
    /// # Errors
    ///
    /// `SIGNING_KEY_UNKNOWN` and `SIGNATURE_INVALID`, as [`verify`](Self::verify).
    pub fn verify_digest<T: SignableType>(
        &self,
        payload_sha256: &[u8; 32],
        signature: &Signature<T>,
    ) -> KmsAeadResult<&VerifyingKey> {
        self.measured(signature.key_id(), T::PAYLOAD_TYPE, || {
            self.verify_raw(
                T::PAYLOAD_TYPE,
                payload_sha256,
                signature.key_id(),
                signature.raw(),
            )
        })
    }

    /// Runs `operation` in the `Signature verify` span and records it.
    fn measured<R>(
        &self,
        key_id: KeyId,
        payload_type: SignedPayloadType,
        operation: impl FnOnce() -> KmsAeadResult<R>,
    ) -> KmsAeadResult<R> {
        let algorithm = self
            .keys
            .key_with_id(key_id)
            .map(|key| key.algorithm().as_str());
        let measurement = Measurement::start(metrics::Call {
            operation: "verify",
            mode: "signature",
            backend: B::NAME,
            algorithm,
        });
        let span = spans::signature(
            IntegritySpan::Verify,
            algorithm,
            B::NAME,
            key_id,
            payload_type,
        );
        let result = spans::in_scope(span, operation);
        measurement.finished(&result);
        result
    }

    /// The key `key_id` names when `raw` verifies under it over the pre-image of `payload_type`
    /// and `payload_sha256`.
    fn verify_raw(
        &self,
        payload_type: SignedPayloadType,
        payload_sha256: &Sha256Digest,
        key_id: KeyId,
        raw: &[u8],
    ) -> KmsAeadResult<&VerifyingKey> {
        let key = self.keys.key_with_id(key_id).ok_or_else(|| {
            KmsAeadSignatureError::create(
                "SIGNING_KEY_UNKNOWN",
                &format!(
                    "No verifying key has the key id {}: the key set is stale, or the signer is \
                     not trusted",
                    key_id.as_u32()
                ),
            )
        })?;
        let invalid = || {
            KmsAeadSignatureError::create(
                "SIGNATURE_INVALID",
                &format!(
                    "The signature does not verify under the {} key with the key id {}",
                    key.algorithm(),
                    key_id.as_u32()
                ),
            )
        };
        if raw.len() != key.algorithm().signature_len() {
            return Err(invalid());
        }
        let pre_image = PreImage::new(payload_type, payload_sha256);
        B::verify(key.algorithm(), key.public_key(), pre_image.as_bytes(), raw)
            .map_err(|_| invalid())?;
        Ok(key)
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::providers::{LocalSigningKeyName, LocalSigningProvider};
    use crate::signing::{
        KmsSigningProvider, RawSignature, Signer, SigningAlgorithm, SigningInput, SigningKeyRef,
    };
    use crate::test_provider::{
        error_code_of, Invoice, TestBackend, INVOICE_PAYLOAD, OTHER_INVOICE_PAYLOAD,
    };

    /// Another document type with the same bytes as an [`Invoice`].
    struct Receipt;

    impl SignableType for Receipt {
        const PAYLOAD_TYPE: SignedPayloadType =
            SignedPayloadType::from_static("example.com/receipts/v1");
    }

    impl Signable for Receipt {
        fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
            Ok(INVOICE_PAYLOAD.to_vec())
        }

        fn from_payload(_: Vec<u8>) -> KmsAeadResult<Self> {
            Ok(Receipt)
        }
    }

    async fn local_signer(
        algorithm: SigningAlgorithm,
    ) -> KmsAeadResult<Signer<LocalSigningProvider<TestBackend>, TestBackend>> {
        Signer::new(LocalSigningProvider::ephemeral(
            LocalSigningKeyName::try_from("invoices".to_string())?,
            algorithm,
        )?)
        .await
    }

    fn test_invoice() -> Invoice {
        Invoice(INVOICE_PAYLOAD.to_vec())
    }

    #[tokio::test]
    async fn a_signature_verifies_detached_attached_and_by_digest() -> KmsAeadResult<()> {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let signer = local_signer(algorithm).await?;
            let verifier = Verifier::<TestBackend>::new(VerifyingKeySet::new([signer
                .verifying_key()
                .clone()])?)?;
            let digest = backends::sha256::<TestBackend>(INVOICE_PAYLOAD)?;

            let detached = signer.sign(&test_invoice()).await?;
            let attached = signer.sign_attached(&test_invoice()).await?;
            let by_digest = signer.sign_digest::<Invoice>(&digest).await?;

            assert_eq!(
                verifier.verify(&test_invoice(), &detached)?,
                signer.verifying_key()
            );
            assert_eq!(verifier.verify_signed(&attached)?.0 .0, INVOICE_PAYLOAD);
            assert_eq!(
                verifier.verify_digest(&digest, &by_digest)?,
                signer.verifying_key()
            );
            assert_eq!(
                verifier.verify_digest(&digest, &detached)?,
                signer.verifying_key()
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_signature_verifies_only_for_its_payload_and_payload_type() -> KmsAeadResult<()> {
        let signer = local_signer(SigningAlgorithm::Ed25519).await?;
        let verifier =
            Verifier::<TestBackend>::new(VerifyingKeySet::new([signer.verifying_key().clone()])?)?;
        let signature = signer.sign(&test_invoice()).await?;
        let attached = signer.sign_attached(&test_invoice()).await?;
        let mut tampered = attached.value().to_vec();
        if let Some(last) = tampered.last_mut() {
            *last ^= 0x01;
        }

        assert_eq!(
            error_code_of(verifier.verify(&Invoice(OTHER_INVOICE_PAYLOAD.to_vec()), &signature)),
            "SIGNATURE_INVALID"
        );
        assert_eq!(
            error_code_of(verifier.verify(&Receipt, &Signature::try_from(signature.into_value())?)),
            "SIGNATURE_INVALID"
        );
        assert_eq!(
            error_code_of(
                verifier
                    .verify_signed(&Signed::<Invoice>::try_from(tampered)?)
                    .map(|_| ())
            ),
            "SIGNATURE_INVALID"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_verifier_tries_only_the_key_the_signature_names() -> KmsAeadResult<()> {
        let unknown_signer = local_signer(SigningAlgorithm::Ed25519).await?;
        let other = local_signer(SigningAlgorithm::Ed25519).await?;
        let renumbered = local_signer(SigningAlgorithm::Ed25519)
            .await?
            .with_key_id(other.verifying_key().key_id());
        let verifier =
            Verifier::<TestBackend>::new(VerifyingKeySet::new([other.verifying_key().clone()])?)?;

        let unknown = verifier.verify(
            &test_invoice(),
            &unknown_signer.sign(&test_invoice()).await?,
        );
        let under_another_key =
            verifier.verify(&test_invoice(), &renumbered.sign(&test_invoice()).await?);

        assert_eq!(error_code_of(unknown), "SIGNING_KEY_UNKNOWN");
        assert_eq!(error_code_of(under_another_key), "SIGNATURE_INVALID");
        Ok(())
    }

    #[tokio::test]
    async fn a_key_id_the_signer_sets_is_in_its_signatures_and_its_key() -> KmsAeadResult<()> {
        let signer = local_signer(SigningAlgorithm::EcdsaP256Sha256)
            .await?
            .with_key_id(KeyId::new(42));
        let verifier =
            Verifier::<TestBackend>::new(VerifyingKeySet::new([signer.verifying_key().clone()])?)?;

        let signature = signer.sign(&test_invoice()).await?;

        assert_eq!(signature.key_id(), KeyId::new(42));
        assert_eq!(signer.verifying_key().key_id(), KeyId::new(42));
        assert_eq!(
            verifier.verify(&test_invoice(), &signature)?,
            signer.verifying_key()
        );
        Ok(())
    }

    /// A provider configured for one algorithm whose key is of another.
    struct Misconfigured(LocalSigningProvider<TestBackend>);

    impl KmsSigningProvider for Misconfigured {
        fn signing_key(&self) -> &SigningKeyRef {
            self.0.signing_key()
        }

        fn algorithm(&self) -> SigningAlgorithm {
            SigningAlgorithm::EcdsaP256Sha256
        }

        async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
            self.0.sign(input).await
        }

        async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
            self.0.verifying_key().await
        }
    }

    #[tokio::test]
    async fn a_signer_refuses_a_key_of_another_algorithm_than_configured() -> KmsAeadResult<()> {
        let provider = Misconfigured(LocalSigningProvider::ephemeral(
            LocalSigningKeyName::try_from("invoices".to_string())?,
            SigningAlgorithm::Ed25519,
        )?);

        let result = Signer::<_, TestBackend>::new(provider).await;

        assert_eq!(
            error_code_of(result.map(|_| ())),
            "SIGNING_ALGORITHM_MISMATCH"
        );
        Ok(())
    }

    #[test]
    fn a_verifier_needs_a_key() {
        assert_eq!(
            error_code_of(Verifier::<TestBackend>::new(VerifyingKeySet::default()).map(|_| ())),
            "EMPTY_KEY_SET"
        );
    }
}
