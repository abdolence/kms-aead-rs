use super::{split_tink_output_prefix, TINK_OUTPUT_PREFIX_LEN};
use crate::errors::KmsAeadEncryptionError;
use crate::{AeadAlgorithm, DeterministicAlgorithm, KeyId, KmsAeadResult};

/// The format of an [`Encrypted`](crate::Encrypted) value, the byte layout its bytes are checked
/// against when they are read: [`Envelope`], [`Bare`], [`Randomized`] or [`Deterministic`].
///
/// Sealed: only the formats of this crate implement it. It has no methods, so code generic over
/// the format names this trait and nothing else.
pub trait Format: private::Sealed {}

mod private {
    /// Seals [`Format`](super::Format). Its crate-private supertrait carries the layout check,
    /// which no other crate can call or implement.
    #[expect(
        private_bounds,
        reason = "a crate-private supertrait is what keeps the layout check uncallable outside \
                  the crate"
    )]
    pub trait Sealed: super::FormatLayout {}
}

/// The layout check of a [`Format`].
pub(crate) trait FormatLayout {
    /// The key id the framing of a value names, which the value keeps: [`KeyId`] for the
    /// TINK-prefixed formats, and none for an envelope, which carries its encrypted DEK instead,
    /// or a bare value.
    type FramedKeyId: Copy;

    /// Checks that `value` is framed as a value of the format, and returns the key id the framing
    /// names. It reads the framing only: whether the bytes are authentic is known when they are
    /// decrypted.
    fn check(value: &[u8]) -> KmsAeadResult<Self::FramedKeyId>;

    /// The length of the plaintext that `value`, a value [`check`](Self::check) passed, seals:
    /// its length less the framing and the algorithm's nonce and tag, or synthetic IV.
    #[cfg_attr(
        not(feature = "opentelemetry"),
        expect(
            dead_code,
            reason = "only the `opentelemetry` feature records plaintext sizes"
        )
    )]
    fn plaintext_len(value: &[u8]) -> usize;
}

/// Tink's KMS envelope:
///
/// ```text
/// [w: u32 BE][encrypted DEK: w][nonce: 12][ciphertext][tag: 16]
/// ```
///
/// [`KmsAeadEnvelope::encrypt`](crate::KmsAeadEnvelope::encrypt) and
/// [`Encrypted::join`](crate::Encrypted::join) write it. With the deprecated `legacy-formats`
/// feature, a value of this format also holds the envelope layouts written by 0.29 and earlier,
/// which [`KmsAeadEnvelope::decrypt`](crate::KmsAeadEnvelope::decrypt) reads and
/// [`Encrypted::separate`](crate::Encrypted::separate) refuses; without it, reading them fails.
#[derive(Debug, Clone, Copy)]
pub enum Envelope {}

/// A value sealed by an [`AeadAlgorithm`] with no framing:
///
/// ```text
/// [nonce: 12][ciphertext][tag: 16]
/// ```
///
/// It is Tink's AEAD output under a key with the output prefix RAW, and the part of every
/// [`Envelope`] value after the encrypted DEK. It names no key: the caller keeps track of the key
/// that opens it. [`AeadCipher::encrypt_bare`](crate::AeadCipher::encrypt_bare) and
/// [`KmsAeadEnvelope::encrypt_with_dek`](crate::KmsAeadEnvelope::encrypt_with_dek) write it.
#[derive(Debug, Clone, Copy)]
pub enum Bare {}

/// A randomised value with Tink's output prefix of type TINK:
///
/// ```text
/// [0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]
/// ```
///
/// The layout of Tink's AEAD with a TINK-prefixed key, and of BigQuery's `AEAD.ENCRYPT` under
/// AES-256-GCM. [`AeadCipher::encrypt`](crate::AeadCipher::encrypt) writes it.
#[derive(Debug, Clone, Copy)]
pub enum Randomized {}

/// A deterministic value with Tink's output prefix of type TINK:
///
/// ```text
/// [0x01][key id: u32 BE][synthetic IV: 16][ciphertext]
/// ```
///
/// The layout of Tink's deterministic AEAD with a TINK-prefixed key, and of BigQuery's
/// `DETERMINISTIC_ENCRYPT`. `DeterministicCipher::encrypt` writes it. The format exists in
/// every build, without the `deterministic` feature too, so that such values pass through a
/// process that does not decrypt them.
#[derive(Debug, Clone, Copy)]
pub enum Deterministic {}

impl Format for Envelope {}
impl private::Sealed for Envelope {}
impl FormatLayout for Envelope {
    type FramedKeyId = ();

    /// With `legacy-formats`, the envelope layouts of 0.29 and earlier pass too, so that a reader
    /// keeps decoding stored rows into its final types until they are upgraded.
    fn check(value: &[u8]) -> KmsAeadResult<()> {
        Bare::check(Envelope::bare(value)?)
    }

    fn plaintext_len(value: &[u8]) -> usize {
        Envelope::bare(value).map_or(0, Bare::plaintext_len)
    }
}

impl Envelope {
    /// The part of `value` after its encrypted DEK.
    fn bare(value: &[u8]) -> KmsAeadResult<&[u8]> {
        #[cfg(feature = "legacy-formats")]
        {
            Ok(super::legacy::StoredEnvelope::split(value)?.bare)
        }
        #[cfg(not(feature = "legacy-formats"))]
        {
            let (_, bare) = super::envelope::split_envelope(value)?;
            Ok(bare)
        }
    }
}

impl Format for Bare {}
impl private::Sealed for Bare {}
impl FormatLayout for Bare {
    type FramedKeyId = ();

    fn check(value: &[u8]) -> KmsAeadResult<()> {
        if value.len() < AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "A cipher text of {} bytes is too short to hold a nonce and a tag",
                    value.len()
                ),
            ));
        }
        Ok(())
    }

    fn plaintext_len(value: &[u8]) -> usize {
        value
            .len()
            .saturating_sub(AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN)
    }
}

impl Format for Randomized {}
impl private::Sealed for Randomized {}
impl FormatLayout for Randomized {
    type FramedKeyId = KeyId;

    fn check(value: &[u8]) -> KmsAeadResult<KeyId> {
        check_tink_prefixed(
            value,
            "a nonce and a tag",
            AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN,
        )
    }

    fn plaintext_len(value: &[u8]) -> usize {
        Bare::plaintext_len(value).saturating_sub(TINK_OUTPUT_PREFIX_LEN)
    }
}

impl Format for Deterministic {}
impl private::Sealed for Deterministic {}
impl FormatLayout for Deterministic {
    type FramedKeyId = KeyId;

    fn check(value: &[u8]) -> KmsAeadResult<KeyId> {
        check_tink_prefixed(
            value,
            "a synthetic IV",
            DeterministicAlgorithm::SYNTHETIC_IV_LEN,
        )
    }

    fn plaintext_len(value: &[u8]) -> usize {
        value
            .len()
            .saturating_sub(TINK_OUTPUT_PREFIX_LEN + DeterministicAlgorithm::SYNTHETIC_IV_LEN)
    }
}

/// The key id of `value`, checked to be Tink's output prefix followed by at least `min_len`
/// bytes, the `shortest` value of the format.
fn check_tink_prefixed(value: &[u8], shortest: &str, min_len: usize) -> KmsAeadResult<KeyId> {
    match split_tink_output_prefix(value) {
        Some((key_id, after_prefix)) if after_prefix.len() >= min_len => Ok(key_id),
        _ => Err(KmsAeadEncryptionError::create(
            "INVALID_CIPHER_TEXT_FORMAT",
            &format!(
                "A value of {} bytes is not Tink's output prefix followed by at least {shortest}",
                value.len()
            ),
        )),
    }
}
