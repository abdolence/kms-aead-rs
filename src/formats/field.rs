use super::TinkOutputPrefix;
use crate::errors::KmsAeadEncryptionError;
use crate::{AeadAlgorithm, CipherTextWithEncryptedKey, DeterministicAlgorithm, KmsAeadResult};

/// The format of an [`Encrypted`](crate::Encrypted) value, the byte layout its bytes are checked
/// against when they are read: [`Envelope`], [`Randomized`] or [`Deterministic`].
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
    /// Checks that `value` is framed as a value of the format. It reads the framing only: whether
    /// the bytes are authentic is known when they are decrypted.
    fn check(value: &[u8]) -> KmsAeadResult<()>;
}

/// Tink's KMS envelope, the bytes of a
/// [`CipherTextWithEncryptedKey`](crate::CipherTextWithEncryptedKey):
///
/// ```text
/// [w: u32 BE][wrapped DEK: w][nonce: 12][ciphertext][tag: 16]
/// ```
///
/// [`KmsAeadEnvelope::encrypt_field`](crate::KmsAeadEnvelope::encrypt_field) writes it. The
/// layouts written by 0.29 and earlier are not values of this format.
pub enum Envelope {}

/// A randomized value with Tink's output prefix of type TINK:
///
/// ```text
/// [0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]
/// ```
///
/// The layout of Tink's AEAD with a TINK-prefixed key, and of BigQuery's `AEAD.ENCRYPT` under
/// AES-256-GCM. kms-aead-keyring writes it.
pub enum Randomized {}

/// A deterministic value with Tink's output prefix of type TINK:
///
/// ```text
/// [0x01][key id: u32 BE][synthetic IV: 16][ciphertext]
/// ```
///
/// The layout of Tink's deterministic AEAD with a TINK-prefixed key, and of BigQuery's
/// `DETERMINISTIC_ENCRYPT`. kms-aead-keyring writes it. The format exists in every build, without
/// the `deterministic` feature too, so that such values pass through a process that does not
/// decrypt them.
pub enum Deterministic {}

impl Format for Envelope {}
impl private::Sealed for Envelope {}
impl FormatLayout for Envelope {
    fn check(value: &[u8]) -> KmsAeadResult<()> {
        let (_, cipher_text) = CipherTextWithEncryptedKey::split(value)?;
        if cipher_text.len() < AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "The cipher text of {} bytes after the wrapped key is too short to hold a \
                     nonce and a tag",
                    cipher_text.len()
                ),
            ));
        }
        Ok(())
    }
}

impl Format for Randomized {}
impl private::Sealed for Randomized {}
impl FormatLayout for Randomized {
    fn check(value: &[u8]) -> KmsAeadResult<()> {
        check_tink_prefixed(
            value,
            "a nonce and a tag",
            AeadAlgorithm::NONCE_LEN + AeadAlgorithm::TAG_LEN,
        )
    }
}

impl Format for Deterministic {}
impl private::Sealed for Deterministic {}
impl FormatLayout for Deterministic {
    fn check(value: &[u8]) -> KmsAeadResult<()> {
        check_tink_prefixed(
            value,
            "a synthetic IV",
            DeterministicAlgorithm::SYNTHETIC_IV_LEN,
        )
    }
}

/// Checks that `value` is Tink's output prefix followed by at least `min_len` bytes, the
/// `shortest` value of the format.
fn check_tink_prefixed(value: &[u8], shortest: &str, min_len: usize) -> KmsAeadResult<()> {
    match TinkOutputPrefix::split(value) {
        Some((_, after_prefix)) if after_prefix.len() >= min_len => Ok(()),
        _ => Err(KmsAeadEncryptionError::create(
            "INVALID_CIPHER_TEXT_FORMAT",
            &format!(
                "A value of {} bytes is not Tink's output prefix followed by at least {shortest}",
                value.len()
            ),
        )),
    }
}
