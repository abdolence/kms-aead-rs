//! The encodings of a keyset export. An encoding names the reader that takes the bytes of a
//! [`EncryptedKeyset`](crate::EncryptedKeyset): [`BigQuery`], for the `first_level_keyset` of
//! `KEYS.KEYSET_CHAIN`, or [`Tink`], for Tink's keyset readers. The export checks the keyring's
//! versions and its KEK against the rules of that reader, and the type parameter of the keyset it
//! returns records which reader it was made for.
//!
//! The public items here are the sealed [`KeysetEncoding`] trait and its two markers.

use kms_aead::formats::TinkKeyType;
use kms_aead::{AeadAlgorithm, DeterministicAlgorithm, KekProvider, KekRef};

use crate::{Interop, KeyAlgorithm};

/// The encoding of a [`EncryptedKeyset`](crate::EncryptedKeyset), which decides the reader of its
/// bytes: [`BigQuery`] or [`Tink`].
///
/// Sealed: only the encodings of this crate implement it. It has no methods, so code generic over
/// the encoding names this trait and nothing else.
pub trait KeysetEncoding: private::Sealed {}

mod private {
    /// Seals [`KeysetEncoding`](super::KeysetEncoding). Its crate-private supertrait carries the
    /// encoding's rules, which no other crate can read or implement.
    #[expect(
        private_bounds,
        reason = "a crate-private supertrait is what keeps the encoding's rules unreadable \
                  outside the crate"
    )]
    pub trait Sealed: super::EncodingRules {}
}

/// The rules of a [`KeysetEncoding`].
pub(crate) trait EncodingRules {
    /// The rules as a value, which the check of a field's [`Interop`] shares.
    const ENCODING: Encoding;
}

/// The keyset of `export_bigquery_keyset`: the KMS ciphertext of the serialised `Keyset`, with no
/// associated data, which is the `first_level_keyset` of BigQuery's `KEYS.KEYSET_CHAIN`.
/// BigQuery decrypts it with Cloud KMS only and reads its AES-256-GCM and AES-SIV keys only.
pub enum BigQuery {}

/// The keyset of [`export_tink_keyset`](crate::Keyring::export_tink_keyset): Tink's
/// `EncryptedKeyset` message around the KMS ciphertext of the serialised `Keyset`, which Tink's
/// keyset readers take with the KMS client of the KEK's Tink key URI. Its keys are the ones every
/// Tink language reads in a keyset: AES-GCM, AES-GCM-SIV and AES-SIV.
pub enum Tink {}

impl KeysetEncoding for BigQuery {}
impl private::Sealed for BigQuery {}
impl EncodingRules for BigQuery {
    const ENCODING: Encoding = Encoding::BigQuery;
}

impl KeysetEncoding for Tink {}
impl private::Sealed for Tink {}
impl EncodingRules for Tink {
    const ENCODING: Encoding = Encoding::Tink;
}

/// A [`KeysetEncoding`] as a value: the rules of the reader of a keyset, which also decide what a
/// field whose values that reader opens may be sealed under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// The rules of [`BigQuery`].
    BigQuery,
    /// The rules of [`Tink`].
    Tink,
}

impl Encoding {
    /// The reader of a field whose values this encoding's keyset reads.
    pub(crate) fn interop(self) -> Interop {
        match self {
            Encoding::BigQuery => Interop::BigQuery,
            Encoding::Tink => Interop::Tink,
        }
    }

    /// The Tink key type the reader reads `algorithm`'s keys as, or `None` for an algorithm it
    /// does not implement.
    pub(crate) fn key_type(self, algorithm: KeyAlgorithm) -> Option<TinkKeyType> {
        match algorithm {
            KeyAlgorithm::Randomized(AeadAlgorithm::Aes256Gcm) => Some(TinkKeyType::AesGcm),
            KeyAlgorithm::Randomized(
                algorithm @ (AeadAlgorithm::Aes128Gcm | AeadAlgorithm::Aes256GcmSiv),
            ) if self == Encoding::Tink => Some(algorithm.into()),
            KeyAlgorithm::Deterministic(DeterministicAlgorithm::Aes256Siv) => {
                Some(TinkKeyType::AesSiv)
            }
            KeyAlgorithm::Randomized(_)
            | KeyAlgorithm::Deterministic(_)
            | KeyAlgorithm::Beacon(_) => None,
        }
    }

    /// Tink's key URI of `kek`, or `None` for a KEK the reader does not decrypt with.
    pub(crate) fn key_uri(self, kek: &KekRef) -> Option<String> {
        let key_uri = kek.tink_key_uri();
        match self {
            Encoding::BigQuery => key_uri.filter(|_| *kek.provider() == KekProvider::Gcp),
            Encoding::Tink => key_uri,
        }
    }
}
