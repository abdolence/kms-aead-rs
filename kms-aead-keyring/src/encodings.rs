//! The encodings of a keyset export. An encoding names the reader that takes the bytes of a
//! [`EncryptedKeyset`](crate::EncryptedKeyset): [`BigQuery`], for the `first_level_keyset` of
//! `KEYS.KEYSET_CHAIN`, or [`Tink`], for Tink's keyset readers. The export checks the keyring's
//! versions and its KEK against the rules of that reader, and the type parameter of the keyset it
//! returns records which reader it was made for.
//!
//! The public items here are the sealed [`KeysetEncoding`] trait and its two markers.

use crate::Interop;

/// The encoding of a [`EncryptedKeyset`](crate::EncryptedKeyset), which decides the reader of its
/// bytes: [`BigQuery`] or [`Tink`].
///
/// Sealed: only the encodings of this crate implement it. It has no methods, so code generic over
/// the encoding names this trait and nothing else.
pub trait KeysetEncoding: private::Sealed {}

mod private {
    use crate::Interop;

    /// Seals [`KeysetEncoding`](super::KeysetEncoding), and carries the reader whose rules the
    /// export checks the keyring against.
    pub trait Sealed {
        /// The reader of the keyset's bytes, whose rules a field read by it shares.
        const INTEROP: Interop;
    }
}

/// The keyset of `export_bigquery_keyset`: the KMS ciphertext of the serialised `Keyset`, with no
/// associated data, which is the `first_level_keyset` of BigQuery's `KEYS.KEYSET_CHAIN`.
/// BigQuery decrypts it with Cloud KMS only and reads its AES-256-GCM and AES-SIV keys only.
#[derive(Debug, Clone, Copy)]
pub enum BigQuery {}

/// The keyset of [`export_tink_keyset`](crate::KeyringAdmin::export_tink_keyset): Tink's
/// `EncryptedKeyset` message around the KMS ciphertext of the serialised `Keyset`, which Tink's
/// keyset readers take with the KMS client of the KEK's Tink key URI. Its keys are the ones every
/// Tink language reads in a keyset: AES-GCM, AES-GCM-SIV and AES-SIV.
#[derive(Debug, Clone, Copy)]
pub enum Tink {}

impl KeysetEncoding for BigQuery {}
impl private::Sealed for BigQuery {
    const INTEROP: Interop = Interop::BigQuery;
}

impl KeysetEncoding for Tink {}
impl private::Sealed for Tink {
    const INTEROP: Interop = Interop::Tink;
}
