use crate::errors::{
    KmsAeadEncryptionError, KmsAeadError, KmsAeadLegacyFormat, KmsAeadLegacyFormatError,
};

use crate::formats::{Bare, Envelope};
use crate::{Encrypted, EncryptedDataEncryptionKey, KmsAeadResult};

/// The layout of a stored [`Envelope`] value, by its first bytes, whether or not this build reads
/// it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeLayout {
    /// `[w: u32 BE]` with `w` from 1, so the first byte is `0x00` and the first four are not
    /// all zero. The 4-byte length prefix of 32-bit targets before 0.24.0 has the same framing;
    /// only the decrypted key tells it apart.
    Tink,
    /// The envelope layout v1 of 0.29: `[0x01][k: u8][key version: k][w: u16 BE][encrypted DEK]`.
    V1,
    /// The 8-byte length prefix written up to 0.28.1. No encrypted DEK reaches 2^32 bytes, so its
    /// first four bytes are zero.
    LengthPrefixed,
}

impl TryFrom<&[u8]> for EnvelopeLayout {
    type Error = KmsAeadError;

    fn try_from(value: &[u8]) -> KmsAeadResult<Self> {
        match value {
            [0x00, 0x00, 0x00, 0x00, ..] => Ok(EnvelopeLayout::LengthPrefixed),
            [0x00, ..] => Ok(EnvelopeLayout::Tink),
            [0x01, ..] => Ok(EnvelopeLayout::V1),
            [_, ..] => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_CIPHER_TEXT_LAYOUT",
                "The cipher text starts with a byte that starts no layout",
            )),
            [] => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_CIPHER_TEXT_LAYOUT",
                "Empty cipher text has no layout",
            )),
        }
    }
}

/// The most bytes of an encrypted DEK, `MAX_LENGTH_ENCRYPTED_DEK` in Tink.
const MAX_ENCRYPTED_DEK_LEN: u32 = 4096;

/// Tink's KMS envelope format, as Tink's `KmsEnvelopeAead` writes and reads it:
///
/// ```text
/// [w: u32 BE][encrypted DEK: w bytes][nonce: 12][ciphertext][tag: 16]
/// ```
///
/// The encrypted DEK is the provider's [`EncryptedDataEncryptionKey`]: the KMS ciphertext of the
/// DEK as Tink serialises it, or of the raw DEK for Azure, 1 to 4,096 bytes, the sizes every Tink
/// implementation reads. The rest is the [`Bare`] value the DEK opens. The layout records neither
/// the algorithm nor the KMS key version, so the writer and the reader of a value are configured
/// with the same algorithm.
impl<T> Encrypted<T, Envelope> {
    /// `bare` and the encrypted DEK that opens it in Tink's KMS envelope format, which
    /// [`separate`](Self::separate) reads back.
    ///
    /// # Errors
    ///
    /// `INVALID_CIPHER_TEXT_FORMAT` when the encrypted DEK is empty or longer than 4,096 bytes,
    /// which Tink does not read.
    pub fn join(
        bare: &Encrypted<T, Bare>,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Self> {
        let mut bytes = envelope_header(encrypted_dek)?;
        bytes.extend_from_slice(bare.value());
        Self::try_from(bytes)
    }

    /// The bare value and the encrypted DEK of a value in Tink's KMS envelope format.
    ///
    /// # Errors
    ///
    /// [`KmsAeadError::LegacyFormat`] with [`KmsAeadLegacyFormat::EnvelopeV1`] or
    /// [`KmsAeadLegacyFormat::LengthPrefixedEnvelope`] on the envelope layouts of 0.29 and
    /// earlier, which a value holds only with the deprecated `legacy-formats` feature, and which
    /// `KmsAeadEnvelope::upgrade_legacy_value` rewrites. A value in Tink's format always
    /// separates.
    pub fn separate(&self) -> KmsAeadResult<(Encrypted<T, Bare>, EncryptedDataEncryptionKey)> {
        let (encrypted_dek_bytes, bare) = split_envelope(self.value())?;
        Ok((
            Encrypted::try_from(bare.to_vec())?,
            EncryptedDataEncryptionKey::new(encrypted_dek_bytes.to_vec()),
        ))
    }
}

/// `[w: u32 BE][encrypted DEK: w]`, the start of every value in Tink's KMS envelope format sealed
/// under the DEK that `encrypted_dek` holds.
///
/// # Errors
///
/// `INVALID_CIPHER_TEXT_FORMAT` when the encrypted DEK is empty or longer than 4,096 bytes, which
/// Tink does not read.
pub(crate) fn envelope_header(
    encrypted_dek: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<Vec<u8>> {
    let encrypted_dek_bytes = encrypted_dek.value();
    let encrypted_dek_len = u32::try_from(encrypted_dek_bytes.len())
        .ok()
        .filter(|len| (1..=MAX_ENCRYPTED_DEK_LEN).contains(len))
        .ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                &format!(
                    "An encrypted DEK of {} bytes is not 1 to {} bytes long, the sizes Tink reads",
                    encrypted_dek_bytes.len(),
                    MAX_ENCRYPTED_DEK_LEN
                ),
            )
        })?;
    let mut header = Vec::with_capacity(4 + encrypted_dek_bytes.len());
    header.extend_from_slice(&encrypted_dek_len.to_be_bytes());
    header.extend_from_slice(encrypted_dek_bytes);
    Ok(header)
}

/// The encrypted DEK and the bare value of `value` in Tink's KMS envelope format, borrowed from
/// it.
///
/// # Errors
///
/// `UNKNOWN_CIPHER_TEXT_LAYOUT` on an empty value or a first byte that starts no layout,
/// `INVALID_CIPHER_TEXT_FORMAT` on an encrypted DEK length outside 1 to 4,096 bytes or past the
/// end of the value, and [`KmsAeadError::LegacyFormat`] on the layouts of 0.29 and earlier.
pub(crate) fn split_envelope(value: &[u8]) -> KmsAeadResult<(&[u8], &[u8])> {
    match EnvelopeLayout::try_from(value)? {
        EnvelopeLayout::Tink => {}
        EnvelopeLayout::V1 => {
            return Err(KmsAeadLegacyFormatError::create(
                KmsAeadLegacyFormat::EnvelopeV1,
            ))
        }
        EnvelopeLayout::LengthPrefixed => {
            return Err(KmsAeadLegacyFormatError::create(
                KmsAeadLegacyFormat::LengthPrefixedEnvelope,
            ))
        }
    }
    let invalid = || {
        KmsAeadEncryptionError::create(
            "INVALID_CIPHER_TEXT_FORMAT",
            &format!(
                "The encrypted DEK length of a cipher text of {} bytes is not 1 to {} bytes \
                 within it",
                value.len(),
                MAX_ENCRYPTED_DEK_LEN
            ),
        )
    };
    let (encrypted_dek_len, rest) = value.split_first_chunk::<4>().ok_or_else(invalid)?;
    let encrypted_dek_len = u32::from_be_bytes(*encrypted_dek_len);
    if encrypted_dek_len > MAX_ENCRYPTED_DEK_LEN {
        return Err(invalid());
    }
    let encrypted_dek_len = usize::try_from(encrypted_dek_len).map_err(|_| invalid())?;
    rest.split_at_checked(encrypted_dek_len).ok_or_else(invalid)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::test_provider::renderings;

    const SEALED: &[u8] = b"sealed";
    const ENCRYPTED_DEK: &[u8] = b"wrapped";
    /// The shortest bare value: a nonce and a tag around an empty plaintext.
    const BARE: [u8; 28] = [0xAB; 28];

    /// Tink 1.16.1 for Python, `KmsEnvelopeAead(AES256_GCM, …)` on a Cloud KMS key: a 116-byte
    /// encrypted DEK and the 21 bytes of `sealed by Tink 1.16.1` with a nonce and a tag.
    const TINK_ENVELOPE: &str = "000000740a25006b8d8e5ab00c118c3b606a67e34d0f7137963ae14dae0cc70cfbb9fe97e86871e0166ff8124b00eaf42f6318880810c8a2cdb5f89e59b5f6d45b8ca2dc3533159eee2360b087938fdea20aa6971e65f4d94d5879fc9b793564402be5a1918a28adde7568d1a26d797f62c33458ac7839e2fba14afad173bcffd7fbf750cd2ab4d3cddfdc2e8d3051677d0aa452474215f065eb815d35760a533c66f96460b129fd28";

    #[test]
    fn tink_envelope_is_pinned() -> KmsAeadResult<()> {
        let bare = Encrypted::<String, Bare>::try_from(BARE.to_vec())?;
        let encrypted_dek = EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec());

        let envelope = Encrypted::<String, Envelope>::join(&bare, &encrypted_dek)?;

        assert_eq!(
            envelope.to_hex_string(),
            format!("0000000777726170706564{}", hex::encode(BARE))
        );
        let (separated_bare, separated_encrypted_dek) = envelope.separate()?;
        assert_eq!(separated_bare.value(), bare.value());
        assert_eq!(separated_encrypted_dek, encrypted_dek);
        Ok(())
    }

    #[test]
    fn a_tink_envelope_separates_into_the_encrypted_dek_and_the_payload() -> KmsAeadResult<()> {
        let envelope =
            Encrypted::<String, Envelope>::try_from(hex::decode(TINK_ENVELOPE).unwrap())?;

        let (bare, encrypted_dek) = envelope.separate()?;

        assert_eq!(encrypted_dek.value().len(), 116);
        assert_eq!(&encrypted_dek.value()[..4], [0x0a, 0x25, 0x00, 0x6b]);
        assert_eq!(bare.value().len(), 12 + 21 + 16);
        Ok(())
    }

    proptest! {
        #[test]
        fn join_and_separate_round_trip(
            bare in prop::collection::vec(any::<u8>(), 28..256),
            encrypted_dek_bytes in prop::collection::vec(any::<u8>(), 1..=4096),
        ) {
            let bare = Encrypted::<String, Bare>::try_from(bare).unwrap();
            let encrypted_dek = EncryptedDataEncryptionKey::new(encrypted_dek_bytes);

            let envelope = Encrypted::<String, Envelope>::join(&bare, &encrypted_dek).unwrap();
            let (separated_bare, separated_encrypted_dek) = envelope.separate().unwrap();

            prop_assert_eq!(separated_bare.value(), bare.value());
            prop_assert_eq!(separated_encrypted_dek, encrypted_dek);
        }

        #[test]
        fn separate_returns_on_arbitrary_bytes(bytes in prop::collection::vec(any::<u8>(), 0..64)) {
            let _ = Encrypted::<String, Envelope>::try_from(bytes).and_then(|value| value.separate());
        }
    }

    #[test]
    fn an_encrypted_dek_tink_does_not_read_is_refused_on_write() -> KmsAeadResult<()> {
        let bare = Encrypted::<String, Bare>::try_from(BARE.to_vec())?;
        for (len, accepted) in [(0, false), (1, true), (4096, true), (4097, false)] {
            let result = Encrypted::<String, Envelope>::join(
                &bare,
                &EncryptedDataEncryptionKey::new(vec![0xAA; len]),
            );
            assert_eq!(result.is_ok(), accepted, "{len} bytes: {result:?}");
            if !accepted {
                assert!(
                    matches!(&result, Err(KmsAeadError::EncryptionError(error))
                        if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                    "{result:?}"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn an_encrypted_dek_length_tink_does_not_read_is_refused() {
        let envelopes: [&[u8]; 4] = [
            &[0x00],
            &[0x00, 0x00, 0x05],
            &[0x00, 0x00, 0x00, 0x05, 0xAA],
            &[0x00, 0x00, 0x10, 0x01, 0xAA],
        ];
        for envelope in envelopes {
            let result = Encrypted::<String, Envelope>::try_from(envelope.to_vec());
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                "{envelope:02x?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_first_byte_that_starts_no_layout_is_refused() {
        let empty = Encrypted::<String, Envelope>::try_from(Vec::new());
        assert!(
            matches!(&empty, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "UNKNOWN_CIPHER_TEXT_LAYOUT"),
            "{empty:?}"
        );
        for first in 0x02..=0xFF {
            let result = Encrypted::<String, Envelope>::try_from(vec![first; 64]);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "UNKNOWN_CIPHER_TEXT_LAYOUT"),
                "{first:#04x}: {result:?}"
            );
        }
    }

    /// Without `legacy-formats` a value in these layouts is refused when it is read, and with it
    /// the value is read and refused by `separate`.
    #[test]
    fn separate_refuses_the_layouts_of_0_29_and_earlier() {
        let envelopes = [
            (
                [
                    &hex::decode("01023138000777726170706564").unwrap()[..],
                    &BARE,
                ]
                .concat(),
                KmsAeadLegacyFormat::EnvelopeV1,
            ),
            (
                [&[0x00; 7][..], &[0x07], ENCRYPTED_DEK, &BARE].concat(),
                KmsAeadLegacyFormat::LengthPrefixedEnvelope,
            ),
        ];
        for (envelope, format) in envelopes {
            let result = Encrypted::<String, Envelope>::try_from(envelope)
                .and_then(|value| value.separate());
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error)) if error.format == format),
                "{format:?}: {result:?}"
            );
        }
    }

    #[test]
    fn read_errors_echo_no_stored_bytes() {
        /// The first byte of a value stored in plain text, which a read error must not echo:
        /// for a one-character value such as `y` or `n`, it is the whole value.
        const PLAIN_TEXT_BYTE: u8 = b'~';

        let errors = [
            vec![PLAIN_TEXT_BYTE, 0x00],
            [&[0x00, 0x00, 0x00, 0x7E][..], SEALED].concat(),
        ]
        .map(Encrypted::<String, Envelope>::try_from);
        for error in errors {
            let text = format!("{error:?}");
            for stored in [&[PLAIN_TEXT_BYTE][..], SEALED] {
                for rendering in renderings(stored) {
                    assert!(!text.contains(&rendering), "{rendering:?} in {text}");
                }
            }
        }
    }
}
