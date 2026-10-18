//! The layouts written by kms-aead 0.29 and earlier, read with the deprecated `legacy-formats`
//! feature, and the upgrades that rewrite them in Tink's format.

use std::sync::atomic::{AtomicBool, Ordering};

use super::envelope::{separate_envelope, EnvelopeLayout};
use super::{unwrap_key, wrap_key};
use crate::errors::{KmsAeadEncryptionError, KmsAeadLegacyFormat};
use crate::providers::kms_key_version::read_key_version;
use crate::providers::KmsKeyVersion;
use crate::types::checked_key_bytes;
use crate::{
    AeadBackend, CipherText, CipherTextWithEncryptedKey, EncryptedDataEncryptionKey, KekProvider,
    KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult,
};

/// A wrapped key as 0.29 and earlier stored it: the KMS's wrapped key, with the key version beside
/// it rather than in it.
struct LegacyWrappedKey<'w> {
    #[cfg_attr(
        not(feature = "azure-kms-encryption-base"),
        expect(
            dead_code,
            reason = "only the Azure provider's bytes carry the key version"
        )
    )]
    key_version: Option<KmsKeyVersion>,
    wrapped: &'w [u8],
}

impl<'w> LegacyWrappedKey<'w> {
    /// `wrapped` with the key version whose bytes are `key_version`: none when they are empty, as
    /// for `k = 0`.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_VERSION` when the key version is not ASCII alphanumeric.
    fn new(key_version: &[u8], wrapped: &'w [u8]) -> KmsAeadResult<Self> {
        let key_version = match key_version {
            [] => None,
            key_version => Some(read_key_version(key_version)?),
        };
        Ok(Self {
            key_version,
            wrapped,
        })
    }

    /// The wrapped key as the provider of `kek` takes it since 0.30: the Azure provider's bytes
    /// carry the key version, and every other provider's are the KMS's wrapped key.
    fn into_encrypted_key(self, kek: &KekProvider) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match kek {
            #[cfg(feature = "azure-kms-encryption-base")]
            KekProvider::Azure => {
                let key_version = self.key_version.ok_or_else(|| {
                    KmsAeadEncryptionError::create(
                        "AZURE_KEY_VERSION_MISSING",
                        "The encrypted data encryption key records no Azure Key Vault key version",
                    )
                })?;
                let wrapped_key = super::azure::AzureWrappedKey {
                    key_version,
                    wrapped: self.wrapped,
                };
                wrapped_key.to_bytes().map(EncryptedDataEncryptionKey::new)
            }
            _ => Ok(EncryptedDataEncryptionKey::new(self.wrapped.to_vec())),
        }
    }
}

/// The cipher text and the wrapped key of the bytes of a value in any layout, the wrapped key in the bytes the
/// provider of `kek` takes:
///
/// - Tink's KMS envelope, as [`separate`](CipherTextWithEncryptedKey::separate) reads it;
/// - the envelope layout v1 of 0.29, `[0x01][k: u8][key version: k][w: u16 BE]
///   [wrapped key: w][cipher text]`;
/// - the length prefix written up to 0.28.1, `[w: u64 BE][wrapped key: w][cipher text]`.
///
/// # Errors
///
/// The errors of [`separate`](CipherTextWithEncryptedKey::separate) but `LEGACY_FORMAT`,
/// `INVALID_CIPHER_TEXT_FORMAT` on a length past the end of a legacy value, and
/// `INVALID_KEY_VERSION` on a key version that is not ASCII alphanumeric.
pub(crate) fn separate_any_layout(
    value: &[u8],
    kek: &KekProvider,
) -> KmsAeadResult<(CipherText, EncryptedDataEncryptionKey)> {
    let layout = EnvelopeLayout::try_from(value)?;
    let fields = match layout {
        EnvelopeLayout::Tink => return separate_envelope(value),
        EnvelopeLayout::V1 => value.split_first().and_then(|(_, header)| {
            let (key_version, rest) = super::split_key_version_field(header)?;
            let (wrapped_len, rest) = rest.split_first_chunk::<2>()?;
            let wrapped_len = usize::from(u16::from_be_bytes(*wrapped_len));
            let (wrapped, cipher_text) = rest.split_at_checked(wrapped_len)?;
            Some((key_version, wrapped, cipher_text))
        }),
        EnvelopeLayout::LengthPrefixed => {
            value
                .split_first_chunk::<8>()
                .and_then(|(wrapped_len, rest)| {
                    let wrapped_len = usize::try_from(u64::from_be_bytes(*wrapped_len)).ok()?;
                    let (wrapped, cipher_text) = rest.split_at_checked(wrapped_len)?;
                    Some((&[][..], wrapped, cipher_text))
                })
        }
    };
    let (key_version, wrapped, cipher_text) = fields.ok_or_else(|| {
        KmsAeadEncryptionError::create(
            "INVALID_CIPHER_TEXT_FORMAT",
            "A length in the cipher text header runs past the end of the buffer",
        )
    })?;
    let wrapped_key = LegacyWrappedKey::new(key_version, wrapped)?;
    match layout {
        EnvelopeLayout::V1 => warn_once(KmsAeadLegacyFormat::EnvelopeV1),
        _ => warn_once(KmsAeadLegacyFormat::LengthPrefixedEnvelope),
    }
    Ok((
        CipherText(cipher_text.to_vec()),
        wrapped_key.into_encrypted_key(kek)?,
    ))
}

/// The wrapped key of stored bytes in the encrypted key layout of 0.29,
/// `[0xFF][0x01][k: u8][key version: k][wrapped key]`, from `after_header`, the bytes after
/// `[0xFF][0x01]`, as the bytes the provider of `kek` takes.
///
/// # Errors
///
/// `INVALID_ENCRYPTED_KEY_FORMAT` when the key version runs past the end, and
/// `INVALID_KEY_VERSION` on a key version that is not ASCII alphanumeric.
pub(super) fn encrypted_key_from_layout_v1(
    after_header: &[u8],
    kek: &KekProvider,
) -> KmsAeadResult<EncryptedDataEncryptionKey> {
    let (key_version, wrapped) = super::split_key_version_field(after_header).ok_or_else(|| {
        KmsAeadEncryptionError::create(
            "INVALID_ENCRYPTED_KEY_FORMAT",
            "The key version length runs past the end of the encrypted key",
        )
    })?;
    LegacyWrappedKey::new(key_version, wrapped)?.into_encrypted_key(kek)
}

/// Logs one `WARN` event the first time a process reads a value in `format`.
pub(super) fn warn_once(format: KmsAeadLegacyFormat) {
    static ENVELOPE_V1: AtomicBool = AtomicBool::new(false);
    static LENGTH_PREFIXED_ENVELOPE: AtomicBool = AtomicBool::new(false);
    static ENCRYPTED_KEY_V1: AtomicBool = AtomicBool::new(false);
    static RAW_WRAPPED_KEY: AtomicBool = AtomicBool::new(false);
    let warned = match format {
        KmsAeadLegacyFormat::EnvelopeV1 => &ENVELOPE_V1,
        KmsAeadLegacyFormat::LengthPrefixedEnvelope => &LENGTH_PREFIXED_ENVELOPE,
        KmsAeadLegacyFormat::EncryptedKeyV1 => &ENCRYPTED_KEY_V1,
        KmsAeadLegacyFormat::RawWrappedKey => &RAW_WRAPPED_KEY,
    };
    if !warned.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            ?format,
            "Read a value in a layout written by kms-aead 0.29 or earlier. Reading it is \
             deprecated and will be removed in a later breaking release: rewrite stored values \
             with KmsAeadEnvelope::upgrade_legacy_value and upgrade_legacy_encrypted_key"
        );
    }
}

/// The upgrades of stored values to Tink's format.
impl<P, B> KmsAeadEnvelope<P, B>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    /// `value`, sealed under `aad`, in Tink's KMS envelope format, or `None` when it already is
    /// in it, so that a sweep over stored rows writes only the ones that change.
    ///
    /// It unwraps the value's DEK with the provider, never through the DEK cache, since only the
    /// key tells a value of 0.30 from one of a 32-bit target before 0.24.0, and for a value in a
    /// legacy layout opens it under the envelope's algorithm and `aad` and wraps the DEK again as
    /// Tink does, a second KMS call. The opening only verifies the value: the AEAD bytes stay as
    /// they are, since every release seals them in Tink's layout, and a value that does not open
    /// is never rewritten with the Tink key type of the envelope's algorithm. The envelope's
    /// algorithm is the one the value was sealed with, as for
    /// [`decrypt_value`](Self::decrypt_value).
    ///
    /// # Errors
    ///
    /// The errors of [`decrypt_value`](Self::decrypt_value), among them `DECRYPT` when the value
    /// was sealed under another algorithm or another AAD, and the provider's errors for the new
    /// wrap.
    #[deprecated(
        since = "0.30.0",
        note = "reading the layouts written by 0.29 and earlier will be removed in a later breaking release"
    )]
    pub async fn upgrade_legacy_value(
        &self,
        aad: &[u8],
        value: &CipherTextWithEncryptedKey,
    ) -> KmsAeadResult<Option<CipherTextWithEncryptedKey>> {
        let layout = EnvelopeLayout::try_from(value.0.as_slice())?;
        let (cipher_text, encrypted_dek) =
            separate_any_layout(&value.0, self.provider.kek().provider())?;
        let (key, legacy_key) = unwrap_key(&encrypted_dek, &self.provider).await?;
        if legacy_key.is_none() && layout == EnvelopeLayout::Tink {
            return Ok(None);
        }
        // A raw key records no algorithm, and every algorithm with its length takes it, so only
        // opening the value shows that the Tink key type written below is the right one.
        self.cipher.decrypt_value(aad, &cipher_text, &key)?;
        let upgraded_dek = match legacy_key {
            Some(_) => wrap_key(&key, self.algorithm().into(), &self.provider).await?,
            None => encrypted_dek,
        };
        CipherTextWithEncryptedKey::join(&cipher_text, &upgraded_dek).map(Some)
    }

    /// `encrypted`, an encrypted key stored by 0.29 or earlier, wrapped again as Tink wraps a
    /// key, or `None` when it already is, so that a sweep writes only the rows that change. The
    /// stored bytes of 0.29's `to_bytes` and `to_hex_string` read as they are, for every
    /// built-in provider.
    ///
    /// It unwraps the key with the provider, never through the DEK cache, and for a key in a
    /// legacy layout wraps it again, a second KMS call. The envelope's algorithm is the one the
    /// key was made for: with no value to open, the upgrade cannot check it, and records the
    /// envelope's algorithm in the Tink key type for any key of its length. Where the values
    /// sealed under the key are at hand, [`upgrade_legacy_value`](Self::upgrade_legacy_value)
    /// opens them and refuses a key of another algorithm.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the unwrapped key is neither a raw key
    /// nor a serialised Tink key, `INVALID_ENCRYPTED_KEY_FORMAT` and `INVALID_KEY_VERSION` on
    /// 0.29's encrypted key layout that cannot be read, and `INVALID_KEY_LENGTH` when the key
    /// does not fit the envelope's algorithm.
    #[deprecated(
        since = "0.30.0",
        note = "reading the layouts written by 0.29 and earlier will be removed in a later breaking release"
    )]
    pub async fn upgrade_legacy_encrypted_key(
        &self,
        encrypted: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Option<EncryptedDataEncryptionKey>> {
        let (key, legacy) = unwrap_key(encrypted, &self.provider).await?;
        if legacy.is_none() {
            return Ok(None);
        }
        let algorithm = self.algorithm();
        checked_key_bytes(&key, algorithm, algorithm.key_len())?;
        wrap_key(&key, algorithm.into(), &self.provider)
            .await
            .map(Some)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::errors::KmsAeadError;
    use crate::ValueStruct;

    const SEALED: &[u8] = b"sealed";
    const WRAPPED: &[u8] = b"wrapped";
    /// `sealed` and the wrapped key `wrapped` with the key version `18`, as 0.29's `join` wrote
    /// them in envelope layout v1.
    const ENVELOPE_V1: &str = "010231380007777261707065647365616c6564";
    /// The same without a key version.
    const ENVELOPE_V1_WITHOUT_KEY_VERSION: &str = "01000007777261707065647365616c6564";
    /// The same as 0.28.1 wrote it, with an 8-byte length.
    const LENGTH_PREFIXED_ENVELOPE: &str = "0000000000000007777261707065647365616c6564";
    /// `wrapped` with the key version `18`, as 0.29's `to_bytes` wrote it.
    const ENCRYPTED_KEY_V1: &str = "ff0102313877726170706564";

    #[test]
    fn values_of_0_29_and_earlier_separate_into_the_wrapped_key() -> KmsAeadResult<()> {
        for stored in [
            ENVELOPE_V1,
            ENVELOPE_V1_WITHOUT_KEY_VERSION,
            LENGTH_PREFIXED_ENVELOPE,
        ] {
            let value = hex::decode(stored).unwrap();

            let (cipher_text, encrypted_dek) = separate_any_layout(&value, &KekProvider::Gcp)?;

            assert_eq!(cipher_text, CipherText(SEALED.to_vec()), "{stored}");
            assert_eq!(*encrypted_dek.value(), WRAPPED, "{stored}");
        }
        let encrypted_dek = encrypted_key_from_layout_v1(
            &hex::decode(ENCRYPTED_KEY_V1).unwrap()[2..],
            &KekProvider::Gcp,
        )?;
        assert_eq!(*encrypted_dek.value(), WRAPPED);
        Ok(())
    }

    #[cfg(feature = "azure-kms-encryption-base")]
    #[test]
    fn the_azure_provider_takes_the_key_version_in_its_bytes() -> KmsAeadResult<()> {
        let azure_bytes = [&[0x01, 0x02, b'1', b'8'][..], WRAPPED].concat();
        let value = hex::decode(ENVELOPE_V1).unwrap();

        let (_, from_envelope) = separate_any_layout(&value, &KekProvider::Azure)?;
        let from_encrypted_key = encrypted_key_from_layout_v1(
            &hex::decode(ENCRYPTED_KEY_V1).unwrap()[2..],
            &KekProvider::Azure,
        )?;
        let without_key_version = separate_any_layout(
            &hex::decode(ENVELOPE_V1_WITHOUT_KEY_VERSION).unwrap(),
            &KekProvider::Azure,
        );

        assert_eq!(*from_envelope.value(), azure_bytes);
        assert_eq!(*from_encrypted_key.value(), azure_bytes);
        assert!(
            matches!(&without_key_version, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "AZURE_KEY_VERSION_MISSING"),
            "{without_key_version:?}"
        );
        Ok(())
    }

    /// A crafted length allocates nothing: the reader cuts the buffer it was given.
    #[test]
    fn lengths_past_the_end_are_refused() {
        let truncated: [&[u8]; 8] = [
            &[0x01],
            &[0x01, 0x02, b'1'],
            &[0x01, 0x00, 0x00],
            &[0x01, 0x00, 0x00, 0x05, 0xAA],
            &[0x00, 0x00, 0x00, 0x00],
            &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            &[
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0xE8, 0x01, 0x02, 0x03,
            ],
            &[0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xAA],
        ];
        for value in truncated {
            let result = separate_any_layout(value, &KekProvider::Gcp);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                "{value:02x?}: {result:?}"
            );
        }
        let result = encrypted_key_from_layout_v1(&[0x05, b'1'], &KekProvider::Gcp);
        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_ENCRYPTED_KEY_FORMAT"),
            "{result:?}"
        );
    }

    #[test]
    fn a_key_version_outside_ascii_alphanumerics_is_refused_without_echoing_it() {
        let stored_version = b"marker/18";
        let mut value = vec![0x01, 0x09];
        value.extend_from_slice(stored_version);
        value.extend_from_slice(&[0x00, 0x01, 0xAA, 0xBB]);

        let result = separate_any_layout(&value, &KekProvider::Gcp);

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_VERSION"
                    && !format!("{error} {error:?}").contains("marker")),
            "{result:?}"
        );
    }

    proptest! {
        #[test]
        fn reading_returns_on_arbitrary_bytes(
            first in prop_oneof![Just(0x00u8), Just(0x01), Just(0xFF), any::<u8>()],
            rest in prop::collection::vec(any::<u8>(), 0..64),
        ) {
            let bytes = [&[first][..], &rest].concat();
            let _ = separate_any_layout(&bytes, &KekProvider::Azure);
            let _ = encrypted_key_from_layout_v1(&bytes, &KekProvider::Azure);
        }
    }

    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    mod upgrade {
        use super::*;
        use crate::formats::TinkKeyType;
        use crate::test_provider::{
            wrapped_by_test_provider, CountingKmsProvider, TestBackend, TestKmsProvider,
        };
        use crate::{AeadAlgorithm, KekRef, KmsAeadEnvelopeOptions};

        const KEY: [u8; 32] = [0x42; 32];

        #[tokio::test]
        #[expect(deprecated, reason = "tests the deprecated upgrade")]
        async fn encrypted_keys_of_0_29_and_earlier_upgrade_to_tink_keys() -> KmsAeadResult<()> {
            let envelope = KmsAeadEnvelope::<_, TestBackend>::with_options(
                CountingKmsProvider::with_kek(
                    TestKmsProvider::Working,
                    KekRef::new(
                        KekProvider::Gcp,
                        "projects/p/locations/l/keyRings/r/cryptoKeys/k",
                    ),
                ),
                KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm),
            )?;
            let tink_key = wrapped_by_test_provider(TinkKeyType::AesGcm, &KEY);
            let stored = [
                // As 0.29's `to_bytes` stored it, and as 0.28.1 stored the bare wrapped key.
                [&[0xFF, 0x01, 0x00][..], &KEY].concat(),
                KEY.to_vec(),
            ];

            for stored in stored {
                let upgraded = envelope
                    .upgrade_legacy_encrypted_key(&EncryptedDataEncryptionKey::new(stored))
                    .await?;
                assert_eq!(upgraded.as_ref(), Some(&tink_key));
            }
            assert_eq!(
                envelope.upgrade_legacy_encrypted_key(&tink_key).await?,
                None
            );
            assert_eq!(envelope.provider().wraps(), 2);
            Ok(())
        }

        #[tokio::test]
        #[expect(deprecated, reason = "tests the deprecated upgrade")]
        async fn a_key_of_another_length_than_the_algorithm_is_not_upgraded() -> KmsAeadResult<()> {
            let envelope = KmsAeadEnvelope::<_, TestBackend>::with_options(
                CountingKmsProvider::new(TestKmsProvider::Working, "orders"),
                KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes128Gcm),
            )?;

            let result = envelope
                .upgrade_legacy_encrypted_key(&EncryptedDataEncryptionKey::new(KEY.to_vec()))
                .await;

            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
                "{result:?}"
            );
            assert_eq!(envelope.provider().wraps(), 0);
            Ok(())
        }
    }
}
