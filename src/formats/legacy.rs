//! The layouts written by kms-aead 0.29 and earlier, read with the deprecated `legacy-formats`
//! feature, and the upgrades that rewrite them in Tink's format.

use std::sync::atomic::{AtomicBool, Ordering};

use super::envelope::{split_envelope, EnvelopeLayout};
use super::{decrypt_dek, encrypt_dek, Envelope};
use crate::aead_cipher::AeadKeyBytesOps;
use crate::backends::AeadBackend;
use crate::errors::{KmsAeadEncryptionError, KmsAeadLegacyFormat};
use crate::metrics::Measurement;
use crate::providers::kek_version::read_kek_version;
use crate::providers::KekVersion;
use crate::types::checked_key_bytes;
use crate::{
    Encrypted, EncryptedDataEncryptionKey, KekProvider, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};

/// An encrypted DEK as 0.29 and earlier stored it: the KMS's encrypted DEK, with the key version
/// beside it rather than in it.
struct LegacyEncryptedDek<'w> {
    #[cfg_attr(
        not(feature = "azure-kms-encryption-base"),
        expect(
            dead_code,
            reason = "only the Azure provider's bytes carry the key version"
        )
    )]
    kek_version: Option<KekVersion>,
    encrypted_dek_bytes: &'w [u8],
}

impl<'w> LegacyEncryptedDek<'w> {
    /// `encrypted_dek_bytes` with the key version whose bytes are `kek_version`: none when they are
    /// empty, as for `k = 0`.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_VERSION` when the key version is not ASCII alphanumeric.
    fn new(kek_version: &[u8], encrypted_dek_bytes: &'w [u8]) -> KmsAeadResult<Self> {
        let kek_version = match kek_version {
            [] => None,
            kek_version => Some(read_kek_version(kek_version)?),
        };
        Ok(Self {
            kek_version,
            encrypted_dek_bytes,
        })
    }

    /// The encrypted DEK as the provider of `kek` takes it since 0.30: the Azure provider's bytes
    /// carry the key version, and every other provider's are the KMS's encrypted DEK.
    fn into_encrypted_dek(self, kek: &KekProvider) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match kek {
            #[cfg(feature = "azure-kms-encryption-base")]
            KekProvider::Azure => {
                let kek_version = self.kek_version.ok_or_else(|| {
                    KmsAeadEncryptionError::create(
                        "AZURE_KEY_VERSION_MISSING",
                        "The encrypted data encryption key records no Azure Key Vault key version",
                    )
                })?;
                let wrapped_key = super::azure::AzureWrappedKey {
                    kek_version,
                    wrapped: self.encrypted_dek_bytes,
                };
                wrapped_key.to_bytes().map(EncryptedDataEncryptionKey::new)
            }
            _ => Ok(EncryptedDataEncryptionKey::new(
                self.encrypted_dek_bytes.to_vec(),
            )),
        }
    }
}

/// A stored value in any envelope layout, its fields borrowed from it:
///
/// - Tink's KMS envelope, as [`separate`](crate::Encrypted::separate) reads it;
/// - the envelope layout v1 of 0.29, `[0x01][k: u8][key version: k][w: u16 BE]
///   [encrypted DEK: w][cipher text]`;
/// - the length prefix written up to 0.28.1, `[w: u64 BE][encrypted DEK: w][cipher text]`.
pub(crate) struct StoredEnvelope<'v> {
    layout: EnvelopeLayout,
    /// Empty in every layout but the envelope layout v1.
    kek_version: &'v [u8],
    encrypted_dek_bytes: &'v [u8],
    pub(crate) bare: &'v [u8],
}

impl<'v> StoredEnvelope<'v> {
    /// The fields of `value`, read from its lengths only.
    ///
    /// # Errors
    ///
    /// The errors of [`separate`](crate::Encrypted::separate) but `LEGACY_FORMAT`, and
    /// `INVALID_CIPHER_TEXT_FORMAT` on a length past the end of a legacy value.
    pub(crate) fn split(value: &'v [u8]) -> KmsAeadResult<Self> {
        let layout = EnvelopeLayout::try_from(value)?;
        let fields = match layout {
            EnvelopeLayout::Tink => {
                let (encrypted_dek_bytes, bare) = split_envelope(value)?;
                Some((&[][..], encrypted_dek_bytes, bare))
            }
            EnvelopeLayout::V1 => value.split_first().and_then(|(_, header)| {
                let (kek_version, rest) = super::split_kek_version_field(header)?;
                let (encrypted_dek_len, rest) = rest.split_first_chunk::<2>()?;
                let encrypted_dek_len = usize::from(u16::from_be_bytes(*encrypted_dek_len));
                let (encrypted_dek_bytes, bare) = rest.split_at_checked(encrypted_dek_len)?;
                Some((kek_version, encrypted_dek_bytes, bare))
            }),
            EnvelopeLayout::LengthPrefixed => {
                value
                    .split_first_chunk::<8>()
                    .and_then(|(encrypted_dek_len, rest)| {
                        let encrypted_dek_len =
                            usize::try_from(u64::from_be_bytes(*encrypted_dek_len)).ok()?;
                        let (encrypted_dek_bytes, bare) =
                            rest.split_at_checked(encrypted_dek_len)?;
                        Some((&[][..], encrypted_dek_bytes, bare))
                    })
            }
        };
        let (kek_version, encrypted_dek_bytes, bare) = fields.ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_CIPHER_TEXT_FORMAT",
                "A length in the cipher text header runs past the end of the buffer",
            )
        })?;
        Ok(Self {
            layout,
            kek_version,
            encrypted_dek_bytes,
            bare,
        })
    }

    /// The encrypted DEK, in the bytes the provider of `kek` takes. A legacy layout logs its
    /// warning once per process.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_VERSION` on a key version that is not ASCII alphanumeric, and under an Azure
    /// KEK `AZURE_KEY_VERSION_MISSING` on a legacy layout with no key version.
    pub(crate) fn encrypted_dek(
        &self,
        kek: &KekProvider,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let format = match self.layout {
            EnvelopeLayout::Tink => {
                return Ok(EncryptedDataEncryptionKey::new(
                    self.encrypted_dek_bytes.to_vec(),
                ))
            }
            EnvelopeLayout::V1 => KmsAeadLegacyFormat::EnvelopeV1,
            EnvelopeLayout::LengthPrefixed => KmsAeadLegacyFormat::LengthPrefixedEnvelope,
        };
        let encrypted_dek = LegacyEncryptedDek::new(self.kek_version, self.encrypted_dek_bytes)?;
        warn_once(format);
        encrypted_dek.into_encrypted_dek(kek)
    }
}

/// The encrypted DEK of stored bytes in the encrypted DEK layout v1 of 0.29,
/// `[0xFF][0x01][k: u8][key version: k][encrypted DEK]`, from `after_header`, the bytes after
/// `[0xFF][0x01]`, as the bytes the provider of `kek` takes.
///
/// # Errors
///
/// `INVALID_ENCRYPTED_KEY_FORMAT` when the key version runs past the end, and
/// `INVALID_KEY_VERSION` on a key version that is not ASCII alphanumeric.
pub(super) fn encrypted_dek_from_layout_v1(
    after_header: &[u8],
    kek: &KekProvider,
) -> KmsAeadResult<EncryptedDataEncryptionKey> {
    let (kek_version, encrypted_dek_bytes) = super::split_kek_version_field(after_header)
        .ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "INVALID_ENCRYPTED_KEY_FORMAT",
                "The key version length runs past the end of the encrypted key",
            )
        })?;
    LegacyEncryptedDek::new(kek_version, encrypted_dek_bytes)?.into_encrypted_dek(kek)
}

/// Logs one `WARN` event the first time a process reads a value in `format`.
pub(super) fn warn_once(format: KmsAeadLegacyFormat) {
    static ENVELOPE_V1: AtomicBool = AtomicBool::new(false);
    static LENGTH_PREFIXED_ENVELOPE: AtomicBool = AtomicBool::new(false);
    static ENCRYPTED_DEK_V1: AtomicBool = AtomicBool::new(false);
    static RAW_ENCRYPTED_DEK: AtomicBool = AtomicBool::new(false);
    let warned = match format {
        KmsAeadLegacyFormat::EnvelopeV1 => &ENVELOPE_V1,
        KmsAeadLegacyFormat::LengthPrefixedEnvelope => &LENGTH_PREFIXED_ENVELOPE,
        KmsAeadLegacyFormat::EncryptedDekV1 => &ENCRYPTED_DEK_V1,
        KmsAeadLegacyFormat::RawEncryptedDek => &RAW_ENCRYPTED_DEK,
    };
    if !warned.swap(true, Ordering::Relaxed) {
        tracing::warn!(
            ?format,
            "Read a value in a layout written by kms-aead 0.29 or earlier. Reading it is \
             deprecated and will be removed in a later breaking release: rewrite stored values \
             with KmsAeadEnvelope::upgrade_legacy_value and upgrade_legacy_encrypted_dek"
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
    /// It decrypts the value's DEK with the provider, never through the DEK cache, since only the
    /// key tells a value of 0.30 from one of a 32-bit target before 0.24.0, and for a value in a
    /// legacy layout opens it under the envelope's algorithm and `aad` and encrypts the DEK again
    /// as Tink does, a second KMS call. The opening only verifies the value: the AEAD bytes stay as
    /// they are, since every release seals them in Tink's layout, and a value that does not open
    /// is never rewritten with the Tink key type of the envelope's algorithm. The envelope's
    /// algorithm is the one the value was sealed with, as for [`decrypt`](Self::decrypt).
    ///
    /// # Errors
    ///
    /// The errors of [`decrypt`](Self::decrypt), among them `DECRYPT` when the value was sealed
    /// under another algorithm or another AAD, and the provider's errors for the new encryption.
    #[deprecated(
        since = "0.30.0",
        note = "reading the layouts written by 0.29 and earlier will be removed in a later breaking release"
    )]
    pub async fn upgrade_legacy_value<T>(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        value: &Encrypted<T, Envelope>,
    ) -> KmsAeadResult<Option<Encrypted<T, Envelope>>> {
        let measurement = Measurement::start(self.reencrypt_call(self.mode()));
        let upgraded = async {
            let stored = StoredEnvelope::split(value.value())?;
            let encrypted_dek = stored.encrypted_dek(self.provider.kek().provider())?;
            let (dek, legacy_format) = decrypt_dek(&encrypted_dek, &self.provider).await?;
            if legacy_format.is_none() && stored.layout == EnvelopeLayout::Tink {
                return Ok(None);
            }
            // A raw key records no algorithm, and every algorithm with its length takes it, so only
            // opening the value shows that the Tink key type written below is the right one.
            self.cipher.open(
                aad.as_ref(),
                stored.bare,
                0,
                dek.value().ref_sensitive_value(),
            )?;
            let upgraded_encrypted_dek = match legacy_format {
                Some(_) => encrypt_dek(&dek, self.algorithm().into(), &self.provider).await?,
                None => encrypted_dek,
            };
            Encrypted::join(
                &Encrypted::try_from(stored.bare.to_vec())?,
                &upgraded_encrypted_dek,
            )
            .map(Some)
        }
        .await;
        measurement.finished(&upgraded);
        upgraded
    }

    /// `encrypted_dek`, an encrypted key stored by 0.29 or earlier, encrypted again as Tink
    /// encrypts a key, or `None` when it already is, so that a sweep writes only the rows that
    /// change. The stored bytes of 0.29's `to_bytes` and `to_hex_string` read as they are, for
    /// every built-in provider.
    ///
    /// It decrypts the key with the provider, never through the DEK cache, and for a key in a
    /// legacy layout encrypts it again, a second KMS call. The envelope's algorithm is the one the
    /// key was made for: with no value to open, the upgrade cannot check it, and records the
    /// envelope's algorithm in the Tink key type for any key of its length. Where the values
    /// sealed under the key are at hand, [`upgrade_legacy_value`](Self::upgrade_legacy_value)
    /// opens them and refuses a key of another algorithm.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the decrypted key is neither a raw key
    /// nor a serialised Tink key, `INVALID_ENCRYPTED_KEY_FORMAT` and `INVALID_KEY_VERSION` on
    /// 0.29's encrypted DEK layout v1 that cannot be read, and `INVALID_KEY_LENGTH` when the key
    /// does not fit the envelope's algorithm.
    #[deprecated(
        since = "0.30.0",
        note = "reading the layouts written by 0.29 and earlier will be removed in a later breaking release"
    )]
    pub async fn upgrade_legacy_encrypted_dek(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<Option<EncryptedDataEncryptionKey>> {
        let measurement = Measurement::start(self.reencrypt_call("caller_dek"));
        let upgraded = async {
            let (dek, legacy) = decrypt_dek(encrypted_dek, &self.provider).await?;
            if legacy.is_none() {
                return Ok(None);
            }
            let algorithm = self.algorithm();
            checked_key_bytes(
                dek.value().ref_sensitive_value(),
                algorithm,
                algorithm.key_len(),
            )?;
            encrypt_dek(&dek, algorithm.into(), &self.provider)
                .await
                .map(Some)
        }
        .await;
        measurement.finished(&upgraded);
        upgraded
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::errors::KmsAeadError;

    /// The shortest sealed value: a nonce and a tag around an empty plaintext.
    const SEALED: [u8; 28] = [0xAB; 28];
    const ENCRYPTED_DEK: &[u8] = b"wrapped";
    /// The header before the sealed value of the encrypted DEK `wrapped` with the key version
    /// `18`, as 0.29's `join` wrote it in envelope layout v1.
    const ENVELOPE_V1_HEADER: &str = "01023138000777726170706564";
    /// The same without a key version.
    const ENVELOPE_V1_WITHOUT_KEY_VERSION_HEADER: &str = "0100000777726170706564";
    /// The same as 0.28.1 wrote it, with an 8-byte length.
    const LENGTH_PREFIXED_ENVELOPE_HEADER: &str = "000000000000000777726170706564";
    /// The encrypted DEK `wrapped` with the key version `18`, as 0.29's `to_bytes` wrote it.
    const ENCRYPTED_DEK_V1: &str = "ff0102313877726170706564";

    #[test]
    fn values_of_0_29_and_earlier_separate_into_the_encrypted_dek() -> KmsAeadResult<()> {
        for header in [
            ENVELOPE_V1_HEADER,
            ENVELOPE_V1_WITHOUT_KEY_VERSION_HEADER,
            LENGTH_PREFIXED_ENVELOPE_HEADER,
        ] {
            let value = [hex::decode(header).unwrap(), SEALED.to_vec()].concat();

            let stored = StoredEnvelope::split(&value)?;
            let encrypted_dek = stored.encrypted_dek(&KekProvider::Gcp)?;

            assert_eq!(stored.bare, SEALED, "{header}");
            assert_eq!(*encrypted_dek.value(), ENCRYPTED_DEK, "{header}");
        }
        let encrypted_dek = encrypted_dek_from_layout_v1(
            &hex::decode(ENCRYPTED_DEK_V1).unwrap()[2..],
            &KekProvider::Gcp,
        )?;
        assert_eq!(*encrypted_dek.value(), ENCRYPTED_DEK);
        Ok(())
    }

    #[cfg(feature = "azure-kms-encryption-base")]
    #[test]
    fn the_azure_provider_takes_the_key_version_in_its_bytes() -> KmsAeadResult<()> {
        let azure_bytes = [&[0x01, 0x02, b'1', b'8'][..], ENCRYPTED_DEK].concat();
        let value = [hex::decode(ENVELOPE_V1_HEADER).unwrap(), SEALED.to_vec()].concat();
        let value_without_key_version = [
            hex::decode(ENVELOPE_V1_WITHOUT_KEY_VERSION_HEADER).unwrap(),
            SEALED.to_vec(),
        ]
        .concat();

        let envelope_encrypted_dek =
            StoredEnvelope::split(&value)?.encrypted_dek(&KekProvider::Azure)?;
        let key_layout_encrypted_dek = encrypted_dek_from_layout_v1(
            &hex::decode(ENCRYPTED_DEK_V1).unwrap()[2..],
            &KekProvider::Azure,
        )?;
        let without_key_version =
            StoredEnvelope::split(&value_without_key_version)?.encrypted_dek(&KekProvider::Azure);

        assert_eq!(*envelope_encrypted_dek.value(), azure_bytes);
        assert_eq!(*key_layout_encrypted_dek.value(), azure_bytes);
        assert!(
            matches!(&without_key_version, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "AZURE_KEY_VERSION_MISSING"),
            "{without_key_version:?}"
        );
        Ok(())
    }

    #[test]
    fn a_legacy_value_too_short_for_a_nonce_and_a_tag_is_refused_when_read() {
        for header in [ENVELOPE_V1_HEADER, LENGTH_PREFIXED_ENVELOPE_HEADER] {
            let value = [&hex::decode(header).unwrap()[..], &SEALED[1..]].concat();

            let result = Encrypted::<String, Envelope>::try_from(value);

            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                "{header}: {result:?}"
            );
        }
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
            let result = StoredEnvelope::split(value);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_CIPHER_TEXT_FORMAT"),
                "{value:02x?}: {:?}",
                result.err()
            );
        }
        let result = encrypted_dek_from_layout_v1(&[0x05, b'1'], &KekProvider::Gcp);
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

        let result = StoredEnvelope::split(&value)
            .and_then(|stored| stored.encrypted_dek(&KekProvider::Gcp));

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
            let _ = StoredEnvelope::split(&bytes)
                .and_then(|stored| stored.encrypted_dek(&KekProvider::Azure));
            let _ = encrypted_dek_from_layout_v1(&bytes, &KekProvider::Azure);
        }
    }

    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    mod upgrade {
        use super::*;
        use crate::formats::TinkKeyType;
        use crate::test_provider::{
            encrypted_by_test_provider, CountingKmsProvider, TestBackend, TestKmsProvider,
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
            let tink_encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &KEY);
            let stored = [
                // As 0.29's `to_bytes` stored it, and as 0.28.1 stored the bare encrypted DEK.
                [&[0xFF, 0x01, 0x00][..], &KEY].concat(),
                KEY.to_vec(),
            ];

            for stored in stored {
                let upgraded_encrypted_dek = envelope
                    .upgrade_legacy_encrypted_dek(&EncryptedDataEncryptionKey::new(stored))
                    .await?;
                assert_eq!(upgraded_encrypted_dek.as_ref(), Some(&tink_encrypted_dek));
            }
            assert_eq!(
                envelope
                    .upgrade_legacy_encrypted_dek(&tink_encrypted_dek)
                    .await?,
                None
            );
            assert_eq!(envelope.provider().encryptions(), 2);
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
                .upgrade_legacy_encrypted_dek(&EncryptedDataEncryptionKey::new(KEY.to_vec()))
                .await;

            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
                "{result:?}"
            );
            assert_eq!(envelope.provider().encryptions(), 0);
            Ok(())
        }
    }
}
