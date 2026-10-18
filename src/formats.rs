//! Every byte layout of kms-aead, and the Tink layouts a keyring of Tink keys writes beside it.
//! The formats chapter of the book describes each of them.
//!
//! kms-aead writes one envelope format for every provider, Tink's KMS envelope,
//! [`CipherTextWithEncryptedKey`](crate::CipherTextWithEncryptedKey). Every data encryption key it
//! wraps, in an envelope or on its own, is the KMS ciphertext of the key as Tink serializes it.
//!
//! The public items here are what a keyring of Tink keys needs on top of that:
//! [`TinkOutputPrefix`], the prefix of its values, and [`TinkKeyset`], the keyset BigQuery reads,
//! and the [`Format`] of an [`Encrypted`](crate::Encrypted) value: [`Envelope`], [`Randomized`]
//! or [`Deterministic`].

use crate::errors::KmsAeadLegacyFormat;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KmsAeadEncryptionProvider,
    KmsAeadResult, ValueStruct,
};

pub(crate) mod envelope;

mod field;
pub use field::{Deterministic, Envelope, Format, Randomized};

mod tink;
pub use tink::{TinkKeyType, TinkKeyset, TinkOutputPrefix};

pub(crate) mod local_kms;

#[cfg(feature = "azure-kms-encryption-base")]
pub(crate) mod azure;

#[cfg(feature = "legacy-formats")]
pub(crate) mod legacy;

impl DataEncryptionKey {
    /// This key wrapped by `provider` as Tink wraps a data encryption key: the KMS ciphertext of
    /// the key serialized as a key of `key_type`, with no associated data.
    ///
    /// # Errors
    ///
    /// The provider's errors.
    pub(crate) async fn wrap_with<P>(
        &self,
        key_type: TinkKeyType,
        provider: &P,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        let serialized = DataEncryptionKey::from(key_type.serialize(self));
        provider.encrypt_data_encryption_key(&serialized).await
    }
}

impl EncryptedDataEncryptionKey {
    /// The first bytes of the encrypted key layout of 0.29, `[0xFF][0x01][k][key version]`
    /// before the wrapped key, which no built-in provider's own bytes start with.
    const LEGACY_LAYOUT_V1: [u8; 2] = [0xFF, 0x01];

    /// The data encryption key this wraps, unwrapped by `provider`, and the layout written by
    /// 0.29 or earlier that it was read from, if any. Only `legacy-formats` reads those layouts:
    /// the bytes of 0.29's encrypted key layout given to a built-in provider, and a wrapped key
    /// that holds the raw key rather than a serialized Tink key. The bytes of an application's
    /// own provider are never inspected.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_FORMAT` when the unwrapped key is not a serialized
    /// Tink key, and without `legacy-formats` `LEGACY_FORMAT` for a layout of 0.29 or earlier.
    pub(crate) async fn unwrap_with<P>(
        &self,
        provider: &P,
    ) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        if !matches!(provider.kek().provider(), KekProvider::Other(_)) {
            #[cfg(feature = "legacy-formats")]
            if let Some(after_header) = self.value().strip_prefix(&Self::LEGACY_LAYOUT_V1) {
                let encrypted =
                    Self::from_encrypted_key_layout_v1(after_header, provider.kek().provider())?;
                let unwrapped = provider.decrypt_data_encryption_key(&encrypted).await?;
                let (key, _) = DataEncryptionKey::from_unwrapped(unwrapped)?;
                KmsAeadLegacyFormat::EncryptedKeyV1.warn_once();
                return Ok((key, Some(KmsAeadLegacyFormat::EncryptedKeyV1)));
            }
            #[cfg(not(feature = "legacy-formats"))]
            if self.value().starts_with(&Self::LEGACY_LAYOUT_V1) {
                return Err(crate::errors::KmsAeadLegacyFormatError::create(
                    KmsAeadLegacyFormat::EncryptedKeyV1,
                ));
            }
        }
        let unwrapped = provider.decrypt_data_encryption_key(self).await?;
        DataEncryptionKey::from_unwrapped(unwrapped)
    }
}

impl DataEncryptionKey {
    /// The key in `unwrapped`, what a provider unwrapped: a serialized Tink key, or with
    /// `legacy-formats` the raw key of 16 or 32 bytes that 0.29 and earlier wrapped. No
    /// serialized Tink key has either length.
    fn from_unwrapped(
        unwrapped: DataEncryptionKey,
    ) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)> {
        match unwrapped.value().ref_sensitive_value().len() {
            #[cfg(feature = "legacy-formats")]
            16 | 32 => {
                KmsAeadLegacyFormat::RawWrappedKey.warn_once();
                Ok((unwrapped, Some(KmsAeadLegacyFormat::RawWrappedKey)))
            }
            #[cfg(not(feature = "legacy-formats"))]
            16 | 32 => Err(crate::errors::KmsAeadLegacyFormatError::create(
                KmsAeadLegacyFormat::RawWrappedKey,
            )),
            _ => Ok((
                Self::from_tink_key(unwrapped.value().ref_sensitive_value())?,
                None,
            )),
        }
    }
}

#[cfg(any(feature = "azure-kms-encryption-base", feature = "legacy-formats"))]
impl crate::KmsKeyVersion {
    /// Splits `[k: u8][key version: k bytes]` off `bytes`, the key version field of the Azure
    /// provider's wrapped keys and of the layouts of 0.29: the key version's bytes and the bytes
    /// after them, or `None` when `k` runs past the end.
    pub(crate) fn split_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
        let (&len, rest) = bytes.split_first()?;
        rest.split_at_checked(usize::from(len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::KmsAeadError;
    use crate::test_provider::{wrapped_by_test_provider, CountingKmsProvider, TestKmsProvider};
    use crate::KekRef;
    use secret_vault_value::SecretValue;

    const KEY: [u8; 32] = [0x42; 32];
    /// A Cloud KMS key, whose provider's own bytes never start with `0xFF 0x01`.
    const CLOUD_KMS_KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";
    /// `KEY` in the encrypted key layout of 0.29, with the key version `18`.
    const ENCRYPTED_KEY_OF_0_29: &str =
        "ff010231384242424242424242424242424242424242424242424242424242424242424242";

    #[tokio::test]
    async fn a_tink_key_unwraps_to_its_key() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &KEY);

        let (key, legacy) = encrypted
            .unwrap_with(&CountingKmsProvider::with_kek(
                TestKmsProvider::Working,
                KekRef::new(KekProvider::Gcp, CLOUD_KMS_KEY),
            ))
            .await?;

        assert_eq!(key, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
        assert_eq!(legacy, None);
        Ok(())
    }

    #[tokio::test]
    async fn the_bytes_of_an_applications_own_provider_are_never_inspected() {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, "orders");

        let result = EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap())
            .unwrap_with(&provider)
            .await;

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_FORMAT"),
            "{result:?}"
        );
        assert_eq!(provider.unwraps(), 1);
    }

    #[cfg(not(feature = "legacy-formats"))]
    #[tokio::test]
    async fn the_layouts_of_0_29_need_legacy_formats() {
        let provider = CountingKmsProvider::with_kek(
            TestKmsProvider::Working,
            KekRef::new(KekProvider::Gcp, CLOUD_KMS_KEY),
        );
        let cases = [
            (
                EncryptedDataEncryptionKey::new(KEY.to_vec()),
                KmsAeadLegacyFormat::RawWrappedKey,
            ),
            (
                EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
                KmsAeadLegacyFormat::EncryptedKeyV1,
            ),
        ];
        for (encrypted, format) in cases {
            let result = encrypted.unwrap_with(&provider).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error)) if error.format == format),
                "{format:?}: {result:?}"
            );
        }
        // The encrypted key layout is refused before any KMS call.
        assert_eq!(provider.unwraps(), 1);
    }

    #[cfg(feature = "legacy-formats")]
    #[tokio::test]
    async fn the_layouts_of_0_29_read_with_legacy_formats() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::with_kek(
            TestKmsProvider::Working,
            KekRef::new(KekProvider::Gcp, CLOUD_KMS_KEY),
        );
        let cases = [
            (
                EncryptedDataEncryptionKey::new(KEY.to_vec()),
                KmsAeadLegacyFormat::RawWrappedKey,
            ),
            (
                EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
                KmsAeadLegacyFormat::EncryptedKeyV1,
            ),
        ];
        for (encrypted, format) in cases {
            let (key, legacy) = encrypted.unwrap_with(&provider).await?;
            assert_eq!(key, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
            assert_eq!(legacy, Some(format));
        }
        Ok(())
    }
}
