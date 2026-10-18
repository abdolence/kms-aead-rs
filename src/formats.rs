//! Every byte layout of kms-aead, Tink's among them. The formats chapter of the book describes
//! each of them.
//!
//! kms-aead writes one envelope format for every provider, Tink's KMS envelope,
//! [`CipherTextWithEncryptedKey`](crate::CipherTextWithEncryptedKey). Every data encryption key it
//! wraps, in an envelope or on its own, is the KMS ciphertext of the key as Tink serializes it,
//! except under an Azure KEK: Azure has no Tink client, so its wrapped key is the raw key.
//!
//! The wrapped keys of two built-in providers are kms-aead's own layouts, crate-private and
//! described on the provider types, `AzureKmsProvider` and
//! [`LocalKmsProvider`](crate::providers::LocalKmsProvider):
//!
//! ```text
//! Azure: [0x01][k: u8][key version: k ASCII alphanumerics][Key Vault wrapped key]
//! local: [0x01][i: u8][KEK id: i bytes][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]
//! ```
//!
//! The public items here are the [`Format`] of an [`Encrypted`](crate::Encrypted) value,
//! [`Envelope`], [`Randomized`] or [`Deterministic`], and the Tink items of the keys the last two
//! are sealed under: [`TinkKeyId`], the key id their prefix names, [`TinkKeyType`], and
//! [`TinkKeyset`], the keyset Tink and BigQuery read them with.

use crate::errors::{KmsAeadEncryptionError, KmsAeadLegacyFormat};
use crate::{
    generate_random_bytes, AeadBackend, DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider,
    KmsAeadEncryptionProvider, KmsAeadResult, ValueStruct,
};

pub(crate) mod envelope;

mod field;
pub use field::{Deterministic, Envelope, Format, Randomized};

mod tink;
pub(crate) use tink::{serialize_tink_key, split_tink_output_prefix};
pub use tink::{TinkKeyId, TinkKeyType, TinkKeyset};

pub(crate) mod local_kms;

#[cfg(feature = "azure-kms-encryption-base")]
pub(crate) mod azure;

#[cfg(feature = "legacy-formats")]
pub(crate) mod legacy;

/// The first bytes of the encrypted key layout of 0.29, `[0xFF][0x01][k][key version]` before
/// the wrapped key, which no built-in provider's own bytes start with.
const LEGACY_ENCRYPTED_KEY_V1: [u8; 2] = [0xFF, 0x01];

/// `key` wrapped by `provider` as Tink wraps a data encryption key: the KMS ciphertext of the key
/// serialized as a key of `key_type`, with no associated data. An Azure KEK wraps the raw key
/// instead: Key Vault's AES key wrap takes only multiples of 8 bytes, which no serialized Tink
/// key is, and no Tink client exists for Azure.
///
/// # Errors
///
/// The provider's errors.
pub(crate) async fn wrap_key<P>(
    key: &DataEncryptionKey,
    key_type: TinkKeyType,
    provider: &P,
) -> KmsAeadResult<EncryptedDataEncryptionKey>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    match provider.kek().provider() {
        KekProvider::Azure => provider.encrypt_data_encryption_key(key).await,
        _ => {
            let serialized = DataEncryptionKey::from(serialize_tink_key(key_type, key));
            provider.encrypt_data_encryption_key(&serialized).await
        }
    }
}

/// A new key of `key_len` bytes and the same key wrapped by `provider` as a key of `key_type`, as
/// [`wrap_key`] wraps it. The key comes from the KMS generator when the provider is configured to
/// use one, and from the CSPRNG of `B` otherwise.
///
/// # Errors
///
/// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material of
/// another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
pub(crate) async fn generate_wrapped_key<B, P>(
    key_type: TinkKeyType,
    key_len: usize,
    provider: &P,
) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
where
    B: AeadBackend,
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    let key = match provider.generate_key_material(key_len).await? {
        Some(material) if material.ref_sensitive_value().len() != key_len => {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!(
                    "The KMS generator returned {} bytes for a key of {key_len} bytes",
                    material.ref_sensitive_value().len()
                ),
            ));
        }
        Some(material) => DataEncryptionKey::from(material),
        None => DataEncryptionKey::from(generate_random_bytes::<B>(key_len)?),
    };
    let encrypted_key = wrap_key(&key, key_type, provider).await?;
    Ok((key, encrypted_key))
}

/// The data encryption key `encrypted` wraps, unwrapped by `provider`, and the layout written by
/// 0.29 or earlier that it was read from, if any. Only `legacy-formats` reads those layouts: the
/// bytes of 0.29's encrypted key layout given to a built-in provider, and a wrapped key that holds
/// the raw key rather than a serialized Tink key. The bytes of an application's own provider are
/// never inspected.
///
/// # Errors
///
/// The provider's errors, `INVALID_KEY_FORMAT` when the unwrapped key is not a serialized Tink
/// key, or under an Azure KEK not a raw key, and without `legacy-formats` `LEGACY_FORMAT` for a
/// layout of 0.29 or earlier.
pub(crate) async fn unwrap_key<P>(
    encrypted: &EncryptedDataEncryptionKey,
    provider: &P,
) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    if !matches!(provider.kek().provider(), KekProvider::Other(_)) {
        #[cfg(feature = "legacy-formats")]
        if let Some(after_header) = encrypted.value().strip_prefix(&LEGACY_ENCRYPTED_KEY_V1) {
            let encrypted =
                legacy::encrypted_key_from_layout_v1(after_header, provider.kek().provider())?;
            let unwrapped = provider.decrypt_data_encryption_key(&encrypted).await?;
            let (key, _) = key_from_unwrapped(unwrapped, provider.kek().provider())?;
            legacy::warn_once(KmsAeadLegacyFormat::EncryptedKeyV1);
            return Ok((key, Some(KmsAeadLegacyFormat::EncryptedKeyV1)));
        }
        #[cfg(not(feature = "legacy-formats"))]
        if encrypted.value().starts_with(&LEGACY_ENCRYPTED_KEY_V1) {
            return Err(crate::errors::KmsAeadLegacyFormatError::create(
                KmsAeadLegacyFormat::EncryptedKeyV1,
            ));
        }
    }
    let unwrapped = provider.decrypt_data_encryption_key(encrypted).await?;
    key_from_unwrapped(unwrapped, provider.kek().provider())
}

/// The key in `unwrapped`, what the provider of `kek` unwrapped: under an Azure KEK the raw key of
/// 16, 32 or 64 bytes, and under any other a serialized Tink key, or with `legacy-formats` the raw
/// key of 16 or 32 bytes that 0.29 and earlier wrapped. No serialized Tink key has any of those
/// lengths.
fn key_from_unwrapped(
    unwrapped: DataEncryptionKey,
    kek: &KekProvider,
) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)> {
    match (kek, unwrapped.value().ref_sensitive_value().len()) {
        (KekProvider::Azure, 16 | 32 | 64) => Ok((unwrapped, None)),
        (KekProvider::Azure, len) => Err(KmsAeadEncryptionError::create(
            "INVALID_KEY_FORMAT",
            &format!("The unwrapped key of {len} bytes is not a raw key of 16, 32 or 64 bytes"),
        )),
        #[cfg(feature = "legacy-formats")]
        (_, 16 | 32) => {
            legacy::warn_once(KmsAeadLegacyFormat::RawWrappedKey);
            Ok((unwrapped, Some(KmsAeadLegacyFormat::RawWrappedKey)))
        }
        #[cfg(not(feature = "legacy-formats"))]
        (_, 16 | 32) => Err(crate::errors::KmsAeadLegacyFormatError::create(
            KmsAeadLegacyFormat::RawWrappedKey,
        )),
        _ => Ok((
            tink::read_tink_key(unwrapped.value().ref_sensitive_value())?,
            None,
        )),
    }
}

/// Splits `[k: u8][key version: k bytes]` off `bytes`, the key version field of the Azure
/// provider's wrapped keys and of the layouts of 0.29: the key version's bytes and the bytes
/// after them, or `None` when `k` runs past the end.
#[cfg(any(feature = "azure-kms-encryption-base", feature = "legacy-formats"))]
fn split_key_version_field(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&len, rest) = bytes.split_first()?;
    rest.split_at_checked(usize::from(len))
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
    const AZURE_KEY: &str = "https://orders.vault.azure.net/keys/orders";
    /// `KEY` in the encrypted key layout of 0.29, with the key version `18`.
    const ENCRYPTED_KEY_OF_0_29: &str =
        "ff010231384242424242424242424242424242424242424242424242424242424242424242";

    #[tokio::test]
    async fn a_tink_key_unwraps_to_its_key() -> KmsAeadResult<()> {
        let encrypted = wrapped_by_test_provider(TinkKeyType::AesGcm, &KEY);

        let (key, legacy) = unwrap_key(
            &encrypted,
            &CountingKmsProvider::with_kek(
                TestKmsProvider::Working,
                KekRef::new(KekProvider::Gcp, CLOUD_KMS_KEY),
            ),
        )
        .await?;

        assert_eq!(key, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
        assert_eq!(legacy, None);
        Ok(())
    }

    #[tokio::test]
    async fn an_azure_kek_wraps_and_unwraps_the_raw_key() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::with_kek(
            TestKmsProvider::Working,
            KekRef::new(KekProvider::Azure, AZURE_KEY),
        );
        for (key_type, len) in [
            (TinkKeyType::AesGcm, 16),
            (TinkKeyType::AesGcm, 32),
            (TinkKeyType::AesSiv, 64),
        ] {
            let key = DataEncryptionKey::from(SecretValue::new(vec![0x42; len]));

            let encrypted = wrap_key(&key, key_type, &provider).await?;
            let (unwrapped, legacy) = unwrap_key(&encrypted, &provider).await?;

            assert_eq!(encrypted.value(), key.value().ref_sensitive_value());
            assert_eq!(unwrapped, key);
            assert_eq!(legacy, None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_bytes_of_an_applications_own_provider_are_never_inspected() {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, "orders");

        let result = unwrap_key(
            &EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
            &provider,
        )
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
            let result = unwrap_key(&encrypted, &provider).await;
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
            let (key, legacy) = unwrap_key(&encrypted, &provider).await?;
            assert_eq!(key, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
            assert_eq!(legacy, Some(format));
        }
        Ok(())
    }
}
