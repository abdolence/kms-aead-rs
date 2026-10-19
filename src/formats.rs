//! Every byte layout of kms-aead, Tink's among them. The formats chapter of the book describes
//! each of them.
//!
//! kms-aead writes one envelope format for every provider, Tink's KMS envelope, [`Envelope`].
//! Every data encryption key it encrypts, in an envelope or on its own, is the KMS ciphertext of
//! the key as Tink serialises it, except under an Azure KEK: Azure has no Tink client, so its
//! encrypted DEK is the raw key.
//!
//! The encrypted DEKs of two built-in providers are kms-aead's own layouts, crate-private and
//! described on the provider types, `AzureKmsProvider` and
//! [`LocalKmsProvider`](crate::providers::LocalKmsProvider):
//!
//! ```text
//! Azure: [0x01][k: u8][key version: k ASCII alphanumerics][Key Vault encrypted DEK]
//! local: [0x01][i: u8][KEK id: i bytes][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]
//! ```
//!
//! The public items here are the [`Format`] of an [`Encrypted`](crate::Encrypted) value,
//! [`Envelope`], [`Bare`], [`Randomized`] or [`Deterministic`], and the Tink items of the keys the
//! last two are sealed under: [`TinkKeyType`], and [`TinkKeyset`], the keyset Tink and BigQuery
//! read them with, whose keys are named by the [`KeyId`](crate::KeyId) their prefix carries.

use crate::backends::AeadBackend;
use crate::errors::{
    KmsAeadEncryptionError, KmsAeadError, KmsAeadLegacyFormat, KmsAeadLegacyFormatError,
};
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekProvider, KmsAeadEncryptionProvider,
    KmsAeadResult,
};

pub(crate) mod envelope;

mod field;
pub use field::{Bare, Deterministic, Envelope, Format, Randomized};

mod tink;
pub(crate) use tink::{
    serialize_tink_key, split_tink_output_prefix, tink_output_prefix, TINK_OUTPUT_PREFIX_LEN,
};
pub use tink::{TinkKeyType, TinkKeyset};

pub(crate) mod local_kms;

#[cfg(feature = "azure-kms-encryption-base")]
pub(crate) mod azure;

#[cfg(feature = "legacy-formats")]
pub(crate) mod legacy;

/// The first bytes of the encrypted DEK layout v1 of 0.29, `[0xFF][0x01][k][key version]` before
/// the encrypted DEK, which no built-in provider's own bytes start with.
const LEGACY_ENCRYPTED_DEK_V1_PREFIX: [u8; 2] = [0xFF, 0x01];

/// `dek` encrypted by `provider` as Tink encrypts a data encryption key: the KMS ciphertext of the
/// key serialised as a key of `key_type`, with no associated data. An Azure KEK encrypts the raw
/// key instead: Key Vault's AES key wrap takes only multiples of 8 bytes, which no serialised Tink
/// key is, and no Tink client exists for Azure.
///
/// # Errors
///
/// The provider's errors.
pub(crate) async fn encrypt_dek<P>(
    dek: &DataEncryptionKey,
    key_type: TinkKeyType,
    provider: &P,
) -> KmsAeadResult<EncryptedDataEncryptionKey>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    match provider.kek().provider() {
        KekProvider::Azure => provider.encrypt_data_encryption_key(dek).await,
        _ => {
            let serialized_dek = DataEncryptionKey::from(serialize_tink_key(key_type, dek));
            provider.encrypt_data_encryption_key(&serialized_dek).await
        }
    }
}

/// A new key of `key_len` bytes and the same key encrypted by `provider` as a key of `key_type`, as
/// [`encrypt_dek`] encrypts it. The key comes from the KMS generator when the provider is
/// configured to use one, and from the CSPRNG of `B` otherwise.
///
/// # Errors
///
/// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material of
/// another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
pub(crate) async fn generate_encrypted_dek<B, P>(
    key_type: TinkKeyType,
    key_len: usize,
    provider: &P,
) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
where
    B: AeadBackend,
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    let dek = match provider.generate_key_material(key_len).await? {
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
        None => DataEncryptionKey::from(B::generate_random_bytes(key_len)?),
    };
    let encrypted_dek = encrypt_dek(&dek, key_type, provider).await?;
    Ok((dek, encrypted_dek))
}

/// The data encryption key that `encrypted_dek` holds, decrypted by `provider`, and the layout
/// written by 0.29 or earlier that it was read from, if any. Only `legacy-formats` reads those
/// layouts: the bytes of 0.29's encrypted DEK layout v1 given to a built-in provider, and an
/// encrypted DEK that holds the raw key rather than a serialised Tink key. The bytes of an
/// application's own provider are never inspected.
///
/// # Errors
///
/// The provider's errors, `INVALID_KEY_FORMAT` when the decrypted key is not a serialised Tink
/// key, or under an Azure KEK not a raw key, and without `legacy-formats` `LEGACY_FORMAT` for a
/// layout of 0.29 or earlier.
pub(crate) async fn decrypt_dek<P>(
    encrypted_dek: &EncryptedDataEncryptionKey,
    provider: &P,
) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    let kek = provider.kek().provider();
    match encrypted_dek_v1_body(encrypted_dek, kek) {
        #[cfg(feature = "legacy-formats")]
        Some(after_header) => {
            let inner_encrypted_dek = legacy::encrypted_dek_from_layout_v1(after_header, kek)?;
            let decrypted_dek = provider
                .decrypt_data_encryption_key(&inner_encrypted_dek)
                .await?;
            let (dek, _) = key_from_decrypted(decrypted_dek, kek)?;
            legacy::warn_once(KmsAeadLegacyFormat::EncryptedDekV1);
            Ok((dek, Some(KmsAeadLegacyFormat::EncryptedDekV1)))
        }
        #[cfg(not(feature = "legacy-formats"))]
        Some(_) => Err(KmsAeadLegacyFormatError::create(
            KmsAeadLegacyFormat::EncryptedDekV1,
        )),
        None => {
            let decrypted_dek = provider.decrypt_data_encryption_key(encrypted_dek).await?;
            key_from_decrypted(decrypted_dek, kek)
        }
    }
}

/// `encrypted_dek` decrypted by `provider` and encrypted again as the provider decrypted it: a
/// serialised Tink key, or under an Azure KEK the raw key. The key is never serialised again from
/// its bytes, which do not record its Tink key type, so the new encrypted DEK holds the same key of
/// the same type, whether an envelope, a beacon or a deterministic key, under the KEK version the
/// provider encrypts with now.
///
/// # Errors
///
/// The provider's errors, `INVALID_KEY_FORMAT` as for [`decrypt_dek`], and `LEGACY_FORMAT` for a
/// layout of 0.29 or earlier, with or without `legacy-formats`, naming the upgrades rather than
/// the feature.
pub(crate) async fn reencrypt_encrypted_dek<P>(
    encrypted_dek: &EncryptedDataEncryptionKey,
    provider: &P,
) -> KmsAeadResult<EncryptedDataEncryptionKey>
where
    P: KmsAeadEncryptionProvider + Sync + ?Sized,
{
    let kek = provider.kek().provider();
    if encrypted_dek_v1_body(encrypted_dek, kek).is_some() {
        return Err(KmsAeadLegacyFormatError::refused_by_reencryption(
            KmsAeadLegacyFormat::EncryptedDekV1,
        ));
    }
    let decrypted_dek = provider.decrypt_data_encryption_key(encrypted_dek).await?;
    match key_from_decrypted(decrypted_dek.clone(), kek) {
        Ok((_, None)) => provider.encrypt_data_encryption_key(&decrypted_dek).await,
        Ok((_, Some(format)))
        | Err(KmsAeadError::LegacyFormat(KmsAeadLegacyFormatError { format, .. })) => {
            Err(KmsAeadLegacyFormatError::refused_by_reencryption(format))
        }
        Err(error) => Err(error),
    }
}

/// The bytes after `[0xFF][0x01]` when `encrypted_dek`, given to a built-in provider of `kek`, is in
/// the encrypted DEK layout v1 of 0.29. The bytes of an application's own provider are never
/// inspected.
fn encrypted_dek_v1_body<'e>(
    encrypted_dek: &'e EncryptedDataEncryptionKey,
    kek: &KekProvider,
) -> Option<&'e [u8]> {
    match kek {
        KekProvider::Other(_) => None,
        _ => encrypted_dek
            .value()
            .strip_prefix(&LEGACY_ENCRYPTED_DEK_V1_PREFIX),
    }
}

/// The key in `decrypted_dek`, what the provider of `kek` decrypted: under an Azure KEK the raw key
/// of 16, 32 or 64 bytes, and under any other a serialised Tink key, or with `legacy-formats` the
/// raw key of 16 or 32 bytes that 0.29 and earlier encrypted. No serialised Tink key has any of
/// those lengths.
fn key_from_decrypted(
    decrypted_dek: DataEncryptionKey,
    kek: &KekProvider,
) -> KmsAeadResult<(DataEncryptionKey, Option<KmsAeadLegacyFormat>)> {
    match (kek, decrypted_dek.value().ref_sensitive_value().len()) {
        (KekProvider::Azure, 16 | 32 | 64) => Ok((decrypted_dek, None)),
        (KekProvider::Azure, len) => Err(KmsAeadEncryptionError::create(
            "INVALID_KEY_FORMAT",
            &format!("The decrypted key of {len} bytes is not a raw key of 16, 32 or 64 bytes"),
        )),
        #[cfg(feature = "legacy-formats")]
        (_, 16 | 32) => {
            legacy::warn_once(KmsAeadLegacyFormat::RawEncryptedDek);
            Ok((decrypted_dek, Some(KmsAeadLegacyFormat::RawEncryptedDek)))
        }
        #[cfg(not(feature = "legacy-formats"))]
        (_, 16 | 32) => Err(KmsAeadLegacyFormatError::create(
            KmsAeadLegacyFormat::RawEncryptedDek,
        )),
        _ => Ok((
            tink::read_tink_key(decrypted_dek.value().ref_sensitive_value())?,
            None,
        )),
    }
}

/// Splits `[k: u8][key version: k bytes]` off `bytes`, the key version field of the Azure
/// provider's encrypted DEKs and of the layouts of 0.29: the key version's bytes and the bytes
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
    use crate::test_provider::{encrypted_by_test_provider, CountingKmsProvider, TestKmsProvider};
    use crate::KekRef;
    use secret_vault_value::SecretValue;

    const KEY: [u8; 32] = [0x42; 32];
    /// A Cloud KMS key, whose provider's own bytes never start with `0xFF 0x01`.
    const CLOUD_KMS_KEY: &str = "projects/p/locations/l/keyRings/r/cryptoKeys/k";
    const AZURE_KEY: &str = "https://orders.vault.azure.net/keys/orders";
    /// `KEY` in the encrypted DEK layout v1 of 0.29, with the key version `18`.
    const ENCRYPTED_KEY_OF_0_29: &str =
        "ff010231384242424242424242424242424242424242424242424242424242424242424242";

    #[tokio::test]
    async fn a_tink_key_decrypts_to_its_key() -> KmsAeadResult<()> {
        let encrypted_dek = encrypted_by_test_provider(TinkKeyType::AesGcm, &KEY);

        let (dek, legacy) = decrypt_dek(
            &encrypted_dek,
            &CountingKmsProvider::with_kek(
                TestKmsProvider::Working,
                KekRef::new(KekProvider::Gcp, CLOUD_KMS_KEY),
            ),
        )
        .await?;

        assert_eq!(dek, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
        assert_eq!(legacy, None);
        Ok(())
    }

    #[tokio::test]
    async fn an_azure_kek_encrypts_and_decrypts_the_raw_key() -> KmsAeadResult<()> {
        let provider = CountingKmsProvider::with_kek(
            TestKmsProvider::Working,
            KekRef::new(KekProvider::Azure, AZURE_KEY),
        );
        for (key_type, len) in [
            (TinkKeyType::AesGcm, 16),
            (TinkKeyType::AesGcm, 32),
            (TinkKeyType::AesSiv, 64),
        ] {
            let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; len]));

            let encrypted_dek = encrypt_dek(&dek, key_type, &provider).await?;
            let (decrypted_dek, legacy) = decrypt_dek(&encrypted_dek, &provider).await?;

            assert_eq!(encrypted_dek.value(), dek.value().ref_sensitive_value());
            assert_eq!(decrypted_dek, dek);
            assert_eq!(legacy, None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_bytes_of_an_applications_own_provider_are_never_inspected() {
        let provider = CountingKmsProvider::new(TestKmsProvider::Working, "orders");

        let result = decrypt_dek(
            &EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
            &provider,
        )
        .await;

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_FORMAT"),
            "{result:?}"
        );
        assert_eq!(provider.decryptions(), 1);
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
                KmsAeadLegacyFormat::RawEncryptedDek,
            ),
            (
                EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
                KmsAeadLegacyFormat::EncryptedDekV1,
            ),
        ];
        for (encrypted_dek, format) in cases {
            let result = decrypt_dek(&encrypted_dek, &provider).await;
            assert!(
                matches!(&result, Err(KmsAeadError::LegacyFormat(error)) if error.format == format),
                "{format:?}: {result:?}"
            );
        }
        // The encrypted DEK layout v1 is refused before any KMS call.
        assert_eq!(provider.decryptions(), 1);
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
                KmsAeadLegacyFormat::RawEncryptedDek,
            ),
            (
                EncryptedDataEncryptionKey::new(hex::decode(ENCRYPTED_KEY_OF_0_29).unwrap()),
                KmsAeadLegacyFormat::EncryptedDekV1,
            ),
        ];
        for (encrypted_dek, format) in cases {
            let (dek, legacy) = decrypt_dek(&encrypted_dek, &provider).await?;
            assert_eq!(dek, DataEncryptionKey::from(SecretValue::new(KEY.to_vec())));
            assert_eq!(legacy, Some(format));
        }
        Ok(())
    }
}
