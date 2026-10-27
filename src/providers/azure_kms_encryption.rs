use rsb_derive::*;

use crate::errors::*;
use crate::*;
use azure_core::credentials::TokenCredential;
use azure_core::http::RequestContent;
use azure_security_keyvault_keys::models::{
    EncryptionAlgorithm, Key, KeyClientGetKeyOptions, KeyClientWrapKeyOptions,
    KeyOperationParameters, KeyType,
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt};
use std::sync::Arc;

use super::KmsKeyVersion;
use crate::formats::asymmetric::PublicKeyEncryptedDek;
use crate::formats::azure::AzureEncryptedDek;
use crate::spans::{self, kms};
use secret_vault_value::SecretValue;

/// A Key Vault or Managed HSM key that encrypts data encryption keys.
///
/// Without `kek_version` the latest version encrypts new keys. Each encrypted key carries the
/// version that encrypted it, and decrypting uses that version, so keys encrypted before a rotation
/// still decrypt afterwards.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AzureKmsKeyRef {
    /// Vault URL, such as `https://my-vault.vault.azure.net`.
    pub vault_url: String,
    /// The key name: `0-9`, `a-z`, `A-Z` and `-`.
    pub key_name: String,
    /// The version that encrypts new keys. Without one, the latest version encrypts them.
    pub kek_version: Option<KmsKeyVersion>,
}

/// The algorithm Key Vault encrypts and decrypts data encryption keys with, the `alg` of its
/// `wrapKey` and `unwrapKey` operations, which encrypt and decrypt a DEK. It must suit the key
/// type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum AzureKmsAlgorithm {
    /// `RSA-OAEP-256`: RSA-OAEP with SHA-256, for an RSA key.
    RsaOaepSha256,
    /// `RSA-OAEP`: RSA-OAEP with SHA-1, for an RSA key whose encrypted DEKs were written with it.
    RsaOaepSha1,
    /// `A128KW`: AES key wrap with a 128-bit key, for a Managed HSM AES key.
    Aes128KeyWrap,
    /// `A192KW`: AES key wrap with a 192-bit key, for a Managed HSM AES key.
    Aes192KeyWrap,
    /// `A256KW`: AES key wrap with a 256-bit key, for a Managed HSM AES key.
    Aes256KeyWrap,
    /// `CKM_AES_KEY_WRAP`: the PKCS#11 AES key wrap, for a Managed HSM AES key.
    Pkcs11AesKeyWrap,
    /// `CKM_AES_KEY_WRAP_PAD`: the PKCS#11 AES key wrap with padding, for a Managed HSM AES key.
    Pkcs11AesKeyWrapWithPadding,
}

/// Options for [`AzureKmsProvider`].
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct AzureKmsProviderOptions {
    /// The algorithm, [`DEFAULT_ALGORITHM`](Self::DEFAULT_ALGORITHM) by default. Encrypted keys
    /// do not record it, so it stays fixed for the life of the key.
    #[default = "Self::DEFAULT_ALGORITHM"]
    pub algorithm: AzureKmsAlgorithm,

    /// Client settings passed to the Azure SDK, such as a custom HTTP transport or retry policy.
    pub client_options: Option<KeyClientOptions>,
}

impl AzureKmsProviderOptions {
    /// The default [`algorithm`](Self::algorithm): [`AzureKmsAlgorithm::RsaOaepSha256`], for an
    /// RSA key.
    pub const DEFAULT_ALGORITHM: AzureKmsAlgorithm = AzureKmsAlgorithm::RsaOaepSha256;
}

/// Encrypts and decrypts data encryption keys with an Azure Key Vault key.
///
/// A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
/// `AZURE_STATUS_<status>` when the response has none. A server error or a rate limit is a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError), any other status an
/// [`EncryptionError`](crate::errors::KmsAeadError::EncryptionError).
///
/// Key Vault decrypts only with the key version that encrypted, and no Tink client exists for
/// Azure, so the provider's [`EncryptedDataEncryptionKey`] is kms-aead's own layout, the key
/// version before Key Vault's encrypted DEK:
///
/// ```text
/// [0x01][k: u8][key version: k ASCII alphanumerics][Key Vault encrypted DEK]
/// ```
///
/// The provider also reads the `0x02` layout of a key a producer encrypted with the public half
/// of the Key Vault RSA key, see [`public_key`](Self::public_key): Key Vault decrypts it with
/// `RSA-OAEP-256` on the version the layout names, whatever [`AzureKmsProviderOptions::algorithm`]
/// is, and the DEK it holds is the raw one, as in the `0x01` layout.
///
/// A decryption of other bytes fails with `AZURE_ENCRYPTED_DEK_FORMAT` before any request, and a
/// `0x02` layout that names a local KEK id or no version with `ASYMMETRIC_ENCRYPTED_DEK_FORMAT`.
///
/// For the same reason, the plaintext Key Vault encrypts is the raw data encryption key of 16, 32
/// or 64 bytes, not the key as Tink serialises it, so every [`AzureKmsAlgorithm`] takes it: AES
/// key wrap takes only multiples of 8 bytes.
pub struct AzureKmsProvider {
    client: KeyClient,
    azure_key_ref: AzureKmsKeyRef,
    options: AzureKmsProviderOptions,
    kek: KekRef,
}

impl AzureKmsProvider {
    /// Uses the key at `kms_key_ref` with any Azure credential, for example one from
    /// `azure_identity`, and the default options. No request is made until the first key is
    /// encrypted or decrypted.
    ///
    /// # Errors
    ///
    /// As [`with_options`](Self::with_options).
    pub fn new(
        kms_key_ref: &AzureKmsKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        Self::with_options(kms_key_ref, AzureKmsProviderOptions::new(), credential)
    }

    /// As [`new`](Self::new), with `options`.
    ///
    /// # Errors
    ///
    /// A [`SystemError`](crate::errors::KmsAeadError::SystemError): `AZURE_KEY_NAME` when the key
    /// name holds characters Key Vault does not allow in it, and `AZURE_VAULT_URL` when the vault
    /// URL is not an HTTP(S) URL.
    pub fn with_options(
        kms_key_ref: &AzureKmsKeyRef,
        options: AzureKmsProviderOptions,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        let client = azure_key_client(
            &kms_key_ref.vault_url,
            &kms_key_ref.key_name,
            options.client_options.clone(),
            credential,
        )?;

        Ok(Self {
            client,
            azure_key_ref: kms_key_ref.clone(),
            options,
            kek: KekRef::new(
                KmsProvider::Azure,
                format!(
                    "{}/keys/{}",
                    kms_key_ref.vault_url.trim_end_matches('/'),
                    kms_key_ref.key_name
                ),
            ),
        })
    }

    /// The Key Vault algorithm of the `0x01` layout.
    fn algorithm(&self) -> EncryptionAlgorithm {
        match self.options.algorithm {
            AzureKmsAlgorithm::RsaOaepSha256 => EncryptionAlgorithm::RsaOaep256,
            AzureKmsAlgorithm::RsaOaepSha1 => EncryptionAlgorithm::RsaOaep,
            AzureKmsAlgorithm::Aes128KeyWrap => EncryptionAlgorithm::A128Kw,
            AzureKmsAlgorithm::Aes192KeyWrap => EncryptionAlgorithm::A192Kw,
            AzureKmsAlgorithm::Aes256KeyWrap => EncryptionAlgorithm::A256Kw,
            AzureKmsAlgorithm::Pkcs11AesKeyWrap => EncryptionAlgorithm::CkmAesKeyWrap,
            AzureKmsAlgorithm::Pkcs11AesKeyWrapWithPadding => EncryptionAlgorithm::CkmAesKeyWrapPad,
        }
    }

    fn key_operation(
        algorithm: EncryptionAlgorithm,
        value: Vec<u8>,
    ) -> KmsAeadResult<RequestContent<KeyOperationParameters>> {
        RequestContent::try_from(KeyOperationParameters {
            algorithm: Some(algorithm),
            value: Some(value),
            ..Default::default()
        })
        .map_err(KmsAeadError::from_azure_error)
    }

    /// The DEK Key Vault's `unwrapKey` returns for `parameters` under `kek_version`, in the span of
    /// the caller.
    async fn decrypt_key(
        &self,
        kek_version: &KmsKeyVersion,
        parameters: RequestContent<KeyOperationParameters>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let decrypted = kms::timed("decrypt_dek", self.kek.provider(), async {
            self.client
                .unwrap_key(
                    &self.azure_key_ref.key_name,
                    kek_version.as_str(),
                    parameters,
                    None,
                )
                .await
                .and_then(|response| response.into_model())
                .map_err(KmsAeadError::from_azure_error)
        })
        .await?;

        let key = decrypted.result.ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "AZURE_UNWRAPPED_KEY",
                "Azure Key Vault returned no decrypted key",
            )
        })?;
        Ok(DataEncryptionKey::from(SecretValue::new(key)))
    }

    /// The public key of the version `kek_version` of an asymmetric KEK, an `RSA` or `RSA-HSM` key
    /// with the `unwrapKey` operation, or of the latest version for `None`, from `GetKey` with
    /// `keys/get`: for the administration, which hands it to the producers. The version is the one
    /// the response's `kid` names.
    ///
    /// # Errors
    ///
    /// Key Vault's errors, and `ASYMMETRIC_KEK_PUBLIC_KEY` when the key is not of type `RSA` or
    /// `RSA-HSM`, lacks the `unwrapKey` operation, or the response names no version or another
    /// key than the configured one.
    pub async fn public_key(
        &self,
        kek_version: Option<&KmsKeyVersion>,
    ) -> KmsAeadResult<AsymmetricKekPublicKey> {
        spans::in_span(kms::kek_public_key_span(&self.kek), async {
            if let Some(kek_version) = kek_version {
                kms::record_kek_version(kek_version.as_str());
            }
            let key = kms::timed("public_key", self.kek.provider(), async {
                self.client
                    .get_key(
                        &self.azure_key_ref.key_name,
                        Some(KeyClientGetKeyOptions {
                            key_version: kek_version.map(KmsKeyVersion::to_string),
                            ..Default::default()
                        }),
                    )
                    .await
                    .and_then(|response| response.into_model())
                    .map_err(KmsAeadError::from_azure_error)
            })
            .await?;
            let public_key = self.kek_public_key(&key)?;
            if let (None, Some(listed)) = (kek_version, public_key.kek_version()) {
                kms::record_kek_version(listed.as_str());
            }
            Ok(public_key)
        })
        .await
    }

    /// The public key of a `GetKey` response for a version of the configured key.
    fn kek_public_key(&self, key: &Key) -> KmsAeadResult<AsymmetricKekPublicKey> {
        let jwk = key.key.as_ref().ok_or_else(|| {
            KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault response holds no JSON Web Key",
            )
        })?;
        if !matches!(jwk.kty, Some(KeyType::Rsa | KeyType::RsaHsm)) {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault key is not an RSA key",
            ));
        }
        if !jwk
            .key_ops
            .iter()
            .flatten()
            .any(|operation| operation == "unwrapKey")
        {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault key does not allow the unwrapKey operation",
            ));
        }
        let key_id = key.resource_id().map_err(|_| {
            KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault response holds no key id",
            )
        })?;
        if key_id.name != self.azure_key_ref.key_name {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault response names another key than the configured one",
            ));
        }
        let kek_version = KmsKeyVersion::try_from(key_id.version.ok_or_else(|| {
            KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault response names no key version",
            )
        })?)?;
        let (Some(modulus), Some(public_exponent)) = (&jwk.n, &jwk.e) else {
            return Err(KmsAeadSystemError::asymmetric_public_key(
                "The Azure Key Vault JSON Web Key holds no modulus or no exponent",
            ));
        };
        AsymmetricKekPublicKey::from_rsa_components(
            self.kek.clone(),
            Some(kek_version),
            AsymmetricKekAlgorithm::RsaOaepSha256,
            modulus,
            public_exponent,
        )
    }

    /// The DEK a `0x02` encrypted DEK holds, decrypted by the version it names with `RSA-OAEP-256`
    /// whatever [`AzureKmsProviderOptions::algorithm`] is.
    async fn asymmetric_decrypt(
        &self,
        encrypted_dek: PublicKeyEncryptedDek<'_>,
    ) -> KmsAeadResult<DataEncryptionKey> {
        let (kek_version, block) = encrypted_dek.into_versioned_block()?;
        kms::record_kek_version(kek_version.as_str());
        let parameters = Self::key_operation(EncryptionAlgorithm::RsaOaep256, block.to_vec())?;
        self.decrypt_key(&kek_version, parameters).await
    }
}

fn is_key_vault_name(name: &str) -> bool {
    !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// The Key Vault client of `vault_url`, once `key_name` is a name Key Vault allows.
///
/// The SDK substitutes the name and version into the request path without escaping, so a `/` or
/// `?` in either would address a different resource. `KmsKeyVersion` admits only alphanumerics.
///
/// # Errors
///
/// `AZURE_KEY_NAME` for a name with characters other than 0-9, a-z, A-Z and `-`, and
/// `AZURE_VAULT_URL` when `vault_url` is not an HTTP(S) URL.
pub(super) fn azure_key_client(
    vault_url: &str,
    key_name: &str,
    client_options: Option<KeyClientOptions>,
    credential: Arc<dyn TokenCredential>,
) -> KmsAeadResult<KeyClient> {
    if !is_key_vault_name(key_name) {
        return Err(KmsAeadSystemError::create(
            "AZURE_KEY_NAME",
            &format!("Azure Key Vault key names allow only 0-9, a-z, A-Z and -: {key_name:?}"),
        ));
    }
    KeyClient::new(vault_url, credential, client_options)
        .map_err(|error| invalid_vault_url(vault_url, &error))
}

/// `AZURE_VAULT_URL` for `vault_url`, which fails for `reason`.
pub(super) fn invalid_vault_url(vault_url: &str, reason: &dyn std::fmt::Display) -> KmsAeadError {
    KmsAeadSystemError::create(
        "AZURE_VAULT_URL",
        &format!("Invalid Azure Key Vault URL {vault_url:?}: {reason}"),
    )
}

impl KmsAeadEncryptionProvider for AzureKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(&self.kek), async {
            let parameters =
                Self::key_operation(self.algorithm(), dek.value().ref_sensitive_value().clone())?;
            let encrypted = kms::timed("encrypt_dek", self.kek.provider(), async {
                self.client
                    .wrap_key(
                        &self.azure_key_ref.key_name,
                        parameters,
                        Some(KeyClientWrapKeyOptions {
                            key_version: self
                                .azure_key_ref
                                .kek_version
                                .as_ref()
                                .map(KmsKeyVersion::to_string),
                            ..Default::default()
                        }),
                    )
                    .await
                    .and_then(|response| response.into_model())
                    .map_err(KmsAeadError::from_azure_error)
            })
            .await?;

            let kek_version = encrypted
                .resource_id()
                .map_err(KmsAeadError::from_azure_error)?
                .version
                .ok_or_else(|| {
                    KmsAeadEncryptionError::create(
                        "AZURE_KEY_VERSION",
                        "Azure Key Vault returned an encrypted DEK without the key version",
                    )
                })?;
            let encrypted_bytes = encrypted.result.ok_or_else(|| {
                KmsAeadEncryptionError::create(
                    "AZURE_WRAPPED_KEY",
                    "Azure Key Vault returned no encrypted DEK",
                )
            })?;
            let azure_dek = AzureEncryptedDek {
                kek_version: KmsKeyVersion::try_from(kek_version)?,
                ciphertext: &encrypted_bytes,
            };
            kms::record_kek_version(azure_dek.kek_version.as_str());
            Ok(EncryptedDataEncryptionKey::new(azure_dek.to_bytes()?)
                .with_kek_version(azure_dek.kek_version))
        })
        .await
    }
}

impl KmsAeadDecryptionProvider for AzureKmsProvider {
    /// Decrypts with the configured key name and the key version the encrypted key carries, so
    /// that Key Vault refuses a key encrypted under another key and accepts one encrypted under an
    /// earlier version of this one.
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::decrypt_span(&self.kek), async {
            if let Some(public_key_dek) = PublicKeyEncryptedDek::read(encrypted_dek.value()) {
                return self.asymmetric_decrypt(public_key_dek?).await;
            }
            let azure_dek = AzureEncryptedDek::try_from(encrypted_dek.value())?;
            kms::record_kek_version(azure_dek.kek_version.as_str());

            let parameters = Self::key_operation(self.algorithm(), azure_dek.ciphertext.to_vec())?;
            self.decrypt_key(&azure_dek.kek_version, parameters).await
        })
        .await
    }
}
