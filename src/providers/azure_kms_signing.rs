use std::sync::Arc;

use azure_core::credentials::TokenCredential;
use azure_core::http::RequestContent;
use azure_security_keyvault_keys::models::{
    CurveName, Key, KeyClientGetKeyOptions, KeyClientSignOptions, KeyType, SignParameters,
    SignatureAlgorithm,
};
use azure_security_keyvault_keys::{KeyClient, KeyClientOptions, ResourceExt, ResourceId};
use rsb_derive::Builder;

use super::azure_kms_encryption::{azure_key_client, invalid_vault_url};
use super::KmsKeyVersion;
use crate::errors::{KmsAeadError, KmsAeadSignatureError};
use crate::formats::PublicKeyFormat;
use crate::signing::{
    KmsSigningProvider, RawSignature, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
};
use crate::spans::{self, kms};
use crate::{KmsAeadResult, KmsProvider};

/// One version of a Key Vault or Managed HSM EC `P-256` key that signs.
#[derive(Debug, Clone, Eq, PartialEq, Builder)]
pub struct AzureKmsSigningKeyRef {
    /// Vault URL, such as `https://my-vault.vault.azure.net`.
    pub vault_url: String,
    /// The key name: `0-9`, `a-z`, `A-Z` and `-`.
    pub key_name: String,
    /// The key version, required: a signer never follows the latest version.
    pub version: KmsKeyVersion,
}

/// The length of each coordinate of a P-256 point.
const P256_COORDINATE_LEN: usize = 32;

/// Signs with one version of an Azure Key Vault or Managed HSM EC `P-256` key, which signs
/// [`EcdsaP256Sha256`](SigningAlgorithm::EcdsaP256Sha256): Key Vault signs no Ed25519.
///
/// The SHA-256 of the pre-image goes to the sign operation as the `value` of `ES256`, and the
/// `result` is `r || s` of RFC 7518, 64 bytes. A response whose `kid` is not the configured key
/// and version is `SIGNING_KEY_MISMATCH`.
///
/// A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
/// `AZURE_STATUS_<status>` when the response has none. A server error or a rate limit is a
/// [`NetworkError`](crate::errors::KmsAeadError::NetworkError), any other status a
/// [`SignatureError`](crate::errors::KmsAeadError::SignatureError).
///
/// The principal needs the `sign` and `get` key operations.
pub struct AzureKmsSigningProvider {
    client: KeyClient,
    key_name: String,
    version: KmsKeyVersion,
    key_id: ResourceId,
    signing_key: SigningKeyRef,
}

impl AzureKmsSigningProvider {
    /// A provider for the key version at `key_ref` with any Azure credential, for example one
    /// from `azure_identity`. No request is made until `Signer::new`.
    ///
    /// # Errors
    ///
    /// As [`with_client_options`](Self::with_client_options).
    pub fn new(
        key_ref: &AzureKmsSigningKeyRef,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        Self::with_client_options(key_ref, None, credential)
    }

    /// As [`new`](Self::new), with `client_options` for the Azure SDK, such as a custom HTTP
    /// transport or retry policy.
    ///
    /// # Errors
    ///
    /// A [`SystemError`](crate::errors::KmsAeadError::SystemError): `AZURE_KEY_NAME` when the key
    /// name holds characters Key Vault does not allow in it, and `AZURE_VAULT_URL` when the vault
    /// URL is not an HTTP(S) URL.
    pub fn with_client_options(
        key_ref: &AzureKmsSigningKeyRef,
        client_options: Option<KeyClientOptions>,
        credential: Arc<dyn TokenCredential>,
    ) -> KmsAeadResult<Self> {
        let client = azure_key_client(
            &key_ref.vault_url,
            &key_ref.key_name,
            client_options,
            credential,
        )?;
        let key = format!(
            "{}/keys/{}/{}",
            key_ref.vault_url.trim_end_matches('/'),
            key_ref.key_name,
            key_ref.version
        );
        let key_id = key
            .parse::<ResourceId>()
            .map_err(|error| invalid_vault_url(&key_ref.vault_url, &error))?;

        Ok(Self {
            client,
            key_name: key_ref.key_name.clone(),
            version: key_ref.version.clone(),
            key_id,
            signing_key: SigningKeyRef::new(KmsProvider::Azure, key),
        })
    }

    /// Refuses a response whose `kid` is missing or is not the configured key and version.
    fn ensure_key(&self, kid: Option<&ResourceId>) -> KmsAeadResult<()> {
        if kid == Some(&self.key_id) {
            Ok(())
        } else {
            Err(KmsAeadSignatureError::create(
                "SIGNING_KEY_MISMATCH",
                "The Azure Key Vault response names another key or version than the configured one",
            ))
        }
    }

    /// The verifying key of the `get key` response `key`, once it names the configured key and
    /// version and is an EC `P-256` key.
    fn verifying_key_from(&self, key: &Key) -> KmsAeadResult<VerifyingKey> {
        let jwk = key.key.as_ref().ok_or_else(|| {
            KmsAeadSignatureError::invalid_public_key(
                "The Azure Key Vault response holds no JSON Web Key",
            )
        })?;
        self.ensure_key(key.resource_id().ok().as_ref())?;
        if !matches!(jwk.kty, Some(KeyType::Ec | KeyType::EcHsm))
            || !matches!(jwk.crv, Some(CurveName::P256))
        {
            return Err(KmsAeadSignatureError::create(
                "SIGNING_ALGORITHM_MISMATCH",
                &format!(
                    "The Azure Key Vault key {} is not an EC P-256 key",
                    self.signing_key.key()
                ),
            ));
        }
        let coordinate = |coordinate: &Option<Vec<u8>>, name: &str| match coordinate {
            Some(bytes) if bytes.len() == P256_COORDINATE_LEN => Ok(bytes.clone()),
            _ => Err(KmsAeadSignatureError::invalid_public_key(&format!(
                "The JSON Web Key has no {name} of {P256_COORDINATE_LEN} bytes"
            ))),
        };
        let point = [
            &[0x04][..],
            &coordinate(&jwk.x, "x")?,
            &coordinate(&jwk.y, "y")?,
        ]
        .concat();
        VerifyingKey::from_bytes(
            SigningAlgorithm::EcdsaP256Sha256,
            &point,
            PublicKeyFormat::Raw,
        )
    }
}

impl KmsSigningProvider for AzureKmsSigningProvider {
    fn signing_key(&self) -> &SigningKeyRef {
        &self.signing_key
    }

    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EcdsaP256Sha256
    }

    async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
        spans::in_span(kms::sign_span(&self.signing_key), async {
            let SigningInput::EcdsaP256Sha256 { digest, .. } = input else {
                return Err(input.algorithm_mismatch(&self.signing_key, self.algorithm()));
            };
            let parameters = RequestContent::try_from(SignParameters {
                algorithm: Some(SignatureAlgorithm::Es256),
                value: Some(digest.to_vec()),
            })
            .map_err(|error| KmsAeadError::from_azure_error(error).into_signature_error())?;

            let signed = kms::timed("sign", self.signing_key.provider(), async {
                self.client
                    .sign(
                        &self.key_name,
                        parameters,
                        Some(KeyClientSignOptions {
                            key_version: Some(self.version.to_string()),
                            ..Default::default()
                        }),
                    )
                    .await
                    .and_then(|response| response.into_model())
                    .map_err(|error| KmsAeadError::from_azure_error(error).into_signature_error())
            })
            .await?;

            self.ensure_key(signed.resource_id().ok().as_ref())?;
            let signature = signed.result.ok_or_else(|| {
                KmsAeadSignatureError::create(
                    "SIGNATURE_ENCODING",
                    "The Azure Key Vault response holds no signature",
                )
            })?;
            RawSignature::new(self.algorithm(), signature)
        })
        .await
    }

    async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
        spans::in_span(kms::public_key_span(&self.signing_key), async {
            let key = kms::timed("public_key", self.signing_key.provider(), async {
                self.client
                    .get_key(
                        &self.key_name,
                        Some(KeyClientGetKeyOptions {
                            key_version: Some(self.version.to_string()),
                            ..Default::default()
                        }),
                    )
                    .await
                    .and_then(|response| response.into_model())
                    .map_err(|error| KmsAeadError::from_azure_error(error).into_signature_error())
            })
            .await?;
            self.verifying_key_from(&key)
        })
        .await
    }
}
