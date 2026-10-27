use std::fmt::{Debug, Formatter};
use std::num::NonZeroU32;
use std::path::Path;

use der::Decode;
use pkcs8::PrivateKeyInfoRef;
use secret_vault_value::SecretValue;

use super::local_key_source::{read_local_key_env, read_local_key_file};
use super::{KmsKeyVersion, LocalKekId, LocalKekVersion, LocalKekVersions, PublicKeyKekProvider};
use crate::asymmetric_kek::{ASYMMETRIC_KEK_RSA_BITS, RSA_ENCRYPTION};
use crate::backends::{AeadBackend, AeadBackendOps};
use crate::errors::{KmsAeadEncryptionError, KmsAeadSystemError, KmsAeadUnsupportedAlgorithmError};
use crate::formats::asymmetric::PublicKeyEncryptedDek;
use crate::formats::{PrivateKeyFormat, PublicKeyFormat};
use crate::spans::{self, kms};
use crate::{
    AsymmetricKekAlgorithm, AsymmetricKekPublicKey, DataEncryptionKey, EncryptedDataEncryptionKey,
    KekRef, KmsAeadDecryptionProvider, KmsAeadEncryptionProvider, KmsAeadResult, KmsProvider,
};

/// The size of the key [`LocalAsymmetricKmsProvider::ephemeral`] generates, the smallest an
/// asymmetric KEK takes, so that a test generates it fast.
const EPHEMERAL_RSA_KEY_BITS: usize = 2048;

/// One version of a local asymmetric KEK: an RSA private key of 2048, 3072 or 4096 bits in a
/// PKCS#8 `PrivateKeyInfo`, zeroised on drop; 2048 bits is deprecated and stays for the keys that
/// exist. The loaders are named as [`LocalKek`](super::LocalKek)'s and take the
/// [`PrivateKeyFormat`]: [`Pkcs8Der`](PrivateKeyFormat::Pkcs8Der), the DER, or
/// [`Pkcs8Pem`](PrivateKeyFormat::Pkcs8Pem), a `PRIVATE KEY` PEM block. The format is never
/// guessed from the bytes. A file or a variable holds at most 32 KiB, the one cap of every local
/// key of the two crates. `Debug` shows the version and the source, never the key.
pub struct LocalAsymmetricKek {
    version: LocalKekVersion,
    pkcs8_der: SecretValue,
    /// `ephemeral`, `file`, `env` or `secret`, with the format, for the log line of the provider.
    source: String,
}

impl LocalAsymmetricKek {
    /// A key the application already holds, as `key` in `format`, such as a credential the init
    /// system passes. The RSA key is parsed by the provider it is given to.
    ///
    /// # Errors
    ///
    /// `ASYMMETRIC_KEK_PRIVATE_KEY` when `key` is not in `format`, is encrypted, or is not an
    /// `rsaEncryption` key.
    pub fn from_secret(
        version: LocalKekVersion,
        key: SecretValue,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        Self::decode(version, key, format, "secret", "the secret")
    }

    /// Reads the key in `format` from a regular file of at most 32 KiB, with the checks of
    /// [`LocalKek::from_file`](super::LocalKek::from_file): the DER bytes for
    /// [`Pkcs8Der`](PrivateKeyFormat::Pkcs8Der), the PEM text for
    /// [`Pkcs8Pem`](PrivateKeyFormat::Pkcs8Pem). A symbolic link is followed, and no permission
    /// or ownership check runs.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_SOURCE` when the file cannot be read or is not a regular file,
    /// `LOCAL_KEK_LENGTH` when it is larger than 32 KiB, and the errors of
    /// [`from_secret`](Self::from_secret). The error names the path, never the content.
    pub fn from_file(
        version: LocalKekVersion,
        path: &Path,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        let origin = format!("the file {}", path.display());
        let content = read_local_key_file(path, &origin)
            .map_err(|error| error.into_error("LOCAL_KEK_SOURCE", "LOCAL_KEK_LENGTH"))?;
        Self::decode(version, content, format, "file", &origin)
    }

    /// Reads the key in `format` from the environment variable `variable`, with the limits of
    /// [`LocalKek::from_env`](super::LocalKek::from_env): the PEM text for
    /// [`Pkcs8Pem`](PrivateKeyFormat::Pkcs8Pem), and for
    /// [`Pkcs8Der`](PrivateKeyFormat::Pkcs8Der) the standard base64 of the DER, since a variable
    /// holds text. The variable stays in the process environment, as for `LocalKek::from_env`.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_SOURCE` when the variable is not set or is not base64 where base64 is expected,
    /// `LOCAL_KEK_LENGTH` when it is larger than 32 KiB, and the errors of
    /// [`from_secret`](Self::from_secret). The error names the variable, never its value.
    pub fn from_env(
        version: LocalKekVersion,
        variable: &str,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        let origin = format!("the environment variable {variable}");
        let content = read_local_key_env(variable, &origin)
            .map_err(|error| error.into_error("LOCAL_KEK_SOURCE", "LOCAL_KEK_LENGTH"))?;
        let content = format.decode_env_text(content).ok_or_else(|| {
            KmsAeadSystemError::create(
                "LOCAL_KEK_SOURCE",
                &format!("{origin} does not hold standard base64"),
            )
        })?;
        Self::decode(version, content, format, "env", &origin)
    }

    /// The key `content` holds in `format`, read from `origin`.
    fn decode(
        version: LocalKekVersion,
        content: SecretValue,
        format: PrivateKeyFormat,
        source: &str,
        origin: &str,
    ) -> KmsAeadResult<Self> {
        let invalid = |reason: &str| {
            KmsAeadSystemError::asymmetric_private_key(&format!(
                "The PKCS#8 key from {origin} {reason}"
            ))
        };
        let pkcs8_der = format.pkcs8_der(content).map_err(invalid)?;
        let info = PrivateKeyInfoRef::from_der(pkcs8_der.ref_sensitive_value())
            .map_err(|_| invalid("is not a DER PKCS#8 PrivateKeyInfo, or is encrypted"))?;
        if info.algorithm.oid != RSA_ENCRYPTION {
            return Err(invalid("is not an rsaEncryption key"));
        }
        let format = match format {
            PrivateKeyFormat::Pkcs8Der => "pkcs8-der",
            PrivateKeyFormat::Pkcs8Pem => "pkcs8-pem",
        };
        Ok(Self {
            version,
            pkcs8_der,
            source: format!("{source} ({format})"),
        })
    }
}

/// The version and the source.
impl Debug for LocalAsymmetricKek {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAsymmetricKek")
            .field("version", &self.version)
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// One version of a provider: the private key that decrypts and its public half that encrypts.
struct LocalAsymmetricVersion<B: AeadBackend> {
    private_key: <B as AeadBackendOps>::RsaPrivateKey,
    /// The modulus length of `private_key` in bytes, the length of every block it decrypts.
    block_len: usize,
    public_half: PublicKeyKekProvider<B>,
}

/// The local KMS with an asymmetric KEK: RSA private keys the process holds, one per version,
/// on the backend `B`, for development, tests and single-host installs, as
/// [`LocalKmsProvider`](super::LocalKmsProvider) is for a symmetric KEK. Its [`KekRef`] is
/// [`KmsProvider::Local`] and the id, as `LocalKmsProvider`'s, so an id names one KEK, symmetric
/// or asymmetric, never both. [`public_key`](Self::public_key) hands a version's public half to
/// the producers, whose DEKs this provider decrypts.
///
/// Each constructor logs one `INFO` event naming the KEK id, its versions, where each came from,
/// and the fingerprint of the version that encrypts, never a key.
///
/// # Encrypted keys
///
/// The highest version encrypts, or the one
/// [`with_encrypting_version`](Self::with_encrypting_version) names, and every version the
/// provider holds decrypts. The encrypted DEK is the layout of every DEK a public key encrypts:
///
/// ```text
/// [0x02][0x01][i: u8][KEK id: i bytes][k: u8][KEK version: k decimal digits][RSA block]
/// ```
///
/// # Limits
///
/// The limits of [`LocalKmsProvider`](super::LocalKmsProvider), and on the RustCrypto backend
/// the timing of the `rsa` crate's private-key operations,
/// [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html): a provider on
/// RustCrypto decrypts DEKs from trusted sources only, such as its own keyring record, and a
/// process that decrypts what others send runs on aws-lc-rs.
///
/// # Errors
///
/// An encryption fails with `RANDOM_GENERATOR` when the backend's CSPRNG fails. A decryption fails
/// with `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` when the key is not in the layout above or its block is
/// not of the length of its version's key, `LOCAL_KEK_ID_MISMATCH` when it was encrypted for
/// another KEK id, `LOCAL_KEK_UNKNOWN_VERSION` when the provider does not hold its version, and
/// `DECRYPT` when it is not a block of that version's key.
pub struct LocalAsymmetricKmsProvider<B: AeadBackend> {
    kek: KekRef,
    algorithm: AsymmetricKekAlgorithm,
    versions: LocalKekVersions<LocalAsymmetricVersion<B>>,
}

impl<B: AeadBackend> LocalAsymmetricKmsProvider<B> {
    /// A provider for the KEK `id` with the versions in `keks`, encrypting and decrypting with
    /// `algorithm` on the backend `B`. The highest version encrypts unless
    /// [`with_encrypting_version`](Self::with_encrypting_version) names another; every version
    /// listed decrypts.
    ///
    /// A 2048-bit key is deprecated: it is taken for the keys that exist, and a new key is of
    /// 3072 bits.
    ///
    /// # Errors
    ///
    /// [`UnsupportedAlgorithm`](crate::errors::KmsAeadError::UnsupportedAlgorithm) when `B` does
    /// not implement `algorithm`, as ring implements no RSA, `ASYMMETRIC_KEK_PRIVATE_KEY` for a key
    /// that is not an RSA key of 2048, 3072 or 4096 bits, and `LOCAL_KEK_VERSIONS` when `keks` is
    /// empty or lists a version twice.
    pub fn new(
        id: LocalKekId,
        algorithm: AsymmetricKekAlgorithm,
        keks: Vec<LocalAsymmetricKek>,
    ) -> KmsAeadResult<Self> {
        if !B::supports_asymmetric_kek(algorithm) {
            return Err(KmsAeadUnsupportedAlgorithmError::create(algorithm, B::NAME));
        }
        let kek = KekRef::new(KmsProvider::Local, id.to_string());
        let loaded = keks
            .into_iter()
            .map(|local_kek| {
                let version = local_kek.version;
                let held = Self::load(&kek, algorithm, &local_kek)?;
                Ok((version, local_kek.source, held))
            })
            .collect::<KmsAeadResult<Vec<_>>>()?;
        let provider = Self {
            kek,
            algorithm,
            versions: LocalKekVersions::new(id.clone(), loaded)?,
        };
        kms::local_asymmetric_kek_loaded(
            &id,
            &provider.versions.listing(),
            &KmsKeyVersion::from(provider.versions.encrypting_version()),
            provider.encrypting()?.public_half.fingerprint(),
        );
        Ok(provider)
    }

    /// The private key of `local_kek` parsed on `B`, and its public half.
    fn load(
        kek: &KekRef,
        algorithm: AsymmetricKekAlgorithm,
        local_kek: &LocalAsymmetricKek,
    ) -> KmsAeadResult<LocalAsymmetricVersion<B>> {
        let refused = |reason: &str| {
            KmsAeadSystemError::asymmetric_private_key(&format!(
                "Version {} of the local KEK {} {reason}",
                local_kek.version,
                kek.key()
            ))
        };
        let private_key = B::rsa_private_key(local_kek.pkcs8_der.ref_sensitive_value())
            .map_err(|_| refused(&format!("is a key the {} backend refuses", B::NAME)))?;
        let bits = B::rsa_private_key_bits(&private_key);
        if !ASYMMETRIC_KEK_RSA_BITS.contains(&bits) {
            return Err(refused(&format!(
                "is an RSA key of {bits} bits, not of 2048, 3072 or 4096"
            )));
        }
        let spki_der = B::rsa_public_key_der(&private_key)
            .map_err(|_| refused("has a public half the backend cannot write"))?;
        let public_key = AsymmetricKekPublicKey::new(
            kek.clone(),
            Some(KmsKeyVersion::from(local_kek.version)),
            algorithm,
            spki_der,
            PublicKeyFormat::SpkiDer,
        )?;
        Ok(LocalAsymmetricVersion {
            private_key,
            block_len: bits / 8,
            public_half: PublicKeyKekProvider::parse(public_key)?,
        })
    }

    /// The provider with `version` encrypting new DEKs in place of the highest version listed,
    /// which every version listed still decrypts beside, as
    /// [`LocalKmsProvider::with_encrypting_version`](super::LocalKmsProvider::with_encrypting_version).
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when the provider does not list `version`.
    pub fn with_encrypting_version(mut self, version: LocalKekVersion) -> KmsAeadResult<Self> {
        self.versions = self.versions.with_encrypting_version(version)?;
        Ok(self)
    }

    /// A provider with one generated version-1 key of 2048 bits, the smallest the algorithm
    /// takes, that lives as long as the provider: the DEKs it encrypts cannot be decrypted once the
    /// process exits. For tests.
    ///
    /// # Errors
    ///
    /// [`UnsupportedAlgorithm`](crate::errors::KmsAeadError::UnsupportedAlgorithm) as for
    /// [`new`](Self::new), and `RANDOM_GENERATOR` when the key cannot be generated.
    pub fn ephemeral(id: LocalKekId, algorithm: AsymmetricKekAlgorithm) -> KmsAeadResult<Self> {
        if !B::supports_asymmetric_kek(algorithm) {
            return Err(KmsAeadUnsupportedAlgorithmError::create(algorithm, B::NAME));
        }
        let pkcs8_der = B::generate_rsa_private_key(EPHEMERAL_RSA_KEY_BITS).map_err(|_| {
            KmsAeadEncryptionError::create("RANDOM_GENERATOR", "Unable to generate an RSA key")
        })?;
        let kek = LocalAsymmetricKek {
            version: LocalKekVersion::from(NonZeroU32::MIN),
            pkcs8_der,
            source: "ephemeral".to_string(),
        };
        Self::new(id, algorithm, vec![kek])
    }

    /// The public half of `version`, or of the encrypting version for `None`, for the producers.
    ///
    /// # Errors
    ///
    /// `LOCAL_KEK_VERSIONS` when the provider does not list `version`.
    pub fn public_key(
        &self,
        version: Option<LocalKekVersion>,
    ) -> KmsAeadResult<AsymmetricKekPublicKey> {
        let version = version.unwrap_or(self.versions.encrypting_version());
        self.versions
            .get(version)
            .map(|held| held.public_half.public_key().clone())
            .ok_or_else(|| {
                KmsAeadSystemError::create(
                    "LOCAL_KEK_VERSIONS",
                    &format!("The local KEK {} has no version {version}", self.kek.key()),
                )
            })
    }

    /// The version that encrypts.
    fn encrypting(&self) -> KmsAeadResult<&LocalAsymmetricVersion<B>> {
        let encrypting_version = self.versions.encrypting_version();
        self.versions.get(encrypting_version).ok_or_else(|| {
            KmsAeadSystemError::create(
                "LOCAL_KEK_VERSIONS",
                &format!(
                    "The local KEK {} has no version {encrypting_version}",
                    self.kek.key()
                ),
            )
        })
    }

    /// The block `encrypted_dek` holds and the version that decrypts it, in the span of the
    /// caller, which records the version.
    fn decrypting<'e>(
        &self,
        encrypted_dek: &'e EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<(&LocalAsymmetricVersion<B>, &'e [u8])> {
        let public_key_dek =
            PublicKeyEncryptedDek::read(encrypted_dek.value()).ok_or_else(|| {
                PublicKeyEncryptedDek::malformed(
                    "is not in the layout of a DEK a public key encrypts",
                )
            })??;
        if public_key_dek.algorithm != self.algorithm {
            return Err(PublicKeyEncryptedDek::malformed(&format!(
                "names {}, and the local KEK decrypts with {}",
                public_key_dek.algorithm, self.algorithm
            )));
        }
        if public_key_dek.kek_id != self.kek.key().as_bytes() {
            return Err(KmsAeadEncryptionError::create(
                "LOCAL_KEK_ID_MISMATCH",
                &format!(
                    "The key was encrypted for another local KEK than {}",
                    self.kek.key()
                ),
            ));
        }
        let version = public_key_dek
            .kek_version
            .as_ref()
            .and_then(KmsKeyVersion::local_kek_version)
            .ok_or_else(|| PublicKeyEncryptedDek::malformed("names no local KEK version"))?;
        kms::record_kek_version(&version.to_string());
        let held = self.versions.get(version).ok_or_else(|| {
            KmsAeadEncryptionError::create(
                "LOCAL_KEK_UNKNOWN_VERSION",
                &format!("The local KEK {} has no version {version}", self.kek.key()),
            )
        })?;
        if public_key_dek.block.len() != held.block_len {
            return Err(PublicKeyEncryptedDek::malformed(&format!(
                "has a block of {} bytes, and version {version} decrypts blocks of {}",
                public_key_dek.block.len(),
                held.block_len
            )));
        }
        Ok((held, public_key_dek.block))
    }
}

/// The KEK, the algorithm, the versions and the version that encrypts, never a key.
impl<B: AeadBackend> Debug for LocalAsymmetricKmsProvider<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalAsymmetricKmsProvider")
            .field("kek", &self.kek)
            .field("algorithm", &self.algorithm)
            .field("versions", &self.versions.versions().collect::<Vec<_>>())
            .field("encrypting_version", &self.versions.encrypting_version())
            .finish()
    }
}

impl<B: AeadBackend> KmsAeadEncryptionProvider for LocalAsymmetricKmsProvider<B> {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(&self.kek), async {
            self.encrypting()?.public_half.encrypt_dek(dek).await
        })
        .await
    }

    fn encrypts_with_public_key(&self) -> bool {
        true
    }
}

impl<B: AeadBackend> KmsAeadDecryptionProvider for LocalAsymmetricKmsProvider<B> {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        spans::in_span(kms::decrypt_span(&self.kek), async {
            let (held, block) = self.decrypting(encrypted_dek)?;
            let dek = kms::timed("decrypt_dek", self.kek.provider(), async {
                B::rsa_oaep_sha256_decrypt(&held.private_key, block)
                    .map_err(crate::backends::Failure::decrypting)
            })
            .await?;
            Ok(DataEncryptionKey::from(dek))
        })
        .await
    }
}

#[cfg(test)]
#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
mod tests {
    use super::*;
    use crate::test_provider::{
        assert_code, renderings, RsaOaepSuite, RsaTestBackend, RSA_1024_PKCS8_DER,
    };

    const ORDERS: &str = "orders";

    fn local_kek_version(version: u32) -> LocalKekVersion {
        LocalKekVersion::from(NonZeroU32::new(version).unwrap())
    }

    fn orders() -> LocalKekId {
        LocalKekId::try_from(ORDERS.to_string()).unwrap()
    }

    fn provider_of<B: AeadBackend>(
        keks: Vec<LocalAsymmetricKek>,
    ) -> KmsAeadResult<LocalAsymmetricKmsProvider<B>> {
        LocalAsymmetricKmsProvider::new(orders(), AsymmetricKekAlgorithm::RsaOaepSha256, keks)
    }

    /// The provider of the Wycheproof key of `bits` bits under `kek_version`.
    fn wycheproof_provider<B: AeadBackend>(
        bits: usize,
        kek_version: u32,
    ) -> KmsAeadResult<LocalAsymmetricKmsProvider<B>> {
        provider_of(vec![LocalAsymmetricKek::from_secret(
            local_kek_version(kek_version),
            RsaOaepSuite::of_bits(bits).pkcs8_der(),
            PrivateKeyFormat::Pkcs8Der,
        )?])
    }

    /// `block` behind the header of the provider's KEK id and `kek_version`.
    fn encrypted_for_orders(kek_version: &str, block: &[u8]) -> EncryptedDataEncryptionKey {
        EncryptedDataEncryptionKey::new(
            PublicKeyEncryptedDek {
                algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                kek_id: ORDERS.as_bytes(),
                kek_version: Some(KmsKeyVersion::try_from(kek_version.to_string()).unwrap()),
                block,
            }
            .to_bytes()
            .unwrap(),
        )
    }

    /// Every valid case without a label decrypts to its message. Every other one fails: with
    /// `DECRYPT` when its block has the key's length, and at the header otherwise, a case with a
    /// label among them, since the KEK's label is empty.
    async fn wycheproof_cases_decrypt_as_the_suite_says<B: AeadBackend>() -> KmsAeadResult<()> {
        let mut checked = 0;
        for bits in ASYMMETRIC_KEK_RSA_BITS {
            let provider = wycheproof_provider::<B>(bits, 1)?;
            for case in RsaOaepSuite::of_bits(bits).cases() {
                let block = hex::decode(&case.ct).unwrap();
                let result = provider
                    .decrypt_data_encryption_key(&encrypted_for_orders("1", &block))
                    .await;
                let context = format!("{} {bits} tcId {}", B::NAME, case.tc_id);
                match (case.result.as_str(), case.label.is_empty()) {
                    ("valid", true) => assert_eq!(
                        hex::encode(result?.value().ref_sensitive_value()),
                        case.msg,
                        "{context}"
                    ),
                    _ if block.len() == bits / 8 => assert_code(result, "DECRYPT"),
                    _ => assert_code(result, "ASYMMETRIC_ENCRYPTED_DEK_FORMAT"),
                }
                checked += 1;
            }
        }
        assert_eq!(checked, 3 * 37);
        Ok(())
    }

    #[cfg(feature = "aws-lc-rs")]
    #[tokio::test]
    async fn wycheproof_cases_decrypt_as_the_suite_says_on_aws_lc() -> KmsAeadResult<()> {
        wycheproof_cases_decrypt_as_the_suite_says::<crate::backends::AwsLc>().await
    }

    #[cfg(feature = "rustcrypto")]
    #[tokio::test]
    async fn wycheproof_cases_decrypt_as_the_suite_says_on_rustcrypto() -> KmsAeadResult<()> {
        wycheproof_cases_decrypt_as_the_suite_says::<crate::backends::RustCrypto>().await
    }

    /// An encryption on one backend decrypts on every other, under one key pair.
    #[cfg(all(feature = "aws-lc-rs", feature = "rustcrypto"))]
    #[tokio::test]
    async fn an_encryption_on_one_backend_decrypts_on_the_other() -> KmsAeadResult<()> {
        use crate::backends::{AwsLc, RustCrypto};
        let aws_lc = wycheproof_provider::<AwsLc>(3072, 2)?;
        let rust_crypto = wycheproof_provider::<RustCrypto>(3072, 2)?;
        let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; 34]));

        let by_aws_lc = aws_lc.encrypt_data_encryption_key(&dek).await?;
        let by_rust_crypto = rust_crypto.encrypt_data_encryption_key(&dek).await?;

        assert_eq!(
            rust_crypto.decrypt_data_encryption_key(&by_aws_lc).await?,
            dek
        );
        assert_eq!(
            aws_lc.decrypt_data_encryption_key(&by_rust_crypto).await?,
            dek
        );
        Ok(())
    }

    /// The layout of the local KMS pinned byte for byte, with a 10-byte KEK id, version 7 and the
    /// block of Wycheproof's 2048-bit case 7, which the provider decrypts to the case's message.
    #[tokio::test]
    async fn a_golden_local_encrypted_dek_decrypts_to_its_message() -> KmsAeadResult<()> {
        // [0x02][0x01: RSA-OAEP-SHA256][10]["orders-eu1"][1]["7"]
        const HEADER: &str = "02010a6f72646572732d6575310137";
        let suite = RsaOaepSuite::of_bits(2048);
        let case = suite.case(7);
        let block = hex::decode(&case.ct).unwrap();
        let provider = LocalAsymmetricKmsProvider::<RsaTestBackend>::new(
            LocalKekId::try_from("orders-eu1".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
            vec![LocalAsymmetricKek::from_secret(
                local_kek_version(7),
                suite.pkcs8_der(),
                PrivateKeyFormat::Pkcs8Der,
            )?],
        )?;
        let encrypted_dek =
            EncryptedDataEncryptionKey::try_from_hex_string(&format!("{HEADER}{}", case.ct))?;

        let dek = provider.decrypt_data_encryption_key(&encrypted_dek).await?;

        assert_eq!(hex::encode(dek.value().ref_sensitive_value()), case.msg);
        assert_eq!(
            PublicKeyEncryptedDek {
                algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                kek_id: b"orders-eu1",
                kek_version: Some(KmsKeyVersion::from(local_kek_version(7))),
                block: &block,
            }
            .to_bytes()?,
            encrypted_dek.value()
        );
        Ok(())
    }

    /// Each refusal of the local reader, before the private key is used.
    #[tokio::test]
    async fn a_local_reader_refuses_another_kek_version_or_block_shape() -> KmsAeadResult<()> {
        let provider = wycheproof_provider::<RsaTestBackend>(2048, 7)?;
        let block = [0xB1; 256];
        let another_kek = EncryptedDataEncryptionKey::new(
            PublicKeyEncryptedDek {
                algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                kek_id: b"invoices",
                kek_version: Some(KmsKeyVersion::try_from("7".to_string())?),
                block: &block,
            }
            .to_bytes()?,
        );
        let cloud = EncryptedDataEncryptionKey::new(
            PublicKeyEncryptedDek {
                algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                kek_id: b"",
                kek_version: Some(KmsKeyVersion::try_from("7".to_string())?),
                block: &block,
            }
            .to_bytes()?,
        );
        let refusals = [
            (another_kek, "LOCAL_KEK_ID_MISMATCH"),
            (cloud, "LOCAL_KEK_ID_MISMATCH"),
            (
                encrypted_for_orders("07", &block),
                "ASYMMETRIC_ENCRYPTED_DEK_FORMAT",
            ),
            (
                encrypted_for_orders("7a", &block),
                "ASYMMETRIC_ENCRYPTED_DEK_FORMAT",
            ),
            (
                encrypted_for_orders("8", &block),
                "LOCAL_KEK_UNKNOWN_VERSION",
            ),
            (
                encrypted_for_orders("7", &[0xB1; 384]),
                "ASYMMETRIC_ENCRYPTED_DEK_FORMAT",
            ),
            (
                EncryptedDataEncryptionKey::new(vec![0x01, 0x06]),
                "ASYMMETRIC_ENCRYPTED_DEK_FORMAT",
            ),
        ];
        for (encrypted_dek, code) in refusals {
            assert_code(
                provider.decrypt_data_encryption_key(&encrypted_dek).await,
                code,
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_highest_version_encrypts_and_every_version_decrypts() -> KmsAeadResult<()> {
        let key = |bits, kek_version| {
            LocalAsymmetricKek::from_secret(
                local_kek_version(kek_version),
                RsaOaepSuite::of_bits(bits).pkcs8_der(),
                PrivateKeyFormat::Pkcs8Der,
            )
        };
        let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; 34]));
        let old = provider_of::<RsaTestBackend>(vec![key(2048, 1)?])?;
        let old_encrypted_dek = old.encrypt_data_encryption_key(&dek).await?;
        let rotated = provider_of::<RsaTestBackend>(vec![key(3072, 2)?, key(2048, 1)?])?;

        let new_encrypted_dek = rotated.encrypt_data_encryption_key(&dek).await?;
        let rolled_back = rotated.with_encrypting_version(local_kek_version(1))?;

        assert_eq!(
            new_encrypted_dek.kek_version(),
            Some(&KmsKeyVersion::try_from("2".to_string())?)
        );
        assert_eq!(new_encrypted_dek.value().len(), 4 + ORDERS.len() + 1 + 384);
        for encrypted_dek in [&old_encrypted_dek, &new_encrypted_dek] {
            assert_eq!(
                rolled_back
                    .decrypt_data_encryption_key(encrypted_dek)
                    .await?,
                dek
            );
        }
        assert_eq!(
            rolled_back.public_key(None)?,
            rolled_back.public_key(Some(local_kek_version(1)))?
        );
        assert_code(
            rolled_back.public_key(Some(local_kek_version(3))),
            "LOCAL_KEK_VERSIONS",
        );
        Ok(())
    }

    #[test]
    fn a_key_is_read_in_either_pkcs8_format_and_any_other_key_is_refused() -> KmsAeadResult<()> {
        let pkcs8_der = RsaOaepSuite::of_bits(2048).pkcs8_der();
        let pem = pem_rfc7468::encode_string(
            PrivateKeyFormat::PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            pkcs8_der.ref_sensitive_value(),
        )
        .unwrap();
        let from_der = provider_of::<RsaTestBackend>(vec![LocalAsymmetricKek::from_secret(
            local_kek_version(1),
            pkcs8_der.clone(),
            PrivateKeyFormat::Pkcs8Der,
        )?])?;
        let from_pem = provider_of::<RsaTestBackend>(vec![LocalAsymmetricKek::from_secret(
            local_kek_version(1),
            SecretValue::from(pem.as_str()),
            PrivateKeyFormat::Pkcs8Pem,
        )?])?;

        assert_eq!(from_der.public_key(None)?, from_pem.public_key(None)?);
        let ed25519 =
            SecretValue::new(hex::decode(crate::test_provider::ED25519_PKCS8_DER).unwrap());
        for (key, format) in [
            (pkcs8_der.clone(), PrivateKeyFormat::Pkcs8Pem),
            (SecretValue::from(pem.as_str()), PrivateKeyFormat::Pkcs8Der),
            (ed25519, PrivateKeyFormat::Pkcs8Der),
        ] {
            assert_code(
                LocalAsymmetricKek::from_secret(local_kek_version(1), key, format),
                "ASYMMETRIC_KEK_PRIVATE_KEY",
            );
        }
        Ok(())
    }

    /// The deprecated 2048 bits is the smallest key taken.
    #[test]
    fn a_1024_bit_key_is_refused() -> KmsAeadResult<()> {
        let kek = LocalAsymmetricKek::from_secret(
            local_kek_version(1),
            SecretValue::new(hex::decode(RSA_1024_PKCS8_DER).unwrap()),
            PrivateKeyFormat::Pkcs8Der,
        )?;

        assert_code(
            provider_of::<RsaTestBackend>(vec![kek]),
            "ASYMMETRIC_KEK_PRIVATE_KEY",
        );
        Ok(())
    }

    #[test]
    fn debug_shows_no_key() -> KmsAeadResult<()> {
        let pkcs8_der = RsaOaepSuite::of_bits(2048).pkcs8_der();
        let kek = LocalAsymmetricKek::from_secret(
            local_kek_version(1),
            pkcs8_der.clone(),
            PrivateKeyFormat::Pkcs8Der,
        )?;
        let kek_debug = format!("{kek:?}");
        let debug = format!(
            "{kek_debug} {:?}",
            provider_of::<RsaTestBackend>(vec![kek])?
        );

        for rendering in renderings(&pkcs8_der.ref_sensitive_value()[40..72]) {
            assert!(!debug.contains(&rendering), "{debug}");
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    #[test]
    fn ring_refuses_rsa_at_construction() {
        use crate::backends::Ring;
        use crate::errors::KmsAeadError;
        use crate::BackendAlgorithm;
        let unsupported = |result: KmsAeadResult<LocalAsymmetricKmsProvider<Ring>>| {
            matches!(result, Err(KmsAeadError::UnsupportedAlgorithm(error))
                if error.algorithm
                    == BackendAlgorithm::AsymmetricKek(AsymmetricKekAlgorithm::RsaOaepSha256))
        };

        assert!(unsupported(LocalAsymmetricKmsProvider::ephemeral(
            orders(),
            AsymmetricKekAlgorithm::RsaOaepSha256
        )));
        assert!(unsupported(provider_of(vec![])));
    }
}
