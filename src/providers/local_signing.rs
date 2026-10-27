use std::collections::BTreeMap;
use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;
use std::num::NonZeroU32;
use std::path::Path;

use secret_vault_value::SecretValue;

use super::local_key_source::{read_local_key_env, read_local_key_file};
use crate::backends::AeadBackend;
use crate::errors::{KmsAeadError, KmsAeadSignatureError, KmsAeadSystemError};
use crate::formats::PrivateKeyFormat;
use crate::signing::private_key::Pkcs8SigningKey;
use crate::signing::{
    KmsSigningProvider, RawSignature, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
    VerifyingKeySet,
};
use crate::spans::{self, kms};
use crate::{KeyId, KmsAeadResult, KmsProvider};

/// The name of a local signing key: 1 to 255 bytes of ASCII alphanumerics, `-`, `_` and `.`, the
/// `key` of its provider's [`SigningKeyRef`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LocalSigningKeyName(String);

impl TryFrom<String> for LocalSigningKeyName {
    type Error = KmsAeadError;

    /// # Errors
    ///
    /// `INVALID_LOCAL_SIGNING_KEY_NAME` when the id is empty, longer than 255 bytes, or holds
    /// another character.
    fn try_from(value: String) -> KmsAeadResult<Self> {
        let valid = (1..=usize::from(u8::MAX)).contains(&value.len())
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
        if valid {
            Ok(Self(value))
        } else {
            Err(KmsAeadSystemError::create(
                "INVALID_LOCAL_SIGNING_KEY_NAME",
                &format!(
                    "A local signing key id of {} bytes is not 1 to 255 ASCII alphanumerics, '-', \
                     '_' or '.'",
                    value.len()
                ),
            ))
        }
    }
}

impl Display for LocalSigningKeyName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The version of a local signing key. The highest version a [`LocalSigningProvider`] holds
/// signs unless the provider is set to sign with another; every version's public key is exported.
/// The version is for the operator and the logs: no signature carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct LocalSigningKeyVersion(NonZeroU32);

impl From<NonZeroU32> for LocalSigningKeyVersion {
    fn from(version: NonZeroU32) -> Self {
        Self(version)
    }
}

/// The version in decimal.
impl Display for LocalSigningKeyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// One version of a local signing key: the private key, zeroised on drop, and its public key.
/// `Debug` shows the version, the algorithm, the key id and where the key came from, never the
/// key.
///
/// A key is read from a PKCS#8 `PrivateKeyInfo`, the container `openssl genpkey` writes, in the
/// [`PrivateKeyFormat`] the caller names: an `id-Ed25519` key, the 32-byte seed, or an
/// `id-ecPublicKey` key on `prime256v1`, the 32-byte scalar with its public point. The algorithm
/// comes from the document, and the format is never guessed from the bytes. A file or a variable
/// holds at most 32 KiB, the one cap of every local key of the two crates.
pub struct LocalSigningKey {
    version: LocalSigningKeyVersion,
    private_key: SecretValue,
    verifying_key: VerifyingKey,
    /// `ephemeral`, `file`, `env` or `secret`, for the log line of the provider.
    source: &'static str,
    /// The format the key was read in, or `None` for a generated key.
    format: Option<PrivateKeyFormat>,
}

impl LocalSigningKey {
    /// `key` as a PKCS#8 `PrivateKeyInfo` in `format`, parsed with the `pkcs8`, `sec1` and
    /// `pem-rfc7468` crates: the bytes an application already holds, such as a credential the
    /// init system passes. Both [`PrivateKeyFormat`] variants are taken.
    ///
    /// # Errors
    ///
    /// `LOCAL_SIGNING_KEY_FORMAT` for bytes that are not the format, another algorithm, an
    /// encrypted PKCS#8 or a P-256 key without its public point.
    pub fn from_secret(
        version: LocalSigningKeyVersion,
        key: SecretValue,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        Self::decode(version, key, format, "secret", "the secret")
    }

    /// The key read from a regular file of at most 32 KiB: the DER bytes for
    /// [`Pkcs8Der`](PrivateKeyFormat::Pkcs8Der), the PEM text for
    /// [`Pkcs8Pem`](PrivateKeyFormat::Pkcs8Pem). A symbolic link is followed, and no
    /// permission or ownership check runs.
    ///
    /// # Errors
    ///
    /// `LOCAL_SIGNING_KEY_SOURCE` when the file cannot be read, is not a regular file or is
    /// larger, then the errors of [`from_secret`](Self::from_secret). The error names the path,
    /// never the content.
    pub fn from_file(
        version: LocalSigningKeyVersion,
        path: &Path,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        let origin = format!("the file {}", path.display());
        let content = read_local_key_file(path, &origin).map_err(|error| {
            error.into_error("LOCAL_SIGNING_KEY_SOURCE", "LOCAL_SIGNING_KEY_SOURCE")
        })?;
        Self::decode(version, content, format, "file", &origin)
    }

    /// The key read from the environment variable `variable`, under the same cap: the standard
    /// base64 of the DER for [`Pkcs8Der`](PrivateKeyFormat::Pkcs8Der), since a variable holds
    /// text, and the PEM itself for [`Pkcs8Pem`](PrivateKeyFormat::Pkcs8Pem). The variable stays
    /// in the process environment, as for `LocalKek::from_env`.
    ///
    /// # Errors
    ///
    /// `LOCAL_SIGNING_KEY_SOURCE` when it is unset, larger or not base64 where base64 is
    /// expected, then the errors of [`from_secret`](Self::from_secret). The error names the
    /// variable, never its value.
    pub fn from_env(
        version: LocalSigningKeyVersion,
        variable: &str,
        format: PrivateKeyFormat,
    ) -> KmsAeadResult<Self> {
        let origin = format!("the environment variable {variable}");
        let content = read_local_key_env(variable, &origin).map_err(|error| {
            error.into_error("LOCAL_SIGNING_KEY_SOURCE", "LOCAL_SIGNING_KEY_SOURCE")
        })?;
        let content = format.decode_env_text(content).ok_or_else(|| {
            KmsAeadSystemError::create(
                "LOCAL_SIGNING_KEY_SOURCE",
                &format!("{origin} does not hold standard base64"),
            )
        })?;
        Self::decode(version, content, format, "env", &origin)
    }

    /// The key `content` holds in `format`, read from `origin`.
    fn decode(
        version: LocalSigningKeyVersion,
        content: SecretValue,
        format: PrivateKeyFormat,
        source: &'static str,
        origin: &str,
    ) -> KmsAeadResult<Self> {
        let invalid = |reason: &str| {
            KmsAeadSystemError::create(
                "LOCAL_SIGNING_KEY_FORMAT",
                &format!("The PKCS#8 key from {origin} {reason}"),
            )
        };
        let der = format.pkcs8_der(content).map_err(invalid)?;
        let key = Pkcs8SigningKey::from_der(der.ref_sensitive_value()).map_err(invalid)?;
        let public_key = match (key.algorithm, key.public_key) {
            (SigningAlgorithm::EcdsaP256Sha256, Some(public_key)) => public_key,
            (SigningAlgorithm::Ed25519, carried) => {
                let derived =
                    ed25519_public_key(key.private_key.ref_sensitive_value()).map_err(invalid)?;
                if carried.is_some_and(|carried| carried != derived) {
                    return Err(invalid("carries a public key of another seed"));
                }
                derived
            }
            (SigningAlgorithm::EcdsaP256Sha256, None) => {
                return Err(invalid("holds a P-256 key without its public point"))
            }
        };
        let verifying_key = VerifyingKey::from_raw(key.algorithm, public_key)
            .map_err(|_| invalid("holds a public key that is not one of its algorithm"))?;
        Ok(Self {
            version,
            private_key: key.private_key,
            verifying_key,
            source,
            format: Some(format),
        })
    }

    /// The same key under `key_id` in place of the derived id.
    pub fn with_key_id(self, key_id: KeyId) -> Self {
        Self {
            verifying_key: self.verifying_key.with_key_id(key_id),
            ..self
        }
    }

    /// The version.
    pub fn local_signing_key_version(&self) -> LocalSigningKeyVersion {
        self.version
    }

    /// The algorithm the key's PKCS#8 names.
    pub fn algorithm(&self) -> SigningAlgorithm {
        self.verifying_key.algorithm()
    }

    /// The public key, under the key's key id.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// `secret (pkcs8-pem)`, `ephemeral`: where the key came from, for the provider's log line.
    fn origin(&self) -> String {
        match self.format {
            Some(PrivateKeyFormat::Pkcs8Der) => format!("{} (pkcs8-der)", self.source),
            Some(PrivateKeyFormat::Pkcs8Pem) => format!("{} (pkcs8-pem)", self.source),
            None => self.source.to_string(),
        }
    }
}

/// The public key of the Ed25519 `seed`, derived on the build's backend, which every backend
/// derives alike, or why it cannot be.
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
fn ed25519_public_key(seed: &[u8]) -> Result<Vec<u8>, &'static str> {
    use crate::backends::{AeadBackendOps, AnyBackend};
    AnyBackend::ed25519_public_key(seed)
        .map(Vec::from)
        .map_err(|_| "holds an Ed25519 seed the backend refuses")
}

#[cfg(not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")))]
fn ed25519_public_key(_seed: &[u8]) -> Result<Vec<u8>, &'static str> {
    Err("is an Ed25519 key, whose public key a build without a crypto backend cannot derive")
}

/// The version, the algorithm, the key id and the source.
impl Debug for LocalSigningKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalSigningKey")
            .field("version", &self.version)
            .field("algorithm", &self.algorithm())
            .field("key_id", &self.verifying_key.key_id().as_u32())
            .field("source", &self.origin())
            .finish_non_exhaustive()
    }
}

/// Signs with a private key the process holds, on the backend `B`: for development, tests and
/// single-host installs, as [`LocalKmsProvider`](super::LocalKmsProvider) is for KEKs. Its
/// `SigningKeyRef` is [`KmsProvider::Local`] and the key id; its `sign` never fails with a
/// network error, and its `verifying_key` makes no call.
///
/// kms-aead builds one only when the application calls one of its constructors. Each logs one
/// `INFO` event naming the key id and its versions, with each version's algorithm, key id, format
/// and source, never the key.
///
/// # Rotation
///
/// The highest version signs, or the one
/// [`with_signing_version`](Self::with_signing_version) names, and
/// [`verifying_keys`](Self::verifying_keys) exports every version's public key. A rotation is two
/// deploys: list the new version while the current one signs and publish the new public key, then
/// let the new version sign. Dropping a version from the list stops its export.
///
/// # Limits
///
/// - the private key is in process memory for the life of the provider: whoever reads that
///   memory, a core dump or a swap file included, signs as the application does;
/// - no IAM, no audit log and no HSM: the key file or variable is the operator's to protect;
/// - a compromise is revoked by removing the key from every verifier's set;
/// - the ECDSA nonce on ring and aws-lc-rs comes from the system CSPRNG, and p256 derives it as
///   RFC 6979 does; Ed25519 is deterministic on every backend;
/// - ring does not zeroise its key pairs, which it builds for each signature.
#[derive(Debug)]
pub struct LocalSigningProvider<B> {
    signing_key: SigningKeyRef,
    /// The version that signs.
    signing: LocalSigningKey,
    /// Every other version, whose public keys are exported.
    others: BTreeMap<LocalSigningKeyVersion, LocalSigningKey>,
    /// The public keys of every version, in the order of their versions.
    verifying_keys: VerifyingKeySet,
    backend: PhantomData<B>,
}

impl<B: AeadBackend> LocalSigningProvider<B> {
    /// A provider for the key `id` with the versions in `keys`, signing on the backend `B`.
    ///
    /// # Errors
    ///
    /// `LOCAL_SIGNING_KEY_VERSIONS` when `keys` is empty or lists a version twice,
    /// `LOCAL_SIGNING_KEY_FORMAT` when the backend refuses a key, and `DUPLICATE_KEY_ID` when two
    /// versions share a key id.
    pub fn new(id: LocalSigningKeyName, keys: Vec<LocalSigningKey>) -> KmsAeadResult<Self> {
        let mut by_version = BTreeMap::new();
        for key in keys {
            B::check_signing_key(
                key.algorithm(),
                key.private_key.ref_sensitive_value(),
                key.verifying_key.public_key(),
            )
            .map_err(|_| {
                KmsAeadSystemError::create(
                    "LOCAL_SIGNING_KEY_FORMAT",
                    &format!(
                        "The {} backend refuses version {} of the local signing key {id}",
                        B::NAME,
                        key.version
                    ),
                )
            })?;
            let version = key.version;
            if by_version.insert(version, key).is_some() {
                return Err(KmsAeadSystemError::create(
                    "LOCAL_SIGNING_KEY_VERSIONS",
                    &format!("The local signing key {id} lists version {version} twice"),
                ));
            }
        }
        let verifying_keys =
            VerifyingKeySet::new(by_version.values().map(|key| key.verifying_key.clone()))?;

        let versions = by_version
            .values()
            .map(|key| {
                format!(
                    "{} ({}, key id {}, {})",
                    key.version,
                    key.algorithm(),
                    key.verifying_key.key_id().as_u32(),
                    key.origin()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let Some((_, signing)) = by_version.pop_last() else {
            return Err(KmsAeadSystemError::create(
                "LOCAL_SIGNING_KEY_VERSIONS",
                &format!("The local signing key {id} has no version"),
            ));
        };
        kms::local_signing_key_loaded(&id, &versions);

        Ok(Self {
            signing_key: SigningKeyRef::new(KmsProvider::Local, id.to_string()),
            signing,
            others: by_version,
            verifying_keys,
            backend: PhantomData,
        })
    }

    /// A provider with one random version-1 key of `algorithm` from the CSPRNG of `B`, which
    /// lives as long as the provider: its signatures verify only against a set that holds its
    /// verifying key, so a test builds the verifier from the provider. For tests.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn ephemeral(id: LocalSigningKeyName, algorithm: SigningAlgorithm) -> KmsAeadResult<Self> {
        let (private_key, public_key) = B::generate_signing_key(algorithm).map_err(|_| {
            KmsAeadSystemError::create(
                "RANDOM_GENERATOR",
                &format!("Unable to generate a {algorithm} key"),
            )
        })?;
        let key = LocalSigningKey {
            version: LocalSigningKeyVersion(NonZeroU32::MIN),
            private_key,
            verifying_key: VerifyingKey::from_raw(algorithm, public_key)?,
            source: "ephemeral",
            format: None,
        };
        Self::new(id, vec![key])
    }

    /// The provider with `version` signing in place of the highest version listed. A rotation
    /// lists the new version and publishes its public key while an older one signs, then makes
    /// the new one sign once every verifier holds it.
    ///
    /// # Errors
    ///
    /// `LOCAL_SIGNING_KEY_VERSIONS` when the provider does not hold `version`.
    pub fn with_signing_version(mut self, version: LocalSigningKeyVersion) -> KmsAeadResult<Self> {
        if version == self.signing.version {
            return Ok(self);
        }
        let Some(signing) = self.others.remove(&version) else {
            return Err(KmsAeadSystemError::create(
                "LOCAL_SIGNING_KEY_VERSIONS",
                &format!(
                    "The local signing key {} does not list version {version} to sign with",
                    self.signing_key.key()
                ),
            ));
        };
        let previous = std::mem::replace(&mut self.signing, signing);
        self.others.insert(previous.version, previous);
        Ok(self)
    }

    /// The version that signs.
    pub fn signing_version(&self) -> LocalSigningKeyVersion {
        self.signing.version
    }

    /// The public keys of every version, in the order of their versions, for the published set.
    pub fn verifying_keys(&self) -> VerifyingKeySet {
        self.verifying_keys.clone()
    }
}

impl<B: AeadBackend> KmsSigningProvider for LocalSigningProvider<B> {
    fn signing_key(&self) -> &SigningKeyRef {
        &self.signing_key
    }

    fn algorithm(&self) -> SigningAlgorithm {
        self.signing.algorithm()
    }

    async fn sign(&self, input: SigningInput<'_>) -> KmsAeadResult<RawSignature> {
        spans::in_span(kms::sign_span(&self.signing_key), async {
            let key = &self.signing;
            input.ensure_algorithm(&self.signing_key, key.algorithm())?;
            let signature = kms::timed("sign", self.signing_key.provider(), async {
                B::sign(
                    key.private_key.ref_sensitive_value(),
                    key.verifying_key.public_key(),
                    &input,
                )
                .map_err(|_| {
                    KmsAeadSignatureError::create(
                        "SIGN",
                        &format!(
                            "The {} backend failed to sign with the local signing key {}",
                            B::NAME,
                            self.signing_key.key()
                        ),
                    )
                })
            })
            .await?;
            RawSignature::new(key.algorithm(), signature)
        })
        .await
    }

    async fn verifying_key(&self) -> KmsAeadResult<VerifyingKey> {
        spans::in_span(kms::public_key_span(&self.signing_key), async {
            Ok(self.signing.verifying_key.clone())
        })
        .await
    }
}

#[cfg(test)]
#[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::signing::{Signer, Verifier};
    use crate::test_provider::{
        renderings, Invoice, TestBackend, ED25519_PKCS8_DER, INVOICE_PAYLOAD, P256_PKCS8_DER,
    };

    const INVOICES: &str = "invoices";

    fn local_signing_key_version(version: u32) -> LocalSigningKeyVersion {
        LocalSigningKeyVersion::from(NonZeroU32::new(version).unwrap())
    }

    fn pkcs8_der_secret(pkcs8_der: &str) -> SecretValue {
        SecretValue::new(hex::decode(pkcs8_der).unwrap())
    }

    fn pkcs8_pem(pkcs8_der: &str) -> String {
        pem_rfc7468::encode_string(
            PrivateKeyFormat::PEM_LABEL,
            pem_rfc7468::LineEnding::LF,
            &hex::decode(pkcs8_der).unwrap(),
        )
        .unwrap()
    }

    fn provider(keys: Vec<LocalSigningKey>) -> KmsAeadResult<LocalSigningProvider<TestBackend>> {
        LocalSigningProvider::new(LocalSigningKeyName::try_from(INVOICES.to_string())?, keys)
    }

    /// A directory of its own under the system temp directory, removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(test: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "kms-aead-local-signing-{}-{test}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str, content: impl AsRef<[u8]>) -> PathBuf {
            let path = self.0.join(name);
            fs::write(&path, content).unwrap();
            path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn every_source_and_format_reads_the_same_key() -> KmsAeadResult<()> {
        let dir = TestDir::new("formats");
        for pkcs8_der in [ED25519_PKCS8_DER, P256_PKCS8_DER] {
            let expected = LocalSigningKey::from_secret(
                local_signing_key_version(1),
                pkcs8_der_secret(pkcs8_der),
                PrivateKeyFormat::Pkcs8Der,
            )?;
            let variable = format!("KMS_AEAD_LOCAL_SIGNING_TEST_{}", &pkcs8_der[..8]);
            std::env::set_var(
                &variable,
                SecretValue::new(hex::decode(pkcs8_der).unwrap()).as_sensitive_base64_str(),
            );
            let keys = [
                LocalSigningKey::from_secret(
                    local_signing_key_version(1),
                    SecretValue::from(pkcs8_pem(pkcs8_der)),
                    PrivateKeyFormat::Pkcs8Pem,
                )?,
                LocalSigningKey::from_file(
                    local_signing_key_version(1),
                    &dir.file("der", hex::decode(pkcs8_der).unwrap()),
                    PrivateKeyFormat::Pkcs8Der,
                )?,
                LocalSigningKey::from_file(
                    local_signing_key_version(1),
                    &dir.file("pem", pkcs8_pem(pkcs8_der)),
                    PrivateKeyFormat::Pkcs8Pem,
                )?,
                LocalSigningKey::from_env(
                    local_signing_key_version(1),
                    &variable,
                    PrivateKeyFormat::Pkcs8Der,
                )?,
            ];
            std::env::remove_var(&variable);

            for key in keys {
                assert_eq!(key.verifying_key(), expected.verifying_key(), "{key:?}");
            }
        }
        Ok(())
    }

    #[test]
    fn a_key_in_another_format_or_of_another_kind_is_refused() {
        // An X25519 key, whose algorithm signs nothing.
        let x25519 = "302e020100300506032b656e042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
        // The RFC 6979 key without the public point, which RFC 5915 makes optional.
        let p256_without_point = "3041020100301306072a8648ce3d020106082a8648ce3d03010704273025020101\
                                  0420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721";
        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nMIH0MF8GCSqGSIb3DQEFDTBSMDEGCSqGSIb3DQEFDDAkBBCQ\n-----END ENCRYPTED PRIVATE KEY-----\n";
        for (key, format) in [
            (pkcs8_der_secret(x25519), PrivateKeyFormat::Pkcs8Der),
            (
                pkcs8_der_secret(p256_without_point),
                PrivateKeyFormat::Pkcs8Der,
            ),
            (
                SecretValue::from(pkcs8_pem(ED25519_PKCS8_DER)),
                PrivateKeyFormat::Pkcs8Der,
            ),
            (
                pkcs8_der_secret(ED25519_PKCS8_DER),
                PrivateKeyFormat::Pkcs8Pem,
            ),
            (SecretValue::from(encrypted), PrivateKeyFormat::Pkcs8Pem),
        ] {
            let result = LocalSigningKey::from_secret(local_signing_key_version(1), key, format);
            assert!(
                matches!(&result, Err(error) if error.code() == "LOCAL_SIGNING_KEY_FORMAT"),
                "{format:?}: {result:?}"
            );
        }
    }

    #[test]
    fn a_source_that_cannot_be_read_is_refused() {
        let dir = TestDir::new("sources");
        std::env::set_var("KMS_AEAD_LOCAL_SIGNING_TEST_NOT_BASE64", "not base64!");
        let large = dir.file("large", vec![0x30; LOCAL_KEY_MAX_LEN_PLUS_ONE]);
        for result in [
            LocalSigningKey::from_file(
                local_signing_key_version(1),
                &dir.0.join("missing"),
                PrivateKeyFormat::Pkcs8Der,
            ),
            LocalSigningKey::from_file(
                local_signing_key_version(1),
                &dir.0,
                PrivateKeyFormat::Pkcs8Der,
            ),
            LocalSigningKey::from_file(
                local_signing_key_version(1),
                &large,
                PrivateKeyFormat::Pkcs8Der,
            ),
            LocalSigningKey::from_env(
                local_signing_key_version(1),
                "KMS_AEAD_LOCAL_SIGNING_TEST_UNSET",
                PrivateKeyFormat::Pkcs8Pem,
            ),
            LocalSigningKey::from_env(
                local_signing_key_version(1),
                "KMS_AEAD_LOCAL_SIGNING_TEST_NOT_BASE64",
                PrivateKeyFormat::Pkcs8Der,
            ),
        ] {
            assert!(
                matches!(&result, Err(error) if error.code() == "LOCAL_SIGNING_KEY_SOURCE"),
                "{result:?}"
            );
        }
        std::env::remove_var("KMS_AEAD_LOCAL_SIGNING_TEST_NOT_BASE64");
    }

    const LOCAL_KEY_MAX_LEN_PLUS_ONE: usize =
        crate::providers::local_key_source::LOCAL_KEY_MAX_LEN + 1;

    #[tokio::test]
    async fn the_highest_version_signs_and_every_version_is_exported() -> KmsAeadResult<()> {
        let v1 = LocalSigningKey::from_secret(
            local_signing_key_version(1),
            pkcs8_der_secret(ED25519_PKCS8_DER),
            PrivateKeyFormat::Pkcs8Der,
        )?;
        let v2 = LocalSigningKey::from_secret(
            local_signing_key_version(2),
            pkcs8_der_secret(P256_PKCS8_DER),
            PrivateKeyFormat::Pkcs8Der,
        )?;
        let (v1_key, v2_key) = (v1.verifying_key().clone(), v2.verifying_key().clone());
        let provider = provider(vec![v2, v1])?;

        assert_eq!(provider.signing_version(), local_signing_key_version(2));
        assert_eq!(
            provider.verifying_keys().keys(),
            [v1_key.clone(), v2_key.clone()]
        );
        assert_eq!(provider.verifying_key().await?, v2_key);

        let provider = provider.with_signing_version(local_signing_key_version(1))?;
        assert_eq!(
            provider.verifying_keys().keys(),
            [v1_key.clone(), v2_key.clone()]
        );
        let signer = Signer::<_, TestBackend>::new(provider).await?;
        let signature = signer.sign(&Invoice(INVOICE_PAYLOAD.to_vec())).await?;

        assert_eq!(signature.key_id(), v1_key.key_id());
        Ok(())
    }

    #[test]
    fn a_version_the_provider_does_not_hold_cannot_sign() -> KmsAeadResult<()> {
        let key = LocalSigningKey::from_secret(
            local_signing_key_version(1),
            pkcs8_der_secret(ED25519_PKCS8_DER),
            PrivateKeyFormat::Pkcs8Der,
        )?;

        let result = provider(vec![key])?.with_signing_version(local_signing_key_version(3));

        assert!(
            matches!(&result, Err(error) if error.code() == "LOCAL_SIGNING_KEY_VERSIONS"),
            "{result:?}"
        );
        Ok(())
    }

    #[test]
    fn invalid_version_lists_fail_with_their_codes() -> KmsAeadResult<()> {
        let key = |version: LocalSigningKeyVersion, pkcs8_der: &str| {
            LocalSigningKey::from_secret(
                version,
                pkcs8_der_secret(pkcs8_der),
                PrivateKeyFormat::Pkcs8Der,
            )
        };

        let empty = provider(Vec::new());
        let twice = provider(vec![
            key(local_signing_key_version(1), ED25519_PKCS8_DER)?,
            key(local_signing_key_version(1), P256_PKCS8_DER)?,
        ]);
        let one_key_id = provider(vec![
            key(local_signing_key_version(1), ED25519_PKCS8_DER)?,
            key(local_signing_key_version(2), P256_PKCS8_DER)?.with_key_id(KeyId::new(0x90fa_cafe)),
        ]);

        for (result, code) in [
            (empty, "LOCAL_SIGNING_KEY_VERSIONS"),
            (twice, "LOCAL_SIGNING_KEY_VERSIONS"),
            (one_key_id, "DUPLICATE_KEY_ID"),
        ] {
            assert!(
                matches!(&result, Err(error) if error.code() == code),
                "{code}: {result:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_ephemeral_key_of_either_algorithm_signs_what_its_key_verifies() -> KmsAeadResult<()>
    {
        for algorithm in [SigningAlgorithm::Ed25519, SigningAlgorithm::EcdsaP256Sha256] {
            let provider = LocalSigningProvider::<TestBackend>::ephemeral(
                LocalSigningKeyName::try_from(INVOICES.to_string())?,
                algorithm,
            )?;
            let verifier = Verifier::<TestBackend>::new(provider.verifying_keys())?;
            let signer = Signer::<_, TestBackend>::new(provider).await?;
            let invoice = Invoice(INVOICE_PAYLOAD.to_vec());

            let signature = signer.sign(&invoice).await?;

            assert_eq!(signer.algorithm(), algorithm);
            assert_eq!(
                verifier.verify(&invoice, &signature)?,
                signer.verifying_key()
            );
        }
        Ok(())
    }

    #[test]
    fn local_signing_key_id_is_1_to_255_ascii_alphanumerics_dashes_underscores_and_dots() {
        assert!(LocalSigningKeyName::try_from("a".repeat(255)).is_ok());
        assert!(LocalSigningKeyName::try_from("invoices-v2_prod.eu".to_string()).is_ok());
        for invalid in [String::new(), "a".repeat(256), "a/b".into(), "a b".into()] {
            let result = LocalSigningKeyName::try_from(invalid.clone());
            assert!(
                matches!(&result, Err(e) if e.code() == "INVALID_LOCAL_SIGNING_KEY_NAME"),
                "{invalid:?}: {result:?}"
            );
        }
    }

    #[test]
    fn debug_prints_no_key_material() -> KmsAeadResult<()> {
        let key = LocalSigningKey::from_secret(
            local_signing_key_version(1),
            pkcs8_der_secret(ED25519_PKCS8_DER),
            PrivateKeyFormat::Pkcs8Der,
        )?;
        let key_printed = format!("{key:?}");
        let printed = format!("{key_printed} {:?}", provider(vec![key])?);

        for rendering in renderings(&hex::decode(&ED25519_PKCS8_DER[32..]).unwrap()) {
            assert!(!printed.contains(&rendering), "{printed}");
        }
        Ok(())
    }
}
