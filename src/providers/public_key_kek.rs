use std::fmt::{Debug, Formatter};

use secret_vault_value::SecretValue;

use crate::backends::{AeadBackend, AeadBackendOps};
use crate::errors::{KmsAeadEncryptionError, KmsAeadSystemError, KmsAeadUnsupportedAlgorithmError};
use crate::formats::asymmetric::PublicKeyEncryptedDek;
use crate::spans::{self, kms};
use crate::{
    AsymmetricKekFingerprint, AsymmetricKekPublicKey, DataEncryptionKey,
    EncryptedDataEncryptionKey, KekRef, KmsAeadDecryptionProvider, KmsAeadEncryptionProvider,
    KmsAeadResult, KmsProvider,
};

/// The bytes of padding RSA-OAEP with SHA-256 takes from a block: two hashes and two marker bytes
/// (RFC 8017, section 7.1.1).
const OAEP_SHA256_OVERHEAD: usize = 2 * 32 + 2;

/// A provider that holds the public half of an asymmetric KEK and no KMS client: it encrypts DEKs
/// on the backend `B` and decrypts nothing. For a producer, which encrypts and must never
/// decrypt: an envelope over it writes with no KMS right and no KMS call, and the readers decrypt
/// its DEKs through their KMS provider.
///
/// It implements [`KmsAeadEncryptionProvider`] and not [`KmsAeadDecryptionProvider`]: an
/// envelope over it has the calls that encrypt and none that decrypts a DEK or a value, and
/// no keyring opens over it. [`kek`](KmsAeadEncryptionProvider::kek) is the public key's KEK;
/// [`encrypt_data_encryption_key`](KmsAeadEncryptionProvider::encrypt_data_encryption_key) encrypts
/// with the public key and puts the public key's version on the result; and
/// [`encrypts_with_public_key`](KmsAeadEncryptionProvider::encrypts_with_public_key) is `true`.
///
/// An encryption is one RSA-OAEP operation with a seed from the backend's CSPRNG, so two
/// encryptions of one DEK differ, and it leaves no KMS audit log: who encrypted which DEK is
/// recorded nowhere unless the producer logs it.
///
/// The guarantee covers the producer's calls into the library. A DEK that
/// [`generate_encrypted_dek`](crate::KmsAeadEnvelope::generate_encrypted_dek) returns is in the
/// producer's hands, and it decrypts its own writes with it through
/// [`AeadCipher::decrypt_bare`](crate::AeadCipher::decrypt_bare). Other code in the process is
/// outside it: a type of the application's own that implements [`KmsAeadDecryptionProvider`]
/// under the producer's [`KekRef`] is served from the producer's DEK cache, as whoever reads the
/// process's memory reads the cached keys. A process that writes and reads holds a KMS provider,
/// and is a reader.
///
/// An envelope over a producer has no `decrypt`:
///
/// ```compile_fail,E0599
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::formats::Envelope;
/// use kms_aead::providers::PublicKeyKekProvider;
/// use kms_aead::{Encrypted, KmsAeadEnvelope, KmsAeadResult};
/// use secret_vault_value::SecretValue;
///
/// async fn read_back<B: AeadBackend>(
///     producer: &KmsAeadEnvelope<PublicKeyKekProvider<B>, B>,
///     encrypted: &Encrypted<SecretValue, Envelope>,
/// ) -> KmsAeadResult<SecretValue> {
///     producer.decrypt(b"orders/1042", encrypted).await
/// }
/// ```
///
/// and its DEK cache, which a store-less producer fills and may share with readers, looks up no
/// key for it:
///
/// ```compile_fail,E0277
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::providers::PublicKeyKekProvider;
/// use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEnvelope, KmsAeadResult};
///
/// async fn cached_dek_len<B: AeadBackend>(
///     producer: &KmsAeadEnvelope<PublicKeyKekProvider<B>, B>,
///     encrypted_dek: &EncryptedDataEncryptionKey,
/// ) -> KmsAeadResult<usize> {
///     let cache = producer.dek_cache();
///     let (len, _) = cache
///         .with_dek(producer.provider(), encrypted_dek, |dek| {
///             dek.value().ref_sensitive_value().len()
///         })
///         .await?;
///     Ok(len)
/// }
/// ```
///
/// An envelope over a reader, the KMS provider of the same KEK, has both:
///
/// ```
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::formats::Envelope;
/// use kms_aead::providers::LocalAsymmetricKmsProvider;
/// use kms_aead::{Encrypted, EncryptedDataEncryptionKey, KmsAeadEnvelope, KmsAeadResult};
/// use secret_vault_value::SecretValue;
///
/// async fn read_back<B: AeadBackend>(
///     reader: &KmsAeadEnvelope<LocalAsymmetricKmsProvider<B>, B>,
///     encrypted: &Encrypted<SecretValue, Envelope>,
/// ) -> KmsAeadResult<SecretValue> {
///     reader.decrypt(b"orders/1042", encrypted).await
/// }
///
/// async fn cached_dek_len<B: AeadBackend>(
///     reader: &KmsAeadEnvelope<LocalAsymmetricKmsProvider<B>, B>,
///     encrypted_dek: &EncryptedDataEncryptionKey,
/// ) -> KmsAeadResult<usize> {
///     let cache = reader.dek_cache();
///     let (len, _) = cache
///         .with_dek(reader.provider(), encrypted_dek, |dek| {
///             dek.value().ref_sensitive_value().len()
///         })
///         .await?;
///     Ok(len)
/// }
/// ```
pub struct PublicKeyKekProvider<B: AeadBackend> {
    public_key: AsymmetricKekPublicKey,
    fingerprint: AsymmetricKekFingerprint,
    max_dek_len: usize,
    rsa_public_key: <B as AeadBackendOps>::RsaPublicKey,
}

impl<B: AeadBackend> PublicKeyKekProvider<B> {
    /// Parses the key on `B` and logs the KEK, the version and the fingerprint at `INFO`.
    ///
    /// A 2048-bit key is deprecated: it is taken for the keys that exist, and a new key is of
    /// 3072 bits.
    ///
    /// # Errors
    ///
    /// [`UnsupportedAlgorithm`](crate::errors::KmsAeadError::UnsupportedAlgorithm) when `B` does
    /// not implement the algorithm, as ring implements no RSA encryption, and
    /// `ASYMMETRIC_KEK_PUBLIC_KEY` when the backend refuses the key.
    pub fn new(public_key: AsymmetricKekPublicKey) -> KmsAeadResult<Self> {
        let provider = Self::parse(public_key)?;
        kms::public_key_loaded(
            provider.public_key.kek(),
            provider.public_key.kek_version(),
            provider.fingerprint,
        );
        Ok(provider)
    }

    /// As [`new`](Self::new), and fails with `ASYMMETRIC_KEK_MISMATCH` when the key's fingerprint
    /// is not `fingerprint`: for a producer whose public key file is written by one system and
    /// whose expected fingerprint comes from another.
    ///
    /// # Errors
    ///
    /// As [`new`](Self::new), and `ASYMMETRIC_KEK_MISMATCH`.
    pub fn pinned(
        public_key: AsymmetricKekPublicKey,
        fingerprint: AsymmetricKekFingerprint,
    ) -> KmsAeadResult<Self> {
        let found = public_key.fingerprint();
        if found != fingerprint {
            return Err(KmsAeadSystemError::asymmetric_kek_mismatch(&format!(
                "The public key of {} has the fingerprint {found}, not the pinned {fingerprint}",
                public_key.kek()
            )));
        }
        Self::new(public_key)
    }

    /// The provider without the `INFO` event, for the providers that log their own.
    pub(crate) fn parse(public_key: AsymmetricKekPublicKey) -> KmsAeadResult<Self> {
        let algorithm = public_key.algorithm();
        if !B::supports_asymmetric_kek(algorithm) {
            return Err(KmsAeadUnsupportedAlgorithmError::create(algorithm, B::NAME));
        }
        let rsa_public_key = B::rsa_public_key(public_key.spki_der()).map_err(|_| {
            KmsAeadSystemError::asymmetric_public_key(&format!(
                "The {} backend refuses the public key of {}",
                B::NAME,
                public_key.kek()
            ))
        })?;
        Ok(Self {
            fingerprint: public_key.fingerprint(),
            max_dek_len: public_key
                .rsa_block_len()?
                .saturating_sub(OAEP_SHA256_OVERHEAD),
            public_key,
            rsa_public_key,
        })
    }

    /// The public key.
    pub fn public_key(&self) -> &AsymmetricKekPublicKey {
        &self.public_key
    }

    /// The SHA-256 of the public key's SubjectPublicKeyInfo.
    pub fn fingerprint(&self) -> AsymmetricKekFingerprint {
        self.fingerprint
    }

    /// `dek` encrypted with the public key, in the span of the caller, which records the version.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when `dek` is longer than the key's OAEP limit, and
    /// `RANDOM_GENERATOR` when the encryption fails otherwise, which the backend's CSPRNG is the
    /// one cause of.
    pub(crate) async fn encrypt_dek(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        let dek_len = dek.value().ref_sensitive_value().len();
        if dek_len > self.max_dek_len {
            return Err(KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!(
                    "A key of {dek_len} bytes does not fit RSA-OAEP under this public key, which \
                     takes {} bytes at most",
                    self.max_dek_len
                ),
            ));
        }
        let kek = self.public_key.kek();
        let kek_version = self.public_key.kek_version();
        if let Some(kek_version) = kek_version {
            kms::record_kek_version(kek_version.as_str());
        }
        let block = kms::timed("encrypt_dek_with_public_key", kek.provider(), async {
            B::rsa_oaep_sha256_encrypt(&self.rsa_public_key, dek.value().ref_sensitive_value())
                .map_err(|_| {
                    KmsAeadEncryptionError::create(
                        "RANDOM_GENERATOR",
                        "Unable to encrypt the data encryption key with the public key",
                    )
                })
        })
        .await?;
        let kek_id = match kek.provider() {
            KmsProvider::Local => kek.key().as_bytes(),
            _ => &[],
        };
        let bytes = PublicKeyEncryptedDek {
            algorithm: self.public_key.algorithm(),
            kek_id,
            kek_version: kek_version.cloned(),
            block: &block,
        }
        .to_bytes()?;
        let encrypted_dek = EncryptedDataEncryptionKey::new(bytes);
        Ok(match kek_version {
            Some(kek_version) => encrypted_dek.with_kek_version(kek_version.clone()),
            None => encrypted_dek,
        })
    }
}

/// The KEK, its version and the fingerprint.
impl<B: AeadBackend> Debug for PublicKeyKekProvider<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKeyKekProvider")
            .field("kek", self.public_key.kek())
            .field("kek_version", &self.public_key.kek_version())
            .field("fingerprint", &self.fingerprint.to_string())
            .finish_non_exhaustive()
    }
}

impl<B: AeadBackend> KmsAeadEncryptionProvider for PublicKeyKekProvider<B> {
    fn kek(&self) -> &KekRef {
        self.public_key.kek()
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(kms::encrypt_span(self.kek()), self.encrypt_dek(dek)).await
    }

    fn encrypts_with_public_key(&self) -> bool {
        true
    }
}

/// A provider that encrypts DEKs with the public half of an asymmetric KEK on the backend `B` and
/// decrypts them through `P`, the KMS provider of the same KEK. For the administration: one
/// provider for a keyring's `rotate`, `reencrypt_deks` and exports, and an envelope's
/// `reencrypt_dek`, with no KMS encrypt right.
///
/// [`kek`](KmsAeadEncryptionProvider::kek) and
/// [`generate_key_material`](KmsAeadEncryptionProvider::generate_key_material) are `P`'s;
/// [`encrypt_data_encryption_key`](KmsAeadEncryptionProvider::encrypt_data_encryption_key) encrypts
/// with the public key;
/// [`decrypt_data_encryption_key`](KmsAeadDecryptionProvider::decrypt_data_encryption_key) is
/// `P`'s, which reads the DEKs its KMS encrypted and the ones a public key encrypted alike; and
/// [`encrypts_with_public_key`](KmsAeadEncryptionProvider::encrypts_with_public_key) is `true`.
pub struct AsymmetricKekProvider<B: AeadBackend, P> {
    public_half: PublicKeyKekProvider<B>,
    private_half: P,
}

impl<B: AeadBackend, P: KmsAeadDecryptionProvider> AsymmetricKekProvider<B, P> {
    /// Parses the key on `B` and logs the KEK, the version and the fingerprint at `INFO`.
    ///
    /// # Errors
    ///
    /// As [`PublicKeyKekProvider::new`], and `ASYMMETRIC_KEK_MISMATCH` when `public_key.kek()` is
    /// not `private_half.kek()`.
    pub fn new(public_key: AsymmetricKekPublicKey, private_half: P) -> KmsAeadResult<Self> {
        if public_key.kek() != private_half.kek() {
            return Err(KmsAeadSystemError::asymmetric_kek_mismatch(&format!(
                "The public key is of {}, and the KMS provider decrypts with {}",
                public_key.kek(),
                private_half.kek()
            )));
        }
        Ok(Self {
            public_half: PublicKeyKekProvider::new(public_key)?,
            private_half,
        })
    }

    /// The public key.
    pub fn public_key(&self) -> &AsymmetricKekPublicKey {
        self.public_half.public_key()
    }

    /// The SHA-256 of the public key's SubjectPublicKeyInfo.
    pub fn fingerprint(&self) -> AsymmetricKekFingerprint {
        self.public_half.fingerprint()
    }

    /// The KMS provider that decrypts.
    pub fn private_half(&self) -> &P {
        &self.private_half
    }
}

/// The public half and the private half's `Debug`.
impl<B: AeadBackend, P: Debug> Debug for AsymmetricKekProvider<B, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsymmetricKekProvider")
            .field("public_half", &self.public_half)
            .field("private_half", &self.private_half)
            .finish()
    }
}

impl<B: AeadBackend, P: KmsAeadDecryptionProvider> KmsAeadEncryptionProvider
    for AsymmetricKekProvider<B, P>
{
    fn kek(&self) -> &KekRef {
        self.private_half.kek()
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        spans::in_span(
            kms::encrypt_span(self.kek()),
            self.public_half.encrypt_dek(dek),
        )
        .await
    }

    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        self.private_half.generate_key_material(len).await
    }

    fn encrypts_with_public_key(&self) -> bool {
        true
    }
}

impl<B: AeadBackend, P: KmsAeadDecryptionProvider> KmsAeadDecryptionProvider
    for AsymmetricKekProvider<B, P>
{
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.private_half
            .decrypt_data_encryption_key(encrypted_dek)
            .await
    }
}

#[cfg(test)]
#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
mod tests {
    use std::num::NonZeroU32;

    use super::*;
    use crate::formats::{Envelope, PrivateKeyFormat};
    use crate::providers::{
        KmsKeyVersion, LocalAsymmetricKek, LocalAsymmetricKmsProvider, LocalKekId, LocalKekVersion,
    };
    use crate::test_provider::{assert_code, RsaOaepSuite, RsaTestBackend};
    use crate::{AsymmetricKekAlgorithm, Encrypted, KmsAeadEnvelope};

    const AAD: &[u8] = b"orders/1042";

    /// The local KMS of the Wycheproof 2048-bit key, version 1, and a producer of its public key.
    fn reader_and_producer() -> KmsAeadResult<(
        LocalAsymmetricKmsProvider<RsaTestBackend>,
        PublicKeyKekProvider<RsaTestBackend>,
    )> {
        let reader = LocalAsymmetricKmsProvider::new(
            LocalKekId::try_from("orders".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
            vec![LocalAsymmetricKek::from_secret(
                LocalKekVersion::from(NonZeroU32::MIN),
                RsaOaepSuite::of_bits(2048).pkcs8_der(),
                PrivateKeyFormat::Pkcs8Der,
            )?],
        )?;
        let producer = PublicKeyKekProvider::new(reader.public_key(None)?)?;
        Ok((reader, producer))
    }

    #[tokio::test]
    async fn a_reader_decrypts_what_a_producer_encrypts() -> KmsAeadResult<()> {
        let (reader, producer) = reader_and_producer()?;
        let producer = KmsAeadEnvelope::<_, RsaTestBackend>::new(producer)?;
        let reader = KmsAeadEnvelope::<_, RsaTestBackend>::new(reader)?;
        let card = SecretValue::from("4111 1111 1111 1111");

        let encrypted: Encrypted<SecretValue, Envelope> = producer.encrypt(AAD, &card).await?;

        assert_eq!(reader.decrypt::<SecretValue>(AAD, &encrypted).await?, card);
        Ok(())
    }

    /// A 2048-bit key takes 190 bytes under OAEP with SHA-256; the encryption names the key length,
    /// not the generator.
    #[tokio::test]
    async fn a_dek_longer_than_the_oaep_limit_is_refused_by_length() -> KmsAeadResult<()> {
        let (_, producer) = reader_and_producer()?;
        let longest = DataEncryptionKey::from(SecretValue::new(vec![0x42; 190]));
        let too_long = DataEncryptionKey::from(SecretValue::new(vec![0x42; 191]));

        producer.encrypt_data_encryption_key(&longest).await?;

        assert_code(
            producer.encrypt_data_encryption_key(&too_long).await,
            "INVALID_KEY_LENGTH",
        );
        Ok(())
    }

    #[test]
    fn a_pinned_producer_refuses_a_key_of_another_fingerprint() -> KmsAeadResult<()> {
        let (reader, producer) = reader_and_producer()?;
        let public_key = reader.public_key(None)?;

        PublicKeyKekProvider::<RsaTestBackend>::pinned(public_key.clone(), producer.fingerprint())?;
        assert_code(
            PublicKeyKekProvider::<RsaTestBackend>::pinned(
                public_key,
                AsymmetricKekFingerprint::from([0x5a; 32]),
            ),
            "ASYMMETRIC_KEK_MISMATCH",
        );
        Ok(())
    }

    #[test]
    fn an_administration_refuses_a_public_key_of_another_kek() -> KmsAeadResult<()> {
        let (reader, _) = reader_and_producer()?;
        let other = LocalAsymmetricKmsProvider::<RsaTestBackend>::ephemeral(
            LocalKekId::try_from("invoices".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
        )?;

        assert_code(
            AsymmetricKekProvider::<RsaTestBackend, _>::new(other.public_key(None)?, reader),
            "ASYMMETRIC_KEK_MISMATCH",
        );
        Ok(())
    }

    /// An Azure KEK's provider of 0.30, whose `0x01` encrypted DEK holds the raw key after the
    /// layout's header, and which decrypts the `0x02` layout with the private half of the KEK's
    /// key, as Key Vault would.
    struct AzureDouble {
        kek: KekRef,
        private_half: LocalAsymmetricKmsProvider<RsaTestBackend>,
    }

    impl KmsAeadEncryptionProvider for AzureDouble {
        fn kek(&self) -> &KekRef {
            &self.kek
        }

        async fn encrypt_data_encryption_key(
            &self,
            _dek: &DataEncryptionKey,
        ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
            unreachable!("an administration over an asymmetric KEK encrypts with the public key")
        }
    }

    impl KmsAeadDecryptionProvider for AzureDouble {
        async fn decrypt_data_encryption_key(
            &self,
            encrypted_dek: &EncryptedDataEncryptionKey,
        ) -> KmsAeadResult<DataEncryptionKey> {
            match encrypted_dek.value() {
                [0x01, version_len, rest @ ..] => Ok(DataEncryptionKey::from(SecretValue::new(
                    rest[usize::from(*version_len)..].to_vec(),
                ))),
                _ => {
                    let public_key_dek = PublicKeyEncryptedDek::read(encrypted_dek.value())
                        .expect("the 0x02 layout")?;
                    let (_, block) = public_key_dek.into_versioned_block()?;
                    let local = PublicKeyEncryptedDek {
                        algorithm: AsymmetricKekAlgorithm::RsaOaepSha256,
                        kek_id: b"orders",
                        kek_version: Some(KmsKeyVersion::try_from("1".to_string())?),
                        block,
                    };
                    self.private_half
                        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(
                            local.to_bytes()?,
                        ))
                        .await
                }
            }
        }
    }

    /// A raw DEK of each length Key Vault encrypts, in the `0x01` layout of 0.30, re-encrypted into
    /// the `0x02` layout and decrypted again: what a block holds follows the KEK, the raw key
    /// under an Azure KEK.
    #[tokio::test]
    async fn an_azure_dek_of_0_30_is_reencrypted_with_the_public_key() -> KmsAeadResult<()> {
        const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";
        let (reader, _) = reader_and_producer()?;
        let kek = KekRef::new(
            KmsProvider::Azure,
            "https://orders.vault.azure.net/keys/orders",
        );
        let public_key = AsymmetricKekPublicKey::new(
            kek.clone(),
            Some(KmsKeyVersion::try_from(KEY_VERSION.to_string())?),
            AsymmetricKekAlgorithm::RsaOaepSha256,
            reader.public_key(None)?.spki_der().to_vec(),
            crate::formats::PublicKeyFormat::SpkiDer,
        )?;
        let administration = KmsAeadEnvelope::<_, RsaTestBackend>::new(AsymmetricKekProvider::<
            RsaTestBackend,
            _,
        >::new(
            public_key,
            AzureDouble {
                kek,
                private_half: reader,
            },
        )?)?;
        for len in [16, 32, 64] {
            let dek = vec![0x42; len];
            let of_0_30 = EncryptedDataEncryptionKey::new(
                [&[0x01, 32][..], KEY_VERSION.as_bytes(), &dek].concat(),
            );

            let reencrypted = administration.reencrypt_encrypted_dek(&of_0_30).await?;

            assert!(reencrypted.is_encrypted_with_public_key(), "{len}");
            assert_eq!(
                administration
                    .provider()
                    .decrypt_data_encryption_key(&reencrypted)
                    .await?,
                DataEncryptionKey::from(SecretValue::new(dek)),
                "{len}"
            );
        }
        Ok(())
    }

    #[cfg(feature = "ring")]
    #[test]
    fn ring_refuses_rsa_at_construction() -> KmsAeadResult<()> {
        use crate::backends::Ring;
        use crate::errors::KmsAeadError;
        use crate::BackendAlgorithm;
        let (reader, _) = reader_and_producer()?;

        let result = PublicKeyKekProvider::<Ring>::new(reader.public_key(None)?);

        assert!(
            matches!(&result, Err(KmsAeadError::UnsupportedAlgorithm(error))
                if error.algorithm
                    == BackendAlgorithm::AsymmetricKek(AsymmetricKekAlgorithm::RsaOaepSha256)),
            "{result:?}"
        );
        Ok(())
    }
}
