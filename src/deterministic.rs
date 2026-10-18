//! Deterministic encryption with AES-SIV (RFC 5297), beside the randomized path.

use std::fmt::{Display, Formatter};
use std::str::FromStr;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};

/// A deterministic AEAD algorithm: equal inputs under one key give equal values. It exists in
/// every build, so that a keyring record names the algorithm of every version even in a process
/// built without the `deterministic` feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DeterministicAlgorithm {
    /// AES-SIV (RFC 5297) with a 64-byte key, two AES-256 keys. RFC 5297 names it
    /// AEAD_AES_SIV_CMAC_512; Tink's AES256_SIV template uses it.
    Aes256Siv,
}

impl DeterministicAlgorithm {
    /// Every algorithm, for the tests that cover each.
    #[cfg(test)]
    pub(crate) const ALL: [DeterministicAlgorithm; 1] = [DeterministicAlgorithm::Aes256Siv];

    /// Every algorithm writes this synthetic IV before the cipher text.
    pub(crate) const SYNTHETIC_IV_LEN: usize = 16;

    /// The length of a data encryption key for this algorithm, in bytes.
    pub fn key_len(self) -> usize {
        match self {
            DeterministicAlgorithm::Aes256Siv => 64,
        }
    }
}

/// `aes-256-siv`: the value of the `/kms_aead/algorithm` span field.
impl Display for DeterministicAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            DeterministicAlgorithm::Aes256Siv => "aes-256-siv",
        })
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for DeterministicAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "aes-256-siv" => Ok(DeterministicAlgorithm::Aes256Siv),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of a deterministic algorithm: the name is aes-256-siv",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::KmsAeadResult;

    #[test]
    fn every_name_parses_back_and_another_name_is_refused() -> KmsAeadResult<()> {
        for algorithm in DeterministicAlgorithm::ALL {
            assert_eq!(
                algorithm.to_string().parse::<DeterministicAlgorithm>()?,
                algorithm
            );
        }
        let unknown = "aes-128-siv".parse::<DeterministicAlgorithm>();
        assert!(
            matches!(&unknown, Err(e) if e.code() == "UNKNOWN_ALGORITHM"),
            "{unknown:?}"
        );
        Ok(())
    }
}

#[cfg(feature = "deterministic")]
pub use aes_siv_cipher::*;

#[cfg(feature = "deterministic")]
mod aes_siv_cipher {
    use std::fmt::{Debug, Formatter};
    use std::marker::PhantomData;

    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit;
    use secret_vault_value::SecretValue;
    use subtle::ConstantTimeEq;

    use rvstruct::ValueStruct;

    use super::DeterministicAlgorithm;
    use crate::errors::KmsAeadEncryptionError;
    use crate::{
        checked_key_material, generate_random_bytes, spans, AeadBackend, DataEncryptionKey,
        EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult,
    };

    /// A value sealed by a [`DeterministicAlgorithm`]: `[synthetic IV: 16][ciphertext]`, the
    /// output order of RFC 5297. Equal plaintexts and AADs under one key give equal values.
    /// Equality compares in constant time.
    #[derive(Clone, ValueStruct)]
    pub struct DeterministicCipherText(Vec<u8>);

    /// The length only: the bytes tell which values are equal.
    impl Debug for DeterministicCipherText {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DeterministicCipherText")
                .field("len", &self.0.len())
                .finish()
        }
    }

    impl DeterministicCipherText {
        /// The lowercase hex of the value.
        pub fn to_hex_string(&self) -> String {
            hex::encode(&self.0)
        }
    }

    impl PartialEq for DeterministicCipherText {
        fn eq(&self, other: &Self) -> bool {
            self.0.ct_eq(&other.0).into()
        }
    }

    /// Deterministic AEAD on the backend `B` and with the algorithm it was made with, without a
    /// KMS: equal inputs under one key give equal values, so a sealed value can be compared or
    /// looked up without opening it, and reveals which values are equal.
    ///
    /// Every backend seals and opens with RustCrypto's `aes-siv`, so a value sealed under one
    /// backend opens under any other. The backend's CSPRNG generates the keys, the FIPS
    /// module's DRBG with `aws-lc-fips`. AES-SIV is not a FIPS-approved mode, so a FIPS
    /// deployment keeps deterministic fields outside its validated boundary.
    ///
    /// It does no I/O and opens no span: it runs once per value, inside the caller's span.
    #[derive(Debug, Clone, Copy)]
    pub struct DeterministicCipher<B> {
        algorithm: DeterministicAlgorithm,
        backend: PhantomData<B>,
    }

    impl<B: AeadBackend> DeterministicCipher<B> {
        /// A cipher for `algorithm` on the backend `B`.
        ///
        /// # Errors
        ///
        /// None today: every backend implements every [`DeterministicAlgorithm`].
        pub fn new(algorithm: DeterministicAlgorithm) -> KmsAeadResult<Self> {
            Ok(Self {
                algorithm,
                backend: PhantomData,
            })
        }

        /// The algorithm this cipher seals and opens with.
        pub fn algorithm(&self) -> DeterministicAlgorithm {
            self.algorithm
        }

        /// A new key of `algorithm().key_len()` bytes from the backend's CSPRNG.
        ///
        /// # Errors
        ///
        /// `RANDOM_GENERATOR` when the CSPRNG fails.
        pub fn generate_key(&self) -> KmsAeadResult<DataEncryptionKey> {
            generate_random_bytes::<B>(self.algorithm.key_len()).map(DataEncryptionKey::from)
        }

        /// A new key and the same key wrapped by `provider`, to store. The key comes from the
        /// KMS generator when the provider is configured to use one, and from the backend's
        /// CSPRNG otherwise. It is wrapped as Tink wraps a key, serialized as Tink's
        /// `AesSivKey`.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
        /// material of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
        pub async fn generate_wrapped_key<P>(
            &self,
            provider: &P,
        ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
        where
            P: KmsAeadEncryptionProvider + Sync + ?Sized,
        {
            let key = match checked_key_material(provider, self.algorithm.key_len()).await? {
                Some(material) => DataEncryptionKey::from(material),
                None => self.generate_key()?,
            };
            let encrypted_key =
                crate::formats::wrap_key(&key, self.algorithm.into(), provider).await?;
            Ok((key, encrypted_key))
        }

        /// Seals `plain_text` under `key`. `aad` is authenticated as one associated-data item,
        /// also when it is empty, as Tink does: the value is equal to a Tink value after its
        /// 5-byte prefix.
        ///
        /// # Errors
        ///
        /// `INVALID_KEY_LENGTH` when `key` does not have `algorithm().key_len()` bytes.
        pub fn encrypt_value(
            &self,
            aad: &[u8],
            plain_text: &SecretValue,
            key: &DataEncryptionKey,
        ) -> KmsAeadResult<DeterministicCipherText> {
            let cipher_text = self
                .siv(key)?
                .encrypt([aad], plain_text.ref_sensitive_value())
                .map_err(|_| KmsAeadEncryptionError::create("ENCRYPT", "Unable to encrypt data"))?;
            Ok(DeterministicCipherText(cipher_text))
        }

        /// Opens a value [`encrypt_value`](Self::encrypt_value) sealed, into a buffer the
        /// returned `SecretValue` owns.
        ///
        /// # Errors
        ///
        /// `INVALID_KEY_LENGTH` when `key` does not have `algorithm().key_len()` bytes,
        /// `INVALID_CIPHER_TEXT_FORMAT` when the value is shorter than the 16-byte synthetic IV, and
        /// `DECRYPT` when the value, the AAD or the key is not the one it was sealed with.
        pub fn decrypt_value(
            &self,
            aad: &[u8],
            cipher_text: &DeterministicCipherText,
            key: &DataEncryptionKey,
        ) -> KmsAeadResult<SecretValue> {
            let mut siv = self.siv(key)?;
            if cipher_text.value().len() < DeterministicAlgorithm::SYNTHETIC_IV_LEN {
                return Err(KmsAeadEncryptionError::create(
                    "INVALID_CIPHER_TEXT_FORMAT",
                    &format!(
                        "A cipher text of {} bytes is too short to hold a synthetic IV",
                        cipher_text.value().len()
                    ),
                ));
            }
            siv.decrypt([aad], cipher_text.value())
                .map(SecretValue::new)
                .map_err(|_| KmsAeadEncryptionError::create("DECRYPT", "Unable to decrypt data"))
        }

        /// The cipher keyed with `key`: the first half keys S2V's CMAC and the second half CTR,
        /// the order of RFC 5297 and of Tink's `AesSivKey`.
        fn siv(&self, key: &DataEncryptionKey) -> KmsAeadResult<Aes256Siv> {
            let key = key.value().ref_sensitive_value();
            match self.algorithm {
                DeterministicAlgorithm::Aes256Siv => Aes256Siv::new_from_slice(key).map_err(|_| {
                    KmsAeadEncryptionError::invalid_key_length(
                        key.len(),
                        self.algorithm,
                        self.algorithm.key_len(),
                    )
                }),
            }
        }
    }

    /// Deterministic keys, wrapped and unwrapped by the envelope's provider.
    impl<P, B> KmsAeadEnvelope<P, B>
    where
        P: KmsAeadEncryptionProvider + Send + Sync,
        B: AeadBackend,
    {
        /// A new deterministic key and the same key wrapped by the provider, to store. The key
        /// comes from the KMS generator when the provider is configured to use one, and from the
        /// CSPRNG of the envelope's backend otherwise.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
        /// material of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
        pub async fn generate_new_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
        ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
            let cipher = DeterministicCipher::<B>::new(algorithm)?;
            let span = spans::generate_dek("deterministic", algorithm, B::NAME);
            spans::in_span(span, cipher.generate_wrapped_key(&self.provider)).await
        }

        /// Unwraps a key [`generate_new_deterministic_dek`](Self::generate_new_deterministic_dek)
        /// wrapped.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_FORMAT` when the unwrapped key is not a serialized
        /// Tink key, and `INVALID_KEY_LENGTH` when it does not fit `algorithm`.
        pub async fn decrypt_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
            encrypted_key: &EncryptedDataEncryptionKey,
        ) -> KmsAeadResult<DataEncryptionKey> {
            let span = spans::decrypt_dek("deterministic", algorithm, self.dek_cache());
            spans::in_span(span, async {
                let (key, _) = crate::formats::unwrap_key(encrypted_key, &self.provider).await?;
                let len = key.value().ref_sensitive_value().len();
                if len == algorithm.key_len() {
                    Ok(key)
                } else {
                    Err(KmsAeadEncryptionError::invalid_key_length(
                        len,
                        algorithm,
                        algorithm.key_len(),
                    ))
                }
            })
            .await
        }
    }

    #[cfg(all(
        test,
        any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
    ))]
    mod tests {
        use super::*;
        use crate::test_provider::TestBackend;

        const AAD: &[u8] = b"orders/1042";
        const PLAIN_TEXT: &str = "4111 1111 1111 1111";

        struct Vector {
            key: &'static str,
            aad: &'static str,
            plain_text: &'static str,
            cipher_text: &'static str,
        }

        /// AES-SIV with a 64-byte key and one associated-data item. The first is RFC 5297's A.1
        /// example adapted to a 64-byte key, as Miscreant and the `aes-siv` crate publish it. The
        /// others are Wycheproof's `aes_siv_cmac_test.json`, the vectors Tink's AES-SIV tests run,
        /// with empty AADs and an empty plaintext among them.
        const VECTORS: &[Vector] = &[
            Vector {
                key: "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f06f6e6d6c6b6a69686766656463626160f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff000102030405060708090a0b0c0d0e0f",
                aad: "101112131415161718191a1b1c1d1e1f2021222324252627",
                plain_text: "112233445566778899aabbccddee",
                cipher_text: "f125274c598065cfc26b0e71575029088b035217e380cac8919ee800c126",
            },
            Vector {
                key: "bc7635c1fd566aa8357fd103714bfaee1c9e5b3c578b3980401a981030254a54b1756a8c96e600b7252fd0aab12f39d115d256b3f3e7c2c41a7fece72ba7c3c4",
                aad: "",
                plain_text: "",
                cipher_text: "44b1c6fe8a8c07dee5377b161f283c31",
            },
            Vector {
                key: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
                aad: "",
                plain_text: "8dbfee9580e7e2bc66100a674497f4e1",
                cipher_text: "000000000000000000000000000000007ef8aa7e4dd49d9cfa09e9cb574fd90d",
            },
            Vector {
                key: "e2c5662bb18fbb411d0304e4241db073fe60a4704fee290073513038a22b4cd542580b2b4edbc37e3de01c0cb61abcad46986cdc491ce9e5ae5af223ff58b953",
                aad: "fab912dec29a34aabfaef176",
                plain_text: "0d",
                cipher_text: "1c6969ecb15741a9959b7a8492250e391a",
            },
        ];

        #[test]
        fn seals_and_opens_the_published_vectors() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            for vector in VECTORS {
                let key =
                    DataEncryptionKey::from(SecretValue::new(hex::decode(vector.key).unwrap()));
                let aad = hex::decode(vector.aad).unwrap();
                let plain_text = SecretValue::new(hex::decode(vector.plain_text).unwrap());

                let cipher_text = cipher.encrypt_value(&aad, &plain_text, &key)?;
                assert_eq!(cipher_text.to_hex_string(), vector.cipher_text);
                assert_eq!(cipher.decrypt_value(&aad, &cipher_text, &key)?, plain_text);
            }
            Ok(())
        }

        #[test]
        fn a_deterministic_cipher_refuses_a_key_of_another_length() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let plain_text = SecretValue::from(PLAIN_TEXT);
            let sealed = cipher.encrypt_value(AAD, &plain_text, &cipher.generate_key()?)?;
            let key = DataEncryptionKey::from(SecretValue::new(vec![0x42; 32]));

            let encrypted = cipher.encrypt_value(AAD, &plain_text, &key);
            let decrypted = cipher.decrypt_value(AAD, &sealed, &key);

            assert!(
                matches!(&encrypted, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
                "{encrypted:?}"
            );
            assert!(
                matches!(&decrypted, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
                "{:?}",
                decrypted.err()
            );
            Ok(())
        }

        #[test]
        fn a_value_shorter_than_the_synthetic_iv_is_invalid() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let key = cipher.generate_key()?;
            for len in [0, 15] {
                let short = DeterministicCipherText::from(vec![0xAA; len]);

                let result = cipher.decrypt_value(AAD, &short, &key);

                assert!(
                    matches!(&result, Err(e) if e.code() == "INVALID_CIPHER_TEXT_FORMAT"),
                    "{len} bytes: {result:?}"
                );
            }
            Ok(())
        }

        #[test]
        fn debug_shows_no_cipher_text_bytes() {
            let sealed = DeterministicCipherText::from(b"zq-cipher-marker-zq".to_vec());

            let debug = format!("{sealed:?}");

            for rendering in crate::test_provider::renderings(b"zq-cipher-marker-zq") {
                assert!(!debug.contains(&rendering), "{debug}");
            }
        }

        #[test]
        fn a_different_aad_gives_a_different_value() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let key = cipher.generate_key()?;
            let plain_text = SecretValue::from(PLAIN_TEXT);

            assert_ne!(
                cipher.encrypt_value(AAD, &plain_text, &key)?,
                cipher.encrypt_value(b"orders/1043", &plain_text, &key)?
            );
            Ok(())
        }

        mod envelope {
            use super::*;
            use crate::test_provider::{wrapped_by_test_provider, TestKmsProvider};

            type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;

            #[tokio::test]
            async fn deterministic_dek_round_trips_through_the_provider() -> KmsAeadResult<()> {
                let envelope = Envelope::new(TestKmsProvider::Working)?;
                let algorithm = DeterministicAlgorithm::Aes256Siv;
                let cipher = DeterministicCipher::<TestBackend>::new(algorithm)?;
                let plain_text = SecretValue::from(PLAIN_TEXT);

                let (key, encrypted_key) =
                    envelope.generate_new_deterministic_dek(algorithm).await?;
                let (other_key, _) = envelope.generate_new_deterministic_dek(algorithm).await?;
                let unwrapped = envelope
                    .decrypt_deterministic_dek(algorithm, &encrypted_key)
                    .await?;

                assert_eq!(
                    encrypted_key,
                    wrapped_by_test_provider(algorithm, key.value().ref_sensitive_value())
                );
                assert_eq!(unwrapped.value(), key.value());
                assert_ne!(key.value(), other_key.value());
                assert_eq!(
                    cipher.encrypt_value(AAD, &plain_text, &unwrapped)?,
                    cipher.encrypt_value(AAD, &plain_text, &key)?
                );
                Ok(())
            }

            #[tokio::test]
            async fn an_unwrapped_key_of_another_length_is_refused() -> KmsAeadResult<()> {
                let envelope = Envelope::new(TestKmsProvider::Working)?;
                let encrypted_key =
                    wrapped_by_test_provider(crate::AeadAlgorithm::Aes256Gcm, &[0x42; 32]);

                let result = envelope
                    .decrypt_deterministic_dek(DeterministicAlgorithm::Aes256Siv, &encrypted_key)
                    .await;

                assert!(
                    matches!(&result, Err(e) if e.code() == "INVALID_KEY_LENGTH"),
                    "{result:?}"
                );
                Ok(())
            }
        }
    }
}
