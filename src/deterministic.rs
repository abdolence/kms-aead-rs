//! Deterministic encryption with AES-SIV (RFC 5297), beside the randomised path.

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
    use std::marker::PhantomData;

    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit;
    use secret_vault_value::SecretValue;

    use super::DeterministicAlgorithm;
    use crate::backends::AeadBackend;
    use crate::errors::KmsAeadEncryptionError;
    use crate::formats::{tink_output_prefix, Deterministic, TINK_OUTPUT_PREFIX_LEN};
    use crate::types::checked_key_bytes;
    use crate::{
        spans, DataEncryptionKey, Encrypted, EncryptedDataEncryptionKey, KeyId,
        KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult, Plaintext,
    };

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

        /// A new data encryption key of `algorithm().key_len()` bytes from the backend's CSPRNG.
        /// It makes no KMS call.
        ///
        /// # Errors
        ///
        /// `RANDOM_GENERATOR` when the CSPRNG fails.
        pub fn generate_dek(&self) -> KmsAeadResult<DataEncryptionKey> {
            B::generate_random_bytes(self.algorithm.key_len()).map(DataEncryptionKey::from)
        }

        /// A new data encryption key and the same key encrypted by `provider`, to store. The key
        /// comes from the KMS generator when the provider is configured to use one, and from the
        /// backend's CSPRNG otherwise. It is encrypted as Tink encrypts a key, serialised as
        /// Tink's `AesSivKey`, or raw under an Azure KEK.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
        /// material of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
        pub async fn generate_encrypted_dek<P>(
            &self,
            provider: &P,
        ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
        where
            P: KmsAeadEncryptionProvider + Sync + ?Sized,
        {
            crate::formats::generate_encrypted_dek::<B, P>(
                self.algorithm.into(),
                self.algorithm.key_len(),
                provider,
            )
            .await
        }

        /// `value`, as [`Plaintext`] encodes it, sealed under `dek` in Tink's layout of a key
        /// with the output prefix TINK and the id `key_id`:
        ///
        /// ```text
        /// [0x01][key id: u32 BE][synthetic IV: 16][ciphertext]
        /// ```
        ///
        /// Equal values and AADs under one key give equal bytes. `aad` is authenticated as one
        /// associated-data item, also when it is empty, as Tink does. Tink's deterministic AEAD
        /// opens it with a keyset that holds `dek` as the key `key_id`, and so does BigQuery's
        /// `DETERMINISTIC_DECRYPT_STRING` or `DETERMINISTIC_DECRYPT_BYTES`.
        ///
        /// # Errors
        ///
        /// `INVALID_PLAINTEXT` when `value` does not encode, and `INVALID_KEY_LENGTH` when `dek`
        /// does not have `algorithm().key_len()` bytes.
        pub fn encrypt<T: Plaintext>(
            &self,
            key_id: KeyId,
            aad: &(impl AsRef<[u8]> + ?Sized),
            value: &T,
            dek: &DataEncryptionKey,
        ) -> KmsAeadResult<Encrypted<T, Deterministic>> {
            let plain_text = value.to_plaintext()?;
            let sealed = self.seal(key_id, aad.as_ref(), plain_text.ref_sensitive_value(), dek)?;
            Encrypted::try_from(sealed)
        }

        /// Opens `value`, sealed under `dek` and `aad` by [`encrypt`](Self::encrypt) or by Tink,
        /// and decodes the plaintext as a `T`. The caller picks `dek` by
        /// [`value.key_id()`](Encrypted::key_id).
        ///
        /// # Errors
        ///
        /// `INVALID_KEY_LENGTH` when `dek` does not have `algorithm().key_len()` bytes, `DECRYPT`
        /// when the value, the AAD or the key is not the one it was sealed with, and
        /// `INVALID_PLAINTEXT` when the plaintext is not an encoding of `T`.
        pub fn decrypt<T: Plaintext>(
            &self,
            aad: &(impl AsRef<[u8]> + ?Sized),
            value: &Encrypted<T, Deterministic>,
            dek: &DataEncryptionKey,
        ) -> KmsAeadResult<T> {
            T::from_plaintext(self.open(aad.as_ref(), value.value(), dek)?)
        }

        /// The output prefix of `key_id`, then `plain_text` sealed under `dek`:
        /// `[prefix][synthetic IV][ciphertext]`.
        fn seal(
            &self,
            key_id: KeyId,
            aad: &[u8],
            plain_text: &[u8],
            dek: &DataEncryptionKey,
        ) -> KmsAeadResult<Vec<u8>> {
            let mut siv = self.siv(dek)?;
            let cipher_text_start =
                TINK_OUTPUT_PREFIX_LEN + DeterministicAlgorithm::SYNTHETIC_IV_LEN;
            // Allocated once at its final size, since growing it would leave a copy of the
            // plaintext in freed memory, and zeroised if sealing fails.
            let mut buffer =
                SecretValue::new(Vec::with_capacity(cipher_text_start + plain_text.len()));
            let value = buffer.ref_sensitive_value_mut();
            value.extend_from_slice(&tink_output_prefix(key_id));
            value.extend_from_slice(&[0; DeterministicAlgorithm::SYNTHETIC_IV_LEN]);
            value.extend_from_slice(plain_text);
            let synthetic_iv = siv
                .encrypt_inout_detached([aad], (&mut value[cipher_text_start..]).into())
                .map_err(|_| KmsAeadEncryptionError::create("ENCRYPT", "Unable to encrypt data"))?;
            value[TINK_OUTPUT_PREFIX_LEN..cipher_text_start].copy_from_slice(&synthetic_iv);
            Ok(std::mem::take(value))
        }

        /// Opens the `[synthetic IV][ciphertext]` after the output prefix of `value`, which its
        /// format has checked.
        fn open(
            &self,
            aad: &[u8],
            value: &[u8],
            dek: &DataEncryptionKey,
        ) -> KmsAeadResult<SecretValue> {
            let mut siv = self.siv(dek)?;
            let sealed = value
                .get(TINK_OUTPUT_PREFIX_LEN..)
                .filter(|sealed| sealed.len() >= DeterministicAlgorithm::SYNTHETIC_IV_LEN)
                .ok_or_else(|| {
                    KmsAeadEncryptionError::create(
                        "INVALID_CIPHER_TEXT_FORMAT",
                        &format!(
                            "A cipher text of {} bytes is too short to hold a synthetic IV",
                            value.len()
                        ),
                    )
                })?;
            siv.decrypt([aad], sealed)
                .map(SecretValue::new)
                .map_err(|_| KmsAeadEncryptionError::create("DECRYPT", "Unable to decrypt data"))
        }

        /// The cipher keyed with `dek`: the first half keys S2V's CMAC and the second half CTR,
        /// the order of RFC 5297 and of Tink's `AesSivKey`.
        fn siv(&self, dek: &DataEncryptionKey) -> KmsAeadResult<Aes256Siv> {
            let key = checked_key_bytes(
                dek.value().ref_sensitive_value(),
                self.algorithm,
                self.algorithm.key_len(),
            )?;
            match self.algorithm {
                DeterministicAlgorithm::Aes256Siv => Aes256Siv::new_from_slice(key).map_err(|_| {
                    KmsAeadEncryptionError::create(
                        "INVALID_KEY_LENGTH",
                        "AES-SIV refused a key of its own length",
                    )
                }),
            }
        }
    }

    /// Deterministic keys, encrypted and decrypted by the envelope's provider.
    impl<P, B> KmsAeadEnvelope<P, B>
    where
        P: KmsAeadEncryptionProvider + Send + Sync,
        B: AeadBackend,
    {
        /// A new deterministic key and the same key encrypted by the provider, to store. The key
        /// comes from the KMS generator when the provider is configured to use one, and from the
        /// CSPRNG of the envelope's backend otherwise.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key
        /// material of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
        pub async fn generate_encrypted_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
        ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)> {
            let cipher = DeterministicCipher::<B>::new(algorithm)?;
            let span = spans::generate_encrypted_dek("deterministic", algorithm, B::NAME);
            spans::in_span(span, cipher.generate_encrypted_dek(&self.provider)).await
        }

        /// Decrypts a key
        /// [`generate_encrypted_deterministic_dek`](Self::generate_encrypted_deterministic_dek)
        /// encrypted.
        ///
        /// # Errors
        ///
        /// The provider's errors, `INVALID_KEY_FORMAT` when the decrypted key is not a serialised
        /// Tink key, and `INVALID_KEY_LENGTH` when it does not fit `algorithm`.
        pub async fn decrypt_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
            encrypted_dek: &EncryptedDataEncryptionKey,
        ) -> KmsAeadResult<DataEncryptionKey> {
            let span = spans::decrypt_dek(algorithm, self.dek_cache());
            spans::in_span(span, async {
                let (dek, _) = crate::formats::decrypt_dek(encrypted_dek, &self.provider).await?;
                checked_key_bytes(
                    dek.value().ref_sensitive_value(),
                    algorithm,
                    algorithm.key_len(),
                )?;
                Ok(dek)
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
        const KEY_ID: KeyId = KeyId::new(7);

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
                let dek =
                    DataEncryptionKey::from(SecretValue::new(hex::decode(vector.key).unwrap()));
                let aad = hex::decode(vector.aad).unwrap();
                let plain_text = hex::decode(vector.plain_text).unwrap();
                let tink_value = [
                    tink_output_prefix(KEY_ID).to_vec(),
                    hex::decode(vector.cipher_text).unwrap(),
                ]
                .concat();

                let sealed = cipher.encrypt(KEY_ID, &aad, &plain_text, &dek)?;
                let opened = cipher.decrypt(
                    &aad,
                    &Encrypted::<Vec<u8>, Deterministic>::try_from(tink_value)?,
                    &dek,
                )?;

                assert_eq!(hex::encode(&sealed.value()[5..]), vector.cipher_text);
                assert_eq!(opened, plain_text);
            }
            Ok(())
        }

        /// The empty plaintext sealed by tink-java's AES-SIV under a TINK-prefixed key: key id
        /// 0x44556677, the bytes 0 to 63 as the key, and one associated-data item, the byte
        /// 0xFF. From `testCreateForEncryptConstructorForDecrypt_tinkPrefix` in
        /// <https://github.com/tink-crypto/tink-java/blob/eadd2736490b50d80b3117a5586ffe0985c9207e/src/test/java/com/google/crypto/tink/subtle/AesSivTest.java#L396-L424>.
        const TINK_VALUE: [u8; 21] = [
            0x01, 0x44, 0x55, 0x66, 0x77, 0x1b, 0xc4, 0x9c, 0x6a, 0x89, 0x4e, 0xf5, 0x74, 0x4a,
            0x0a, 0x01, 0xd4, 0x66, 0x08, 0xcb, 0xcc,
        ];

        #[test]
        fn a_field_is_the_value_tink_seals() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let dek = DataEncryptionKey::from(SecretValue::new((0u8..64).collect()));
            let key_id = KeyId::new(0x4455_6677);

            let field = cipher.encrypt(key_id, &[0xFF], &Vec::<u8>::new(), &dek)?;
            let tink_value = Encrypted::<Vec<u8>, Deterministic>::try_from(TINK_VALUE.to_vec())?;

            assert_eq!(*field.value(), TINK_VALUE);
            assert_eq!(tink_value.key_id(), key_id);
            assert_eq!(
                cipher.decrypt(&[0xFF], &tink_value, &dek)?,
                Vec::<u8>::new()
            );
            Ok(())
        }

        #[test]
        fn a_deterministic_cipher_refuses_a_key_of_another_length() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let plain_text = SecretValue::from(PLAIN_TEXT);
            let sealed = cipher.encrypt(KEY_ID, AAD, &plain_text, &cipher.generate_dek()?)?;
            let dek = DataEncryptionKey::from(SecretValue::new(vec![0x42; 32]));

            let encrypted = cipher.encrypt(KEY_ID, AAD, &plain_text, &dek);
            let decrypted = cipher.decrypt(AAD, &sealed, &dek);

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
        fn a_different_aad_gives_a_different_value() -> KmsAeadResult<()> {
            let cipher =
                DeterministicCipher::<TestBackend>::new(DeterministicAlgorithm::Aes256Siv)?;
            let dek = cipher.generate_dek()?;
            let plain_text = SecretValue::from(PLAIN_TEXT);

            assert_ne!(
                cipher.encrypt(KEY_ID, AAD, &plain_text, &dek)?,
                cipher.encrypt(KEY_ID, b"orders/1043", &plain_text, &dek)?
            );
            Ok(())
        }

        mod envelope {
            use super::*;
            use crate::test_provider::{encrypted_by_test_provider, TestKmsProvider};

            type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;

            #[tokio::test]
            async fn deterministic_dek_round_trips_through_the_provider() -> KmsAeadResult<()> {
                let envelope = Envelope::new(TestKmsProvider::Working)?;
                let algorithm = DeterministicAlgorithm::Aes256Siv;
                let cipher = DeterministicCipher::<TestBackend>::new(algorithm)?;
                let plain_text = SecretValue::from(PLAIN_TEXT);

                let (dek, encrypted_dek) = envelope
                    .generate_encrypted_deterministic_dek(algorithm)
                    .await?;
                let (other_dek, _) = envelope
                    .generate_encrypted_deterministic_dek(algorithm)
                    .await?;
                let decrypted_dek = envelope
                    .decrypt_deterministic_dek(algorithm, &encrypted_dek)
                    .await?;

                assert_eq!(
                    encrypted_dek,
                    encrypted_by_test_provider(algorithm, dek.value().ref_sensitive_value())
                );
                assert_eq!(decrypted_dek.value(), dek.value());
                assert_ne!(dek.value(), other_dek.value());
                assert_eq!(
                    cipher.encrypt(KEY_ID, AAD, &plain_text, &decrypted_dek)?,
                    cipher.encrypt(KEY_ID, AAD, &plain_text, &dek)?
                );
                Ok(())
            }

            #[tokio::test]
            async fn a_decrypted_key_of_another_length_is_refused() -> KmsAeadResult<()> {
                let envelope = Envelope::new(TestKmsProvider::Working)?;
                let encrypted_dek =
                    encrypted_by_test_provider(crate::AeadAlgorithm::Aes256Gcm, &[0x42; 32]);

                let result = envelope
                    .decrypt_deterministic_dek(DeterministicAlgorithm::Aes256Siv, &encrypted_dek)
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
