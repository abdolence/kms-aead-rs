//! Deterministic encryption with AES-SIV (RFC 5297), beside the randomized path.

use std::fmt::{Display, Formatter};

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

#[cfg(feature = "deterministic")]
pub use aes_siv_cipher::*;

#[cfg(feature = "deterministic")]
mod aes_siv_cipher {
    use aes_siv::siv::Aes256Siv;
    use aes_siv::KeyInit;
    use secret_vault_value::SecretValue;
    use subtle::ConstantTimeEq;

    use super::DeterministicAlgorithm;
    use crate::backend::AeadBackend;
    use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
    use crate::{
        checked_key_material, spans, DataEncryptionKey, EncryptedDataEncryptionKey,
        KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult,
    };

    /// A key for deterministic encryption only, zeroized on drop and shown as `***` by `Debug`.
    /// There is no conversion to or from [`DataEncryptionKey`], so a key of one purpose never
    /// serves the other.
    #[derive(Debug)]
    pub struct DeterministicDataEncryptionKey(SecretValue);

    impl DeterministicDataEncryptionKey {
        /// The key bytes.
        pub fn value(&self) -> &SecretValue {
            &self.0
        }
    }

    impl From<SecretValue> for DeterministicDataEncryptionKey {
        fn from(value: SecretValue) -> Self {
            Self(value)
        }
    }

    /// A value sealed by a [`DeterministicAlgorithm`]: `[synthetic IV: 16][ciphertext]`, the
    /// output order of RFC 5297. Equal plaintexts and AADs under one key give equal values.
    /// Equality compares in constant time.
    #[derive(Debug, Clone)]
    pub struct DeterministicCipherText(Vec<u8>);

    impl DeterministicCipherText {
        /// The sealed bytes.
        pub fn value(&self) -> &[u8] {
            &self.0
        }

        /// The lowercase hex of the value.
        pub fn to_hex_string(&self) -> String {
            hex::encode(&self.0)
        }
    }

    impl From<Vec<u8>> for DeterministicCipherText {
        fn from(value: Vec<u8>) -> Self {
            Self(value)
        }
    }

    impl PartialEq for DeterministicCipherText {
        fn eq(&self, other: &Self) -> bool {
            self.0.ct_eq(&other.0).into()
        }
    }

    /// Deterministic AEAD with the algorithm it was made with, without a KMS: equal inputs under
    /// one key give equal values, so a sealed value can be compared or looked up without opening
    /// it, and reveals which values are equal.
    ///
    /// It runs on RustCrypto's `aes-siv` whatever AEAD backend the build enables, does no I/O
    /// and opens no span: it runs once per value, inside the caller's span.
    #[derive(Debug, Clone, Copy)]
    pub struct DeterministicCipher {
        algorithm: DeterministicAlgorithm,
    }

    impl DeterministicCipher {
        /// The value of the `backend` span field: AES-SIV exists only in RustCrypto.
        const BACKEND_NAME: &'static str = "rustcrypto";

        /// A cipher for `algorithm`.
        ///
        /// # Errors
        ///
        /// None today: every [`DeterministicAlgorithm`] is implemented. A later algorithm may be
        /// refused with `UNSUPPORTED_ALGORITHM`.
        pub fn new(algorithm: DeterministicAlgorithm) -> KmsAeadResult<Self> {
            Ok(Self { algorithm })
        }

        /// The algorithm this cipher seals and opens with.
        pub fn algorithm(&self) -> DeterministicAlgorithm {
            self.algorithm
        }

        /// A new key of `algorithm().key_len()` bytes from the operating system's generator.
        ///
        /// # Errors
        ///
        /// `ENCRYPTION` when the generator fails.
        pub fn generate_key(&self) -> KmsAeadResult<DeterministicDataEncryptionKey> {
            let mut key = SecretValue::new(vec![0; self.algorithm.key_len()]);
            getrandom::fill(key.ref_sensitive_value_mut()).map_err(|_| {
                KmsAeadEncryptionError::create("ENCRYPTION", "Unable to initialise a random key")
            })?;
            Ok(DeterministicDataEncryptionKey(key))
        }

        /// A new key from the KMS generator of `provider` when it is configured to use one, and
        /// from the operating system's generator otherwise. Calls the KMS only in the first case.
        ///
        /// # Errors
        ///
        /// The provider's error when the KMS call fails, `INVALID_KEY_LENGTH` when the KMS returns
        /// a key of another length, and `ENCRYPTION` when the generator fails.
        pub async fn generate_key_with<P>(
            &self,
            provider: &P,
        ) -> KmsAeadResult<DeterministicDataEncryptionKey>
        where
            P: KmsAeadEncryptionProvider + Sync + ?Sized,
        {
            match checked_key_material(provider, self.algorithm.key_len()).await? {
                Some(material) => Ok(DeterministicDataEncryptionKey(material)),
                None => self.generate_key(),
            }
        }

        /// Seals `plain_text` under `key`. `aad` is authenticated as exactly one associated-data
        /// item, also when it is empty, as Tink and BigQuery's `DETERMINISTIC_ENCRYPT` do, so
        /// their values and these are the same bytes.
        ///
        /// # Errors
        ///
        /// `INVALID_KEY_LENGTH` when `key` does not have `algorithm().key_len()` bytes.
        pub fn encrypt_value(
            &self,
            aad: &[u8],
            plain_text: &SecretValue,
            key: &DeterministicDataEncryptionKey,
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
        /// `INVALID_KEY_LENGTH` when `key` does not have `algorithm().key_len()` bytes, and
        /// `DECRYPT` when the value, the AAD or the key is not the one it was sealed with.
        pub fn decrypt_value(
            &self,
            aad: &[u8],
            cipher_text: &DeterministicCipherText,
            key: &DeterministicDataEncryptionKey,
        ) -> KmsAeadResult<SecretValue> {
            self.siv(key)?
                .decrypt([aad], cipher_text.value())
                .map(SecretValue::new)
                .map_err(|_| KmsAeadEncryptionError::create("DECRYPT", "Unable to decrypt data"))
        }

        /// The cipher keyed with `key`: the first half keys S2V's CMAC and the second half CTR,
        /// the order of RFC 5297 and of Tink's `AesSivKey`.
        fn siv(&self, key: &DeterministicDataEncryptionKey) -> KmsAeadResult<Aes256Siv> {
            let key = key.value().ref_sensitive_value();
            match self.algorithm {
                DeterministicAlgorithm::Aes256Siv => {
                    Aes256Siv::new_from_slice(key).map_err(|_| self.invalid_key_length(key.len()))
                }
            }
        }

        fn invalid_key_length(&self, len: usize) -> KmsAeadError {
            KmsAeadEncryptionError::create(
                "INVALID_KEY_LENGTH",
                &format!(
                    "A key of {len} bytes does not fit {}, which takes {} bytes",
                    self.algorithm,
                    self.algorithm.key_len()
                ),
            )
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
        /// operating system's generator otherwise.
        ///
        /// # Errors
        ///
        /// The provider's errors, and `INVALID_KEY_LENGTH` when the KMS generator returns key
        /// material of another length.
        pub async fn generate_new_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
        ) -> KmsAeadResult<(DeterministicDataEncryptionKey, EncryptedDataEncryptionKey)> {
            let cipher = DeterministicCipher::new(algorithm)?;
            let span = spans::generate_dek(
                "deterministic",
                algorithm,
                DeterministicCipher::BACKEND_NAME,
            );
            spans::in_span(span, async {
                let key = cipher.generate_key_with(&self.provider).await?;
                let encrypted_key = self
                    .provider
                    .encrypt_data_encryption_key(&DataEncryptionKey::from(key.value().clone()))
                    .await?;
                Ok((key, encrypted_key))
            })
            .await
        }

        /// Unwraps a key [`generate_new_deterministic_dek`](Self::generate_new_deterministic_dek)
        /// wrapped.
        ///
        /// # Errors
        ///
        /// The provider's errors, and `INVALID_KEY_LENGTH` when the unwrapped key does not fit
        /// `algorithm`.
        pub async fn decrypt_deterministic_dek(
            &self,
            algorithm: DeterministicAlgorithm,
            encrypted_key: &EncryptedDataEncryptionKey,
        ) -> KmsAeadResult<DeterministicDataEncryptionKey> {
            let cipher = DeterministicCipher::new(algorithm)?;
            spans::in_span(spans::decrypt_dek("deterministic", algorithm), async {
                let key = self
                    .provider
                    .decrypt_data_encryption_key(encrypted_key)
                    .await?;
                let len = key.value().ref_sensitive_value().len();
                if len == algorithm.key_len() {
                    Ok(DeterministicDataEncryptionKey(key.value().clone()))
                } else {
                    Err(cipher.invalid_key_length(len))
                }
            })
            .await
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use aes_siv::aead::{Aead, Payload};
        use aes_siv::Aes256SivAead;

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

        fn cipher() -> DeterministicCipher {
            DeterministicCipher::new(DeterministicAlgorithm::Aes256Siv).unwrap()
        }

        fn key_of(hex_key: &str) -> DeterministicDataEncryptionKey {
            DeterministicDataEncryptionKey::from(SecretValue::new(hex::decode(hex_key).unwrap()))
        }

        fn sealed(aad: &[u8], key: &DeterministicDataEncryptionKey) -> DeterministicCipherText {
            cipher()
                .encrypt_value(aad, &SecretValue::from(PLAIN_TEXT), key)
                .unwrap()
        }

        fn rfc_key() -> DeterministicDataEncryptionKey {
            key_of(VECTORS[0].key)
        }

        #[test]
        fn seals_and_opens_the_published_vectors() {
            for vector in VECTORS {
                let key = key_of(vector.key);
                let aad = hex::decode(vector.aad).unwrap();
                let plain_text = SecretValue::new(hex::decode(vector.plain_text).unwrap());

                let cipher_text = cipher().encrypt_value(&aad, &plain_text, &key).unwrap();
                assert_eq!(cipher_text.to_hex_string(), vector.cipher_text);

                let opened = cipher().decrypt_value(&aad, &cipher_text, &key).unwrap();
                assert_eq!(opened, plain_text);
            }
        }

        #[test]
        fn aad_is_one_header_item() {
            let key = rfc_key();
            let aead_form = Aes256SivAead::new_from_slice(key.value().ref_sensitive_value())
                .unwrap()
                .encrypt(
                    &aes_siv::Nonce::default(),
                    Payload {
                        msg: PLAIN_TEXT.as_bytes(),
                        aad: AAD,
                    },
                )
                .unwrap();
            let one_header = Aes256Siv::new_from_slice(key.value().ref_sensitive_value())
                .unwrap()
                .encrypt([AAD], PLAIN_TEXT.as_bytes())
                .unwrap();

            let cipher_text = sealed(AAD, &key);

            assert_eq!(cipher_text.value(), one_header.as_slice());
            assert_ne!(cipher_text.value(), aead_form.as_slice());
        }

        #[test]
        fn an_empty_aad_is_one_empty_item() {
            let key = rfc_key();
            let mut siv = Aes256Siv::new_from_slice(key.value().ref_sensitive_value()).unwrap();
            let one_empty_header = siv.encrypt([b""], PLAIN_TEXT.as_bytes()).unwrap();
            let no_header = siv
                .encrypt::<[&[u8]; 0], _>([], PLAIN_TEXT.as_bytes())
                .unwrap();

            let cipher_text = sealed(b"", &key);

            assert_eq!(cipher_text.value(), one_empty_header.as_slice());
            assert_ne!(cipher_text.value(), no_header.as_slice());
        }

        #[test]
        fn a_32_byte_key_is_refused_by_aes256siv() {
            let key = DeterministicDataEncryptionKey::from(SecretValue::new(vec![0x42; 32]));

            let result = cipher().encrypt_value(AAD, &SecretValue::from(PLAIN_TEXT), &key);

            assert_eq!(result.unwrap_err().code(), "INVALID_KEY_LENGTH");
        }

        #[test]
        fn equal_inputs_give_equal_values() {
            let key = cipher().generate_key().unwrap();

            assert_eq!(sealed(AAD, &key), sealed(AAD, &key));
        }

        #[test]
        fn a_different_aad_gives_a_different_value() {
            let key = cipher().generate_key().unwrap();

            assert_ne!(sealed(AAD, &key), sealed(b"orders/1043", &key));
        }

        #[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
        mod envelope {
            use super::*;
            use crate::test_provider::{TestBackend, TestKmsProvider};

            type Envelope = KmsAeadEnvelope<TestKmsProvider, TestBackend>;

            #[tokio::test]
            async fn deterministic_dek_round_trips_through_the_provider() {
                let envelope = Envelope::new(TestKmsProvider::Working).await.unwrap();
                let algorithm = DeterministicAlgorithm::Aes256Siv;

                let (key, encrypted_key) = envelope
                    .generate_new_deterministic_dek(algorithm)
                    .await
                    .unwrap();
                let (other_key, _) = envelope
                    .generate_new_deterministic_dek(algorithm)
                    .await
                    .unwrap();
                let unwrapped = envelope
                    .decrypt_deterministic_dek(algorithm, &encrypted_key)
                    .await
                    .unwrap();

                assert_eq!(unwrapped.value(), key.value());
                assert_ne!(key.value(), other_key.value());
                assert_eq!(sealed(AAD, &unwrapped), sealed(AAD, &key));
            }

            #[tokio::test]
            async fn an_unwrapped_key_of_another_length_is_refused() {
                let envelope = Envelope::new(TestKmsProvider::Working).await.unwrap();
                let encrypted_key = EncryptedDataEncryptionKey::new(vec![0x42; 32], None);

                let result = envelope
                    .decrypt_deterministic_dek(DeterministicAlgorithm::Aes256Siv, &encrypted_key)
                    .await;

                assert_eq!(result.unwrap_err().code(), "INVALID_KEY_LENGTH");
            }
        }
    }
}
