//! The deterministic calls of [`Keyring`], which run AES-SIV and so need the `deterministic`
//! feature.

use std::cmp::Reverse;

use kms_aead::cache::DekCache;
use kms_aead::{
    DeterministicCipher, DeterministicCipherText, DeterministicDataEncryptionKey,
    EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, ValueStruct,
};
use secret_vault_value::SecretValue;

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::spans;
use crate::store::KeyringStore;
use crate::{
    Decrypted, Deterministic, DeterministicAad, Encrypted, KeyAlgorithm, KeyTrust, KeyVersion,
    Keyring, KeyringRecord, Plaintext, Purpose,
};

/// The `backend` span value of a deterministic call: kms-aead runs AES-SIV on RustCrypto whatever
/// the keyring's AEAD backend.
const DETERMINISTIC_BACKEND: &str = "rustcrypto";

/// Deterministic fields: equal plaintexts under one version give equal values, so that a data
/// store finds a row by an encrypted column.
///
/// A deterministic column leaks which rows hold equal values and how often each value occurs,
/// to anyone who reads the column, without any key. Without a nonce, a leaked key lets its
/// holder test guesses against the whole column offline. It fits fields that are queried and
/// have high entropy, such as emails and external ids, and never low-cardinality fields, such
/// as a status or a country, whose values the frequencies give away. A value opens in any row of
/// the same kind and field (see [`DeterministicAad`]), so a deterministic field never decides
/// identity or authorization on its own.
impl<S, P> Keyring<S, P>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
{
    /// Seals `value` with `aad` under the active deterministic version: the same `value` and
    /// `aad` give the same bytes until that version is rotated. The column it goes into leaks
    /// equality and frequency; see the leaks above.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the keyring has no deterministic version, or lost
    /// it to a `mark_compromised` whose new key could not be wrapped; [`KeyringError::Interop`]
    /// when sealing breaks the [`Interop`](crate::Interop) requirement `aad` carries;
    /// [`KeyringError::Plaintext`] when the value does not encode; and the provider's error
    /// when the version's key is not in the [`DekCache`] and cannot be unwrapped.
    pub async fn encrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T, Deterministic>> {
        let span = spans::encrypt(self.id(), Purpose::Deterministic, DETERMINISTIC_BACKEND);
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let (version, dek) = record.active_dek(Purpose::Deterministic).ok_or_else(|| {
                KeyringError::no_active_version(self.id(), Purpose::Deterministic)
            })?;
            spans::record_sealing_version(version);
            self.check_interop(aad.interop, version)?;
            let plaintext = value.to_plaintext()?;
            let sealed = self
                .seal_cached(&record, version, dek, aad, &plaintext)
                .await?;
            Ok(Encrypted::new(version.key_id(), sealed.value()))
        })
        .await
    }

    /// Opens `value` with `aad`, under the version it names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy.
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt).
    pub async fn decrypt_deterministic<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<T> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            self.apply_read_policy(version, compromise)?;
            let cipher = self.deterministic_cipher(version)?;
            let body = DeterministicCipherText::from(value.body().to_vec());
            let plaintext = self
                .with_cached_key(&record, version.key_id(), dek, async |cache, binding| {
                    cache
                        .with_deterministic_key(
                            &self.provider,
                            cipher.algorithm(),
                            dek,
                            binding,
                            |key| cipher.decrypt_value(&aad.bytes, &body, key),
                        )
                        .await
                })
                .await??;
            T::from_plaintext(plaintext)
        })
        .await
    }

    /// Opens `value` with `aad` and reports which version opened it and whether that version is
    /// compromised, without applying the read policy, as
    /// [`decrypt_with_status`](Self::decrypt_with_status) does for randomized values. A
    /// compromised version's key is unwrapped through the provider, never through the
    /// [`DekCache`].
    ///
    /// # Errors
    ///
    /// As [`decrypt`](Self::decrypt), without `KeyVersionCompromised`.
    pub async fn decrypt_deterministic_with_status<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &Encrypted<T, Deterministic>,
    ) -> KeyringResult<Decrypted<T>> {
        let span = spans::decrypt(self.id(), value.key_id());
        spans::in_span(span, async {
            let (record, reload) = self.cache.find(value.key_id()).await;
            spans::record_reload(reload);
            let (version, dek, compromise) = self.readable(&record, value.key_id())?;
            let cipher = self.deterministic_cipher(version)?;
            let body = DeterministicCipherText::from(value.body().to_vec());
            let open =
                |key: &DeterministicDataEncryptionKey| cipher.decrypt_value(&aad.bytes, &body, key);
            let (plaintext, trust) = match compromise {
                None => (
                    self.with_cached_key(&record, version.key_id(), dek, async |cache, binding| {
                        cache
                            .with_deterministic_key(
                                &self.provider,
                                cipher.algorithm(),
                                dek,
                                binding,
                                open,
                            )
                            .await
                    })
                    .await??,
                    KeyTrust::Trusted,
                ),
                Some(compromise) => (
                    self.with_uncached_key(version, dek, &cipher, open)
                        .await??,
                    KeyTrust::Compromised(compromise.clone()),
                ),
            };
            Ok(Decrypted {
                value: T::from_plaintext(plaintext)?,
                key_id: version.key_id(),
                trust,
            })
        })
        .await
    }

    /// `value` sealed with `aad` under every deterministic version that still decrypts, active
    /// or decrypt-only, compromised ones included, newest first: the `IN` list of an equality
    /// query, which finds the rows sealed before a rotation as well as after it. Retired and
    /// destroyed versions give no probe. A compromised version's key is unwrapped for each
    /// call, never through the [`DekCache`].
    ///
    /// A query that sends the list links the values of one plaintext across the versions for
    /// whoever reads the query, so a rotation does not unlink a value's history from that reader.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Plaintext`] when the value does not encode, and the provider's error when
    /// a version's key cannot be unwrapped.
    pub async fn equality_probes<T: Plaintext>(
        &self,
        aad: &DeterministicAad,
        value: &T,
    ) -> KeyringResult<Vec<Encrypted<T, Deterministic>>> {
        let span = spans::encrypt(self.id(), Purpose::Deterministic, DETERMINISTIC_BACKEND);
        spans::in_span(span, async {
            let record = self.cache.current().await;
            let plaintext = value.to_plaintext()?;
            let mut versions = record
                .versions()
                .iter()
                .filter(|version| version.key_id().purpose() == Purpose::Deterministic)
                .filter_map(|version| {
                    let (dek, compromise) = version.readable_dek()?;
                    Some((version, dek, compromise))
                })
                .collect::<Vec<_>>();
            versions.sort_by_key(|(version, ..)| Reverse(version.key_id()));
            let mut probes = Vec::with_capacity(versions.len());
            for (version, dek, compromise) in versions {
                let sealed = match compromise {
                    None => {
                        self.seal_cached(&record, version, dek, aad, &plaintext)
                            .await?
                    }
                    Some(_) => {
                        let cipher = self.deterministic_cipher(version)?;
                        self.with_uncached_key(version, dek, &cipher, |key| {
                            cipher.encrypt_value(&aad.bytes, &plaintext, key)
                        })
                        .await??
                    }
                };
                probes.push(Encrypted::new(version.key_id(), sealed.value()));
            }
            Ok(probes)
        })
        .await
    }

    fn deterministic_cipher(&self, version: &KeyVersion) -> KeyringResult<DeterministicCipher> {
        match version.algorithm() {
            KeyAlgorithm::Deterministic(algorithm) => Ok(DeterministicCipher::new(algorithm)?),
            KeyAlgorithm::Randomized(_) => Err(KeyringError::record_invalid(
                self.id(),
                RecordInvalidReason::PurposeMismatch(version.key_id()),
            )),
        }
    }

    /// Seals `plaintext` with `aad` under `version` of `record`, whose wrapped key is `dek`, with
    /// the key through the [`DekCache`].
    async fn seal_cached(
        &self,
        record: &KeyringRecord,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        aad: &DeterministicAad,
        plaintext: &SecretValue,
    ) -> KeyringResult<DeterministicCipherText> {
        let cipher = self.deterministic_cipher(version)?;
        Ok(self
            .with_cached_key(record, version.key_id(), dek, async |cache, binding| {
                cache
                    .with_deterministic_key(
                        &self.provider,
                        cipher.algorithm(),
                        dek,
                        binding,
                        |key| cipher.encrypt_value(&aad.bytes, plaintext, key),
                    )
                    .await
            })
            .await??)
    }

    /// Runs `use_key` with the key of `version`, which the provider unwraps for this call only
    /// and which never enters the [`DekCache`].
    async fn with_uncached_key<T>(
        &self,
        version: &KeyVersion,
        dek: &EncryptedDataEncryptionKey,
        cipher: &DeterministicCipher,
        use_key: impl FnOnce(&DeterministicDataEncryptionKey) -> T,
    ) -> KeyringResult<T> {
        let binding = self.cache.binding(version.key_id())?;
        let (result, _) = DekCache::disabled()
            .with_deterministic_key(
                &self.provider,
                cipher.algorithm(),
                dek,
                binding.as_ref(),
                use_key,
            )
            .await?;
        spans::record_dek_cache_bypassed();
        Ok(result)
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests;
