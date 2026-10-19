//! [`KeyringAdmin`]: the calls that change a keyring's record or export its keys, behind the
//! `admin` feature.

use jiff::Timestamp;
use kms_aead::backends::AeadBackend;
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEncryptionProvider};

use crate::errors::KeyringResult;
use crate::purpose::unreserved;
use crate::record::{NewVersion, RecordEdit};
use crate::spans;
use crate::store::KeyringStore;
use crate::{
    Compromise, KeyAlgorithm, KeyId, KeyVersion, KeyVersionState, Keyring, KeyringRecord, Purpose,
};

mod export;
pub use export::{EncryptedKeyset, KeysetSelection};

/// The administrative handle on one keyring of a [`KeyringRegistry`](crate::KeyringRegistry),
/// which its [`create`](crate::KeyringRegistry::create),
/// [`open_or_create`](crate::KeyringRegistry::open_or_create) and
/// [`admin`](crate::KeyringRegistry::admin) return: the lifecycle calls that write the record, and
/// the keyset exports. It needs the `admin` feature.
///
/// The lifecycle calls write the record, which needs write access to the store, and `rotate`,
/// `change_algorithm`, `mark_compromised` and `reencrypt_deks`, like the registry's `create`,
/// encrypt DEKs too. The exports decrypt the exported keys and encrypt the keyset. So an
/// administrative handle runs under a principal with the KMS's encrypt and decrypt rights and
/// write access to the store, such as an infrastructure job, while the application builds without
/// the feature and holds the decrypt right and read access only.
///
/// It holds a [`Keyring`] of the same keyring, [`keyring`](Self::keyring), for the calls it shares
/// with the application: `id`, `record`, `reload`, encryption and sweeps. The handles of one
/// keyring in a registry share its cached record and watch, so a write through this one is seen
/// by every `Keyring` at once. Its writes retry
/// [`cas_retries`](crate::KeyringOptions::cas_retries) conflicts of the registry's
/// [`keyring`](crate::KeyringRegistryOptions::keyring) options.
pub struct KeyringAdmin<S: KeyringStore, P, B> {
    keyring: Keyring<S, P, B>,
}

impl<S, P, B> KeyringAdmin<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    pub(crate) fn new(keyring: Keyring<S, P, B>) -> Self {
        Self { keyring }
    }

    /// The handle on the same keyring for the calls an application makes, with the same provider
    /// and options.
    pub fn keyring(&self) -> &Keyring<S, P, B> {
        &self.keyring
    }

    /// Stages a new version of `purpose`, with the record's algorithm for it, and returns its
    /// key id. The version is [`Pending`](KeyVersionState::Pending): every process decrypts under
    /// it once its record refreshes, and none encrypts under it until
    /// [`promote`](Self::promote) makes it active.
    ///
    /// Promote it only after the longest time any process may run without a successful refresh
    /// of its record, from [`staged_at`](KeyVersion::staged_at): a process that has not seen the
    /// pending version reads a value under it as an unknown key id, and reloads its record first.
    ///
    /// # Errors
    ///
    /// The provider's and the store's errors,
    /// [`KeyringError::NoAlgorithm`](crate::KeyringError::NoAlgorithm) for a purpose the record
    /// names no algorithm for,
    /// [`KeyringError::InvalidTransition`](crate::KeyringError::InvalidTransition) with
    /// [`Transition::Rotate`](crate::Transition::Rotate) naming the pending version when the
    /// purpose has one already,
    /// [`KeyringError::RecordRegressed`](crate::KeyringError::RecordRegressed) when the stored
    /// record moves backwards from the cached one, and
    /// [`KeyringError::RecordConflict`](crate::KeyringError::RecordConflict) after
    /// [`cas_retries`](crate::KeyringOptions::cas_retries) conflicts.
    pub async fn rotate(&self, purpose: Purpose) -> KeyringResult<KeyId> {
        let keyring = &self.keyring;
        spans::in_span(spans::rotate(keyring.id(), purpose), async {
            let algorithm = keyring.record().algorithm_of(purpose)?;
            let new = NewVersion::generate::<P, B>(algorithm, &keyring.provider).await?;
            let staged = keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| {
                        let algorithm = edit.record().algorithm_of(purpose)?;
                        let new = if algorithm == new.algorithm {
                            new.clone()
                        } else {
                            // Another writer changed the purpose's algorithm since the key was
                            // made.
                            NewVersion::generate::<P, B>(algorithm, &keyring.provider).await?
                        };
                        edit.stage(new, Timestamp::now())
                    },
                )
                .await?;
            spans::record_rotation(None, staged);
            Ok(staged)
        })
        .await
    }

    /// Makes the pending version `key_id` the active version of its purpose; the version it
    /// replaces decrypts only. Processes on the old record keep sealing under the previous
    /// version until their record refreshes, and those values decrypt.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`](crate::KeyringError::ReservedKeyId), before any store call,
    /// for a reserved key id; the store's errors,
    /// [`KeyringError::KeyVersionUnknown`](crate::KeyringError::KeyVersionUnknown),
    /// [`KeyringError::InvalidTransition`](crate::KeyringError::InvalidTransition) for a version
    /// that is not pending, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn promote(&self, key_id: KeyId) -> KeyringResult<Rotation> {
        unreserved(key_id)?;
        let keyring = &self.keyring;
        spans::in_span(spans::promote(keyring.id(), key_id), async {
            let rotation = keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| edit.promote(key_id, Timestamp::now()),
                )
                .await?;
            spans::record_rotation(rotation.previous, rotation.current);
            Ok(rotation)
        })
        .await
    }

    /// Makes `algorithm` the one new versions of its purpose use, and stages a version of it as
    /// [`rotate`](Self::rotate) does, returning its key id.
    ///
    /// # Errors
    ///
    /// As [`rotate`](Self::rotate), and `UNSUPPORTED_ALGORITHM` from kms-aead when the backend
    /// does not implement `algorithm`.
    pub async fn change_algorithm(&self, algorithm: KeyAlgorithm) -> KeyringResult<KeyId> {
        let keyring = &self.keyring;
        spans::in_span(spans::rotate(keyring.id(), algorithm.purpose()), async {
            let new = NewVersion::generate::<P, B>(algorithm, &keyring.provider).await?;
            let staged = keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| {
                        let now = Timestamp::now();
                        edit.set_algorithm(algorithm, now);
                        edit.stage(new.clone(), now)
                    },
                )
                .await?;
            spans::record_rotation(None, staged);
            Ok(staged)
        })
        .await
    }

    /// Flags the version `key_id` compromised, for good, and drops its key from this process's
    /// [`DekCache`](kms_aead::cache::DekCache) before returning; other processes drop it when
    /// their record refreshes.
    ///
    /// For the active version, it also adds a new version in the same write, active at once
    /// rather than pending, and returns the rotation: every encryption under the compromised key
    /// stops as soon as each process refreshes, and the processes that have not seen the new
    /// version yet reload their record when they read a value under it. A pending version of the
    /// purpose stays pending. When the KMS cannot encrypt the new key, during an outage or without
    /// the encrypt right, it writes the flag alone, logs a `WARN` naming the error and returns
    /// `Ok(None)`: the purpose then has no active version, and a sealer's `encrypt` fails with
    /// `NoActiveVersion` until a version is promoted. For any other version it returns
    /// `Ok(None)`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`](crate::KeyringError::ReservedKeyId), before any store call,
    /// for a reserved key id; the store's errors,
    /// [`KeyringError::KeyVersionUnknown`](crate::KeyringError::KeyVersionUnknown),
    /// [`KeyringError::InvalidTransition`](crate::KeyringError::InvalidTransition) for a pending,
    /// destroyed or already compromised version, and the errors of a write as for
    /// [`rotate`](Self::rotate). A pending version never sealed a value: [`destroy`](Self::destroy)
    /// it instead.
    pub async fn mark_compromised(
        &self,
        key_id: KeyId,
        note: Option<String>,
    ) -> KeyringResult<Option<Rotation>> {
        unreserved(key_id)?;
        let keyring = &self.keyring;
        spans::in_span(spans::mark_compromised(keyring.id(), key_id), async {
            // `None` when the cached record has no active `key_id`, and `Some(None)` when the
            // replacement's key could not be encrypted, which is not tried again in the write.
            let cached = keyring.record();
            let prepared = match cached.version(key_id) {
                Some(version) if version.state() == KeyVersionState::Active => {
                    Some(self.replacement(&cached, version).await)
                }
                _ => None,
            };
            let rotation = keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| {
                        let record = edit.record();
                        let replacement = match record.version(key_id) {
                            Some(version) if version.state() == KeyVersionState::Active => {
                                match &prepared {
                                    Some(Some(new))
                                        if record.algorithms().of(new.algorithm.purpose())
                                            == Some(new.algorithm) =>
                                    {
                                        Some(new.clone())
                                    }
                                    Some(None) => None,
                                    // The record changed since the cached one: another writer
                                    // promoted this version or changed its purpose's algorithm.
                                    _ => self.replacement(record, version).await,
                                }
                            }
                            _ => None,
                        };
                        let now = Timestamp::now();
                        edit.mark_compromised(
                            key_id,
                            Compromise::new(now, note.clone()),
                            replacement,
                            now,
                        )
                    },
                )
                .await?;
            if let Some(rotation) = &rotation {
                spans::record_rotation(None, rotation.current);
            }
            Ok(rotation)
        })
        .await
    }

    /// Moves a decrypt-only version to `Retired`, once a sweep found no value left under it:
    /// reads under it fail from then on, and [`reinstate`](Self::reinstate) undoes it.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`](crate::KeyringError::ReservedKeyId), before any store call,
    /// for a reserved key id; the store's errors,
    /// [`KeyringError::KeyVersionUnknown`](crate::KeyringError::KeyVersionUnknown),
    /// [`KeyringError::InvalidTransition`](crate::KeyringError::InvalidTransition) for any version
    /// that is not decrypt-only, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn retire(&self, key_id: KeyId) -> KeyringResult<()> {
        unreserved(key_id)?;
        let keyring = &self.keyring;
        spans::in_span(spans::retire(keyring.id(), key_id), async {
            keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| edit.retire(key_id, Timestamp::now()),
                )
                .await
        })
        .await
    }

    /// Moves a retired version back to `DecryptOnly`, for a value that turned up after all. A
    /// compromised flag stays.
    ///
    /// # Errors
    ///
    /// As [`retire`](Self::retire), for any version that is not retired.
    pub async fn reinstate(&self, key_id: KeyId) -> KeyringResult<()> {
        unreserved(key_id)?;
        let keyring = &self.keyring;
        spans::in_span(spans::reinstate(keyring.id(), key_id), async {
            keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| edit.reinstate(key_id, Timestamp::now()),
                )
                .await
        })
        .await
    }

    /// Removes a retired or pending version's encrypted DEK from the record: the values under it
    /// can never be read again, from this record. The version stays, so that its id is never
    /// reused.
    ///
    /// # Errors
    ///
    /// As [`retire`](Self::retire), for any version that is neither retired nor pending.
    pub async fn destroy(&self, key_id: KeyId) -> KeyringResult<()> {
        unreserved(key_id)?;
        let keyring = &self.keyring;
        spans::in_span(spans::destroy(keyring.id(), key_id), async {
            keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| edit.destroy(key_id, Timestamp::now()),
                )
                .await
        })
        .await
    }

    /// Destroys every version of every purpose in one write, whatever its state: their encrypted
    /// DEKs leave the record, and from then on the keyring encrypts nothing and decrypts nothing.
    /// It cannot be undone from this record, and it is the shredding of one keyring's values
    /// under a KEK that other keyrings share.
    ///
    /// A backup of the record still holds the encrypted DEKs, which the KMS decrypts for as long
    /// as the KEK version that encrypted them exists. So the record's backups are deleted too, or
    /// the KEK is rotated, every other keyring under it runs
    /// [`reencrypt_deks`](Self::reencrypt_deks), and the previous KEK version is destroyed.
    ///
    /// # Errors
    ///
    /// The store's errors, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn dangerously_destroy_all_versions(&self) -> KeyringResult<()> {
        let keyring = &self.keyring;
        spans::in_span(spans::destroy_all_versions(keyring.id()), async {
            keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| {
                        edit.destroy_all(Timestamp::now());
                        Ok(())
                    },
                )
                .await
        })
        .await
    }

    /// Decrypts and encrypts again the key of every version that holds one, so that all of them sit
    /// under the KEK's current version after the KEK rotated in the KMS. No value changes. The
    /// keys are decrypted through the provider, never through the
    /// [`DekCache`](kms_aead::cache::DekCache). Returns the number of versions encrypted again.
    ///
    /// # Errors
    ///
    /// The provider's errors, and the errors of a write as for [`rotate`](Self::rotate).
    pub async fn reencrypt_deks(&self) -> KeyringResult<usize> {
        let keyring = &self.keyring;
        spans::in_span(spans::reencrypt_deks(keyring.id()), async {
            let mut reencrypted = Vec::new();
            for (_, encrypted_dek) in keyring.record().encrypted_deks() {
                let new_encrypted_dek = self.reencrypted(&encrypted_dek).await?;
                reencrypted.push((encrypted_dek, new_encrypted_dek));
            }
            let versions = keyring
                .cache
                .write(
                    keyring.options.cas_retries,
                    async |edit: &mut RecordEdit| {
                        let encrypted_deks = edit.record().encrypted_deks();
                        for (key_id, encrypted_dek) in &encrypted_deks {
                            let prepared = reencrypted
                                .iter()
                                .find(|(held, _)| held == encrypted_dek)
                                .map(|(_, new_encrypted_dek)| new_encrypted_dek.clone());
                            let new_encrypted_dek = match prepared {
                                Some(new_encrypted_dek) => new_encrypted_dek,
                                // A version that another writer added or encrypted again meanwhile.
                                None => self.reencrypted(encrypted_dek).await?,
                            };
                            edit.replace_dek(*key_id, new_encrypted_dek, Timestamp::now())?;
                        }
                        Ok(encrypted_deks.len())
                    },
                )
                .await?;
            spans::record_versions(versions);
            Ok(versions)
        })
        .await
    }

    /// A new version to replace `replaced`, the active version of `record` being flagged
    /// compromised, or `None`, with a `WARN`, when its key cannot be encrypted: the flag goes in
    /// without it.
    async fn replacement(
        &self,
        record: &KeyringRecord,
        replaced: &KeyVersion,
    ) -> Option<NewVersion> {
        let new = match record.algorithm_of(replaced.algorithm().purpose()) {
            Ok(algorithm) => NewVersion::generate::<P, B>(algorithm, &self.keyring.provider).await,
            Err(error) => Err(error),
        };
        new.inspect_err(|error| {
            spans::compromised_without_rotation(self.keyring.id(), replaced.id(), error)
        })
        .ok()
    }

    /// `encrypted_dek` decrypted through the provider and encrypted again. What the KMS decrypts
    /// is the serialised Tink key it encrypted, so it is encrypted again as it is.
    async fn reencrypted(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KeyringResult<EncryptedDataEncryptionKey> {
        let provider = &self.keyring.provider;
        let dek = provider.decrypt_data_encryption_key(encrypted_dek).await?;
        Ok(provider.encrypt_data_encryption_key(&dek).await?)
    }
}

/// What a promotion, or the replacement of a compromised active version, did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rotation {
    /// The purpose rotated.
    pub purpose: Purpose,
    /// The version that was active before, and decrypts only now.
    pub previous: Option<KeyId>,
    /// The new active version.
    pub current: KeyId,
}
