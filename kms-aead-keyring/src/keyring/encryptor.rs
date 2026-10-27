//! [`Encryptor`]: the fields of one write encrypted under one keyring record, whose encryption
//! marker the write stores beside them.

use std::sync::Arc;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Randomized;
use kms_aead::{Encrypted, KmsAeadDecryptionProvider, Plaintext};

use crate::errors::{KeyringError, KeyringResult};
use crate::metrics::KeyringCall;
use crate::purpose::unreserved_key_id;
use crate::record_cache::VersionLookup;
use crate::spans;
use crate::store::KeyringStore;
use crate::{FieldAad, KeyId, KeyVersionState, Keyring, KeyringRecord, Purpose, Reencrypted};

/// The encrypting calls of one write of an application record, under the active versions of one
/// keyring record, [`record`](Self::record), whose
/// [`encryption_marker`](KeyringRecord::encryption_marker) the write stores beside the fields it
/// encrypts.
///
/// The marker then names the epoch of every version the fields are under, so the record lies in
/// each version's [`reencrypt_range`](crate::KeyVersion::reencrypt_range), and the range query of a
/// version finds every record that holds a value under it. [`Keyring::encryptor`] takes the cached
/// record once, and a refresh of the cache leaves the encryptor's record as it was.
///
/// One encryptor serves one write, and encrypts every encrypted field of the record, beacons and
/// deterministic fields included: a write that touches any encrypted field encrypts all of them
/// again, so that none stays under a version the new marker does not name. An encryptor goes on
/// encrypting under its record's versions after a refresh has taken them out of use, as after a
/// compromise, for as long as it is held, so it is held for one write and no longer. One write
/// may cover many records, such as a batch of a [`reencrypt_records_batched`](crate::sweep::reencrypt_records_batched) sweep,
/// since every record in it is stamped with the marker of the encryptor's record.
pub struct Encryptor<'k, S: KeyringStore, P, B> {
    pub(super) keyring: &'k Keyring<S, P, B>,
    pub(super) record: Arc<KeyringRecord>,
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// An [`Encryptor`] over the cached record, revalidated first when it is older than
    /// [`record_ttl`](crate::KeyringRegistryOptions::record_ttl), for one write of an
    /// application record.
    pub async fn encryptor(&self) -> Encryptor<'_, S, P, B> {
        Encryptor {
            keyring: self,
            record: self.cache.current().await,
        }
    }
}

impl<S, P, B> Encryptor<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// The record every call of this encryptor encrypts under. Its
    /// [`encryption_marker`](KeyringRecord::encryption_marker) is the marker to store beside the
    /// fields, and its active versions are the ones a re-encryption compares a stored value or
    /// beacon with.
    pub fn record(&self) -> &KeyringRecord {
        &self.record
    }

    /// Encrypts `value` with `aad` under the record's active randomised version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the record has none, which follows a
    /// `mark_compromised` whose new key could not be encrypted; [`KeyringError::Interop`] when
    /// encrypting breaks the [`Interop`](crate::Interop) requirement `aad` carries;
    /// [`KeyringError::KmsAead`] with code `INVALID_PLAINTEXT` when the value does not encode; and
    /// the provider's error when the version's key is not in the
    /// [`DekCache`](kms_aead::cache::DekCache) and cannot be decrypted.
    pub async fn encrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &T,
    ) -> KeyringResult<Encrypted<T, Randomized>> {
        let keyring = self.keyring;
        let span = spans::encrypt(keyring.id(), Purpose::Randomized, Some(B::NAME));
        let call = KeyringCall::new(
            keyring.cache.keyring_attribute(),
            "encrypt",
            Purpose::Randomized,
            B::NAME,
        );
        let encryption = spans::in_span(span, async {
            let (version, encrypted_dek) =
                self.record.active_dek(Purpose::Randomized).ok_or_else(|| {
                    KeyringError::no_active_version(keyring.id(), Purpose::Randomized)
                })?;
            spans::record_encrypting_version(version);
            call.version(version);
            keyring.check_interop(aad.interop, &self.record, version)?;
            let cipher = keyring.cipher(version)?;
            let (encrypted, outcome) = keyring
                .with_cached_dek(&self.record, version.id(), encrypted_dek, |dek| {
                    cipher.encrypt(version.id(), &aad.bytes, value, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(encrypted?)
        });
        call.encrypted(encryption).await
    }

    /// `value` encrypted again with `aad` under the record's active randomised version, with the
    /// trust of the version it was read under, or `None` when it is under that version already.
    ///
    /// A value is encrypted again only when its version is older than the encryptor's, by the rule
    /// of [`is_current`](Self::is_current): a version that a rotation left behind, a decrypt-only
    /// version above the active one, which `KeyringAdmin::promote` of an older pending version
    /// leaves after `KeyringAdmin::mark_compromised`, or a compromised one. A value under a version
    /// that is pending in the encryptor's record, or missing from it, was encrypted under a newer
    /// record, and is never encrypted back under the encryptor's versions:
    /// [`KeyringError::EncryptorOutdated`] tells the write to take a new encryptor and run again.
    ///
    /// The value is read with [`Keyring::decrypt_with_trust`], so a value under a compromised
    /// version is re-encrypted too, and [`Reencrypted::trust`] says so: the caller decides whether
    /// to keep it, see [`ReencryptOutcome`](crate::sweep::ReencryptOutcome).
    ///
    /// [`Reencrypted`] holds no plaintext, and a value under the active version is not decrypted,
    /// so a field with a beacon is read with `decrypt_with_trust` instead: its plaintext gives both
    /// the value under the active version, through [`encrypt`](Self::encrypt), and the beacon under
    /// the active beacon version, through [`beacon`](Self::beacon), since a beacon rotation leaves
    /// the value itself current.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KeyPurposeMismatch`] for a value whose key id is of another purpose, and
    /// the errors of `is_current`, before any decryption; then the errors of
    /// `decrypt_with_trust` and of [`encrypt`](Self::encrypt).
    pub async fn reencrypt<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<Option<Reencrypted<T, Randomized>>> {
        let call = KeyringCall::new(
            self.keyring.cache.keyring_attribute(),
            "reencrypt",
            Purpose::Randomized,
            B::NAME,
        );
        call.timed(async {
            let key_id = Purpose::Randomized.check(value.key_id())?;
            if self.is_current(key_id).await? {
                return Ok(None);
            }
            let decrypted = self.keyring.decrypt_with_trust(aad, value).await?;
            Ok(Some(Reencrypted {
                value: self.encrypt(aad, &decrypted.value).await?,
                trust: decrypted.trust,
            }))
        })
        .await
    }

    /// Whether a value or beacon under `key_id` is current for this encryptor: `true` when `key_id`
    /// is the active version of its purpose in the encryptor's record, and `false` when it is
    /// another version the record holds past pending, so the value is encrypted again, or the
    /// beacon derived again, under the active version.
    ///
    /// A version that is pending in the record, or missing from it, was active in a newer record
    /// than the encryptor's, under which another process encrypted. Encrypting again under the
    /// encryptor's versions would move the value back to an older version, one possibly flagged
    /// compromised since, so the call fails instead. It first reloads the cached record when that
    /// record lacks the version too, or holds it as pending, under the rate limit of
    /// [`Keyring::decrypt`]'s reload for a key id it lacks, so that an encryptor taken after the
    /// failure has the version. The encryptor's own record stays as it is, so that its marker keeps
    /// naming every version the write encrypts under.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`] for a reserved `key_id` and
    /// [`KeyringError::NoActiveVersion`] when the record has no active version of its purpose,
    /// before any store call; [`KeyringError::EncryptorOutdated`] for a version pending in the
    /// record or missing from it, when the cached record has it; and
    /// [`KeyringError::KeyVersionUnknown`] when the reloaded record lacks it too.
    pub async fn is_current(&self, key_id: KeyId) -> KeyringResult<bool> {
        let keyring = self.keyring;
        let purpose = Purpose::of(unreserved_key_id(key_id)?);
        let active = self
            .record
            .active(purpose)
            .ok_or_else(|| KeyringError::no_active_version(keyring.id(), purpose))?;
        if active.id() == key_id {
            return Ok(true);
        }
        if self
            .record
            .version(key_id)
            .is_some_and(|version| version.state() != KeyVersionState::Pending)
        {
            return Ok(false);
        }
        let (cached, _) = keyring.cache.find(key_id, VersionLookup::PastPending).await;
        Err(match cached.version(key_id) {
            Some(_) => KeyringError::encryptor_outdated(keyring.id(), key_id),
            None => KeyringError::key_version_unknown(keyring.id(), key_id),
        })
    }
}
