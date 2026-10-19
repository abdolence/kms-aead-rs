//! [`Sealer`]: the fields of one write sealed under one keyring record, whose seal marker the
//! write stores beside them.

use std::sync::Arc;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Randomized;
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, Plaintext};

use crate::errors::{KeyringError, KeyringResult};
use crate::purpose::unreserved;
use crate::record_cache::VersionLookup;
use crate::spans;
use crate::store::KeyringStore;
use crate::{FieldAad, KeyId, KeyVersionState, Keyring, KeyringRecord, Purpose, Resealed};

/// The sealing calls of one write of an application record, under the active versions of one
/// keyring record, [`record`](Self::record), whose
/// [`seal_marker`](KeyringRecord::seal_marker) the write stores beside the fields it seals.
///
/// The marker then names the epoch of every version the fields are under, so the record lies in
/// each version's [`seal_range`](crate::KeyVersion::seal_range), and the range query of a version
/// finds every record that holds a value under it. [`Keyring::sealer`] takes the cached record
/// once, and a refresh of the cache leaves the sealer's record as it was.
///
/// One sealer serves one write, and seals every encrypted field of the record, beacons and
/// deterministic fields included: a write that touches any encrypted field seals all of them
/// again, so that none stays under a version the new marker does not name. A sealer goes on
/// sealing under its record's versions after a refresh has taken them out of use, as after a
/// compromise, for as long as it is held, so it is held for one write and no longer. One write
/// may cover many records, such as a batch of a [`run_batched`](crate::sweep::run_batched) sweep,
/// since every record in it is stamped with the marker of the sealer's record.
pub struct Sealer<'k, S: KeyringStore, P, B> {
    pub(super) keyring: &'k Keyring<S, P, B>,
    pub(super) record: Arc<KeyringRecord>,
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// A [`Sealer`] over the cached record, revalidated first when it is older than
    /// [`record_ttl`](crate::KeyringRegistryOptions::record_ttl), for one write of an
    /// application record.
    pub async fn sealer(&self) -> Sealer<'_, S, P, B> {
        Sealer {
            keyring: self,
            record: self.cache.current().await,
        }
    }
}

impl<S, P, B> Sealer<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// The record every call of this sealer seals under. Its
    /// [`seal_marker`](KeyringRecord::seal_marker) is the marker to store beside the fields, and
    /// its active versions are the ones a re-seal compares a stored value or beacon with.
    pub fn record(&self) -> &KeyringRecord {
        &self.record
    }

    /// Seals `value` with `aad` under the record's active randomised version.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the record has none, which follows a
    /// `mark_compromised` whose new key could not be encrypted; [`KeyringError::Interop`] when
    /// sealing breaks the [`Interop`](crate::Interop) requirement `aad` carries;
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
        spans::in_span(span, async {
            let (version, encrypted_dek) =
                self.record.active_dek(Purpose::Randomized).ok_or_else(|| {
                    KeyringError::no_active_version(keyring.id(), Purpose::Randomized)
                })?;
            spans::record_sealing_version(version);
            keyring.check_interop(aad.interop, version)?;
            let cipher = keyring.cipher(version)?;
            let (sealed, outcome) = keyring
                .with_cached_dek(&self.record, version.id(), encrypted_dek, |dek| {
                    cipher.encrypt(version.id(), &aad.bytes, value, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(sealed?)
        })
        .await
    }

    /// `value` sealed again with `aad` under the record's active randomised version, with the
    /// trust of the version it was read under, or `None` when it is under that version already.
    ///
    /// A value is sealed again only when its version is older than the sealer's, by the rule of
    /// [`is_current`](Self::is_current): a version that a rotation left behind, a decrypt-only
    /// version above the active one, which `KeyringAdmin::promote` of an older pending version
    /// leaves after `KeyringAdmin::mark_compromised`, or a compromised one. A value under a
    /// version that is pending in the sealer's record, or missing from it, was sealed under a
    /// newer record, and is never sealed back under the sealer's versions:
    /// [`KeyringError::SealerOutdated`] tells the write to take a new sealer and run again.
    ///
    /// The value is read with [`Keyring::decrypt_with_trust`], so a value under a compromised
    /// version is re-sealed too, and [`Resealed::trust`] says so: the caller decides whether to
    /// keep it, see [`ResealOutcome`](crate::sweep::ResealOutcome).
    ///
    /// [`Resealed`] holds no plaintext, and a value under the active version is not opened, so a
    /// field with a beacon is read with `decrypt_with_trust` instead: its plaintext gives both the
    /// value under the active version, through [`encrypt`](Self::encrypt), and the beacon under the
    /// active beacon version, through [`beacon`](Self::beacon), since a beacon rotation leaves the
    /// value itself current.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KeyPurposeMismatch`] for a value whose key id is of another purpose, and
    /// the errors of `is_current`, before any decryption; then the errors of
    /// `decrypt_with_trust` and of [`encrypt`](Self::encrypt).
    pub async fn reseal<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<Option<Resealed<T, Randomized>>> {
        let key_id = Purpose::Randomized.check(value.key_id())?;
        if self.is_current(key_id).await? {
            return Ok(None);
        }
        let decrypted = self.keyring.decrypt_with_trust(aad, value).await?;
        Ok(Some(Resealed {
            value: self.encrypt(aad, &decrypted.value).await?,
            trust: decrypted.trust,
        }))
    }

    /// Whether a value or beacon under `key_id` is current for this sealer: `true` when `key_id`
    /// is the active version of its purpose in the sealer's record, and `false` when it is
    /// another version the record holds past pending, so the value is sealed again, or the beacon
    /// derived again, under the active version.
    ///
    /// A version that is pending in the record, or missing from it, was active in a newer record
    /// than the sealer's, under which another process sealed. Sealing again under the sealer's
    /// versions would move the value back to an older version, one possibly flagged compromised
    /// since, so the call fails instead. It first reloads the cached record when that record
    /// lacks the version too, or holds it as pending, under the rate limit of
    /// [`Keyring::decrypt`]'s reload for a key id it lacks, so that a sealer taken after the
    /// failure has the version. The sealer's own record stays as it is, so that its marker keeps
    /// naming every version the write seals under.
    ///
    /// # Errors
    ///
    /// [`KeyringError::ReservedKeyId`] for a reserved `key_id` and
    /// [`KeyringError::NoActiveVersion`] when the record has no active version of its purpose,
    /// before any store call; [`KeyringError::SealerOutdated`] for a version pending in the
    /// record or missing from it, when the cached record has it; and
    /// [`KeyringError::KeyVersionUnknown`] when the reloaded record lacks it too.
    pub async fn is_current(&self, key_id: KeyId) -> KeyringResult<bool> {
        let keyring = self.keyring;
        let purpose = Purpose::of(unreserved(key_id)?);
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
            Some(_) => KeyringError::sealer_outdated(keyring.id(), key_id),
            None => KeyringError::key_version_unknown(keyring.id(), key_id),
        })
    }
}
