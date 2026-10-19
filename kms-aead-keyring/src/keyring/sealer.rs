//! [`Sealer`]: the fields of one write sealed under one keyring record, whose seal marker the
//! write stores beside them.

use std::sync::Arc;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Randomized;
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, Plaintext};

use crate::errors::{KeyringError, KeyringResult};
use crate::spans;
use crate::store::KeyringStore;
use crate::{FieldAad, KeyId, Keyring, KeyringRecord, Purpose, Resealed};

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
/// compromise, for as long as it is held, so it is held for one write and no longer.
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
    /// Any other version is re-sealed, whatever its key id: a version that a rotation left behind,
    /// a decrypt-only version above the active one, which `KeyringAdmin::promote` of an older
    /// pending version leaves after `KeyringAdmin::mark_compromised`, and a version still pending
    /// in the sealer's record, which a process with a fresher record promoted and sealed under. In
    /// the last case the value goes back under the version the sealer's marker names, and the
    /// record stays in the query of the next sweep. A key id the sealer's record lacks is read as
    /// [`Keyring::decrypt`] reads it, after one reload of the cached record.
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
    /// [`KeyringError::ReservedKeyId`] and [`KeyringError::KeyPurposeMismatch`] for the value's
    /// key id, before any store or KMS call; [`KeyringError::NoActiveVersion`] before any
    /// decryption; and the errors of `decrypt_with_trust`, among them
    /// [`KeyringError::KeyVersionUnknown`] when the reloaded record lacks the key id too, and of
    /// [`encrypt`](Self::encrypt).
    pub async fn reseal<T: Plaintext>(
        &self,
        aad: &FieldAad,
        value: &Encrypted<T, Randomized>,
    ) -> KeyringResult<Option<Resealed<T, Randomized>>> {
        let key_id = Purpose::Randomized.check(value.key_id())?;
        if self.is_active(Purpose::Randomized, key_id)? {
            return Ok(None);
        }
        let decrypted = self.keyring.decrypt_with_trust(aad, value).await?;
        Ok(Some(Resealed {
            value: self.encrypt(aad, &decrypted.value).await?,
            trust: decrypted.trust,
        }))
    }

    /// Whether `key_id` is the active version of `purpose` in the record, or
    /// [`KeyringError::NoActiveVersion`] when the purpose has none.
    pub(super) fn is_active(&self, purpose: Purpose, key_id: KeyId) -> KeyringResult<bool> {
        let active = self
            .record
            .active(purpose)
            .ok_or_else(|| KeyringError::no_active_version(self.keyring.id(), purpose))?;
        Ok(active.id() == key_id)
    }
}
