//! [`RecordEdit`]: the lifecycle transitions of an administrative write, applied to the record
//! as the store holds it, and the record a new keyring starts from.

use jiff::Timestamp;
use kms_aead::backends::AeadBackend;
use kms_aead::{AeadCipher, BeaconMac, DekEncryption, KekRef, KmsAeadEncryptionProvider};

use super::{RetainedDek, VersionState};
use crate::errors::{
    InvalidTransitionError, KeyringError, KeyringResult, PurposeError, RecordInvalidReason,
};
use crate::purpose::next_key_id;
use crate::sweep::{SealMarker, SealRange};
use crate::{
    Compromise, KeyAlgorithm, KeyId, KeyVersion, KeyVersionState, KeyringAlgorithms, KeyringId,
    KeyringRecord, Purpose, Rotation, Transition,
};

/// A version about to be created: the algorithm its key was made for, and the encrypted DEK with
/// the KEK version that encrypted it. Its key id is the next one of its purpose in the record it is
/// added to, so one key serves every attempt of a write.
#[derive(Clone)]
pub(crate) struct NewVersion {
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) dek_encryption: DekEncryption,
}

impl NewVersion {
    /// A version with a new key for `algorithm`, from the KMS generator when the provider uses
    /// one and from the CSPRNG of `B` otherwise, encrypted by `provider`. Made before a write
    /// takes the record, so that no KMS call runs while the record is held, and a conflict
    /// retries with the same key.
    pub(crate) async fn generate<P, B>(algorithm: KeyAlgorithm, provider: &P) -> KeyringResult<Self>
    where
        P: KmsAeadEncryptionProvider + Sync,
        B: AeadBackend,
    {
        let (_, dek_encryption) = match algorithm {
            KeyAlgorithm::Randomized(algorithm) => {
                AeadCipher::<B>::new(algorithm)?
                    .generate_encrypted_dek(provider)
                    .await?
            }
            #[cfg(feature = "deterministic")]
            KeyAlgorithm::Deterministic(algorithm) => {
                kms_aead::DeterministicCipher::<B>::new(algorithm)?
                    .generate_encrypted_dek(provider)
                    .await?
            }
            #[cfg(not(feature = "deterministic"))]
            KeyAlgorithm::Deterministic(_) => return Err(KeyringError::DeterministicDisabled),
            KeyAlgorithm::Beacon(algorithm) => {
                BeaconMac::<B>::new(algorithm)
                    .generate_encrypted_dek(provider)
                    .await?
            }
        };
        Ok(Self {
            algorithm,
            dek_encryption,
        })
    }
}

impl KeyringAlgorithms {
    /// The record of a new keyring `id` with these algorithms, and one active version of each
    /// purpose they name an algorithm for, each encrypted by `provider`.
    pub(crate) async fn new_record<P, B>(
        &self,
        id: KeyringId,
        provider: &P,
    ) -> KeyringResult<KeyringRecord>
    where
        P: KmsAeadEncryptionProvider + Sync,
        B: AeadBackend,
    {
        let now = Timestamp::now();
        let mut edit = RecordEdit::from(KeyringRecord::new(id, provider.kek().clone(), *self, now));
        for purpose in Purpose::ALL {
            if let Some(algorithm) = self.of(purpose) {
                let new = NewVersion::generate::<P, B>(algorithm, provider).await?;
                let key_id = edit.stage(new, now)?;
                edit.promote(key_id, now)?;
            }
        }
        edit.finish()
    }
}

impl KeyringRecord {
    /// A record with no version yet, to which the creation of a keyring stages and promotes the
    /// first version of each purpose. Its seal epoch is 0 until that write finishes.
    fn new(id: KeyringId, kek: KekRef, algorithms: KeyringAlgorithms, now: Timestamp) -> Self {
        Self {
            id,
            kek,
            algorithms,
            seal_marker: SealMarker::ENVELOPE,
            versions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// The id the next version of `purpose` takes.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] with `KeyIdsExhausted` once the purpose's ordinals run
    /// out.
    pub(crate) fn next_key_id(&self, purpose: Purpose) -> KeyringResult<KeyId> {
        match self
            .versions
            .iter()
            .filter(|version| version.algorithm.purpose() == purpose)
            .map(KeyVersion::id)
            .max_by_key(|key_id| key_id.as_u32())
        {
            None => Ok(purpose.first_key_id()),
            Some(last) => next_key_id(last).ok_or_else(|| {
                KeyringError::record_invalid(
                    &self.id,
                    RecordInvalidReason::KeyIdsExhausted(purpose),
                )
            }),
        }
    }

    /// The algorithm the record names for new versions of `purpose`.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoAlgorithm`] when it names none.
    pub(crate) fn algorithm_of(&self, purpose: Purpose) -> KeyringResult<KeyAlgorithm> {
        self.algorithms.of(purpose).ok_or_else(|| {
            KeyringError::NoAlgorithm(PurposeError {
                keyring: self.id.clone(),
                purpose,
            })
        })
    }
}

impl KeyringAlgorithms {
    /// The algorithm of new versions of `purpose`, or `None` for a purpose the keyring has no
    /// versions of.
    pub(crate) fn of(&self, purpose: Purpose) -> Option<KeyAlgorithm> {
        match purpose {
            Purpose::Randomized => Some(KeyAlgorithm::Randomized(self.randomized)),
            Purpose::Deterministic => self.deterministic.map(KeyAlgorithm::Deterministic),
            Purpose::Beacon => self.beacon.map(KeyAlgorithm::Beacon),
        }
    }
}

impl RetainedDek {
    /// The same key flagged with `compromise`, or `None` when it already is: the flag and its
    /// time never change once set.
    fn flagged(&self, compromise: &Compromise) -> Option<Self> {
        self.compromised.is_none().then(|| Self {
            dek_encryption: self.dek_encryption.clone(),
            compromised: Some(compromise.clone()),
            seal_range: self.seal_range,
        })
    }
}

/// A record that an administrative write is changing: the lifecycle transitions apply to it,
/// and [`finish`](Self::finish) checks the result as a reader would, before it is written.
///
/// A version that a transition makes active starts its seal range at the epoch after the
/// record's, and a version that stops being active keeps an open range: `finish` moves the
/// epoch on to that start and closes every open range of a version that is not active, in the
/// same record, so that one compare-and-swap writes the epoch and the ranges together.
pub(crate) struct RecordEdit {
    record: KeyringRecord,
}

impl From<KeyringRecord> for RecordEdit {
    fn from(record: KeyringRecord) -> Self {
        Self { record }
    }
}

impl RecordEdit {
    /// The record as changed so far.
    pub(crate) fn record(&self) -> &KeyringRecord {
        &self.record
    }

    /// The changed record as a reader parses it from the store, so that a record that would fail
    /// its invariants or caps there is never written. When a version became active, the seal
    /// epoch moves on once, however many versions became active, and the seal range of every
    /// version that is not active and still open ends at the new epoch: no process seals under
    /// such a version once it holds the new record.
    ///
    /// # Errors
    ///
    /// The errors of a read.
    pub(crate) fn finish(self) -> KeyringResult<KeyringRecord> {
        let mut record = self.record;
        let held = record.seal_marker;
        let activated = record
            .versions
            .iter()
            .find_map(|version| match version.state {
                VersionState::Active { seal_start, .. } if seal_start > held => Some(seal_start),
                _ => None,
            });
        if let Some(epoch) = activated {
            record.seal_marker = epoch;
            for version in &mut record.versions {
                let open = match &mut version.state {
                    VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => {
                        Some(&mut kept.seal_range)
                    }
                    VersionState::Destroyed { seal_range, .. } => seal_range.as_mut(),
                    VersionState::Pending(_) | VersionState::Active { .. } => None,
                };
                if let Some(range) = open.filter(|range| range.end().is_none()) {
                    *range = SealRange::new(range.start(), Some(epoch));
                }
            }
        }
        KeyringRecord::from_json(&record.id, &record.to_json()?)
    }

    /// The marker of the epoch the versions this write makes active start their seal range at:
    /// the one after the record's.
    ///
    /// # Errors
    ///
    /// `RecordInvalid` with `SealEpochOutOfRange` when the epoch cannot count up any more.
    fn activation_marker(&self) -> KeyringResult<SealMarker> {
        self.record.seal_marker.next().ok_or_else(|| {
            KeyringError::record_invalid(&self.record.id, RecordInvalidReason::SealEpochOutOfRange)
        })
    }

    /// Adds `new` as the pending version of its purpose, under the purpose's next key id, and
    /// returns that id.
    ///
    /// # Errors
    ///
    /// `InvalidTransition` with [`Transition::Rotate`], naming the pending version, when the
    /// purpose has one already, and `RecordInvalid` with `KeyIdsExhausted` once its ids run out.
    pub(crate) fn stage(&mut self, new: NewVersion, now: Timestamp) -> KeyringResult<KeyId> {
        if let Some(pending) = self.record.pending(new.algorithm.purpose()) {
            return Err(KeyringError::InvalidTransition(InvalidTransitionError {
                keyring: self.record.id.clone(),
                key_id: pending.key_id,
                from: KeyVersionState::Pending,
                transition: Transition::Rotate,
            }));
        }
        self.push(new, VersionState::Pending, now)
    }

    /// Makes the pending version `key_id` the active version of its purpose; the active version
    /// it replaces decrypts only.
    ///
    /// # Errors
    ///
    /// `KeyVersionUnknown`, `RecordInvalid` with `SealEpochOutOfRange` when the seal epoch cannot
    /// count up any more, and `InvalidTransition` for a version that is not pending.
    pub(crate) fn promote(&mut self, key_id: KeyId, now: Timestamp) -> KeyringResult<Rotation> {
        let purpose = self.version_mut(key_id)?.algorithm.purpose();
        let previous = self.record.active(purpose).map(KeyVersion::id);
        let seal_start = self.activation_marker()?;
        self.change_state(key_id, Transition::Promote, now, |state| match state {
            VersionState::Pending(dek_encryption) => Some(VersionState::Active {
                dek_encryption: dek_encryption.clone(),
                seal_start,
            }),
            _ => None,
        })?;
        if let Some(previous) = previous {
            self.change_state(previous, Transition::Promote, now, |state| match state {
                VersionState::Active {
                    dek_encryption,
                    seal_start,
                } => Some(VersionState::DecryptOnly(RetainedDek {
                    dek_encryption: dek_encryption.clone(),
                    compromised: None,
                    seal_range: SealRange::new(*seal_start, None),
                })),
                _ => None,
            })?;
        }
        Ok(Rotation {
            purpose,
            previous,
            current: key_id,
        })
    }

    /// Flags `key_id` compromised. An active version decrypts only from then on, and
    /// `replacement`, when there is one, becomes the active version of its purpose in the same
    /// change; without one the purpose has no active version.
    pub(crate) fn mark_compromised(
        &mut self,
        key_id: KeyId,
        compromise: Compromise,
        replacement: Option<NewVersion>,
        now: Timestamp,
    ) -> KeyringResult<Option<Rotation>> {
        let was_active = self
            .record
            .version(key_id)
            .is_some_and(|version| version.state() == KeyVersionState::Active);
        self.change_state(
            key_id,
            Transition::MarkCompromised,
            now,
            |state| match state {
                VersionState::Pending(_) => None,
                VersionState::Active {
                    dek_encryption,
                    seal_start,
                } => Some(VersionState::DecryptOnly(RetainedDek {
                    dek_encryption: dek_encryption.clone(),
                    compromised: Some(compromise.clone()),
                    seal_range: SealRange::new(*seal_start, None),
                })),
                VersionState::DecryptOnly(kept) => {
                    kept.flagged(&compromise).map(VersionState::DecryptOnly)
                }
                VersionState::Retired(kept) => kept.flagged(&compromise).map(VersionState::Retired),
                VersionState::Destroyed { .. } => None,
            },
        )?;
        match replacement {
            Some(new) if was_active => {
                let purpose = new.algorithm.purpose();
                let seal_start = self.activation_marker()?;
                let current = self.push(
                    new,
                    |dek_encryption| VersionState::Active {
                        dek_encryption,
                        seal_start,
                    },
                    now,
                )?;
                Ok(Some(Rotation {
                    purpose,
                    previous: Some(key_id),
                    current,
                }))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn retire(&mut self, key_id: KeyId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Retire, now, |state| match state {
            VersionState::DecryptOnly(kept) => Some(VersionState::Retired(kept.clone())),
            _ => None,
        })
    }

    pub(crate) fn reinstate(&mut self, key_id: KeyId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Reinstate, now, |state| match state {
            VersionState::Retired(kept) => Some(VersionState::DecryptOnly(kept.clone())),
            _ => None,
        })
    }

    pub(crate) fn destroy(&mut self, key_id: KeyId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Destroy, now, |state| match state {
            VersionState::Pending(_) => Some(VersionState::Destroyed {
                compromised: None,
                seal_range: None,
            }),
            VersionState::Retired(kept) => Some(VersionState::Destroyed {
                compromised: kept.compromised.clone(),
                seal_range: Some(kept.seal_range),
            }),
            _ => None,
        })
    }

    /// Moves every version that is not destroyed yet to `Destroyed`, keeping its compromised flag
    /// and its seal range.
    pub(crate) fn destroy_all(&mut self, now: Timestamp) {
        let record = &mut self.record;
        for version in &mut record.versions {
            if !matches!(version.state, VersionState::Destroyed { .. }) {
                version.state = VersionState::Destroyed {
                    compromised: version.compromised().cloned(),
                    seal_range: version.seal_range(),
                };
                version.state_changed_at = now;
            }
        }
        record.updated_at = now;
    }

    /// Puts `dek_encryption`, the same key encrypted again, in place of `key_id`'s encrypted
    /// DEK and its KEK version, in whatever state the version is.
    pub(crate) fn replace_dek(
        &mut self,
        key_id: KeyId,
        dek_encryption: DekEncryption,
        now: Timestamp,
    ) -> KeyringResult<()> {
        match &mut self.version_mut(key_id)?.state {
            VersionState::Pending(held_dek_encryption)
            | VersionState::Active {
                dek_encryption: held_dek_encryption,
                ..
            } => *held_dek_encryption = dek_encryption,
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => {
                kept.dek_encryption = dek_encryption
            }
            VersionState::Destroyed { .. } => {
                return Err(KeyringError::record_invalid(
                    &self.record.id,
                    RecordInvalidReason::MissingMaterial(key_id),
                ))
            }
        }
        self.record.updated_at = now;
        Ok(())
    }

    pub(crate) fn set_algorithm(&mut self, algorithm: KeyAlgorithm, now: Timestamp) {
        let algorithms = &mut self.record.algorithms;
        match algorithm {
            KeyAlgorithm::Randomized(algorithm) => algorithms.randomized = algorithm,
            KeyAlgorithm::Deterministic(algorithm) => algorithms.deterministic = Some(algorithm),
            KeyAlgorithm::Beacon(algorithm) => algorithms.beacon = Some(algorithm),
        }
        self.record.updated_at = now;
    }

    /// Appends `new`, under the next key id of its purpose, in the state `state` makes of its
    /// encrypted DEK, and returns the key id.
    fn push(
        &mut self,
        new: NewVersion,
        state: impl FnOnce(DekEncryption) -> VersionState,
        now: Timestamp,
    ) -> KeyringResult<KeyId> {
        let key_id = self.record.next_key_id(new.algorithm.purpose())?;
        let record = &mut self.record;
        record.versions.push(KeyVersion {
            key_id,
            algorithm: new.algorithm,
            created_at: now,
            state_changed_at: now,
            state: state(new.dek_encryption),
        });
        record.updated_at = now;
        Ok(key_id)
    }

    /// Moves `key_id` to the state `next` returns for its current one, or fails with
    /// `InvalidTransition` when it returns `None`.
    fn change_state(
        &mut self,
        key_id: KeyId,
        transition: Transition,
        now: Timestamp,
        next: impl FnOnce(&VersionState) -> Option<VersionState>,
    ) -> KeyringResult<()> {
        let version = self.version_mut(key_id)?;
        let Some(state) = next(&version.state) else {
            let from = version.state.kind();
            return Err(KeyringError::InvalidTransition(InvalidTransitionError {
                keyring: self.record.id.clone(),
                key_id,
                from,
                transition,
            }));
        };
        version.state = state;
        version.state_changed_at = now;
        self.record.updated_at = now;
        Ok(())
    }

    /// The version `key_id`, or `KeyVersionUnknown`.
    fn version_mut(&mut self, key_id: KeyId) -> KeyringResult<&mut KeyVersion> {
        let KeyringRecord { id, versions, .. } = &mut self.record;
        versions
            .iter_mut()
            .find(|version| version.key_id == key_id)
            .ok_or_else(|| KeyringError::key_version_unknown(id, key_id))
    }
}

#[cfg(test)]
mod tests;
