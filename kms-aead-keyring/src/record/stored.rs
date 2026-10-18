//! The stored form of a keyring record: one JSON document, the same in every store, which a
//! record is parsed from and checked against its invariants.

use std::collections::HashSet;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jiff::Timestamp;
use kms_aead::{EncryptedDataEncryptionKey, KekProvider, KekRef, ValueStruct};
use serde::{Deserialize, Serialize};

use super::{
    Algorithms, Compromise, KeyAlgorithm, KeyVersion, KeyVersionState, KeyringId, KeyringRecord,
    RetainedDek, VersionState,
};
use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::{KeyId, Purpose};

/// The largest document a reader parses. A record the crate writes takes under 400 bytes per
/// version, so this holds a few thousand versions.
pub(crate) const MAX_DOCUMENT_LEN: usize = 1 << 20;
const SCHEMA: u32 = 1;

/// The JSON document of a record. Its fields are primitives, so that every rule of the record
/// is checked once, in [`KeyringRecord::from_json`], with a reason naming the rule.
#[derive(Serialize, Deserialize)]
struct StoredRecord {
    schema: u32,
    id: String,
    kek: StoredKek,
    algorithms: StoredAlgorithms,
    versions: Vec<StoredVersion>,
    created_at: Timestamp,
    updated_at: Timestamp,
}

#[derive(Serialize, Deserialize)]
struct StoredKek {
    provider: String,
    key: String,
}

#[derive(Serialize, Deserialize)]
struct StoredAlgorithms {
    randomized: String,
    deterministic: Option<String>,
    beacon: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredVersion {
    key_id: u32,
    algorithm: String,
    state: String,
    compromised: Option<StoredCompromise>,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    /// The standard base64 of the wrapped key's bytes, as the provider returned them; `None`
    /// once destroyed.
    wrapped_dek: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredCompromise {
    at: Timestamp,
    note: Option<String>,
}

impl From<&KeyringRecord> for StoredRecord {
    fn from(record: &KeyringRecord) -> Self {
        let versions = record
            .versions
            .iter()
            .map(|version| StoredVersion {
                key_id: version.key_id.as_u32(),
                algorithm: version.algorithm.to_string(),
                state: version.state().to_string(),
                compromised: version.compromised().map(|compromise| StoredCompromise {
                    at: compromise.at,
                    note: compromise.note.clone(),
                }),
                created_at: version.created_at,
                state_changed_at: version.state_changed_at,
                wrapped_dek: version
                    .wrapped_dek()
                    .map(|dek| STANDARD.encode(dek.value())),
            })
            .collect();
        Self {
            schema: SCHEMA,
            id: record.id.to_string(),
            kek: StoredKek {
                provider: record.kek.provider().to_string(),
                key: record.kek.key().to_string(),
            },
            algorithms: StoredAlgorithms {
                randomized: record.algorithms.randomized.to_string(),
                deterministic: record
                    .algorithms
                    .deterministic
                    .map(|algorithm| algorithm.to_string()),
                beacon: record
                    .algorithms
                    .beacon
                    .map(|algorithm| algorithm.to_string()),
            },
            versions,
            created_at: record.created_at,
            updated_at: record.updated_at,
        }
    }
}

impl KeyringRecord {
    /// The record's JSON document, the stored form every store keeps.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] when serde_json fails to write the document.
    pub fn to_json(&self) -> KeyringResult<Vec<u8>> {
        serde_json::to_vec(&StoredRecord::from(self))
            .map_err(|error| KeyringError::malformed(&self.id, Some(&error)))
    }

    /// Parses the JSON document a store holds for the keyring `id`, and checks it: at most
    /// 1 MiB, the record of `id`, and every invariant of [`KeyringRecord`].
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] with the first cap or invariant the document breaks.
    pub fn from_json(id: &KeyringId, document: &[u8]) -> KeyringResult<Self> {
        if document.len() > MAX_DOCUMENT_LEN {
            return Err(KeyringError::record_invalid(
                id,
                RecordInvalidReason::TooLarge,
            ));
        }
        let stored: StoredRecord = serde_json::from_slice(document)
            .map_err(|error| KeyringError::malformed(id, Some(&error)))?;
        let invalid = |reason| KeyringError::record_invalid(id, reason);
        if stored.schema != SCHEMA {
            return Err(invalid(RecordInvalidReason::UnsupportedSchema(
                stored.schema,
            )));
        }
        if stored.id != id.as_str() {
            return Err(invalid(RecordInvalidReason::IdMismatch));
        }
        let algorithms = Algorithms {
            randomized: match stored.algorithms.randomized.parse() {
                Ok(KeyAlgorithm::Randomized(algorithm)) => algorithm,
                _ => return Err(invalid(RecordInvalidReason::UnknownAlgorithm(None))),
            },
            deterministic: match stored.algorithms.deterministic.as_deref().map(str::parse) {
                None => None,
                Some(Ok(KeyAlgorithm::Deterministic(algorithm))) => Some(algorithm),
                Some(_) => return Err(invalid(RecordInvalidReason::UnknownAlgorithm(None))),
            },
            beacon: match stored.algorithms.beacon.as_deref().map(str::parse) {
                None => None,
                Some(Ok(KeyAlgorithm::Beacon(algorithm))) => Some(algorithm),
                Some(_) => return Err(invalid(RecordInvalidReason::UnknownAlgorithm(None))),
            },
        };
        let versions = stored
            .versions
            .into_iter()
            .map(KeyVersion::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        let record = Self {
            id: id.clone(),
            kek: KekRef::new(
                KekProvider::from_str(&stored.kek.provider).unwrap_or_else(|never| match never {}),
                stored.kek.key,
            ),
            algorithms,
            versions,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
        };
        record.check_versions().map_err(invalid)?;
        Ok(record)
    }

    /// The rules across versions: unique key ids, increasing within a purpose in creation
    /// order, and at most one active and one pending version per purpose.
    fn check_versions(&self) -> Result<(), RecordInvalidReason> {
        let mut seen = HashSet::new();
        let mut last_randomized = None;
        let mut last_deterministic = None;
        let mut last_beacon = None;
        for version in &self.versions {
            let key_id = version.key_id;
            if !seen.insert(key_id) {
                return Err(RecordInvalidReason::DuplicateKeyId(key_id));
            }
            if version.algorithm.purpose() != key_id.purpose() {
                return Err(RecordInvalidReason::PurposeMismatch(key_id));
            }
            let last = match key_id.purpose() {
                Purpose::Randomized => &mut last_randomized,
                Purpose::Deterministic => &mut last_deterministic,
                Purpose::Beacon => &mut last_beacon,
            };
            if last.is_some_and(|last| last > key_id) {
                return Err(RecordInvalidReason::OrdinalOrder(key_id));
            }
            *last = Some(key_id);
        }
        for purpose in Purpose::ALL {
            let in_state = |state| {
                self.versions
                    .iter()
                    .filter(|version| {
                        version.key_id.purpose() == purpose && version.state() == state
                    })
                    .count()
            };
            if in_state(KeyVersionState::Active) > 1 {
                return Err(RecordInvalidReason::TwoActiveVersions(purpose));
            }
            if in_state(KeyVersionState::Pending) > 1 {
                return Err(RecordInvalidReason::TwoPendingVersions(purpose));
            }
        }
        Ok(())
    }
}

impl TryFrom<StoredVersion> for KeyVersion {
    type Error = RecordInvalidReason;

    /// Checks one version on its own; the checks across versions are the record's.
    fn try_from(stored: StoredVersion) -> Result<Self, RecordInvalidReason> {
        let key_id =
            KeyId::try_from(stored.key_id).map_err(|_| RecordInvalidReason::ReservedKeyId)?;
        let algorithm: KeyAlgorithm = stored
            .algorithm
            .parse()
            .map_err(|_| RecordInvalidReason::UnknownAlgorithm(Some(key_id)))?;
        let dek = stored
            .wrapped_dek
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .ok()
                    .filter(|bytes| !bytes.is_empty())
                    .map(EncryptedDataEncryptionKey::new)
                    .ok_or(RecordInvalidReason::MalformedWrappedDek(key_id))
            })
            .transpose()?;
        let compromised = stored
            .compromised
            .map(|compromise| Compromise::new(compromise.at, compromise.note));
        let kind: KeyVersionState = stored
            .state
            .parse()
            .map_err(|_| RecordInvalidReason::UnknownState(key_id))?;
        let state = match (kind, dek) {
            (KeyVersionState::Destroyed, None) => VersionState::Destroyed(compromised),
            (KeyVersionState::Destroyed, Some(_)) => {
                return Err(RecordInvalidReason::DestroyedWithMaterial(key_id))
            }
            (_, None) => return Err(RecordInvalidReason::MissingMaterial(key_id)),
            (KeyVersionState::Active, Some(_)) if compromised.is_some() => {
                return Err(RecordInvalidReason::CompromisedActive(key_id))
            }
            (KeyVersionState::Active, Some(dek)) => VersionState::Active(dek),
            (KeyVersionState::Pending, Some(_)) if compromised.is_some() => {
                return Err(RecordInvalidReason::CompromisedPending(key_id))
            }
            (KeyVersionState::Pending, Some(dek)) => VersionState::Pending(dek),
            (KeyVersionState::DecryptOnly, Some(dek)) => {
                VersionState::DecryptOnly(RetainedDek { dek, compromised })
            }
            (KeyVersionState::Retired, Some(dek)) => {
                VersionState::Retired(RetainedDek { dek, compromised })
            }
        };
        Ok(Self {
            key_id,
            algorithm,
            created_at: stored.created_at,
            state_changed_at: stored.state_changed_at,
            state,
        })
    }
}
