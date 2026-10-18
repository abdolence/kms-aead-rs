//! The stored form of a keyring record: one JSON document, the same in every store, which a
//! record is parsed from and checked against its invariants.

use std::collections::HashSet;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jiff::Timestamp;
use kms_aead::{EncryptedDataEncryptionKey, KekProvider, KekRef};
use serde::{Deserialize, Serialize};

use super::{
    Algorithms, Compromise, KeyAlgorithm, KeyVersion, KeyVersionState, KeyringId, KeyringRecord,
    RetainedDek, VersionState,
};
use crate::errors::{KeyringError, KeyringResult, MalformedRecord, RecordInvalidReason};
use crate::{KeyId, Purpose};

/// The largest document a reader parses. A record the crate writes takes under 400 bytes per
/// version, so this holds a few thousand versions.
pub(crate) const MAX_DOCUMENT_LEN: usize = 1 << 20;
const MAX_VERSIONS: usize = 10_000;
const SCHEMA: u32 = 1;

/// The JSON document of a record. Its fields are primitives, so that every rule of the record
/// is checked once, in [`KeyringRecord::from_stored`], with a reason naming the rule.
#[derive(Serialize, Deserialize)]
pub(crate) struct StoredRecord {
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
}

#[derive(Serialize, Deserialize)]
struct StoredVersion {
    key_id: u32,
    algorithm: String,
    state: String,
    compromised: Option<StoredCompromise>,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    /// The standard base64 of `EncryptedDataEncryptionKey::to_bytes`, so that the KEK version
    /// travels with the wrapped key; `None` once destroyed.
    wrapped_dek: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredCompromise {
    at: Timestamp,
    note: Option<String>,
}

impl TryFrom<&KeyringRecord> for StoredRecord {
    type Error = KeyringError;

    fn try_from(record: &KeyringRecord) -> KeyringResult<Self> {
        let versions = record
            .versions
            .iter()
            .map(|version| {
                Ok(StoredVersion {
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
                        .map(|dek| dek.to_bytes().map(|bytes| STANDARD.encode(bytes)))
                        .transpose()?,
                })
            })
            .collect::<KeyringResult<_>>()?;
        Ok(Self {
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
            },
            versions,
            created_at: record.created_at,
            updated_at: record.updated_at,
        })
    }
}

impl KeyringRecord {
    /// The record's JSON document, the stored form every store keeps.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Kms`] when a wrapped key does not encode, which kms-aead's wrapped keys
    /// always do.
    pub fn to_json(&self) -> KeyringResult<Vec<u8>> {
        serde_json::to_vec(&StoredRecord::try_from(self)?)
            .map_err(|error| malformed(&self.id, &error))
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
        let stored = serde_json::from_slice(document).map_err(|error| malformed(id, &error))?;
        Self::from_stored(id, stored)
    }

    /// The record `stored` holds, checked as [`from_json`](Self::from_json) checks it, for a
    /// store that reads the document through serde rather than as bytes.
    pub(crate) fn from_stored(id: &KeyringId, stored: StoredRecord) -> KeyringResult<Self> {
        let invalid = |reason| KeyringError::record_invalid(id, reason);
        if stored.schema != SCHEMA {
            return Err(invalid(RecordInvalidReason::UnsupportedSchema(
                stored.schema,
            )));
        }
        if stored.versions.len() > MAX_VERSIONS {
            return Err(invalid(RecordInvalidReason::TooManyVersions));
        }
        if stored.id != id.as_str() {
            return Err(invalid(RecordInvalidReason::IdMismatch));
        }
        let algorithms = Algorithms {
            randomized: match algorithm(&stored.algorithms.randomized) {
                Some(KeyAlgorithm::Randomized(algorithm)) => algorithm,
                _ => return Err(invalid(RecordInvalidReason::UnknownAlgorithm(None))),
            },
            deterministic: match stored.algorithms.deterministic.as_deref().map(algorithm) {
                None => None,
                Some(Some(KeyAlgorithm::Deterministic(algorithm))) => Some(algorithm),
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
    /// order, and at most one active version per purpose.
    fn check_versions(&self) -> Result<(), RecordInvalidReason> {
        let mut seen = HashSet::new();
        let mut last_randomized = None;
        let mut last_deterministic = None;
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
            };
            if last.is_some_and(|last| last > key_id) {
                return Err(RecordInvalidReason::OrdinalOrder(key_id));
            }
            *last = Some(key_id);
        }
        for purpose in [Purpose::Randomized, Purpose::Deterministic] {
            let active = self.versions.iter().filter(|version| {
                version.key_id.purpose() == purpose && version.state() == KeyVersionState::Active
            });
            if active.count() > 1 {
                return Err(RecordInvalidReason::TwoActiveVersions(purpose));
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
        let algorithm = algorithm(&stored.algorithm)
            .ok_or(RecordInvalidReason::UnknownAlgorithm(Some(key_id)))?;
        let dek = stored
            .wrapped_dek
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| {
                        // With kms-aead's `legacy-formats`, `try_from` also reads the bare
                        // layout of 0.28.1, which a keyring record never holds: only bytes
                        // that write back unchanged are in the current layout.
                        EncryptedDataEncryptionKey::try_from(bytes.as_slice())
                            .ok()
                            .filter(|dek| dek.to_bytes().is_ok_and(|written| written == bytes))
                    })
                    .ok_or(RecordInvalidReason::MalformedWrappedDek(key_id))
            })
            .transpose()?;
        let compromised = stored
            .compromised
            .map(|compromise| Compromise::new(compromise.at, compromise.note));
        let kind = state(&stored.state).ok_or(RecordInvalidReason::UnknownState(key_id))?;
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

/// The `Malformed` error of `id` at the position of serde_json's `error`, whose message is left
/// out: it quotes the value it refused, which can be a wrapped key.
fn malformed(id: &KeyringId, error: &serde_json::Error) -> KeyringError {
    let position = |at: usize| (at > 0).then_some(at);
    KeyringError::record_invalid(
        id,
        RecordInvalidReason::Malformed(MalformedRecord {
            line: position(error.line()),
            column: position(error.column()),
        }),
    )
}

fn algorithm(name: &str) -> Option<KeyAlgorithm> {
    name.parse()
        .map(KeyAlgorithm::Randomized)
        .or_else(|_| name.parse().map(KeyAlgorithm::Deterministic))
        .ok()
}

fn state(name: &str) -> Option<KeyVersionState> {
    [
        KeyVersionState::Active,
        KeyVersionState::DecryptOnly,
        KeyVersionState::Retired,
        KeyVersionState::Destroyed,
    ]
    .into_iter()
    .find(|state| state.to_string() == name)
}
