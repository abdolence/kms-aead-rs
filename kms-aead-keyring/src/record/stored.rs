//! The stored form of a keyring record: one JSON document, the same in every store, which a
//! record is parsed from and checked against its invariants.

use std::collections::HashSet;
use std::str::FromStr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use jiff::Timestamp;
use kms_aead::providers::KmsKeyVersion;
use kms_aead::signing::Signature;
use kms_aead::{EncryptedDataEncryptionKey, KekRef, KmsProvider};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use super::canonical::{canonical_json, CanonicalError};
use super::{
    Compromise, KeyAlgorithm, KeyVersion, KeyVersionState, KeyringAlgorithms, KeyringId,
    KeyringRecord, RetainedDek, VersionState,
};
use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::purpose::is_reserved_key_id;
use crate::sweep::{EncryptionMarker, ReencryptRange};
use crate::{KeyId, Purpose};

/// The largest document a reader parses. A record the crate writes takes from about 360 bytes per
/// version under the local KMS to about 1,000 under an Azure RSA 4096-bit key, so this holds
/// a thousand versions or more.
pub(crate) const MAX_RECORD_DOCUMENT_LEN: usize = 1 << 20;
const RECORD_SCHEMA_VERSION: u32 = 1;
/// The member of the record's document that holds its signature, the one member the canonical
/// document leaves out.
const SIGNATURE_MEMBER: &str = "signature";

/// The JSON document of a record. Its fields are primitives, so that every rule of the record
/// is checked once, in [`KeyringRecord::from_json`], with a reason naming the rule.
#[derive(Serialize, Deserialize)]
struct StoredRecord {
    schema: u32,
    id: String,
    kek: StoredKek,
    algorithms: StoredAlgorithms,
    /// Named `seal_epoch` in the stored document, the key 0.30 writes and reads.
    #[serde(rename = "seal_epoch")]
    reencrypt_epoch: u32,
    versions: Vec<StoredVersion>,
    created_at: Timestamp,
    updated_at: Timestamp,
    /// The standard base64 of the detached signature's bytes; absent from an unsigned record,
    /// which 0.30 writes and reads.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
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
    mac: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredVersion {
    key_id: u32,
    algorithm: String,
    state: String,
    compromised: Option<StoredCompromise>,
    /// The epochs of the version's re-encryption range, `None` for a version that was never active.
    /// Named `seal_epochs` in the stored document, the key 0.30 writes and reads.
    #[serde(rename = "seal_epochs")]
    reencrypt_epochs: Option<StoredReencryptEpochs>,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    /// The standard base64 of the encrypted DEK's bytes, as the provider returned them; `None`
    /// once destroyed.
    encrypted_dek: Option<String>,
    /// The KEK version that encrypted `encrypted_dek`, as the KMS reported it; `None` once
    /// destroyed, and under a KMS that reports none.
    kek_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredCompromise {
    at: Timestamp,
    note: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct StoredReencryptEpochs {
    start: u32,
    /// `None` while the range is open-ended.
    end: Option<u32>,
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
                reencrypt_epochs: version
                    .reencrypt_range()
                    .map(|range| StoredReencryptEpochs {
                        start: range.start().epoch(),
                        end: range.end().map(EncryptionMarker::epoch),
                    }),
                created_at: version.created_at,
                state_changed_at: version.state_changed_at,
                encrypted_dek: version
                    .encrypted_dek()
                    .map(|encrypted_dek| STANDARD.encode(encrypted_dek.value())),
                kek_version: version.kek_version().map(KmsKeyVersion::to_string),
            })
            .collect();
        Self {
            schema: RECORD_SCHEMA_VERSION,
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
                mac: record.algorithms.mac.map(|algorithm| algorithm.to_string()),
            },
            reencrypt_epoch: record.encryption_marker.epoch(),
            versions,
            created_at: record.created_at,
            updated_at: record.updated_at,
            signature: record
                .signature
                .as_ref()
                .map(|signature| STANDARD.encode(signature.value())),
        }
    }
}

impl KeyringRecord {
    /// The record's JSON document, the stored form every store keeps, with the record's signature
    /// in its `signature` member when it carries one.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] when serde_json fails to write the document.
    pub fn to_json(&self) -> KeyringResult<Vec<u8>> {
        serde_json::to_vec(&StoredRecord::from(self))
            .map_err(|error| KeyringError::malformed(&self.id, Some(&error)))
    }

    /// Parses the JSON document a store holds for the keyring `id`, and checks it: at most
    /// 1 MiB, the record of `id`, and every invariant of [`KeyringRecord`]. It verifies nothing:
    /// it keeps the record's signature and the SHA-256 of its canonical document, which the
    /// registry verifies before it uses the record. Every store calls it.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] with the first cap or invariant the document breaks, a
    /// `signature` member that is not the standard base64 of a detached signature among them.
    pub fn from_json(id: &KeyringId, document: &[u8]) -> KeyringResult<Self> {
        if document.len() > MAX_RECORD_DOCUMENT_LEN {
            return Err(KeyringError::record_invalid(
                id,
                RecordInvalidReason::TooLarge,
            ));
        }
        let mut parsed: Value = serde_json::from_slice(document)
            .map_err(|error| KeyringError::malformed(id, Some(&error)))?;
        let invalid = |reason| KeyringError::record_invalid(id, reason);
        let signature = match parsed
            .as_object_mut()
            .and_then(|members| members.remove(SIGNATURE_MEMBER))
        {
            None => None,
            Some(Value::String(encoded)) => Some(
                STANDARD
                    .decode(encoded)
                    .ok()
                    .and_then(|bytes| Signature::try_from(bytes).ok())
                    .ok_or(invalid(RecordInvalidReason::MalformedSignature))?,
            ),
            Some(_) => return Err(invalid(RecordInvalidReason::MalformedSignature)),
        };
        let canonical_digest =
            canonical_digest(&parsed).map_err(|_| KeyringError::malformed(id, None))?;
        let stored: StoredRecord = serde_json::from_value(parsed)
            .map_err(|error| KeyringError::malformed(id, Some(&error)))?;
        if stored.schema != RECORD_SCHEMA_VERSION {
            return Err(invalid(RecordInvalidReason::UnsupportedSchema(
                stored.schema,
            )));
        }
        if stored.id != id.as_str() {
            return Err(invalid(RecordInvalidReason::IdMismatch));
        }
        let algorithms = KeyringAlgorithms {
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
            mac: match stored.algorithms.mac.as_deref().map(str::parse) {
                None => None,
                Some(Ok(KeyAlgorithm::Mac(algorithm))) => Some(algorithm),
                Some(_) => return Err(invalid(RecordInvalidReason::UnknownAlgorithm(None))),
            },
        };
        let versions = stored
            .versions
            .into_iter()
            .map(KeyVersion::try_from)
            .collect::<Result<Vec<_>, _>>()
            .map_err(invalid)?;
        if stored.reencrypt_epoch == 0 {
            return Err(invalid(RecordInvalidReason::ReencryptEpochOutOfRange));
        }
        let encryption_marker = EncryptionMarker::of_epoch(stored.reencrypt_epoch);
        if let Some(version) = versions.iter().find(|version| {
            version.reencrypt_range().is_some_and(|range| {
                let start = range.start();
                start == EncryptionMarker::ENVELOPE
                    || start > encryption_marker
                    || range
                        .end()
                        .is_some_and(|end| end <= start || end > encryption_marker)
            })
        }) {
            return Err(invalid(RecordInvalidReason::ReencryptRangeInvalid(
                version.key_id,
            )));
        }
        let record = Self {
            id: id.clone(),
            kek: KekRef::new(
                KmsProvider::from_str(&stored.kek.provider).unwrap_or_else(|never| match never {}),
                stored.kek.key,
            ),
            algorithms,
            encryption_marker,
            versions,
            created_at: stored.created_at,
            updated_at: stored.updated_at,
            signature,
            canonical_digest,
        };
        record.check_versions().map_err(invalid)?;
        Ok(record)
    }

    /// The rules across versions: unique key ids, increasing within a purpose in creation
    /// order, no encrypted DEK under two versions, and at most one active and one pending
    /// version per purpose.
    fn check_versions(&self) -> Result<(), RecordInvalidReason> {
        let mut seen = HashSet::new();
        let mut seen_deks = HashSet::new();
        let mut last_randomized = None;
        let mut last_deterministic = None;
        let mut last_beacon = None;
        let mut last_mac = None;
        for version in &self.versions {
            let key_id = version.key_id;
            if !seen.insert(key_id) {
                return Err(RecordInvalidReason::DuplicateKeyId(key_id));
            }
            let purpose = version.algorithm.purpose();
            if purpose != Purpose::of(key_id) {
                return Err(RecordInvalidReason::PurposeMismatch(key_id));
            }
            let last = match purpose {
                Purpose::Randomized => &mut last_randomized,
                Purpose::Deterministic => &mut last_deterministic,
                Purpose::Beacon => &mut last_beacon,
                Purpose::Mac => &mut last_mac,
            };
            if last.is_some_and(|last: KeyId| last.as_u32() > key_id.as_u32()) {
                return Err(RecordInvalidReason::OrdinalOrder(key_id));
            }
            *last = Some(key_id);
            if let Some(encrypted_dek) = version.encrypted_dek() {
                if !seen_deks.insert(encrypted_dek.value()) {
                    return Err(RecordInvalidReason::DuplicateEncryptedDek(key_id));
                }
            }
        }
        for purpose in Purpose::ALL {
            let in_state = |state| {
                self.versions
                    .iter()
                    .filter(|version| {
                        version.algorithm.purpose() == purpose && version.state() == state
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

/// The SHA-256 of RFC 8785's canonical form of `document`.
fn canonical_digest(document: &Value) -> Result<[u8; 32], CanonicalError> {
    canonical_json(document).map(|canonical| Sha256::digest(canonical).into())
}

impl TryFrom<StoredVersion> for KeyVersion {
    type Error = RecordInvalidReason;

    /// Checks one version on its own; the checks across versions are the record's.
    fn try_from(stored: StoredVersion) -> Result<Self, RecordInvalidReason> {
        let key_id = KeyId::new(stored.key_id);
        if is_reserved_key_id(key_id) {
            return Err(RecordInvalidReason::ReservedKeyId);
        }
        let algorithm: KeyAlgorithm = stored
            .algorithm
            .parse()
            .map_err(|_| RecordInvalidReason::UnknownAlgorithm(Some(key_id)))?;
        let encrypted_dek = stored
            .encrypted_dek
            .map(|encoded| {
                STANDARD
                    .decode(encoded)
                    .ok()
                    .filter(|bytes| !bytes.is_empty())
                    .map(EncryptedDataEncryptionKey::new)
                    .ok_or(RecordInvalidReason::MalformedEncryptedDek(key_id))
            })
            .transpose()?;
        let kek_version = stored
            .kek_version
            .map(|kek_version| {
                KmsKeyVersion::try_from(kek_version)
                    .map_err(|_| RecordInvalidReason::MalformedKekVersion(key_id))
            })
            .transpose()?;
        let kind: KeyVersionState = stored
            .state
            .parse()
            .map_err(|_| RecordInvalidReason::UnknownState(key_id))?;
        let encrypted_dek = match (encrypted_dek, kek_version) {
            (Some(encrypted_dek), Some(kek_version)) => {
                Some(encrypted_dek.with_kek_version(kek_version))
            }
            (encrypted_dek, None) => encrypted_dek,
            (None, Some(_)) if kind == KeyVersionState::Destroyed => {
                return Err(RecordInvalidReason::DestroyedWithMaterial(key_id))
            }
            (None, Some(_)) => return Err(RecordInvalidReason::MissingMaterial(key_id)),
        };
        let compromised = stored
            .compromised
            .map(|compromise| Compromise::new(compromise.at, compromise.note));
        let reencrypt_range = stored.reencrypt_epochs.map(|epochs| {
            ReencryptRange::new(
                EncryptionMarker::of_epoch(epochs.start),
                epochs.end.map(EncryptionMarker::of_epoch),
            )
        });
        let state = match (kind, encrypted_dek) {
            (KeyVersionState::Destroyed, None) => VersionState::Destroyed {
                compromised,
                reencrypt_range,
            },
            (KeyVersionState::Destroyed, Some(_)) => {
                return Err(RecordInvalidReason::DestroyedWithMaterial(key_id))
            }
            (_, None) => return Err(RecordInvalidReason::MissingMaterial(key_id)),
            (KeyVersionState::Active, Some(_)) if compromised.is_some() => {
                return Err(RecordInvalidReason::CompromisedActive(key_id))
            }
            (KeyVersionState::Active, Some(encrypted_dek)) => match reencrypt_range {
                Some(range) if range.end().is_none() => VersionState::Active {
                    encrypted_dek,
                    reencrypt_start: range.start(),
                },
                _ => return Err(RecordInvalidReason::ReencryptRangeInvalid(key_id)),
            },
            (KeyVersionState::Pending, Some(_)) if compromised.is_some() => {
                return Err(RecordInvalidReason::CompromisedPending(key_id))
            }
            (KeyVersionState::Pending, Some(encrypted_dek)) => match reencrypt_range {
                None => VersionState::Pending(encrypted_dek),
                Some(_) => return Err(RecordInvalidReason::ReencryptRangeInvalid(key_id)),
            },
            (KeyVersionState::DecryptOnly, Some(encrypted_dek)) => {
                VersionState::DecryptOnly(RetainedDek {
                    encrypted_dek,
                    compromised,
                    reencrypt_range: reencrypt_range
                        .ok_or(RecordInvalidReason::ReencryptRangeInvalid(key_id))?,
                })
            }
            (KeyVersionState::Retired, Some(encrypted_dek)) => VersionState::Retired(RetainedDek {
                encrypted_dek,
                compromised,
                reencrypt_range: reencrypt_range
                    .ok_or(RecordInvalidReason::ReencryptRangeInvalid(key_id))?,
            }),
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
