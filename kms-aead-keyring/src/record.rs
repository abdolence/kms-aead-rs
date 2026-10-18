//! The keyring record: every key version of one keyring, each with its wrapped data encryption
//! key and its state, and the lifecycle that moves the states.

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

use jiff::Timestamp;
use kms_aead::{AeadAlgorithm, DeterministicAlgorithm, EncryptedDataEncryptionKey, KekRef};

use crate::errors::{
    Identifier, IdentifierRule, InvalidTransitionError, KeyringError, KeyringResult,
    RecordInvalidReason, RegressionRule,
};
use crate::{KeyId, Purpose, Rotation};

pub(crate) mod stored;

/// The id of a keyring, the scope it encrypts for, such as a tenant: 1 to 128 ASCII
/// alphanumerics, `-`, `_` and `.`, except `.` and `..` as the whole id and ids that start and
/// end with `__`. Such an id is a Firestore document id, a PostgreSQL key, a part of a GCS
/// object name and a BigQuery string, all without escaping.
///
/// It is an identifier, not a secret: it appears in spans, events and errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyringId(Cow<'static, str>);

impl KeyringId {
    const MAX_LEN: usize = 128;

    /// `id`, checked at compile time when it initializes a constant:
    ///
    /// ```compile_fail,E0080
    /// use kms_aead_keyring::KeyringId;
    /// const PARENT: KeyringId = KeyringId::from_static("..");
    /// ```
    ///
    /// # Panics
    ///
    /// On an `id` that breaks the rule, when called at run time.
    pub const fn from_static(id: &'static str) -> Self {
        match Self::rule(id) {
            Ok(()) => Self(Cow::Borrowed(id)),
            Err(rule) => panic!("{}", rule.message()),
        }
    }

    /// The rule of the type docs. A loop, since slice methods are not `const fn`.
    const fn rule(id: &str) -> Result<(), IdentifierRule> {
        let bytes = id.as_bytes();
        let len = bytes.len();
        if len == 0 || len > Self::MAX_LEN {
            return Err(IdentifierRule::Length);
        }
        let mut index = 0;
        while index < len {
            let byte = bytes[index];
            if !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'.') {
                return Err(IdentifierRule::Character);
            }
            index += 1;
        }
        let dots = matches!(bytes, [b'.'] | [b'.', b'.']);
        let underscores = len >= 4
            && bytes[0] == b'_'
            && bytes[1] == b'_'
            && bytes[len - 2] == b'_'
            && bytes[len - 1] == b'_';
        if dots || underscores {
            return Err(IdentifierRule::Reserved);
        }
        Ok(())
    }

    /// The id, for a store's document, row or object name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for KeyringId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `id` breaks.
    fn try_from(id: String) -> KeyringResult<Self> {
        Self::rule(&id)
            .map_err(|rule| KeyringError::invalid_identifier(Identifier::KeyringId, rule))?;
        Ok(Self(Cow::Owned(id)))
    }
}

impl TryFrom<&str> for KeyringId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// As `TryFrom<String>`.
    fn try_from(id: &str) -> KeyringResult<Self> {
        Self::try_from(id.to_string())
    }
}

impl Display for KeyringId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The algorithms new versions of each purpose use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Algorithms {
    randomized: AeadAlgorithm,
    deterministic: Option<DeterministicAlgorithm>,
}

impl Algorithms {
    pub(crate) fn new(
        randomized: AeadAlgorithm,
        deterministic: Option<DeterministicAlgorithm>,
    ) -> Self {
        Self {
            randomized,
            deterministic,
        }
    }

    /// The algorithm of new randomized versions.
    pub fn randomized(&self) -> AeadAlgorithm {
        self.randomized
    }

    /// The algorithm of new deterministic versions, or `None` for a keyring without them.
    pub fn deterministic(&self) -> Option<DeterministicAlgorithm> {
        self.deterministic
    }

    pub(crate) fn of(&self, purpose: Purpose) -> Option<KeyAlgorithm> {
        match purpose {
            Purpose::Randomized => Some(KeyAlgorithm::Randomized(self.randomized)),
            Purpose::Deterministic => self.deterministic.map(KeyAlgorithm::Deterministic),
        }
    }
}

/// The algorithm of one key version, which also fixes its purpose. Both algorithm enums exist
/// in every build, so a process without the `deterministic` feature keeps deterministic
/// versions intact when it writes the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// A randomized AEAD algorithm.
    Randomized(AeadAlgorithm),
    /// A deterministic AEAD algorithm.
    Deterministic(DeterministicAlgorithm),
}

impl KeyAlgorithm {
    /// The purpose of the versions that use this algorithm.
    pub fn purpose(self) -> Purpose {
        match self {
            KeyAlgorithm::Randomized(_) => Purpose::Randomized,
            KeyAlgorithm::Deterministic(_) => Purpose::Deterministic,
        }
    }
}

/// The algorithm's name in kms-aead, such as `aes-256-gcm`: the value of the `algorithm` span
/// field and of the record's JSON.
impl Display for KeyAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyAlgorithm::Randomized(algorithm) => Display::fmt(algorithm, f),
            KeyAlgorithm::Deterministic(algorithm) => Display::fmt(algorithm, f),
        }
    }
}

/// The lifecycle state of a key version.
///
/// ```text
///                      rotate                 retire               destroy
///   (new) ──create──▶ Active ──────▶ DecryptOnly ──────▶ Retired ──────▶ Destroyed
///                       │                 ▲    │            ▲
///                       │ mark_compromised│    └─reinstate──┘
///                       └─────────────────┘
/// ```
///
/// Every state right of `Active` may also be compromised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyVersionState {
    /// Encrypts new values and decrypts. At most one per purpose.
    Active,
    /// Decrypts only: every version a rotation replaced.
    DecryptOnly,
    /// Refused on read. The wrapped key is kept, so that `reinstate` can undo a retirement.
    Retired,
    /// The wrapped key is gone. The version stays, so that its id is never reused.
    Destroyed,
}

impl KeyVersionState {
    /// Whether a version in this state can later be in `next`, along the lifecycle.
    fn reaches(self, next: KeyVersionState) -> bool {
        match (self, next) {
            (KeyVersionState::Active, _) => true,
            (_, KeyVersionState::Active) => false,
            (KeyVersionState::Destroyed, next) => next == KeyVersionState::Destroyed,
            (KeyVersionState::DecryptOnly | KeyVersionState::Retired, _) => true,
        }
    }
}

/// `active`, `decrypt_only`, `retired`, `destroyed`: the record's JSON and the `key_state` span
/// field.
impl Display for KeyVersionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyVersionState::Active => "active",
            KeyVersionState::DecryptOnly => "decrypt_only",
            KeyVersionState::Retired => "retired",
            KeyVersionState::Destroyed => "destroyed",
        })
    }
}

/// A lifecycle operation on a key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transition {
    /// The active version gives way to a new one, and decrypts only.
    Rotate,
    /// The version is flagged compromised.
    MarkCompromised,
    /// A decrypt-only version is refused on read.
    Retire,
    /// A retired version decrypts again.
    Reinstate,
    /// A retired version's wrapped key is removed.
    Destroy,
}

/// `rotate`, `mark_compromised`, `retire`, `reinstate`, `destroy`.
impl Display for Transition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Transition::Rotate => "rotate",
            Transition::MarkCompromised => "mark_compromised",
            Transition::Retire => "retire",
            Transition::Reinstate => "reinstate",
            Transition::Destroy => "destroy",
        })
    }
}

/// When a key version was flagged compromised, and the operator's note. The flag never clears.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compromise {
    at: Timestamp,
    note: Option<String>,
}

impl Compromise {
    pub(crate) fn new(at: Timestamp, note: Option<String>) -> Self {
        Self { at, note }
    }

    /// When the version was flagged.
    pub fn at(&self) -> Timestamp {
        self.at
    }

    /// The operator's note, if one was given.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }
}

/// One data encryption key of a keyring, wrapped by the KEK, with its state.
///
/// `Debug` shows the id, the algorithm, the state and the times, never the wrapped key.
pub struct KeyVersion {
    key_id: KeyId,
    algorithm: KeyAlgorithm,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    state: VersionState,
}

impl KeyVersion {
    /// The id every value under this version carries.
    pub fn key_id(&self) -> KeyId {
        self.key_id
    }

    /// The algorithm values under this version are sealed with.
    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    /// The lifecycle state.
    pub fn state(&self) -> KeyVersionState {
        self.state.kind()
    }

    /// The compromised flag, set by `mark_compromised` and never cleared.
    pub fn compromised(&self) -> Option<&Compromise> {
        self.state.compromised()
    }

    /// When the version was created.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// When the state or the compromised flag last changed.
    pub fn state_changed_at(&self) -> Timestamp {
        self.state_changed_at
    }

    pub(crate) fn wrapped_dek(&self) -> Option<&EncryptedDataEncryptionKey> {
        self.state.dek()
    }

    /// The wrapped key that opens values under this version, with its compromised flag, or
    /// `None` for a retired or destroyed version, which opens nothing.
    pub(crate) fn readable_dek(
        &self,
    ) -> Option<(&EncryptedDataEncryptionKey, Option<&Compromise>)> {
        match &self.state {
            VersionState::Active(dek) => Some((dek, None)),
            VersionState::DecryptOnly(kept) => Some((&kept.dek, kept.compromised.as_ref())),
            VersionState::Retired(_) | VersionState::Destroyed(_) => None,
        }
    }
}

impl Debug for KeyVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyVersion")
            .field("key_id", &self.key_id)
            .field("algorithm", &self.algorithm)
            .field("state", &self.state())
            .field("compromised", &self.compromised())
            .field("created_at", &self.created_at)
            .field("state_changed_at", &self.state_changed_at)
            .finish()
    }
}

/// A state with what it holds, so that a destroyed version without its key and an active one
/// without a compromised flag are the only shapes there are.
#[derive(Clone)]
enum VersionState {
    Active(EncryptedDataEncryptionKey),
    DecryptOnly(RetainedDek),
    Retired(RetainedDek),
    Destroyed(Option<Compromise>),
}

impl VersionState {
    fn kind(&self) -> KeyVersionState {
        match self {
            VersionState::Active(_) => KeyVersionState::Active,
            VersionState::DecryptOnly(_) => KeyVersionState::DecryptOnly,
            VersionState::Retired(_) => KeyVersionState::Retired,
            VersionState::Destroyed(_) => KeyVersionState::Destroyed,
        }
    }

    fn compromised(&self) -> Option<&Compromise> {
        match self {
            VersionState::Active(_) => None,
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => {
                kept.compromised.as_ref()
            }
            VersionState::Destroyed(compromised) => compromised.as_ref(),
        }
    }

    fn dek(&self) -> Option<&EncryptedDataEncryptionKey> {
        match self {
            VersionState::Active(dek) => Some(dek),
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => Some(&kept.dek),
            VersionState::Destroyed(_) => None,
        }
    }
}

/// The wrapped key of a version past `Active`, which may be compromised.
#[derive(Clone)]
struct RetainedDek {
    dek: EncryptedDataEncryptionKey,
    compromised: Option<Compromise>,
}

impl RetainedDek {
    /// The same key flagged with `compromise`, or `None` when it already is: the flag and its
    /// time never change once set.
    fn flagged(&self, compromise: &Compromise) -> Option<Self> {
        self.compromised.is_none().then(|| Self {
            dek: self.dek.clone(),
            compromised: Some(compromise.clone()),
        })
    }
}

/// The wrapped key of a version about to be created, and the algorithm it was made for.
pub(crate) struct NewVersion {
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) dek: EncryptedDataEncryptionKey,
}

/// The record of one keyring: the KEK its keys are wrapped under, the algorithms of new
/// versions, and every version ever created, in creation order. It is stored as one JSON
/// document, the same in every store; see [`to_json`](Self::to_json).
///
/// Every record that exists holds its invariants: at most one active version per purpose, an
/// active version never compromised, a wrapped key on every version but the destroyed ones,
/// unique key ids of the purpose of their algorithm, increasing within a purpose in creation
/// order, at most 1 MiB of JSON and at most 10,000 versions. The size cap is the one that
/// binds: at about 400 bytes per version with its wrapped key, 1 MiB holds about 2,600.
///
/// `Debug` shows identifiers, states and times, never a wrapped key.
#[derive(Debug)]
pub struct KeyringRecord {
    id: KeyringId,
    kek: KekRef,
    algorithms: Algorithms,
    versions: Vec<KeyVersion>,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl KeyringRecord {
    /// A record with no version yet: `rotate` adds the first one of each purpose.
    pub(crate) fn new(id: KeyringId, kek: KekRef, algorithms: Algorithms, now: Timestamp) -> Self {
        Self {
            id,
            kek,
            algorithms,
            versions: Vec::new(),
            created_at: now,
            updated_at: now,
        }
    }

    /// The keyring this record belongs to.
    pub fn id(&self) -> &KeyringId {
        &self.id
    }

    /// The KEK of the provider the keyring was created with. It is informational: it catches a
    /// keyring opened with the wrong configuration, and is no security control, since a writer
    /// of the record sets it as freely as any other field. What refuses a key wrapped under
    /// another KEK is the KMS, which every unwrap names the configured KEK to.
    pub fn kek(&self) -> &KekRef {
        &self.kek
    }

    /// The algorithms new versions use.
    pub fn algorithms(&self) -> &Algorithms {
        &self.algorithms
    }

    /// Every version ever created, in creation order.
    pub fn versions(&self) -> &[KeyVersion] {
        &self.versions
    }

    /// The version with `key_id`.
    pub fn version(&self, key_id: KeyId) -> Option<&KeyVersion> {
        self.versions
            .iter()
            .find(|version| version.key_id == key_id)
    }

    /// The version of `purpose` that encrypts new values.
    pub fn active(&self, purpose: Purpose) -> Option<&KeyVersion> {
        self.active_dek(purpose).map(|(version, _)| version)
    }

    /// The active version of `purpose` and its wrapped key.
    pub(crate) fn active_dek(
        &self,
        purpose: Purpose,
    ) -> Option<(&KeyVersion, &EncryptedDataEncryptionKey)> {
        self.versions
            .iter()
            .find_map(|version| match &version.state {
                VersionState::Active(dek) if version.key_id.purpose() == purpose => {
                    Some((version, dek))
                }
                _ => None,
            })
    }

    /// When the record was created.
    pub fn created_at(&self) -> Timestamp {
        self.created_at
    }

    /// When the record was last written.
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    /// The wrapped key of every version that holds one, by key id.
    pub(crate) fn wrapped_deks(&self) -> Vec<(KeyId, EncryptedDataEncryptionKey)> {
        self.versions
            .iter()
            .filter_map(|version| Some((version.key_id, version.wrapped_dek()?.clone())))
            .collect()
    }
}

/// A record that an administrative write is changing: the lifecycle transitions apply to it,
/// and [`finish`](Self::finish) checks the result as a reader would, before it is written.
pub(crate) struct RecordEdit(KeyringRecord);

impl From<KeyringRecord> for RecordEdit {
    fn from(record: KeyringRecord) -> Self {
        Self(record)
    }
}

impl RecordEdit {
    /// The record as changed so far.
    pub(crate) fn record(&self) -> &KeyringRecord {
        &self.0
    }

    /// The changed record as a reader parses it from the store, so that a record that would
    /// fail its invariants or caps there is never written.
    pub(crate) fn finish(self) -> KeyringResult<KeyringRecord> {
        KeyringRecord::from_json(&self.0.id, &self.0.to_json()?)
    }

    /// Adds `new` as the active version of its purpose; the active version it replaces decrypts
    /// only.
    pub(crate) fn rotate(&mut self, new: NewVersion, now: Timestamp) -> KeyringResult<Rotation> {
        let purpose = new.algorithm.purpose();
        let previous = self.0.active(purpose).map(KeyVersion::key_id);
        if let Some(previous) = previous {
            self.change_state(previous, Transition::Rotate, now, |state| match state {
                VersionState::Active(dek) => Some(VersionState::DecryptOnly(RetainedDek {
                    dek: dek.clone(),
                    compromised: None,
                })),
                _ => None,
            })?;
        }
        let current = self.push_active(new, now)?;
        Ok(Rotation {
            purpose,
            previous,
            current,
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
            .0
            .version(key_id)
            .is_some_and(|version| version.state() == KeyVersionState::Active);
        self.change_state(
            key_id,
            Transition::MarkCompromised,
            now,
            |state| match state {
                VersionState::Active(dek) => Some(VersionState::DecryptOnly(RetainedDek {
                    dek: dek.clone(),
                    compromised: Some(compromise.clone()),
                })),
                VersionState::DecryptOnly(kept) => {
                    kept.flagged(&compromise).map(VersionState::DecryptOnly)
                }
                VersionState::Retired(kept) => kept.flagged(&compromise).map(VersionState::Retired),
                VersionState::Destroyed(_) => None,
            },
        )?;
        match replacement {
            Some(new) if was_active => {
                let purpose = new.algorithm.purpose();
                let current = self.push_active(new, now)?;
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
            VersionState::Retired(kept) => Some(VersionState::Destroyed(kept.compromised.clone())),
            _ => None,
        })
    }

    /// Puts `dek`, the same key wrapped again, in place of `key_id`'s wrapped key, in whatever
    /// state the version is.
    pub(crate) fn replace_dek(
        &mut self,
        key_id: KeyId,
        dek: EncryptedDataEncryptionKey,
        now: Timestamp,
    ) -> KeyringResult<()> {
        match &mut self.version_mut(key_id)?.state {
            VersionState::Active(held) => *held = dek,
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => kept.dek = dek,
            VersionState::Destroyed(_) => {
                return Err(KeyringError::record_invalid(
                    &self.0.id,
                    RecordInvalidReason::MissingMaterial(key_id),
                ))
            }
        }
        self.0.updated_at = now;
        Ok(())
    }

    pub(crate) fn set_algorithm(&mut self, algorithm: KeyAlgorithm, now: Timestamp) {
        let algorithms = &mut self.0.algorithms;
        match algorithm {
            KeyAlgorithm::Randomized(algorithm) => algorithms.randomized = algorithm,
            KeyAlgorithm::Deterministic(algorithm) => algorithms.deterministic = Some(algorithm),
        }
        self.0.updated_at = now;
    }

    fn push_active(&mut self, new: NewVersion, now: Timestamp) -> KeyringResult<KeyId> {
        let record = &mut self.0;
        let purpose = new.algorithm.purpose();
        let key_id = match record
            .versions
            .iter()
            .map(KeyVersion::key_id)
            .filter(|key_id| key_id.purpose() == purpose)
            .max()
        {
            None => KeyId::first(purpose),
            Some(last) => last.next().ok_or_else(|| {
                KeyringError::record_invalid(
                    &record.id,
                    RecordInvalidReason::KeyIdsExhausted(purpose),
                )
            })?,
        };
        record.versions.push(KeyVersion {
            key_id,
            algorithm: new.algorithm,
            created_at: now,
            state_changed_at: now,
            state: VersionState::Active(new.dek),
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
                keyring: self.0.id.clone(),
                key_id,
                from,
                transition,
            }));
        };
        version.state = state;
        version.state_changed_at = now;
        self.0.updated_at = now;
        Ok(())
    }

    /// The version `key_id`, or `KeyVersionUnknown`.
    fn version_mut(&mut self, key_id: KeyId) -> KeyringResult<&mut KeyVersion> {
        let KeyringRecord { id, versions, .. } = &mut self.0;
        versions
            .iter_mut()
            .find(|version| version.key_id == key_id)
            .ok_or_else(|| KeyringError::key_version_unknown(id, key_id))
    }
}

/// Whether `next`, a record read from the store, moves forward from `held`: every version of
/// `held` is still there, with the same algorithm and creation time, its compromised flag kept
/// with its time, and its state moved along the lifecycle. New versions are free.
pub(crate) fn check_successor(
    held: &KeyringRecord,
    next: &KeyringRecord,
) -> Result<(), RegressionRule> {
    for held in &held.versions {
        let key_id = held.key_id;
        let Some(version) = next.version(key_id) else {
            return Err(RegressionRule::VersionMissing(key_id));
        };
        if version.algorithm != held.algorithm || version.created_at != held.created_at {
            return Err(RegressionRule::VersionAltered(key_id));
        }
        match (held.compromised(), version.compromised()) {
            (Some(_), None) => return Err(RegressionRule::CompromiseCleared(key_id)),
            (Some(held), Some(compromise)) if held.at != compromise.at => {
                return Err(RegressionRule::CompromiseAltered(key_id))
            }
            _ => {}
        }
        if !held.state().reaches(version.state()) {
            return Err(RegressionRule::StateReverted(key_id));
        }
    }
    Ok(())
}

/// The wrapped keys `held` reads under that `next` takes out of use: their version is gone,
/// retired or destroyed, newly flagged compromised, or holds another wrapped key, as after a
/// rewrap, which leaves the cached plaintext of the old bytes orphaned.
pub(crate) fn withdrawn_deks<'a>(
    held: &'a KeyringRecord,
    next: &'a KeyringRecord,
) -> impl Iterator<Item = &'a EncryptedDataEncryptionKey> + 'a {
    held.versions.iter().filter_map(move |held| {
        let (dek, compromise) = held.readable_dek()?;
        let withdrawn = match next.version(held.key_id).and_then(KeyVersion::readable_dek) {
            None => true,
            Some((next_dek, next_compromise)) => {
                next_dek != dek || (next_compromise.is_some() && compromise.is_none())
            }
        };
        withdrawn.then_some(dek)
    })
}

#[cfg(test)]
mod tests;
