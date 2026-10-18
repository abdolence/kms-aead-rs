//! The keyring record: every key version of one keyring, each with its wrapped data encryption
//! key and its state, and the lifecycle that moves the states.

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use jiff::Timestamp;
use kms_aead::{
    AeadAlgorithm, BeaconAlgorithm, DeterministicAlgorithm, EncryptedDataEncryptionKey, KekRef,
};

use crate::errors::{
    Identifier, IdentifierRule, InvalidTransitionError, KeyringError, KeyringResult,
    RecordInvalidReason, RegressionRule,
};
use crate::{KeyVersionId, Purpose, Rotation};

pub(crate) mod stored;

/// The id of a keyring, the scope it encrypts for, such as a tenant: 1 to 128 ASCII
/// alphanumerics, `-`, `_` and `.`, except `.` and `..` as the whole id and ids that start and
/// end with `__`. Such an id is a Firestore document id, a PostgreSQL key, a part of a GCS
/// object name or an S3 object key, and a BigQuery string, all without escaping.
///
/// It is an identifier, not a secret: it appears in spans, events and errors.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyringId(Cow<'static, str>);

impl KeyringId {
    const MAX_LEN: usize = 128;

    /// `id`, checked at compile time when it initialises a constant:
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
    beacon: Option<BeaconAlgorithm>,
}

impl Algorithms {
    pub(crate) fn new(
        randomized: AeadAlgorithm,
        deterministic: Option<DeterministicAlgorithm>,
        beacon: Option<BeaconAlgorithm>,
    ) -> Self {
        Self {
            randomized,
            deterministic,
            beacon,
        }
    }

    /// The algorithm of new randomised versions.
    pub fn randomized(&self) -> AeadAlgorithm {
        self.randomized
    }

    /// The algorithm of new deterministic versions, or `None` for a keyring without them.
    pub fn deterministic(&self) -> Option<DeterministicAlgorithm> {
        self.deterministic
    }

    /// The algorithm of new beacon versions, or `None` for a keyring without them.
    pub fn beacon(&self) -> Option<BeaconAlgorithm> {
        self.beacon
    }

    pub(crate) fn of(&self, purpose: Purpose) -> Option<KeyAlgorithm> {
        match purpose {
            Purpose::Randomized => Some(KeyAlgorithm::Randomized(self.randomized)),
            Purpose::Deterministic => self.deterministic.map(KeyAlgorithm::Deterministic),
            Purpose::Beacon => self.beacon.map(KeyAlgorithm::Beacon),
        }
    }
}

/// The algorithm of one key version, which also fixes its purpose. Every algorithm enum exists
/// in every build, so a process without the `deterministic` feature keeps deterministic
/// versions intact when it writes the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyAlgorithm {
    /// A randomised AEAD algorithm.
    Randomized(AeadAlgorithm),
    /// A deterministic AEAD algorithm.
    Deterministic(DeterministicAlgorithm),
    /// A beacon algorithm.
    Beacon(BeaconAlgorithm),
}

impl KeyAlgorithm {
    /// The purpose of the versions that use this algorithm.
    pub fn purpose(self) -> Purpose {
        match self {
            KeyAlgorithm::Randomized(_) => Purpose::Randomized,
            KeyAlgorithm::Deterministic(_) => Purpose::Deterministic,
            KeyAlgorithm::Beacon(_) => Purpose::Beacon,
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
            KeyAlgorithm::Beacon(algorithm) => Display::fmt(algorithm, f),
        }
    }
}

/// Reads what `Display` writes, kms-aead's name of any kind of algorithm.
///
/// # Errors
///
/// [`KeyringError::Kms`] with code `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for KeyAlgorithm {
    type Err = KeyringError;

    fn from_str(name: &str) -> KeyringResult<Self> {
        if let Ok(algorithm) = name.parse() {
            return Ok(KeyAlgorithm::Randomized(algorithm));
        }
        if let Ok(algorithm) = name.parse() {
            return Ok(KeyAlgorithm::Deterministic(algorithm));
        }
        Ok(KeyAlgorithm::Beacon(name.parse()?))
    }
}

/// The lifecycle state of a key version.
///
/// ```text
/// rotate ─▶ Pending ──promote──▶ Active ───▶ DecryptOnly ──retire──▶ Retired ──destroy──▶ Destroyed
///              │                   ▲                ▲                   │                    ▲
///              │       create ─────┘                └─────reinstate─────┘                    │
///              └─────────────────────────────────destroy─────────────────────────────────────┘
/// ```
///
/// A rotation stages a version as `Pending`, which decrypts and never encrypts, and `promote`
/// makes it `Active` once every process has had time to refresh its record. The active version
/// moves to `DecryptOnly` when the next one is promoted or when it is flagged compromised.
/// `create`, and the replacement `mark_compromised` makes for an active version, are `Active` at
/// once. Every state right of `Active` may also be compromised; `Pending` and `Active` never are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyVersionState {
    /// Staged by a rotation: decrypts, and never encrypts until it is promoted. At most one per
    /// purpose.
    Pending,
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
            (current, next) if current == next => true,
            (_, KeyVersionState::Pending) => false,
            (KeyVersionState::Pending, _) => true,
            (_, KeyVersionState::Active) => false,
            (KeyVersionState::Active, _) => true,
            (KeyVersionState::Destroyed, _) => false,
            (KeyVersionState::DecryptOnly | KeyVersionState::Retired, _) => true,
        }
    }
}

/// `pending`, `active`, `decrypt_only`, `retired`, `destroyed`: the record's JSON and the
/// `key_state` span field.
impl Display for KeyVersionState {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            KeyVersionState::Pending => "pending",
            KeyVersionState::Active => "active",
            KeyVersionState::DecryptOnly => "decrypt_only",
            KeyVersionState::Retired => "retired",
            KeyVersionState::Destroyed => "destroyed",
        })
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// [`KeyringError::UnknownKeyVersionState`] for any other name.
impl FromStr for KeyVersionState {
    type Err = KeyringError;

    fn from_str(name: &str) -> KeyringResult<Self> {
        match name {
            "pending" => Ok(KeyVersionState::Pending),
            "active" => Ok(KeyVersionState::Active),
            "decrypt_only" => Ok(KeyVersionState::DecryptOnly),
            "retired" => Ok(KeyVersionState::Retired),
            "destroyed" => Ok(KeyVersionState::Destroyed),
            _ => Err(KeyringError::UnknownKeyVersionState),
        }
    }
}

/// A lifecycle operation on a key version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Transition {
    /// A new version of the purpose is staged as pending.
    Rotate,
    /// A pending version becomes the active one.
    Promote,
    /// The version is flagged compromised.
    MarkCompromised,
    /// A decrypt-only version is refused on read.
    Retire,
    /// A retired version decrypts again.
    Reinstate,
    /// A retired or pending version's wrapped key is removed.
    Destroy,
}

/// `rotate`, `mark_compromised`, `retire`, `reinstate`, `destroy`.
impl Display for Transition {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Transition::Rotate => "rotate",
            Transition::Promote => "promote",
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
    key_id: KeyVersionId,
    algorithm: KeyAlgorithm,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    state: VersionState,
}

impl KeyVersion {
    /// The id every value under this version carries.
    pub fn id(&self) -> KeyVersionId {
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

    /// When the version was staged, while it is pending: the time from which a promotion waits
    /// out the longest any process may run without a successful refresh of its record.
    pub fn staged_at(&self) -> Option<Timestamp> {
        matches!(self.state, VersionState::Pending(_)).then_some(self.state_changed_at)
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
            VersionState::Pending(dek) | VersionState::Active(dek) => Some((dek, None)),
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

/// A state with what it holds, so that a destroyed version without its key, and a pending or
/// active one without a compromised flag, are the only shapes there are.
#[derive(Clone)]
enum VersionState {
    Pending(EncryptedDataEncryptionKey),
    Active(EncryptedDataEncryptionKey),
    DecryptOnly(RetainedDek),
    Retired(RetainedDek),
    Destroyed(Option<Compromise>),
}

impl VersionState {
    fn kind(&self) -> KeyVersionState {
        match self {
            VersionState::Pending(_) => KeyVersionState::Pending,
            VersionState::Active(_) => KeyVersionState::Active,
            VersionState::DecryptOnly(_) => KeyVersionState::DecryptOnly,
            VersionState::Retired(_) => KeyVersionState::Retired,
            VersionState::Destroyed(_) => KeyVersionState::Destroyed,
        }
    }

    fn compromised(&self) -> Option<&Compromise> {
        match self {
            VersionState::Pending(_) | VersionState::Active(_) => None,
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => {
                kept.compromised.as_ref()
            }
            VersionState::Destroyed(compromised) => compromised.as_ref(),
        }
    }

    fn dek(&self) -> Option<&EncryptedDataEncryptionKey> {
        match self {
            VersionState::Pending(dek) | VersionState::Active(dek) => Some(dek),
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

/// A version about to be created: its key id, the algorithm its key was made for, and the
/// wrapped key.
pub(crate) struct NewVersion {
    pub(crate) key_id: KeyVersionId,
    pub(crate) algorithm: KeyAlgorithm,
    pub(crate) dek: EncryptedDataEncryptionKey,
}

/// The record of one keyring: the KEK its keys are wrapped under, the algorithms of new
/// versions, and every version ever created, in creation order. It is stored as one JSON
/// document, the same in every store; see [`to_json`](Self::to_json).
///
/// Every record that exists holds its invariants: at most one active and one pending version
/// per purpose, neither of them compromised, a wrapped key on every version but the destroyed ones,
/// unique key ids of the purpose of their algorithm, increasing within a purpose in creation
/// order, and at most 1 MiB of JSON: at about 400 bytes per version with its wrapped key, about
/// 2,600 versions.
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
    pub fn version(&self, key_id: KeyVersionId) -> Option<&KeyVersion> {
        self.versions
            .iter()
            .find(|version| version.key_id == key_id)
    }

    /// The version of `purpose` that encrypts new values.
    pub fn active(&self, purpose: Purpose) -> Option<&KeyVersion> {
        self.active_dek(purpose).map(|(version, _)| version)
    }

    /// The version of `purpose` a rotation staged, which decrypts and waits for its promotion.
    pub fn pending(&self, purpose: Purpose) -> Option<&KeyVersion> {
        self.versions.iter().find(|version| {
            version.key_id.purpose() == purpose && matches!(version.state, VersionState::Pending(_))
        })
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

    /// The id the next version of `purpose` takes.
    ///
    /// # Errors
    ///
    /// [`KeyringError::RecordInvalid`] with `KeyIdsExhausted` once the purpose's ordinals run
    /// out.
    pub(crate) fn next_key_id(&self, purpose: Purpose) -> KeyringResult<KeyVersionId> {
        match self
            .versions
            .iter()
            .map(KeyVersion::id)
            .filter(|key_id| key_id.purpose() == purpose)
            .max()
        {
            None => Ok(KeyVersionId::first(purpose)),
            Some(last) => last.next().ok_or_else(|| {
                KeyringError::record_invalid(
                    &self.id,
                    RecordInvalidReason::KeyIdsExhausted(purpose),
                )
            }),
        }
    }

    /// The wrapped key of every version that holds one, by key id.
    pub(crate) fn wrapped_deks(&self) -> Vec<(KeyVersionId, EncryptedDataEncryptionKey)> {
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

    /// Adds `new` as the pending version of its purpose.
    ///
    /// # Errors
    ///
    /// `InvalidTransition` with [`Transition::Rotate`], naming the pending version, when the
    /// purpose has one already.
    pub(crate) fn stage(&mut self, new: NewVersion, now: Timestamp) -> KeyringResult<KeyVersionId> {
        if let Some(pending) = self.0.pending(new.algorithm.purpose()) {
            return Err(KeyringError::InvalidTransition(InvalidTransitionError {
                keyring: self.0.id.clone(),
                key_id: pending.key_id,
                from: KeyVersionState::Pending,
                transition: Transition::Rotate,
            }));
        }
        let key_id = new.key_id;
        self.push(new, VersionState::Pending, now);
        Ok(key_id)
    }

    /// Makes the pending version `key_id` the active version of its purpose; the active version
    /// it replaces decrypts only.
    pub(crate) fn promote(
        &mut self,
        key_id: KeyVersionId,
        now: Timestamp,
    ) -> KeyringResult<Rotation> {
        let purpose = key_id.purpose();
        let previous = self.0.active(purpose).map(KeyVersion::id);
        self.change_state(key_id, Transition::Promote, now, |state| match state {
            VersionState::Pending(dek) => Some(VersionState::Active(dek.clone())),
            _ => None,
        })?;
        if let Some(previous) = previous {
            self.change_state(previous, Transition::Promote, now, |state| match state {
                VersionState::Active(dek) => Some(VersionState::DecryptOnly(RetainedDek {
                    dek: dek.clone(),
                    compromised: None,
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
        key_id: KeyVersionId,
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
                VersionState::Pending(_) => None,
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
                let current = new.key_id;
                self.push(new, VersionState::Active, now);
                Ok(Some(Rotation {
                    purpose,
                    previous: Some(key_id),
                    current,
                }))
            }
            _ => Ok(None),
        }
    }

    pub(crate) fn retire(&mut self, key_id: KeyVersionId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Retire, now, |state| match state {
            VersionState::DecryptOnly(kept) => Some(VersionState::Retired(kept.clone())),
            _ => None,
        })
    }

    pub(crate) fn reinstate(&mut self, key_id: KeyVersionId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Reinstate, now, |state| match state {
            VersionState::Retired(kept) => Some(VersionState::DecryptOnly(kept.clone())),
            _ => None,
        })
    }

    pub(crate) fn destroy(&mut self, key_id: KeyVersionId, now: Timestamp) -> KeyringResult<()> {
        self.change_state(key_id, Transition::Destroy, now, |state| match state {
            VersionState::Pending(_) => Some(VersionState::Destroyed(None)),
            VersionState::Retired(kept) => Some(VersionState::Destroyed(kept.compromised.clone())),
            _ => None,
        })
    }

    /// Puts `dek`, the same key wrapped again, in place of `key_id`'s wrapped key, in whatever
    /// state the version is.
    pub(crate) fn replace_dek(
        &mut self,
        key_id: KeyVersionId,
        dek: EncryptedDataEncryptionKey,
        now: Timestamp,
    ) -> KeyringResult<()> {
        match &mut self.version_mut(key_id)?.state {
            VersionState::Pending(held) | VersionState::Active(held) => *held = dek,
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
            KeyAlgorithm::Beacon(algorithm) => algorithms.beacon = Some(algorithm),
        }
        self.0.updated_at = now;
    }

    /// Appends `new` in the state `state` makes of its wrapped key. A key id that does not
    /// follow the record's, such as one computed on an older record, fails the record's checks in
    /// [`finish`](Self::finish).
    fn push(
        &mut self,
        new: NewVersion,
        state: fn(EncryptedDataEncryptionKey) -> VersionState,
        now: Timestamp,
    ) {
        let record = &mut self.0;
        record.versions.push(KeyVersion {
            key_id: new.key_id,
            algorithm: new.algorithm,
            created_at: now,
            state_changed_at: now,
            state: state(new.dek),
        });
        record.updated_at = now;
    }

    /// Moves `key_id` to the state `next` returns for its current one, or fails with
    /// `InvalidTransition` when it returns `None`.
    fn change_state(
        &mut self,
        key_id: KeyVersionId,
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
    fn version_mut(&mut self, key_id: KeyVersionId) -> KeyringResult<&mut KeyVersion> {
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
///
/// The wrapped key is left out: a changed one under an unchanged id is a rewrap.
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

/// The wrapped keys `held` reads under that `next` takes out of use, with their key ids: their
/// version is gone, retired or destroyed, newly flagged compromised, or holds another wrapped
/// key, as after a rewrap, which leaves the cached plaintext of the old bytes orphaned.
pub(crate) fn withdrawn_deks<'a>(
    held: &'a KeyringRecord,
    next: &'a KeyringRecord,
) -> impl Iterator<Item = (KeyVersionId, &'a EncryptedDataEncryptionKey)> + 'a {
    held.versions.iter().filter_map(move |held| {
        let (dek, compromise) = held.readable_dek()?;
        let withdrawn = match next.version(held.key_id).and_then(KeyVersion::readable_dek) {
            None => true,
            Some((next_dek, next_compromise)) => {
                next_dek != dek || (next_compromise.is_some() && compromise.is_none())
            }
        };
        withdrawn.then_some((held.key_id, dek))
    })
}

#[cfg(test)]
mod tests;
