//! The keyring record: every key version of one keyring, each with its encrypted data encryption
//! key and its state, and the lifecycle that moves the states.

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};
use std::str::FromStr;

use jiff::Timestamp;
use kms_aead::{
    AeadAlgorithm, BeaconAlgorithm, DeterministicAlgorithm, EncryptedDataEncryptionKey, KekRef,
};
use rsb_derive::Builder;

use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult, RegressionRule};
use crate::sweep::SealMarker;
use crate::{KeyId, Purpose};

#[cfg(feature = "admin")]
mod edit;
#[cfg(feature = "admin")]
pub(crate) use edit::{NewVersion, RecordEdit};

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

/// The algorithms new versions of each purpose use: those a new keyring is created with, and
/// those its record names from then on, which `KeyringAdmin::change_algorithm` changes per
/// purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Builder)]
#[non_exhaustive]
pub struct KeyringAlgorithms {
    /// The algorithm of new randomised versions:
    /// [`DEFAULT_RANDOMIZED`](Self::DEFAULT_RANDOMIZED) by default.
    #[default = "Self::DEFAULT_RANDOMIZED"]
    pub randomized: AeadAlgorithm,
    /// The algorithm of new deterministic versions, or `None`, the default, for a keyring without
    /// them. Creating one needs the `deterministic` feature.
    pub deterministic: Option<DeterministicAlgorithm>,
    /// The algorithm of new beacon versions, or `None`, the default, for a keyring without them.
    pub beacon: Option<BeaconAlgorithm>,
}

impl KeyringAlgorithms {
    /// The default [`randomized`](Self::randomized) algorithm: AES-256-GCM, the one Tink and
    /// BigQuery read.
    pub const DEFAULT_RANDOMIZED: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;
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
/// [`KeyringError::KmsAead`] with code `UNKNOWN_ALGORITHM` for any other name.
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
///                        promote                          retire           destroy
///   rotate ──▶ Pending ──────────▶ Active ──▶ DecryptOnly ──────▶ Retired ─────────▶ Destroyed
///                 │                   ▲            ▲                 │                   ▲
///                 │       create ─────┘            └────reinstate────┘                   │
///                 └───────────────────────────────destroy────────────────────────────────┘
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
    /// Refused on read. The encrypted DEK is kept, so that `reinstate` can undo a retirement.
    Retired,
    /// The encrypted DEK is gone. The version stays, so that its id is never reused.
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
    /// A retired or pending version's encrypted DEK is removed.
    Destroy,
}

/// `rotate`, `promote`, `mark_compromised`, `retire`, `reinstate`, `destroy`.
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

/// One data encryption key of a keyring, encrypted by the KEK, with its state.
///
/// `Debug` shows the id, the algorithm, the state and the times, never the encrypted DEK.
pub struct KeyVersion {
    key_id: KeyId,
    algorithm: KeyAlgorithm,
    created_at: Timestamp,
    state_changed_at: Timestamp,
    state: VersionState,
}

impl KeyVersion {
    /// The key id every value and beacon under this version carries. The keyring numbers the
    /// versions of each purpose from its first id: randomised versions are `1, 2, 3, …`,
    /// deterministic ones `2147483649, 2147483650, …` and beacon ones `1073741825, 1073741826, …`.
    /// Ids are never reused: a destroyed version keeps its id.
    pub fn id(&self) -> KeyId {
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

    pub(crate) fn encrypted_dek(&self) -> Option<&EncryptedDataEncryptionKey> {
        self.state.dek()
    }

    /// The encrypted DEK that opens values under this version, with its compromised flag, or
    /// `None` for a retired or destroyed version, which opens nothing.
    pub(crate) fn readable_dek(
        &self,
    ) -> Option<(&EncryptedDataEncryptionKey, Option<&Compromise>)> {
        match &self.state {
            VersionState::Pending(encrypted_dek) | VersionState::Active(encrypted_dek) => {
                Some((encrypted_dek, None))
            }
            VersionState::DecryptOnly(kept) => {
                Some((&kept.encrypted_dek, kept.compromised.as_ref()))
            }
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
            VersionState::Pending(encrypted_dek) | VersionState::Active(encrypted_dek) => {
                Some(encrypted_dek)
            }
            VersionState::DecryptOnly(kept) | VersionState::Retired(kept) => {
                Some(&kept.encrypted_dek)
            }
            VersionState::Destroyed(_) => None,
        }
    }
}

/// The encrypted DEK of a version past `Active`, which may be compromised.
#[derive(Clone)]
struct RetainedDek {
    encrypted_dek: EncryptedDataEncryptionKey,
    compromised: Option<Compromise>,
}

/// The record of one keyring: the KEK its keys are encrypted under, the algorithms of new
/// versions, the seal epoch, and every version ever created, in creation order. It is stored as
/// one JSON document, the same in every store; see [`to_json`](Self::to_json).
///
/// Every record that exists holds its invariants: at most one active and one pending version
/// per purpose, neither of them compromised, an encrypted DEK on every version but the destroyed
/// ones, unique key ids of the purpose of their algorithm, increasing within a purpose in creation
/// order, a seal epoch of 1 or more, and at most 1 MiB of JSON: at about 400 bytes per version
/// with its encrypted DEK, about 2,600 versions.
///
/// `Debug` shows identifiers, states and times, never an encrypted DEK.
#[derive(Debug)]
pub struct KeyringRecord {
    id: KeyringId,
    kek: KekRef,
    algorithms: KeyringAlgorithms,
    seal_marker: SealMarker,
    versions: Vec<KeyVersion>,
    created_at: Timestamp,
    updated_at: Timestamp,
}

impl KeyringRecord {
    /// The keyring this record belongs to.
    pub fn id(&self) -> &KeyringId {
        &self.id
    }

    /// The KEK of the provider the keyring was created with. It is informational: it catches a
    /// keyring opened with the wrong configuration, and is no security control, since a writer
    /// of the record sets it as freely as any other field. What refuses a key encrypted under
    /// another KEK is the KMS, which every decryption names the configured KEK to.
    pub fn kek(&self) -> &KekRef {
        &self.kek
    }

    /// The algorithms new versions use.
    pub fn algorithms(&self) -> &KeyringAlgorithms {
        &self.algorithms
    }

    /// The marker of the record's seal epoch, which every administrative write that makes a
    /// version active moves on by one: the keyring's creation, at epoch 1, `promote`, and the
    /// replacement of a compromised active version by `mark_compromised`.
    ///
    /// A write of an application record stores it beside the encrypted fields it seals, and a
    /// sweep visits the records whose marker is below it, see [`sweep`](crate::sweep). The
    /// marker is read before the first field is sealed: the cached record moves forward only, so
    /// such a marker is never newer than the versions the fields are sealed under, while one read
    /// after them can be.
    pub fn seal_marker(&self) -> SealMarker {
        self.seal_marker
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

    /// The version of `purpose` a rotation staged, which decrypts and waits for its promotion.
    pub fn pending(&self, purpose: Purpose) -> Option<&KeyVersion> {
        self.versions.iter().find(|version| {
            version.algorithm.purpose() == purpose
                && matches!(version.state, VersionState::Pending(_))
        })
    }

    /// The active version of `purpose` and its encrypted DEK.
    pub(crate) fn active_dek(
        &self,
        purpose: Purpose,
    ) -> Option<(&KeyVersion, &EncryptedDataEncryptionKey)> {
        self.versions
            .iter()
            .find_map(|version| match &version.state {
                VersionState::Active(encrypted_dek) if version.algorithm.purpose() == purpose => {
                    Some((version, encrypted_dek))
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

    /// The encrypted DEK of every version that holds one, by key id.
    pub(crate) fn encrypted_deks(&self) -> Vec<(KeyId, EncryptedDataEncryptionKey)> {
        self.versions
            .iter()
            .filter_map(|version| Some((version.key_id, version.encrypted_dek()?.clone())))
            .collect()
    }
}

/// Whether `next`, a record read from the store, moves forward from `held`: every version of
/// `held` is still there, with the same algorithm and creation time, its compromised flag kept
/// with its time, and its state moved along the lifecycle, and the seal epoch is not below
/// `held`'s. New versions are free.
///
/// The encrypted DEK is left out: a changed one under an unchanged id is a re-encryption.
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
    if next.seal_marker < held.seal_marker {
        return Err(RegressionRule::SealEpochReverted);
    }
    Ok(())
}

/// The encrypted DEKs `held` reads under that `next` takes out of use, with their key ids: their
/// version is gone, retired or destroyed, newly flagged compromised, or holds another encrypted
/// key, as after a re-encryption, which leaves the cached plaintext of the old bytes orphaned.
pub(crate) fn withdrawn_deks<'a>(
    held: &'a KeyringRecord,
    next: &'a KeyringRecord,
) -> impl Iterator<Item = (KeyId, &'a EncryptedDataEncryptionKey)> + 'a {
    held.versions.iter().filter_map(move |held| {
        let (encrypted_dek, compromise) = held.readable_dek()?;
        let withdrawn = match next.version(held.key_id).and_then(KeyVersion::readable_dek) {
            None => true,
            Some((next_encrypted_dek, next_compromise)) => {
                next_encrypted_dek != encrypted_dek
                    || (next_compromise.is_some() && compromise.is_none())
            }
        };
        withdrawn.then_some((held.key_id, encrypted_dek))
    })
}

#[cfg(test)]
mod tests;
