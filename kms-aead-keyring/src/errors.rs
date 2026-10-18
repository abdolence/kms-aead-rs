//! The error type of every fallible operation, [`KeyringError`].
//!
//! No error carries plaintext, a data encryption key in any form, wrapped or not, KEK material,
//! AAD content, cipher text bytes, or the length of a value or of its AAD, in `Display` or in
//! `Debug`. Keyring ids, key ids, KEK names and store names are identifiers and appear.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use kms_aead::errors::KmsAeadError;
use kms_aead::{KekProvider, KekRef};
use rsb_derive::Builder;

use crate::store::{StoreKind, StoreOperation};
use crate::{
    Compromise, Interop, KeyAlgorithm, KeyId, KeyVersionState, KeyringId, Purpose, Transition,
};

/// The result of every fallible operation of the crate.
pub type KeyringResult<T> = Result<T, KeyringError>;

/// Every error of the crate. Match on the variant and its fields: the `Display` text is for
/// people and may change in any release.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyringError {
    /// A KMS or AEAD operation of kms-aead failed: an unwrap, a wrap, or a value that is not
    /// authentic under its key and AAD (code `DECRYPT`).
    Kms(KmsAeadError),
    /// The keyring store failed.
    Store(KeyringStoreError),
    /// A keyring id, key id or AAD part that breaks the rule of its type.
    InvalidIdentifier(InvalidIdentifierError),
    /// The store holds no record for the keyring, when a keyring is opened or a record is
    /// read before an administrative write.
    RecordMissing(KeyringId),
    /// [`Keyring::create`](crate::Keyring::create) found a record for the keyring.
    RecordExists(KeyringId),
    /// A record breaks a size cap or an invariant of the keyring record.
    RecordInvalid(RecordInvalidError),
    /// A record read from the store moves a version backwards from the record this process
    /// holds: returned by a forced reload and by the read before an administrative write.
    RecordRegressed(RecordRegressedError),
    /// An administrative write lost every compare-and-swap to concurrent writers.
    RecordConflict(RecordConflictError),
    /// The provider's KEK is not the one the record names.
    KekMismatch(KekMismatchError),
    /// The keyring has no active version of the purpose, so nothing new is encrypted under it.
    NoActiveVersion(PurposeError),
    /// The record names no algorithm for the purpose, so no version of it can be created.
    NoAlgorithm(PurposeError),
    /// The record has no version with the value's key id, also after a reload.
    KeyVersionUnknown(KeyVersionError),
    /// The value's key version is retired: it decrypts again after
    /// [`reinstate`](crate::Keyring::reinstate).
    KeyVersionRetired(KeyVersionError),
    /// The value's key version is destroyed: its key is gone.
    KeyVersionDestroyed(KeyVersionError),
    /// The value's key version is compromised and the read policy is
    /// [`Block`](crate::CompromisedReadPolicy::Block).
    KeyVersionCompromised(KeyVersionCompromisedError),
    /// A value whose key id belongs to the other purpose.
    KeyPurposeMismatch(KeyPurposeMismatchError),
    /// A lifecycle operation that does not apply to the version's state.
    InvalidTransition(InvalidTransitionError),
    /// Bytes that are not a keyring value.
    ValueLayout(ValueLayoutError),
    /// A decrypted value that does not decode as its plaintext type, or a plaintext that does
    /// not encode.
    Plaintext(PlaintextError),
    /// Creating a deterministic key version needs the `deterministic` feature.
    DeterministicDisabled,
    /// A field's [`Interop`] requirement that sealing would break, checked before sealing.
    Interop(InteropError),
}

impl KeyringError {
    /// The variant name, the value of the `error_code` span field.
    pub(crate) fn code(&self) -> &'static str {
        match self {
            KeyringError::Kms(_) => "Kms",
            KeyringError::Store(_) => "Store",
            KeyringError::InvalidIdentifier(_) => "InvalidIdentifier",
            KeyringError::RecordMissing(_) => "RecordMissing",
            KeyringError::RecordExists(_) => "RecordExists",
            KeyringError::RecordInvalid(_) => "RecordInvalid",
            KeyringError::RecordRegressed(_) => "RecordRegressed",
            KeyringError::RecordConflict(_) => "RecordConflict",
            KeyringError::KekMismatch(_) => "KekMismatch",
            KeyringError::NoActiveVersion(_) => "NoActiveVersion",
            KeyringError::NoAlgorithm(_) => "NoAlgorithm",
            KeyringError::KeyVersionUnknown(_) => "KeyVersionUnknown",
            KeyringError::KeyVersionRetired(_) => "KeyVersionRetired",
            KeyringError::KeyVersionDestroyed(_) => "KeyVersionDestroyed",
            KeyringError::KeyVersionCompromised(_) => "KeyVersionCompromised",
            KeyringError::KeyPurposeMismatch(_) => "KeyPurposeMismatch",
            KeyringError::InvalidTransition(_) => "InvalidTransition",
            KeyringError::ValueLayout(_) => "ValueLayout",
            KeyringError::Plaintext(_) => "Plaintext",
            KeyringError::DeterministicDisabled => "DeterministicDisabled",
            KeyringError::Interop(_) => "Interop",
        }
    }

    /// The code an event reports: kms-aead's code for a KMS error, which names what the KMS
    /// refused, and the variant name otherwise.
    pub(crate) fn event_code(&self) -> &str {
        match self {
            KeyringError::Kms(error) => error.code(),
            other => other.code(),
        }
    }

    pub(crate) fn record_invalid(keyring: &KeyringId, reason: RecordInvalidReason) -> Self {
        KeyringError::RecordInvalid(RecordInvalidError {
            keyring: keyring.clone(),
            reason,
        })
    }

    pub(crate) fn key_version_unknown(keyring: &KeyringId, key_id: KeyId) -> Self {
        KeyringError::KeyVersionUnknown(KeyVersionError {
            keyring: keyring.clone(),
            key_id,
        })
    }

    pub(crate) fn no_active_version(keyring: &KeyringId, purpose: Purpose) -> Self {
        KeyringError::NoActiveVersion(PurposeError {
            keyring: keyring.clone(),
            purpose,
        })
    }

    pub(crate) fn no_algorithm(keyring: &KeyringId, purpose: Purpose) -> Self {
        KeyringError::NoAlgorithm(PurposeError {
            keyring: keyring.clone(),
            purpose,
        })
    }

    pub(crate) fn invalid_identifier(identifier: Identifier, rule: IdentifierRule) -> Self {
        KeyringError::InvalidIdentifier(InvalidIdentifierError { identifier, rule })
    }

    /// A [`Plaintext`](KeyringError::Plaintext) error of the type `T`. `reason` never quotes the
    /// value.
    pub(crate) fn plaintext<T>(reason: impl Into<String>) -> Self {
        KeyringError::Plaintext(PlaintextError {
            type_name: std::any::type_name::<T>(),
            reason: reason.into(),
        })
    }

    /// A [`Plaintext`](KeyringError::Plaintext) error of the type `T` with serde_json's category
    /// and position of `error`, never its message, which quotes the input.
    #[cfg(feature = "serde-json")]
    pub(crate) fn json<T>(error: &serde_json::Error) -> Self {
        Self::plaintext::<T>(format!(
            "{:?} error at line {} column {}",
            error.classify(),
            error.line(),
            error.column()
        ))
    }
}

impl From<KmsAeadError> for KeyringError {
    fn from(error: KmsAeadError) -> Self {
        KeyringError::Kms(error)
    }
}

impl Display for KeyringError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyringError::Kms(error) => error.fmt(f),
            KeyringError::Store(error) => write!(
                f,
                "The {} keyring store failed to {}: {}",
                error.store, error.operation, error.message
            ),
            KeyringError::InvalidIdentifier(error) => {
                write!(f, "Invalid {}: {}", error.identifier, error.rule)
            }
            KeyringError::RecordMissing(keyring) => {
                write!(f, "The keyring store holds no record for {keyring}")
            }
            KeyringError::RecordExists(keyring) => {
                write!(f, "The keyring store already holds a record for {keyring}")
            }
            KeyringError::RecordInvalid(error) => write!(
                f,
                "The keyring record of {} is invalid: {}",
                error.keyring, error.reason
            ),
            KeyringError::RecordRegressed(error) => write!(
                f,
                "The keyring record of {} moves backwards from the record this process holds: {}",
                error.keyring, error.rule
            ),
            KeyringError::RecordConflict(error) => write!(
                f,
                "The keyring record of {} changed under each of {} write attempts",
                error.keyring, error.attempts
            ),
            KeyringError::KekMismatch(error) => write!(
                f,
                "The keyring record of {} names the KEK {}, and the provider wraps with {}",
                error.keyring, error.recorded, error.provider
            ),
            KeyringError::NoActiveVersion(error) => write!(
                f,
                "The keyring {} has no active {} version: rotate to create one",
                error.keyring, error.purpose
            ),
            KeyringError::NoAlgorithm(error) => write!(
                f,
                "The keyring {} names no {} algorithm: change_algorithm sets one",
                error.keyring, error.purpose
            ),
            KeyringError::KeyVersionUnknown(error) => write!(
                f,
                "The keyring {} has no key version {}",
                error.keyring, error.key_id
            ),
            KeyringError::KeyVersionRetired(error) => write!(
                f,
                "The key version {} of the keyring {} is retired",
                error.key_id, error.keyring
            ),
            KeyringError::KeyVersionDestroyed(error) => write!(
                f,
                "The key version {} of the keyring {} is destroyed",
                error.key_id, error.keyring
            ),
            KeyringError::KeyVersionCompromised(error) => write!(
                f,
                "The key version {} of the keyring {} is compromised since {}",
                error.key_id,
                error.keyring,
                error.compromise.at()
            ),
            KeyringError::KeyPurposeMismatch(error) => write!(
                f,
                "The key id {} is not a {} key id",
                error.key_id, error.expected
            ),
            KeyringError::InvalidTransition(error) => write!(
                f,
                "The key version {} of the keyring {} is {}: {} does not apply",
                error.key_id, error.keyring, error.from, error.transition
            ),
            KeyringError::ValueLayout(error) => write!(f, "Not a keyring value: {error}"),
            KeyringError::Plaintext(error) => write!(
                f,
                "The plaintext does not convert to or from {}: {}",
                error.type_name, error.reason
            ),
            KeyringError::DeterministicDisabled => {
                f.write_str("Creating a deterministic key version needs the deterministic feature")
            }
            KeyringError::Interop(error) => write!(
                f,
                "A field of the keyring {} that {:?} reads cannot be sealed: {}",
                error.keyring, error.interop, error.requirement
            ),
        }
    }
}

impl Error for KeyringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyringError::Kms(error) => Some(error),
            KeyringError::Store(error) => error
                .root_cause
                .as_ref()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            _ => None,
        }
    }
}

/// See [`KeyringError::Store`]. A store implementation builds it with the client's error as
/// the root cause, and never formats the record or the request into it: both carry wrapped
/// data encryption keys.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct KeyringStoreError {
    /// The store that failed.
    pub store: StoreKind,
    /// What the store was asked to do.
    pub operation: StoreOperation,
    /// What failed, as the client reported it.
    pub message: String,
    /// The client's error.
    pub root_cause: Option<Arc<dyn Error + Send + Sync>>,
}

/// See [`KeyringError::InvalidIdentifier`]. Names the rule, never the value: an entity id can
/// be personal data.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidIdentifierError {
    /// What the value was meant to be.
    pub identifier: Identifier,
    /// The rule it breaks.
    pub rule: IdentifierRule,
}

/// The identifiers of the crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Identifier {
    /// [`KeyringId`].
    KeyringId,
    /// [`KeyId`].
    KeyId,
    /// [`EntityKind`](crate::EntityKind).
    EntityKind,
    /// [`EntityId`](crate::EntityId).
    EntityId,
    /// [`FieldName`](crate::FieldName).
    FieldName,
    /// The table name of the PostgreSQL store.
    PostgresTable,
    /// The bucket name of the GCS store.
    GcsBucketName,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Identifier::KeyringId => "keyring id",
            Identifier::KeyId => "key id",
            Identifier::EntityKind => "entity kind",
            Identifier::EntityId => "entity id",
            Identifier::FieldName => "field name",
            Identifier::PostgresTable => "PostgreSQL table name",
            Identifier::GcsBucketName => "GCS bucket name",
        })
    }
}

/// The rule an identifier breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentifierRule {
    /// Empty, or longer than the type allows.
    Length,
    /// A character the type does not allow.
    Character,
    /// A value the type reserves: `.`, `..` or `__…__` for a keyring id, an ordinal of zero for
    /// a key id.
    Reserved,
}

impl IdentifierRule {
    /// The rule as a phrase, also for the panic of a `from_static` constant.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            IdentifierRule::Length => "empty or too long",
            IdentifierRule::Character => "holds a character its type does not allow",
            IdentifierRule::Reserved => "a reserved value",
        }
    }
}

impl Display for IdentifierRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// See [`KeyringError::RecordInvalid`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordInvalidError {
    /// The keyring whose record was read or built.
    pub keyring: KeyringId,
    /// The first cap or invariant the record breaks.
    pub reason: RecordInvalidReason,
}

/// A size cap or an invariant of the keyring record. A reason names key ids and purposes,
/// never the record's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecordInvalidReason {
    /// The stored document is larger than 1 MiB.
    TooLarge,
    /// The record holds more than 10,000 versions.
    TooManyVersions,
    /// The document is not the JSON of a keyring record.
    Malformed(MalformedRecord),
    /// The record's schema is not 1, the only one this release reads.
    UnsupportedSchema(u32),
    /// The record names another keyring than the one it was read for.
    IdMismatch,
    /// An algorithm name this release does not know: of the version with this key id, or of
    /// the record's algorithms for new versions when there is none.
    UnknownAlgorithm(Option<KeyId>),
    /// A state name this release does not know, on the version with this key id.
    UnknownState(KeyId),
    /// A key id of 0 or 2^31, which name no version.
    ReservedKeyId,
    /// Two versions with one key id.
    DuplicateKeyId(KeyId),
    /// The key id's purpose is not its algorithm's.
    PurposeMismatch(KeyId),
    /// Two active versions of one purpose.
    TwoActiveVersions(Purpose),
    /// An active version flagged compromised.
    CompromisedActive(KeyId),
    /// A destroyed version that still holds a wrapped key.
    DestroyedWithMaterial(KeyId),
    /// A version that is not destroyed and holds no wrapped key.
    MissingMaterial(KeyId),
    /// A version whose ordinal is not above every earlier version of its purpose.
    OrdinalOrder(KeyId),
    /// A wrapped key that is not standard base64 of encrypted key layout v1.
    MalformedWrappedDek(KeyId),
    /// Every key id of the purpose is taken, so no version of it can be created.
    KeyIdsExhausted(Purpose),
}

impl Display for RecordInvalidReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordInvalidReason::TooLarge => f.write_str("the document is larger than 1 MiB"),
            RecordInvalidReason::TooManyVersions => {
                f.write_str("the record holds more than 10000 versions")
            }
            RecordInvalidReason::Malformed(malformed) => {
                f.write_str("the document is not a keyring record")?;
                if let Some(line) = malformed.line {
                    write!(f, ", at line {line}")?;
                }
                if let Some(column) = malformed.column {
                    write!(f, " column {column}")?;
                }
                Ok(())
            }
            RecordInvalidReason::UnsupportedSchema(schema) => {
                write!(f, "schema {schema} is not 1")
            }
            RecordInvalidReason::IdMismatch => f.write_str("the record names another keyring"),
            RecordInvalidReason::UnknownAlgorithm(Some(key_id)) => {
                write!(f, "key version {key_id} names an unknown algorithm")
            }
            RecordInvalidReason::UnknownAlgorithm(None) => {
                f.write_str("the algorithms for new versions name an unknown algorithm")
            }
            RecordInvalidReason::UnknownState(key_id) => {
                write!(f, "key version {key_id} names an unknown state")
            }
            RecordInvalidReason::ReservedKeyId => f.write_str("a key id of 0 or 2147483648"),
            RecordInvalidReason::DuplicateKeyId(key_id) => {
                write!(f, "two versions with key id {key_id}")
            }
            RecordInvalidReason::PurposeMismatch(key_id) => write!(
                f,
                "the purpose of key id {key_id} is not the purpose of its algorithm"
            ),
            RecordInvalidReason::TwoActiveVersions(purpose) => {
                write!(f, "two active {purpose} versions")
            }
            RecordInvalidReason::CompromisedActive(key_id) => {
                write!(f, "the active key version {key_id} is compromised")
            }
            RecordInvalidReason::DestroyedWithMaterial(key_id) => {
                write!(f, "the destroyed key version {key_id} holds a wrapped key")
            }
            RecordInvalidReason::MissingMaterial(key_id) => {
                write!(f, "key version {key_id} holds no wrapped key")
            }
            RecordInvalidReason::OrdinalOrder(key_id) => write!(
                f,
                "key version {key_id} is not above every earlier version of its purpose"
            ),
            RecordInvalidReason::MalformedWrappedDek(key_id) => {
                write!(f, "the wrapped key of key version {key_id} does not parse")
            }
            RecordInvalidReason::KeyIdsExhausted(purpose) => {
                write!(f, "every {purpose} key id is taken")
            }
        }
    }
}

/// Where a document stopped parsing as a keyring record. The parser's own message is not kept:
/// it quotes the value it refused, which can be a wrapped key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct MalformedRecord {
    /// The line, from 1, or `None` when the parser reported none.
    pub line: Option<usize>,
    /// The column, from 1, or `None` when the parser reported none.
    pub column: Option<usize>,
}

/// See [`KeyringError::RecordRegressed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordRegressedError {
    /// The keyring whose record was read.
    pub keyring: KeyringId,
    /// The first rule the record breaks.
    pub rule: RegressionRule,
}

/// How a record read from the store moves backwards from the record a process holds. Each
/// names the version of the held record that it concerns.
///
/// Two more properties hold whenever these do, so they need no rule of their own: a destroyed
/// version never regains a wrapped key, since `Destroyed` moves nowhere and holds none, and the
/// highest key id of a purpose never decreases, since no version goes missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegressionRule {
    /// The version is gone.
    VersionMissing(KeyId),
    /// The version's algorithm or creation time changed.
    VersionAltered(KeyId),
    /// The version's compromised flag was cleared.
    CompromiseCleared(KeyId),
    /// The time the version was flagged compromised changed.
    CompromiseAltered(KeyId),
    /// The version's state moved against the lifecycle, back to `Active` or out of
    /// `Destroyed`.
    StateReverted(KeyId),
}

impl Display for RegressionRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RegressionRule::VersionMissing(key_id) => write!(f, "key version {key_id} is gone"),
            RegressionRule::VersionAltered(key_id) => write!(
                f,
                "key version {key_id} changed its algorithm or creation time"
            ),
            RegressionRule::CompromiseCleared(key_id) => {
                write!(f, "key version {key_id} is no longer compromised")
            }
            RegressionRule::CompromiseAltered(key_id) => {
                write!(
                    f,
                    "key version {key_id} changed the time it was compromised"
                )
            }
            RegressionRule::StateReverted(key_id) => {
                write!(f, "key version {key_id} moved back in its lifecycle")
            }
        }
    }
}

/// See [`KeyringError::RecordConflict`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct RecordConflictError {
    /// The keyring whose record was written.
    pub keyring: KeyringId,
    /// The compare-and-swap attempts made, one more than
    /// [`cas_retries`](crate::KeyringOptions::cas_retries).
    pub attempts: u32,
}

/// See [`KeyringError::KekMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KekMismatchError {
    /// The keyring that was opened.
    pub keyring: KeyringId,
    /// The KEK the record names.
    pub recorded: KekRef,
    /// The KEK of the provider the keyring was opened with.
    pub provider: KekRef,
}

/// See [`KeyringError::NoActiveVersion`] and [`KeyringError::NoAlgorithm`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PurposeError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The purpose it has no version or algorithm for.
    pub purpose: Purpose,
}

/// See [`KeyringError::KeyVersionUnknown`], [`KeyringError::KeyVersionRetired`] and
/// [`KeyringError::KeyVersionDestroyed`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyVersionError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The value's key id.
    pub key_id: KeyId,
}

/// See [`KeyringError::KeyVersionCompromised`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyVersionCompromisedError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The value's key id.
    pub key_id: KeyId,
    /// When the version was flagged, and the operator's note.
    pub compromise: Compromise,
}

/// See [`KeyringError::KeyPurposeMismatch`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct KeyPurposeMismatchError {
    /// The purpose of the value's type.
    pub expected: Purpose,
    /// The key id the value carries.
    pub key_id: KeyId,
}

/// See [`KeyringError::InvalidTransition`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InvalidTransitionError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The version the operation named.
    pub key_id: KeyId,
    /// The version's state.
    pub from: KeyVersionState,
    /// The operation.
    pub transition: Transition,
}

/// See [`KeyringError::ValueLayout`]. No variant carries a byte of the value or its length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueLayoutError {
    /// The value does not start with `0x01`, the version byte of Tink's TINK prefix.
    NoTinkPrefix,
    /// The value is shorter than an empty value of this purpose: 33 bytes for a randomized
    /// value, 21 for a deterministic one.
    TooShort(Purpose),
    /// The key id is 0 or 2^31, which name no version.
    ReservedKeyId,
}

impl Display for ValueLayoutError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ValueLayoutError::NoTinkPrefix => f.write_str("it does not start with 0x01"),
            ValueLayoutError::TooShort(purpose) => {
                write!(f, "it is shorter than an empty {purpose} value")
            }
            ValueLayoutError::ReservedKeyId => f.write_str("its key id is 0 or 2147483648"),
        }
    }
}

/// See [`KeyringError::Interop`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InteropError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The field's requirement.
    pub interop: Interop,
    /// The first part of it that sealing would break.
    pub requirement: InteropRequirement,
}

/// What a field's [`Interop`] needs and sealing would not give it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InteropRequirement {
    /// The active version of the purpose uses an algorithm the reader does not implement.
    Algorithm(KeyAlgorithm),
    /// The KEK is in a KMS the reader does not unwrap with.
    Kek(KekProvider),
}

impl Display for InteropRequirement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InteropRequirement::Algorithm(algorithm) => {
                write!(f, "the reader does not implement {algorithm}")
            }
            InteropRequirement::Kek(provider) => {
                write!(f, "the reader does not unwrap keys with {provider}")
            }
        }
    }
}

/// See [`KeyringError::Plaintext`]. The reason never quotes the value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PlaintextError {
    /// The plaintext type.
    pub type_name: &'static str,
    /// Why the bytes do not convert.
    pub reason: String,
}
