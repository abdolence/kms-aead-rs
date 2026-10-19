//! The error type of every fallible operation, [`KeyringError`].
//!
//! No error carries plaintext, a data encryption key in any form, encrypted or not, KEK material,
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

/// Every error of the crate. Match on the variant and its fields, or on [`code`](Self::code):
/// the `Display` text is for people and may change in any release.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum KeyringError {
    /// An operation of kms-aead failed: a decryption, an encryption, a value that is not authentic
    /// under its key and AAD (code `DECRYPT`), or a plaintext that does not encode or decode as its
    /// type (code `INVALID_PLAINTEXT`).
    KmsAead(KmsAeadError),
    /// The keyring store failed.
    Store(KeyringStoreError),
    /// A keyring id, AAD part or store name that breaks the rule of its type.
    InvalidIdentifier(InvalidIdentifierError),
    /// The store holds no record for the keyring, when a keyring is opened or a record is
    /// read before an administrative write.
    RecordMissing(KeyringId),
    /// `KeyringRegistry::create` found the keyring's record, in the store or already open.
    RecordExists(KeyringId),
    /// A record breaks a size cap or an invariant of the keyring record.
    RecordInvalid(RecordInvalidError),
    /// A record read from the store moves a version backwards from the record this process
    /// holds: returned by a forced reload and by the read before an administrative write.
    RecordRegressed(RecordRegressedError),
    /// An administrative write lost every compare-and-swap to concurrent writers.
    RecordConflict(RecordConflictError),
    /// The provider's KEK is not the one the record names. Boxed, since its two KEK names are
    /// the largest payload of any variant.
    KekMismatch(Box<KekMismatchError>),
    /// The keyring has no active version of the purpose, so nothing new is encrypted under it.
    NoActiveVersion(PurposeError),
    /// The record names no algorithm for the purpose, so no version of it can be created.
    NoAlgorithm(PurposeError),
    /// The record has no version with the value's key id, also after a reload.
    KeyVersionUnknown(KeyVersionError),
    /// The value's key version is retired: it decrypts again after `KeyringAdmin::reinstate`.
    KeyVersionRetired(KeyVersionError),
    /// The value's key version is destroyed: its key is gone.
    KeyVersionDestroyed(KeyVersionError),
    /// A pending version selected as the primary of a keyset export: a pending version never
    /// encrypts.
    KeyVersionPending(KeyVersionError),
    /// The value's key version is compromised and the read policy is
    /// [`Block`](crate::CompromisedReadPolicy::Block).
    KeyVersionCompromised(KeyVersionCompromisedError),
    /// A value or beacon under a key version that the [`Sealer`](crate::Sealer)'s record holds
    /// as pending, or lacks while the cached record, reloaded for it, has it: a process with a
    /// newer record sealed it. A sealer never seals such a value again under its own versions,
    /// which are older and may have been flagged compromised since.
    ///
    /// The write is safe to retry: it takes a new sealer from
    /// [`Keyring::sealer`](crate::Keyring::sealer) and runs again. Once the cached record holds
    /// the version as active or older, from the reload that returned this error, a watch signal
    /// or the record TTL, the new sealer finds the value current or seals it under the active
    /// version. A sweep counts the record as failed, and its next run visits it again.
    SealerOutdated(KeyVersionError),
    /// A value or beacon whose key id belongs to another purpose.
    KeyPurposeMismatch(KeyPurposeMismatchError),
    /// A lifecycle operation that does not apply to the version's state.
    InvalidTransition(InvalidTransitionError),
    /// A key id that a value or beacon carries, or that an operation names, is reserved: its
    /// ordinal is zero, or it sets both purpose bits, so no version has it.
    ReservedKeyId,
    /// Creating a deterministic key version needs the `deterministic` feature.
    DeterministicDisabled,
    /// An [`Interop`] requirement that sealing a field or exporting a keyset would break,
    /// checked before sealing and before any KMS call of an export.
    Interop(InteropError),
    /// [`FieldSpec::custom_aad`](crate::FieldSpec::custom_aad) on a field whose reader rebuilds
    /// the AAD itself, which bytes of the application's own choosing would not match: a field
    /// that [`Interop::BigQuery`] decrypts in SQL.
    CustomAadUnsupported(Interop),
    /// A version selected for a keyset export whose algorithm the keyset's reader does not
    /// read: for BigQuery neither AES-256-GCM nor AES-SIV, for Tink ChaCha20-Poly1305 or a
    /// beacon's.
    ExportAlgorithmUnsupported(KeyVersionError),
    /// A name that is not one a [`KeyVersionState`] displays as.
    UnknownKeyVersionState,
    /// Stored bytes that are not a [`SealMarker`](crate::sweep::SealMarker): not 5 bytes long,
    /// or not starting with the marker version `0x01`.
    InvalidSealMarker,
}

impl KeyringError {
    /// The code to match on and the `error_code` span field: kms-aead's own code for
    /// [`KmsAead`](KeyringError::KmsAead), such as `DECRYPT` or a KMS's code, and the variant's name in
    /// upper snake case otherwise, such as `KEY_VERSION_COMPROMISED`.
    pub fn code(&self) -> &str {
        match self {
            KeyringError::KmsAead(error) => error.code(),
            KeyringError::Store(_) => "STORE",
            KeyringError::InvalidIdentifier(_) => "INVALID_IDENTIFIER",
            KeyringError::RecordMissing(_) => "RECORD_MISSING",
            KeyringError::RecordExists(_) => "RECORD_EXISTS",
            KeyringError::RecordInvalid(_) => "RECORD_INVALID",
            KeyringError::RecordRegressed(_) => "RECORD_REGRESSED",
            KeyringError::RecordConflict(_) => "RECORD_CONFLICT",
            KeyringError::KekMismatch(_) => "KEK_MISMATCH",
            KeyringError::NoActiveVersion(_) => "NO_ACTIVE_VERSION",
            KeyringError::NoAlgorithm(_) => "NO_ALGORITHM",
            KeyringError::KeyVersionUnknown(_) => "KEY_VERSION_UNKNOWN",
            KeyringError::KeyVersionRetired(_) => "KEY_VERSION_RETIRED",
            KeyringError::KeyVersionDestroyed(_) => "KEY_VERSION_DESTROYED",
            KeyringError::KeyVersionPending(_) => "KEY_VERSION_PENDING",
            KeyringError::KeyVersionCompromised(_) => "KEY_VERSION_COMPROMISED",
            KeyringError::SealerOutdated(_) => "SEALER_OUTDATED",
            KeyringError::KeyPurposeMismatch(_) => "KEY_PURPOSE_MISMATCH",
            KeyringError::InvalidTransition(_) => "INVALID_TRANSITION",
            KeyringError::ReservedKeyId => "RESERVED_KEY_ID",
            KeyringError::DeterministicDisabled => "DETERMINISTIC_DISABLED",
            KeyringError::Interop(_) => "INTEROP",
            KeyringError::CustomAadUnsupported(_) => "CUSTOM_AAD_UNSUPPORTED",
            KeyringError::ExportAlgorithmUnsupported(_) => "EXPORT_ALGORITHM_UNSUPPORTED",
            KeyringError::UnknownKeyVersionState => "UNKNOWN_KEY_VERSION_STATE",
            KeyringError::InvalidSealMarker => "INVALID_SEAL_MARKER",
        }
    }

    pub(crate) fn interop(
        keyring: &KeyringId,
        interop: Interop,
        requirement: InteropRequirement,
    ) -> Self {
        KeyringError::Interop(InteropError {
            keyring: keyring.clone(),
            interop,
            requirement,
        })
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

    pub(crate) fn sealer_outdated(keyring: &KeyringId, key_id: KeyId) -> Self {
        KeyringError::SealerOutdated(KeyVersionError {
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

    /// A [`Malformed`](RecordInvalidReason::Malformed) record of `keyring`, at the position of
    /// serde_json's `error` when there is one. The parser's message is left out: it quotes the
    /// value it refused, which can be an encrypted DEK.
    pub(crate) fn malformed(keyring: &KeyringId, error: Option<&serde_json::Error>) -> Self {
        let position = |at: usize| (at > 0).then_some(at);
        Self::record_invalid(
            keyring,
            RecordInvalidReason::Malformed(MalformedRecord {
                line: error.and_then(|error| position(error.line())),
                column: error.and_then(|error| position(error.column())),
            }),
        )
    }

    /// A failure of the store `store` that no client error caused, such as a response without
    /// the metadata the store needs.
    #[cfg_attr(
        not(any(
            feature = "firestore",
            feature = "postgres",
            feature = "gcs",
            feature = "s3"
        )),
        expect(
            dead_code,
            reason = "only the stores fail with it, and none is in the build"
        )
    )]
    pub(crate) fn store(store: StoreKind, operation: StoreOperation, message: &str) -> Self {
        KeyringError::Store(KeyringStoreError::new(
            store,
            operation,
            message.to_string(),
        ))
    }

    /// A failure of the store `store` that the client error `root_cause` caused. The message is
    /// the error followed by each of its sources, since some clients name only the kind of
    /// failure in their own `Display`.
    #[cfg_attr(
        not(any(
            feature = "firestore",
            feature = "postgres",
            feature = "gcs",
            feature = "s3"
        )),
        expect(
            dead_code,
            reason = "only the stores fail with it, and none is in the build"
        )
    )]
    pub(crate) fn store_caused_by(
        store: StoreKind,
        operation: StoreOperation,
        root_cause: Arc<dyn Error + Send + Sync>,
    ) -> Self {
        let mut message = root_cause.to_string();
        let mut source = root_cause.source();
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        KeyringError::Store(
            KeyringStoreError::new(store, operation, message).with_root_cause(root_cause),
        )
    }

    pub(crate) fn invalid_identifier(identifier: Identifier, rule: IdentifierRule) -> Self {
        KeyringError::InvalidIdentifier(InvalidIdentifierError { identifier, rule })
    }
}

impl From<KmsAeadError> for KeyringError {
    fn from(error: KmsAeadError) -> Self {
        KeyringError::KmsAead(error)
    }
}

impl Display for KeyringError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyringError::KmsAead(error) => error.fmt(f),
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
                "The keyring record of {} names the KEK {}, and the provider encrypts with {}",
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
                error.keyring, error.key_id.as_u32()
            ),
            KeyringError::KeyVersionRetired(error) => write!(
                f,
                "The key version {} of the keyring {} is retired",
                error.key_id.as_u32(), error.keyring
            ),
            KeyringError::KeyVersionDestroyed(error) => write!(
                f,
                "The key version {} of the keyring {} is destroyed",
                error.key_id.as_u32(), error.keyring
            ),
            KeyringError::KeyVersionPending(error) => write!(
                f,
                "The key version {} of the keyring {} is pending",
                error.key_id.as_u32(), error.keyring
            ),
            KeyringError::KeyVersionCompromised(error) => write!(
                f,
                "The key version {} of the keyring {} is compromised since {}",
                error.key_id.as_u32(),
                error.keyring,
                error.compromise.at()
            ),
            KeyringError::SealerOutdated(error) => write!(
                f,
                "The key version {} of the keyring {} is newer than the sealer's record: take a new sealer",
                error.key_id.as_u32(), error.keyring
            ),
            KeyringError::KeyPurposeMismatch(error) => write!(
                f,
                "The key id {} is not a {} key id",
                error.key_id.as_u32(), error.expected
            ),
            KeyringError::InvalidTransition(error) => write!(
                f,
                "The key version {} of the keyring {} is {}: {} does not apply",
                error.key_id.as_u32(), error.keyring, error.from, error.transition
            ),
            KeyringError::ReservedKeyId => f.write_str("The key id is reserved"),
            KeyringError::DeterministicDisabled => {
                f.write_str("Creating a deterministic key version needs the deterministic feature")
            }
            KeyringError::Interop(error) => write!(
                f,
                "{} does not read the keyring {}: {}",
                error.interop, error.keyring, error.requirement
            ),
            KeyringError::CustomAadUnsupported(interop) => write!(
                f,
                "{interop} rebuilds the AAD of the field itself and cannot rebuild a custom one"
            ),
            KeyringError::ExportAlgorithmUnsupported(error) => write!(
                f,
                "The key version {} of the keyring {} has an algorithm the keyset's reader does not read",
                error.key_id.as_u32(), error.keyring
            ),
            KeyringError::UnknownKeyVersionState => f.write_str(
                "Not the name of a key version state: the names are pending, active, \
                 decrypt_only, retired and destroyed",
            ),
            KeyringError::InvalidSealMarker => f.write_str(
                "Not a seal marker: a marker is the version byte 1 and a 4-byte seal epoch",
            ),
        }
    }
}

impl Error for KeyringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyringError::KmsAead(error) => Some(error),
            KeyringError::Store(error) => error
                .root_cause
                .as_ref()
                .map(|cause| cause.as_ref() as &(dyn Error + 'static)),
            _ => None,
        }
    }
}

/// See [`KeyringError::Store`]. A store implementation builds it with the client's error as
/// the root cause, and never formats the record or the request into it: both carry encrypted
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
    /// The bucket name of the S3 store.
    S3BucketName,
}

impl Display for Identifier {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Identifier::KeyringId => "keyring id",
            Identifier::EntityKind => "entity kind",
            Identifier::EntityId => "entity id",
            Identifier::FieldName => "field name",
            Identifier::PostgresTable => "PostgreSQL table name",
            Identifier::GcsBucketName => "GCS bucket name",
            Identifier::S3BucketName => "S3 bucket name",
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
    /// A value the type reserves: `.`, `..` or `__…__` for a keyring id.
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
    /// A key id whose ordinal is zero or that sets both purpose bits, which names no version.
    ReservedKeyId,
    /// Two versions with one key id.
    DuplicateKeyId(KeyId),
    /// The key id's purpose is not its algorithm's.
    PurposeMismatch(KeyId),
    /// Two active versions of one purpose.
    TwoActiveVersions(Purpose),
    /// Two pending versions of one purpose.
    TwoPendingVersions(Purpose),
    /// An active version flagged compromised.
    CompromisedActive(KeyId),
    /// A pending version flagged compromised.
    CompromisedPending(KeyId),
    /// A destroyed version that still holds an encrypted DEK.
    DestroyedWithMaterial(KeyId),
    /// A version that is not destroyed and holds no encrypted DEK.
    MissingMaterial(KeyId),
    /// A version whose ordinal is not above every earlier version of its purpose.
    OrdinalOrder(KeyId),
    /// An encrypted DEK that is not standard base64 of one byte or more.
    MalformedEncryptedDek(KeyId),
    /// Every key id of the purpose is taken, so no version of it can be created.
    KeyIdsExhausted(Purpose),
    /// The seal epoch is 0, the epoch of records sealed before the keyring, or a version would
    /// become active past the last one, 2^32 - 1.
    SealEpochOutOfRange,
    /// The version's seal range does not fit its state: a pending version with one, an active
    /// version without one or with an end, or a decrypt-only or retired version without one; or
    /// it starts at epoch 0, ends where or before it starts, or lies past the record's seal
    /// epoch.
    SealRangeInvalid(KeyId),
}

impl Display for RecordInvalidReason {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RecordInvalidReason::TooLarge => f.write_str("the document is larger than 1 MiB"),
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
                write!(
                    f,
                    "key version {key_id} names an unknown algorithm",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::UnknownAlgorithm(None) => {
                f.write_str("the algorithms for new versions name an unknown algorithm")
            }
            RecordInvalidReason::UnknownState(key_id) => {
                write!(
                    f,
                    "key version {key_id} names an unknown state",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::ReservedKeyId => f.write_str("a reserved key id"),
            RecordInvalidReason::DuplicateKeyId(key_id) => {
                write!(
                    f,
                    "two versions with key id {key_id}",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::PurposeMismatch(key_id) => write!(
                f,
                "the purpose of key id {key_id} is not the purpose of its algorithm",
                key_id = key_id.as_u32()
            ),
            RecordInvalidReason::TwoActiveVersions(purpose) => {
                write!(f, "two active {purpose} versions")
            }
            RecordInvalidReason::TwoPendingVersions(purpose) => {
                write!(f, "two pending {purpose} versions")
            }
            RecordInvalidReason::CompromisedActive(key_id) => {
                write!(
                    f,
                    "the active key version {key_id} is compromised",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::CompromisedPending(key_id) => {
                write!(
                    f,
                    "the pending key version {key_id} is compromised",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::DestroyedWithMaterial(key_id) => {
                write!(
                    f,
                    "the destroyed key version {key_id} holds an encrypted DEK",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::MissingMaterial(key_id) => {
                write!(
                    f,
                    "key version {key_id} holds no encrypted DEK",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::OrdinalOrder(key_id) => write!(
                f,
                "key version {key_id} is not above every earlier version of its purpose",
                key_id = key_id.as_u32()
            ),
            RecordInvalidReason::MalformedEncryptedDek(key_id) => {
                write!(
                    f,
                    "the encrypted DEK of key version {key_id} does not parse",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::KeyIdsExhausted(purpose) => {
                write!(f, "every {purpose} key id is taken")
            }
            RecordInvalidReason::SealEpochOutOfRange => {
                f.write_str("the seal epoch is 0 or cannot count up any more")
            }
            RecordInvalidReason::SealRangeInvalid(key_id) => write!(
                f,
                "the seal range of key version {key_id} does not fit its state or the seal epoch",
                key_id = key_id.as_u32()
            ),
        }
    }
}

/// Where a document stopped parsing as a keyring record. The parser's own message is not kept:
/// it quotes the value it refused, which can be an encrypted DEK.
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

/// How a record read from the store moves backwards from the record a process holds. Each rule
/// of a version names the version of the held record that it concerns.
///
/// Two more properties hold whenever these do, so they need no rule of their own: a destroyed
/// version never regains an encrypted DEK, since `Destroyed` moves nowhere and holds none, and the
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
    /// The record's seal epoch is below the held one, so that records sealed under different
    /// active versions would carry the same [`SealMarker`](crate::sweep::SealMarker).
    SealEpochReverted,
    /// The version's [`SealRange`](crate::sweep::SealRange) lost its start or its end, one of
    /// them moved, or one was set at or below the held seal epoch, so that records the held
    /// record sealed under the version could fall outside it.
    SealRangeReverted(KeyId),
}

impl Display for RegressionRule {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            RegressionRule::VersionMissing(key_id) => {
                write!(f, "key version {key_id} is gone", key_id = key_id.as_u32())
            }
            RegressionRule::VersionAltered(key_id) => write!(
                f,
                "key version {key_id} changed its algorithm or creation time",
                key_id = key_id.as_u32()
            ),
            RegressionRule::CompromiseCleared(key_id) => {
                write!(
                    f,
                    "key version {key_id} is no longer compromised",
                    key_id = key_id.as_u32()
                )
            }
            RegressionRule::CompromiseAltered(key_id) => {
                write!(
                    f,
                    "key version {key_id} changed the time it was compromised",
                    key_id = key_id.as_u32()
                )
            }
            RegressionRule::StateReverted(key_id) => {
                write!(
                    f,
                    "key version {key_id} moved back in its lifecycle",
                    key_id = key_id.as_u32()
                )
            }
            RegressionRule::SealEpochReverted => f.write_str("the seal epoch moved back"),
            RegressionRule::SealRangeReverted(key_id) => write!(
                f,
                "the seal range of key version {key_id} moved back",
                key_id = key_id.as_u32()
            ),
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

/// See [`KeyringError::KeyVersionUnknown`], [`KeyringError::KeyVersionRetired`],
/// [`KeyringError::KeyVersionDestroyed`], [`KeyringError::KeyVersionPending`],
/// [`KeyringError::SealerOutdated`] and [`KeyringError::ExportAlgorithmUnsupported`].
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

/// See [`KeyringError::Interop`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InteropError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The reader whose requirement is broken: the field's, or the export's.
    pub interop: Interop,
    /// The first part of it that sealing or the export would break.
    pub requirement: InteropRequirement,
}

/// What an [`Interop`] reader needs and sealing or an export would not give it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InteropRequirement {
    /// The active version of the purpose uses an algorithm the reader does not implement.
    Algorithm(KeyAlgorithm),
    /// The KEK is in a KMS the reader does not decrypt with, or has no key URI the reader
    /// addresses it by, such as an AWS key named without its ARN.
    Kek(KekProvider),
}

impl Display for InteropRequirement {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            InteropRequirement::Algorithm(algorithm) => {
                write!(f, "the reader does not implement {algorithm}")
            }
            InteropRequirement::Kek(provider) => {
                write!(f, "the reader does not decrypt keys with {provider}")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use kms_aead::errors::KmsAeadEncryptionError;

    use super::*;
    use crate::test_support::TENANT;

    #[test]
    fn a_kms_error_keeps_the_kms_aead_code() {
        let decrypt = KeyringError::from(KmsAeadEncryptionError::create("DECRYPT", "refused"));

        assert_eq!(decrypt.code(), "DECRYPT");
        assert_eq!(KeyringError::RecordMissing(TENANT).code(), "RECORD_MISSING");
    }
}
