//! The error type of every fallible operation, [`KeyringError`].
//!
//! No error carries plaintext, a data encryption key in any form, encrypted or not, KEK material,
//! AAD content, cipher text bytes, or the length of a value or of its AAD, in `Display` or in
//! `Debug`. Keyring ids, key ids, KEK names and store names are identifiers and appear.

use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;
use std::time::Duration;

use kms_aead::errors::KmsAeadError;
use kms_aead::{KekRef, KmsProvider};
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
    /// The store holds no record for the keyring, when a keyring is opened, reloaded or read
    /// before an administrative write, or a read before found it gone: the process then holds
    /// the keyring with every version destroyed.
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
    /// A value or beacon under a key version that the [`Encryptor`](crate::Encryptor)'s record
    /// holds as pending, or lacks, while the cached record, reloaded for it, has it: a process with
    /// a newer record encrypted it. An encryptor never encrypts such a value again under its own
    /// versions, which are older and may have been flagged compromised since.
    ///
    /// The write is safe to retry: it takes a new encryptor from
    /// [`Keyring::encryptor`](crate::Keyring::encryptor) and runs again. The reload that returned
    /// this error took the store's record, so the new encryptor finds the value current or encrypts
    /// it under the active version. Inside `reload_min_interval` of another such reload, which
    /// bounds the store reads that values under unknown or pending key ids cause, the cached record
    /// may still hold the version as pending, and the retry fails the same way until the next
    /// reload, a watch signal or the record TTL. When the store's record itself holds the version
    /// as pending, as for a value from another keyring whose key id is pending here or after a
    /// restore from an older backup, every retry fails with `ENCRYPTOR_OUTDATED`, at no more than
    /// one store read per `reload_min_interval`. A sweep counts the record as failed.
    EncryptorOutdated(KeyVersionError),
    /// A value or beacon whose key id belongs to another purpose.
    KeyPurposeMismatch(KeyPurposeMismatchError),
    /// A lifecycle operation that does not apply to the version's state.
    InvalidTransition(InvalidTransitionError),
    /// A promotion of a pending version before the registry's
    /// [`record_ttl`](crate::KeyringRegistryOptions::record_ttl) has passed since it was staged,
    /// so a process may not have seen the version yet. The promotion succeeds once
    /// [`remaining`](PromotionTooEarlyError::remaining) has passed, and
    /// `KeyringAdmin::promote_now` makes it without the wait.
    PromotionTooEarly(PromotionTooEarlyError),
    /// A key id that a value, beacon or MAC carries, or that an operation names, is reserved: its
    /// ordinal is zero, so no version has it.
    ReservedKeyId(KeyId),
    /// Creating a deterministic key version needs the `deterministic` feature.
    DeterministicDisabled,
    /// An [`Interop`] requirement that encrypting a field or exporting a keyset would break,
    /// checked before encrypting and before any KMS call of an export.
    Interop(InteropError),
    /// [`FieldSpec::custom_aad`](crate::FieldSpec::custom_aad) on a field whose reader rebuilds
    /// the AAD itself, which bytes of the application's own choosing would not match: a field
    /// that [`Interop::BigQuery`] decrypts in SQL.
    CustomAadUnsupported(Interop),
    /// A version selected for a keyset export whose algorithm the keyset's reader does not
    /// read: for BigQuery neither AES-256-GCM nor AES-SIV, for Tink ChaCha20-Poly1305 or a
    /// beacon's.
    ExportAlgorithmUnsupported(KeyVersionError),
    /// A name that is not one a [`KeyVersionState`] displays as, which it holds.
    UnknownKeyVersionState(String),
    /// Stored bytes that are not a [`EncryptionMarker`](crate::sweep::EncryptionMarker): not 5 bytes
    /// long, or not starting with the marker version `0x01`. The bytes are left out: they come from
    /// a column of the application's, which may hold a plaintext.
    InvalidEncryptionMarker,
    /// A record without a signature, read under
    /// [`RecordSignaturePolicy::Required`](crate::RecordSignaturePolicy::Required); or one that a
    /// signing `KeyringAdmin` read before a write other than `sign_record`, which never turns an
    /// unsigned record into a signed one.
    RecordUnsigned(KeyringId),
    /// A record whose signature does not verify under the registry's verifying keys, or a new
    /// signature that does not verify under its signer's own key before the write.
    RecordSignatureInvalid(RecordSignatureInvalidError),
    /// A write by a `KeyringAdmin` without a record signer over a signed record, `sign_record`
    /// included, other than `dangerously_unsign_record`. Refused before any store write.
    RecordSignerMissing(KeyringId),
    /// An unsigned record read under
    /// [`RecordSignaturePolicy::VerifyIfSigned`](crate::RecordSignaturePolicy::VerifyIfSigned) by a
    /// process whose held record of the keyring is signed: at a revalidation, a reload, a read
    /// for an administrative write or an export's load. A new process holds nothing, so `open`
    /// never returns it.
    RecordSignatureRemoved(KeyringId),
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
            KeyringError::EncryptorOutdated(_) => "ENCRYPTOR_OUTDATED",
            KeyringError::KeyPurposeMismatch(_) => "KEY_PURPOSE_MISMATCH",
            KeyringError::InvalidTransition(_) => "INVALID_TRANSITION",
            KeyringError::PromotionTooEarly(_) => "PROMOTION_TOO_EARLY",
            KeyringError::ReservedKeyId(_) => "RESERVED_KEY_ID",
            KeyringError::DeterministicDisabled => "DETERMINISTIC_DISABLED",
            KeyringError::Interop(_) => "INTEROP",
            KeyringError::CustomAadUnsupported(_) => "CUSTOM_AAD_UNSUPPORTED",
            KeyringError::ExportAlgorithmUnsupported(_) => "EXPORT_ALGORITHM_UNSUPPORTED",
            KeyringError::UnknownKeyVersionState(_) => "UNKNOWN_KEY_VERSION_STATE",
            KeyringError::InvalidEncryptionMarker => "INVALID_ENCRYPTION_MARKER",
            KeyringError::RecordUnsigned(_) => "RECORD_UNSIGNED",
            KeyringError::RecordSignatureInvalid(_) => "RECORD_SIGNATURE_INVALID",
            KeyringError::RecordSignerMissing(_) => "RECORD_SIGNER_MISSING",
            KeyringError::RecordSignatureRemoved(_) => "RECORD_SIGNATURE_REMOVED",
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

    pub(crate) fn encryptor_outdated(keyring: &KeyringId, key_id: KeyId) -> Self {
        KeyringError::EncryptorOutdated(KeyVersionError {
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
            KeyringError::EncryptorOutdated(error) => write!(
                f,
                "The key version {} of the keyring {} is newer than the encryptor's record: take a new encryptor",
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
            KeyringError::PromotionTooEarly(error) => write!(
                f,
                "The key version {} of the keyring {} was staged less than the record TTL ago: \
                 promote it in {} ms",
                error.key_id.as_u32(),
                error.keyring,
                error.remaining.as_millis()
            ),
            KeyringError::ReservedKeyId(key_id) => write!(f, "The key id {} is reserved", key_id.as_u32()),
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
            KeyringError::UnknownKeyVersionState(name) => write!(
                f,
                "{name:?} is not the name of a key version state: the names are pending, active, \
                 decrypt_only, retired and destroyed"
            ),
            KeyringError::InvalidEncryptionMarker => f.write_str(
                "Not an encryption marker: a marker is the version byte 1 and a 4-byte re-encryption epoch",
            ),
            KeyringError::RecordUnsigned(keyring) => {
                write!(f, "The keyring record of {keyring} carries no signature")
            }
            KeyringError::RecordSignatureInvalid(error) => write!(
                f,
                "The signature of the keyring record of {} does not verify: {}",
                error.keyring,
                error.cause.code()
            ),
            KeyringError::RecordSignerMissing(keyring) => write!(
                f,
                "The keyring record of {keyring} is signed, and this administrative handle has no \
                 record signer to sign what it writes"
            ),
            KeyringError::RecordSignatureRemoved(keyring) => write!(
                f,
                "The keyring record of {keyring} lost the signature of the record this process \
                 holds"
            ),
        }
    }
}

impl Error for KeyringError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            KeyringError::KmsAead(error) => Some(error),
            KeyringError::RecordSignatureInvalid(error) => Some(&error.cause),
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
    /// A key id whose ordinal is zero, which names no version.
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
    /// A destroyed version that still holds an encrypted DEK or a KEK version.
    DestroyedWithMaterial(KeyId),
    /// A version that is not destroyed and holds no encrypted DEK.
    MissingMaterial(KeyId),
    /// A version whose ordinal is not above every earlier version of its purpose.
    OrdinalOrder(KeyId),
    /// An encrypted DEK that is not standard base64 of one byte or more.
    MalformedEncryptedDek(KeyId),
    /// A KEK version that is not 1 to 255 ASCII alphanumerics.
    MalformedKekVersion(KeyId),
    /// Every key id of the purpose is taken, so no version of it can be created.
    KeyIdsExhausted(Purpose),
    /// The re-encryption epoch is 0, the epoch of records encrypted before the keyring, or a
    /// version would become active past the last one, 2^32 - 1.
    ReencryptEpochOutOfRange,
    /// A `signature` member that is not the standard base64 of a detached signature,
    /// `[0x01][key id: u32 BE][signature]`.
    MalformedSignature,
    /// The version's re-encryption range does not fit its state: a pending version with one, an
    /// active version without one or with an end, or a decrypt-only or retired version without one;
    /// or it starts at epoch 0, ends where or before it starts, or lies past the record's
    /// re-encryption epoch.
    ReencryptRangeInvalid(KeyId),
    /// Two versions, the one named and an earlier one, hold the same encrypted DEK bytes: a key
    /// filed under a second id, such as a MAC key copied into a beacon version.
    DuplicateEncryptedDek(KeyId),
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
                    "the destroyed key version {key_id} holds an encrypted DEK or a KEK version",
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
            RecordInvalidReason::MalformedKekVersion(key_id) => {
                write!(
                    f,
                    "the KEK version of key version {key_id} does not parse",
                    key_id = key_id.as_u32()
                )
            }
            RecordInvalidReason::KeyIdsExhausted(purpose) => {
                write!(f, "every {purpose} key id is taken")
            }
            RecordInvalidReason::ReencryptEpochOutOfRange => {
                f.write_str("the re-encryption epoch is 0 or cannot count up any more")
            }
            RecordInvalidReason::MalformedSignature => {
                f.write_str("the signature member is not the base64 of a detached signature")
            }
            RecordInvalidReason::ReencryptRangeInvalid(key_id) => write!(
                f,
                "the re-encryption range of key version {key_id} does not fit its state or the re-encryption epoch",
                key_id = key_id.as_u32()
            ),
            RecordInvalidReason::DuplicateEncryptedDek(key_id) => write!(
                f,
                "key version {key_id} holds the encrypted DEK of an earlier version",
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

/// See [`KeyringError::RecordSignatureInvalid`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct RecordSignatureInvalidError {
    /// The keyring whose record was read or written.
    pub keyring: KeyringId,
    /// kms-aead's error: `SIGNATURE_INVALID`, or `SIGNING_KEY_UNKNOWN` for a signature under a
    /// key the registry does not hold, any signature under a registry with no key included.
    pub cause: KmsAeadError,
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
    /// The record's re-encryption epoch is below the held one, so that records encrypted under
    /// different active versions would carry the same
    /// [`EncryptionMarker`](crate::sweep::EncryptionMarker).
    ReencryptEpochReverted,
    /// The version's [`ReencryptRange`](crate::sweep::ReencryptRange) lost its start or its end,
    /// one of them moved, or one was set at or below the held re-encryption epoch, so that records
    /// the held record encrypted under the version could fall outside it.
    ReencryptRangeReverted(KeyId),
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
            RegressionRule::ReencryptEpochReverted => {
                f.write_str("the re-encryption epoch moved back")
            }
            RegressionRule::ReencryptRangeReverted(key_id) => write!(
                f,
                "the re-encryption range of key version {key_id} moved back",
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
/// [`KeyringError::EncryptorOutdated`] and [`KeyringError::ExportAlgorithmUnsupported`].
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

/// See [`KeyringError::PromotionTooEarly`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PromotionTooEarlyError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The pending version the promotion named.
    pub key_id: KeyId,
    /// How much longer the promotion waits, at most the record TTL.
    pub remaining: Duration,
}

/// See [`KeyringError::Interop`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct InteropError {
    /// The keyring.
    pub keyring: KeyringId,
    /// The reader whose requirement is broken: the field's, or the export's.
    pub interop: Interop,
    /// The first part of it that encrypting or the export would break.
    pub requirement: InteropRequirement,
}

/// What an [`Interop`] reader needs and encrypting or an export would not give it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum InteropRequirement {
    /// The active version of the purpose uses an algorithm the reader does not implement.
    Algorithm(KeyAlgorithm),
    /// The KEK is in a KMS the reader does not decrypt with, or has no key URI the reader
    /// addresses it by, such as an AWS key named without its ARN.
    Kek(KmsProvider),
    /// The reader does not read streamed values.
    Format,
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
            InteropRequirement::Format => f.write_str("the reader does not read streamed values"),
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
