//! The associated data (AAD) of field values: by default the logical place of a value in the
//! application's model, `<kind>/<id>/<field>`, never its physical location, so that a value
//! moves between data stores without being encrypted again.

use std::borrow::Cow;
use std::fmt::{Debug, Display, Formatter};

use kms_aead::BeaconBits;

use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult};

/// The bytes an AAD part may hold: 1 to 255 bytes of UTF-8 without `/`, which separates the
/// parts, and without NUL or another ASCII control character. A loop, since slice methods are
/// not `const fn`.
const fn aad_part_rule(part: &str) -> Result<(), IdentifierRule> {
    let bytes = part.as_bytes();
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(IdentifierRule::Length);
    }
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'/' || bytes[index].is_ascii_control() {
            return Err(IdentifierRule::Character);
        }
        index += 1;
    }
    Ok(())
}

fn check_aad_part(part: &str, identifier: Identifier) -> KeyringResult<()> {
    aad_part_rule(part).map_err(|rule| KeyringError::invalid_identifier(identifier, rule))
}

/// The kind of entity a field belongs to, such as `user`: the first part of a default AAD.
///
/// 1 to 255 bytes of UTF-8 without `/`, NUL or another ASCII control character.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityKind(Cow<'static, str>);

impl EntityKind {
    /// `kind`, checked at compile time when it initializes a constant.
    ///
    /// # Panics
    ///
    /// On a `kind` that breaks the rule, when called at run time.
    pub const fn from_static(kind: &'static str) -> Self {
        match aad_part_rule(kind) {
            Ok(()) => Self(Cow::Borrowed(kind)),
            Err(rule) => panic!("{}", rule.message()),
        }
    }
}

impl TryFrom<String> for EntityKind {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `kind` breaks.
    fn try_from(kind: String) -> KeyringResult<Self> {
        check_aad_part(&kind, Identifier::EntityKind)?;
        Ok(Self(Cow::Owned(kind)))
    }
}

impl TryFrom<&str> for EntityKind {
    type Error = KeyringError;

    /// # Errors
    ///
    /// As `TryFrom<String>`.
    fn try_from(kind: &str) -> KeyringResult<Self> {
        Self::try_from(kind.to_string())
    }
}

impl Display for EntityKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The id of one entity, such as a user id: the middle part of a default AAD, which binds a
/// value to its row. An id that holds `/` is encoded by the application first, with
/// percent-encoding for example, or the field uses [`FieldAad::custom`].
///
/// 1 to 255 bytes of UTF-8 without `/`, NUL or another ASCII control character. It can be
/// personal data, so no span, event or error of the crate carries it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct EntityId(String);

impl TryFrom<String> for EntityId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `id` breaks, never the id.
    fn try_from(id: String) -> KeyringResult<Self> {
        check_aad_part(&id, Identifier::EntityId)?;
        Ok(Self(id))
    }
}

impl TryFrom<&str> for EntityId {
    type Error = KeyringError;

    /// # Errors
    ///
    /// As `TryFrom<String>`.
    fn try_from(id: &str) -> KeyringResult<Self> {
        Self::try_from(id.to_string())
    }
}

impl Display for EntityId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The name of an encrypted field, such as `email`: the last part of a default AAD.
///
/// 1 to 255 bytes of UTF-8 without `/`, NUL or another ASCII control character.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FieldName(Cow<'static, str>);

impl FieldName {
    /// `field`, checked at compile time when it initializes a constant.
    ///
    /// # Panics
    ///
    /// On a `field` that breaks the rule, when called at run time.
    pub const fn from_static(field: &'static str) -> Self {
        match aad_part_rule(field) {
            Ok(()) => Self(Cow::Borrowed(field)),
            Err(rule) => panic!("{}", rule.message()),
        }
    }
}

impl TryFrom<String> for FieldName {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `field` breaks.
    fn try_from(field: String) -> KeyringResult<Self> {
        check_aad_part(&field, Identifier::FieldName)?;
        Ok(Self(Cow::Owned(field)))
    }
}

impl TryFrom<&str> for FieldName {
    type Error = KeyringError;

    /// # Errors
    ///
    /// As `TryFrom<String>`.
    fn try_from(field: &str) -> KeyringResult<Self> {
        Self::try_from(field.to_string())
    }
}

impl Display for FieldName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which reader other than this crate decrypts a field's values, and so what
/// [`Keyring`](crate::Keyring) checks before it seals one. A value that was written always
/// decrypts: only sealing checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Interop {
    /// No other reader: any algorithm, any AAD and any KEK.
    None,
    /// BigQuery decrypts the field through `KEYS.KEYSET_CHAIN`, which implements AES-256-GCM
    /// and AES-SIV only and unwraps with Cloud KMS only: sealing needs an AES-256-GCM version
    /// for a randomized value, an AES-SIV version for a deterministic one, and a Cloud KMS KEK.
    /// The AAD is the default one, which SQL rebuilds.
    BigQuery,
}

/// An encrypted field of one kind of entity: the source of the default AAD of its values, of
/// the interop requirement that AAD carries, and of the context and bits of its beacons.
#[derive(Debug, Clone)]
pub struct FieldSpec {
    kind: EntityKind,
    field: FieldName,
    interop: Interop,
    beacon_bits: BeaconBits,
}

impl FieldSpec {
    /// The field `field` of the entities of `kind`, with [`Interop::None`] and beacons of
    /// [`BeaconBits::DEFAULT`].
    pub const fn new(kind: EntityKind, field: FieldName) -> Self {
        Self {
            kind,
            field,
            interop: Interop::None,
            beacon_bits: BeaconBits::DEFAULT,
        }
    }

    /// The same field, read by `interop` as well.
    pub const fn with_interop(mut self, interop: Interop) -> Self {
        self.interop = interop;
        self
    }

    /// The same field, with beacons that keep `bits` bits of their HMAC. A field's beacons and
    /// the probes that look them up use the same bits.
    pub const fn with_beacon_bits(mut self, bits: BeaconBits) -> Self {
        self.beacon_bits = bits;
        self
    }

    /// The bits the field's beacons keep.
    pub(crate) fn beacon_bits(&self) -> BeaconBits {
        self.beacon_bits
    }

    /// `<kind>/<field>` as UTF-8: the field, without an entity id, as its deterministic AAD and
    /// its beacon context name it.
    pub(crate) fn context(&self) -> Vec<u8> {
        [&*self.kind.0, &*self.field.0].join("/").into_bytes()
    }

    /// The AAD of the field's value in the entity `id`: `<kind>/<id>/<field>` as UTF-8, for
    /// example `user/42/email`, which SQL rebuilds as `CONCAT('user/', id, '/email')`.
    pub fn aad(&self, id: &EntityId) -> FieldAad {
        FieldAad {
            bytes: [&*self.kind.0, id.0.as_str(), &*self.field.0]
                .join("/")
                .into_bytes(),
            interop: self.interop,
        }
    }

    /// The AAD of the field's deterministic values: `<kind>/<field>`, for example `user/email`.
    /// It holds no entity id, so that equal plaintexts in different rows give equal values.
    pub fn deterministic_aad(&self) -> DeterministicAad {
        DeterministicAad {
            bytes: self.context(),
            interop: self.interop,
        }
    }
}

/// The associated data of one randomized value. A value opens only with the AAD it was
/// sealed with.
///
/// `Debug` shows nothing of the bytes, not even their length: the default AAD holds an entity
/// id.
pub struct FieldAad {
    pub(crate) bytes: Vec<u8>,
    pub(crate) interop: Interop,
}

impl FieldAad {
    /// Any bytes, with no structure: as free as the AAD of kms-aead's `AeadCipher`. SQL cannot
    /// rebuild it, so it carries [`Interop::None`] and a field BigQuery reads cannot use it.
    pub fn custom(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            interop: Interop::None,
        }
    }

    /// Appends `/` and `context`, any bytes; a value sealed with a context opens only with the
    /// same context. `context` may itself hold `/`, so two contexts can produce the same AAD
    /// from different splits: the caller owns both sides of its AAD and keeps them apart.
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.bytes.push(b'/');
        self.bytes.extend_from_slice(context);
        self
    }

    /// The bytes, for a reader that rebuilds the AAD elsewhere, such as in a SQL query.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Debug for FieldAad {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FieldAad").finish_non_exhaustive()
    }
}

/// The associated data of one deterministic value, `<kind>/<field>`. It reaches AES-SIV as one
/// associated-data item, as Tink and BigQuery compute it.
///
/// There is no constructor from arbitrary bytes: a deterministic value exists to be queried,
/// and the query rebuilds its AAD. A value with this AAD opens in any row of the same kind and
/// field, so a deterministic field never decides identity or authorization on its own.
///
/// `Debug` shows nothing of the bytes.
pub struct DeterministicAad {
    pub(crate) bytes: Vec<u8>,
    #[cfg_attr(
        not(feature = "deterministic"),
        expect(dead_code, reason = "only the deterministic calls seal")
    )]
    pub(crate) interop: Interop,
}

impl DeterministicAad {
    /// Appends `/` and `context`. A context that differs per row defeats equality across rows,
    /// so it is a constant, such as a tenant.
    pub fn with_context(mut self, context: &[u8]) -> Self {
        self.bytes.push(b'/');
        self.bytes.extend_from_slice(context);
        self
    }

    /// The bytes, for a reader that rebuilds the AAD elsewhere, such as the literal of a
    /// BigQuery `DETERMINISTIC_DECRYPT_STRING`.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl Debug for DeterministicAad {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeterministicAad").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_ID: &str = "4711-personal";

    fn email() -> KeyringResult<FieldSpec> {
        Ok(FieldSpec::new(
            EntityKind::try_from("user")?,
            FieldName::try_from("email")?,
        ))
    }

    #[test]
    fn the_default_aad_is_kind_id_field() -> KeyringResult<()> {
        let aad = email()?.aad(&EntityId::try_from("42")?);
        assert_eq!(aad.as_bytes(), b"user/42/email");
        assert_eq!(aad.with_context(b"eu/1").as_bytes(), b"user/42/email/eu/1");
        Ok(())
    }

    #[test]
    fn the_deterministic_aad_leaves_the_entity_id_out() -> KeyringResult<()> {
        let aad = email()?.deterministic_aad();
        assert_eq!(aad.as_bytes(), b"user/email");
        assert_eq!(
            aad.with_context(b"tenant-7").as_bytes(),
            b"user/email/tenant-7"
        );
        Ok(())
    }

    #[test]
    fn aad_parts_refuse_separators_and_control_characters() {
        for part in ["user/admin", "a\0b", "line\nbreak", "\u{7f}"] {
            assert!(matches!(
                EntityId::try_from(part),
                Err(KeyringError::InvalidIdentifier(error))
                    if error.identifier == Identifier::EntityId
                        && error.rule == IdentifierRule::Character
            ));
        }
    }

    #[test]
    fn aad_parts_are_one_to_255_bytes() -> KeyringResult<()> {
        EntityKind::try_from("é".repeat(127))?;
        for part in [String::new(), "x".repeat(256)] {
            assert!(matches!(
                FieldName::try_from(part),
                Err(KeyringError::InvalidIdentifier(error))
                    if error.identifier == Identifier::FieldName
                        && error.rule == IdentifierRule::Length
            ));
        }
        Ok(())
    }

    #[test]
    #[should_panic]
    fn a_static_aad_part_is_checked_like_any_other() {
        FieldName::from_static("contact/email");
    }

    #[test]
    fn field_aad_debug_carries_no_aad_bytes() -> KeyringResult<()> {
        let spec = email()?;
        let aad = spec.aad(&EntityId::try_from(USER_ID)?);
        let deterministic = spec.deterministic_aad().with_context(USER_ID.as_bytes());
        for debug in [format!("{aad:?}"), format!("{deterministic:?}")] {
            assert!(!debug.contains(USER_ID), "{debug}");
            assert!(!debug.contains("117, 115, 101, 114"), "{debug}");
            assert!(
                !debug.contains(&b"user/4711-personal/email".len().to_string()),
                "{debug}"
            );
        }
        Ok(())
    }
}
