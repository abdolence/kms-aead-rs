/// The id of the key a typed field value or a beacon is sealed under, a `u32` with no reserved
/// value.
///
/// [`Encrypted<T, Randomized>`](crate::Encrypted), `Encrypted<T, Deterministic>` and
/// [`Beacon`](crate::Beacon) bytes start with `[0x01][key id: u32 BE]`, and the four bytes after
/// the version byte are this id: the one that picks the key that opens the value, and the id of
/// that key in an exported [`TinkKeyset`](crate::formats::TinkKeyset), so that Tink and BigQuery
/// pick the same key. The prefix is not authenticated: a value whose key id is changed still opens
/// only under the key it was sealed with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KeyId(u32);

impl KeyId {
    /// `key_id` as a key id: every `u32` is one.
    pub const fn new(key_id: u32) -> Self {
        Self(key_id)
    }

    /// The id as the prefix and a keyset store it.
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}
