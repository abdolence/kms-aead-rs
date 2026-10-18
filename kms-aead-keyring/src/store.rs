//! Where keyring records live: the [`KeyringStore`] trait, [`MemoryKeyringStore`], and the
//! store of each store feature.

use std::fmt::{Debug, Display, Formatter};
use std::future::Future;

use tokio::sync::mpsc;

use crate::errors::KeyringResult;
use crate::{KeyringId, KeyringRecord};

mod memory;
pub use memory::*;

#[cfg(feature = "firestore")]
mod firestore;
#[cfg(feature = "firestore")]
pub use self::firestore::*;

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "postgres")]
pub use postgres::*;

#[cfg(feature = "gcs")]
mod gcs;
#[cfg(feature = "gcs")]
pub use gcs::*;

/// A store of keyring records, one per keyring id, with a compare-and-swap on each.
///
/// The store's access control is what the record's integrity rests on: only the administrative
/// principal writes it, and the serving principal reads it. A process accepts a record that
/// moves a version backwards from the one it holds only at startup, when it has none.
///
/// # Implementing a store
///
/// - Write each method as an `async fn`. Its future must be `Send`, so that a keyring runs on a
///   multi-threaded runtime. A keyring is generic over its store: the trait has no `dyn` form.
/// - Read a stored document with [`KeyringRecord::from_json`] and write one with
///   [`KeyringRecord::to_json`], so that every store keeps the same document and every read
///   checks it.
/// - Wrap the client's errors in [`KeyringError::Store`](crate::KeyringError::Store) with the
///   client's error as the root cause. Never format the record or the request into an error,
///   and never log either: both carry wrapped data encryption keys.
pub trait KeyringStore: Send + Sync + 'static {
    /// The store's change marker for one record, such as a counter or an update time. Equal
    /// revisions mean an unchanged record. `Display` gives the `revision` span field.
    type Revision: Clone + Eq + Debug + Display + Send + Sync + 'static;

    /// The store, for the `store` span field and for errors.
    const KIND: StoreKind;

    /// The record of `id` and its revision, or `None` when the store holds none.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Store`](crate::KeyringError::Store) when the store fails, and
    /// [`KeyringError::RecordInvalid`](crate::KeyringError::RecordInvalid) when the stored
    /// document is no valid record of `id`.
    fn load(
        &self,
        id: &KeyringId,
    ) -> impl Future<Output = KeyringResult<Option<Stored<Self::Revision>>>> + Send;

    /// [`Revalidation::Unchanged`] when the stored revision is `known`, otherwise the current
    /// record, or [`Revalidation::Missing`] when there is none. A store with a conditional read
    /// sends no record when it is unchanged.
    ///
    /// # Errors
    ///
    /// As [`load`](Self::load).
    fn revalidate(
        &self,
        id: &KeyringId,
        known: &Self::Revision,
    ) -> impl Future<Output = KeyringResult<Revalidation<Self::Revision>>> + Send;

    /// Writes the whole `record` when the stored revision of its id is `expected`, and returns
    /// the new revision. `None` creates the record. [`Swap::Conflict`] when the stored revision
    /// is another, or when `None` finds a record, or `Some` none.
    ///
    /// # Errors
    ///
    /// As [`load`](Self::load).
    fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&Self::Revision>,
    ) -> impl Future<Output = KeyringResult<Swap<Self::Revision>>> + Send;

    /// Change signals for `id`, or `None` for a store that has no push. A signal carries no
    /// record: the keyring revalidates when it receives one.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Store`](crate::KeyringError::Store) when the listener cannot start.
    fn watch(
        &self,
        id: &KeyringId,
    ) -> impl Future<Output = KeyringResult<Option<KeyringWatch>>> + Send;
}

/// A record and the revision it was read or written at.
#[derive(Debug)]
pub struct Stored<R> {
    /// The record.
    pub record: KeyringRecord,
    /// Its revision in the store.
    pub revision: R,
}

/// What [`KeyringStore::revalidate`] found.
#[derive(Debug)]
pub enum Revalidation<R> {
    /// The stored revision is the known one.
    Unchanged,
    /// The record changed: here it is.
    Changed(Stored<R>),
    /// The store holds no record for the id.
    Missing,
}

/// What [`KeyringStore::compare_and_swap`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Swap<R> {
    /// The record was written at this revision.
    Written(R),
    /// The stored revision was not the expected one, and nothing was written.
    Conflict,
}

/// The change signals of one keyring's record, from a store's listener.
///
/// The listener holds the sender and stops when the watch is dropped: it ends once
/// [`Sender::closed`](mpsc::Sender::closed) resolves or a send fails.
#[derive(Debug)]
pub struct KeyringWatch {
    pub(crate) events: mpsc::Receiver<WatchEvent>,
}

impl KeyringWatch {
    /// The signals `events` receives.
    pub fn new(events: mpsc::Receiver<WatchEvent>) -> Self {
        Self { events }
    }

    /// The next signal, or `None` once the listener has stopped.
    pub async fn next(&mut self) -> Option<WatchEvent> {
        self.events.recv().await
    }
}

/// A signal from a store's listener.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WatchEvent {
    /// The record may have changed.
    Changed,
    /// The listener lost its connection; changes are not signalled until it reconnects.
    Disconnected,
    /// The listener is connected again, and changes made while it was not may have been missed.
    Reconnected,
}

/// A kind of keyring store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreKind {
    /// [`MemoryKeyringStore`].
    Memory,
    /// `FirestoreKeyringStore`, of the `firestore` feature.
    Firestore,
    /// `PostgresKeyringStore`, of the `postgres` feature.
    Postgres,
    /// `GcsKeyringStore`, of the `gcs` feature.
    Gcs,
    /// An application's own store, by the name it gives.
    Other(&'static str),
}

/// `memory`, `firestore`, `postgres`, `gcs`, or the application's name: the value of the `store`
/// span field.
impl Display for StoreKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreKind::Memory => "memory",
            StoreKind::Firestore => "firestore",
            StoreKind::Postgres => "postgres",
            StoreKind::Gcs => "gcs",
            StoreKind::Other(name) => name,
        })
    }
}

/// An operation of [`KeyringStore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreOperation {
    /// [`KeyringStore::load`].
    Load,
    /// [`KeyringStore::revalidate`].
    Revalidate,
    /// [`KeyringStore::compare_and_swap`].
    CompareAndSwap,
    /// [`KeyringStore::watch`].
    Watch,
}

/// `load`, `revalidate`, `compare and swap`, `watch`.
impl Display for StoreOperation {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            StoreOperation::Load => "load",
            StoreOperation::Revalidate => "revalidate",
            StoreOperation::CompareAndSwap => "compare and swap",
            StoreOperation::Watch => "watch",
        })
    }
}
