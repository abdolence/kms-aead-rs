//! Re-encrypting stored values under the active key versions: the [`EncryptionMarker`] a record
//! carries beside its encrypted fields, and [`reencrypt_records`] and [`reencrypt_records_batched`], which drive an
//! application's re-encryption over the records a query of that marker finds, one record or one
//! batch at a time.
//!
//! A sweep is a job the application runs, a CLI or a Kubernetes Job, never a task inside the
//! library: only the application knows its tables, its queries and its write rules. It re-encrypts
//! after a rotation, to retire the old version, and migrates envelope values to keyring values. It
//! runs on a schedule, and again until its [`SweepReport`] shows nothing scanned; retiring the old
//! version is a separate step of the administrative job.
//!
//! # The encryption marker
//!
//! A keyring record counts a re-encryption epoch, which moves on by one with every administrative
//! write that makes a version active: the creation of the keyring, at epoch 1,
//! `KeyringAdmin::promote`, and `KeyringAdmin::mark_compromised` when it puts a new version in
//! place of the active one.
//! [`KeyringRecord::encryption_marker`](crate::KeyringRecord::encryption_marker) returns it as a
//! [`EncryptionMarker`], 5 bytes that order as the epochs do.
//!
//! A write that touches any encrypted field of a record encrypts all of them again through one
//! [`Encryptor`](crate::Encryptor), and stores the marker of the encryptor's record beside them, in
//! the same write. The marker then names the epoch of the versions every field is under. The
//! records a sweep still has to visit are those whose marker is below the current one:
//! `encryption_marker < $1` on one indexed field, in Firestore, PostgreSQL and BigQuery alike, and
//! `<` on a [`EncryptionMarker`] in Rust.
//!
//! The query also matches a record with nothing to re-encrypt: after a rotation of a purpose the
//! record holds no value of, such as a beacon rotation for a record without beacons, its marker is
//! below the current one all the same. [`Encryptor::reencrypt`](crate::Encryptor::reencrypt)
//! returns `None` for a value under the active version without decrypting it or calling the KMS, so
//! the re-encryption writes the encryptor's marker alone, conditional on the record as it read it,
//! and returns [`ReencryptOutcome::Skipped`]. Such a record matches once.
//!
//! Each process stamps the epoch of the record it caches. A process that has not refreshed its
//! record since a promotion encrypts under the previous version and stamps the previous epoch, so
//! its writes stay below the current marker and the next sweep visits them. Once a sweep reports
//! `failed == 0`, and the query returns nothing after every process has had time to refresh its
//! record, the administrative job can retire the old version with `KeyringAdmin::retire`.
//!
//! An encryptor never encrypts a value back under an older version. A value under a version that is
//! pending in the encryptor's record, or missing from it, was encrypted under a newer record:
//! [`Encryptor::reencrypt`](crate::Encryptor::reencrypt) fails with
//! [`KeyringError::EncryptorOutdated`], and so does
//! [`Encryptor::is_current`](crate::Encryptor::is_current) for a beacon. Inside a sweep, this
//! happens when a process with a newer record rewrote the record after the query returned it.
//! [`reencrypt_records`] counts the record as failed, and the next run's query no longer returns it: the process
//! that encrypted it stamped a marker at or past the activation of the newer version. A value under
//! a version the store's record itself holds as pending, such as a value from another keyring whose
//! key id is pending here, fails in every run instead, as [`KeyringError::EncryptorOutdated`]
//! states.
//!
//! The re-encryption reads every field with
//! [`decrypt_with_trust`](crate::Keyring::decrypt_with_trust), as
//! [`Encryptor::reencrypt`](crate::Encryptor::reencrypt) does, and reports in
//! [`ReencryptOutcome::Reencrypted`] whether the [`KeyTrust`](crate::KeyTrust) of any of them is
//! compromised; for a record of one field, `ReencryptOutcome::from(&reencrypted)` of the `Option`
//! that `reencrypt` returns gives the outcome. A value read under a compromised version is untrusted data, since whoever holds the
//! leaked key can have forged it, and re-encrypting makes it read as trusted everywhere. The
//! application decides per record before it re-encrypts, with a quarantine field beside the marker,
//! a comparison against a backup taken before the compromise, or acceptance;
//! [`SweepReport::reencrypted_from_compromised`] counts the records that went through that
//! decision.
//!
//! # The records under a version
//!
//! [`KeyVersion::reencrypt_range`](crate::KeyVersion::reencrypt_range) returns the
//! [`ReencryptRange`] of a version: the markers from the epoch at which it became active up to the
//! first epoch at which no process encrypts under it, open-ended while one still may. The records
//! that can hold a value under the version are those whose marker lies in it:
//! `encryption_marker >= $1 AND encryption_marker < $2`, or `encryption_marker >= $1` for an open
//! range, on the same indexed field, and [`ReencryptRange::contains`] in Rust.
//!
//! - After `KeyringAdmin::mark_compromised`, the range of the compromised version finds every
//!   record to re-encrypt and decide on, those of processes that had not seen the flag yet
//!   included: they encrypt under the version and stamp an epoch below the range's end. The query
//!   runs again once every process has had time to refresh its record, for the writes of the last
//!   of them. A version flagged compromised after it stopped being active moves no epoch, and keeps
//!   the range it had.
//! - Before `KeyringAdmin::retire` or `KeyringAdmin::destroy`, the same query returning nothing
//!   shows that no record holds a value under the version.
//!
//! One epoch counts the activations of every purpose of the keyring, so a range can also match a
//! record with no field of the version's purpose, such as a record without beacons in the range of
//! a beacon version. Its re-encryption finds every value current and writes the marker alone. No
//! range holds [`EncryptionMarker::ENVELOPE`], since every range starts at epoch 1 or later.
//!
//! # Migration from envelope values
//!
//! Values that kms-aead's [`KmsAeadEnvelope`](kms_aead::KmsAeadEnvelope) wrote, per call or
//! store-less, move to keyring values in five steps:
//!
//! 1. the model gains `encryption_marker: EncryptionMarker`, and a record without one reads as
//!    [`EncryptionMarker::ENVELOPE`], epoch 0: through `#[serde(default)]`, or a column default of
//!    its bytes, `01 00 00 00 00`;
//! 2. the field keeps its stored bytes, whose layout the marker names: envelope values under
//!    `ENVELOPE`, keyring values under any other marker, since the epochs of a keyring start at 1;
//! 3. reads go through the marker: [`Keyring::decrypt_envelope_for_migration`](crate::Keyring::decrypt_envelope_for_migration)
//!    decrypts an envelope value, with the AAD the application used for it, and
//!    [`Keyring::decrypt`](crate::Keyring::decrypt) a keyring value;
//! 4. the sweep's query, `encryption_marker < $1`, finds every envelope record too, and the
//!    re-encryption encrypts it as keyring values through an encryptor and writes the marker of the
//!    encryptor's record;
//! 5. once no record holds `ENVELOPE`, the read path drops its envelope branch.
//!
//! A query never matches a record whose marker is missing: an inequality filter of Firestore
//! skips a document without the field, and `<` in SQL is never true on `NULL`. A PostgreSQL
//! column added with a default gives every existing row the default. Firestore documents and
//! BigQuery rows written before the marker get `ENVELOPE` written into them first, or the
//! migration scans them once instead of querying.
//!
//! Values written by kms-aead 0.29 or earlier are in layouts this call does not read: they are
//! upgraded in place first, with kms-aead's `legacy-formats` feature and
//! `KmsAeadEnvelope::upgrade_legacy_value`, which takes the value's AAD. The layout of a value
//! is always the marker's, never guessed from its bytes.
//!
//! # Cancellation
//!
//! A job runner may cancel [`reencrypt_records`] and start it again over the same marker query. A sweep keeps
//! no state of its own beyond the counts of its report: a cancelled run drops the re-encryptions in
//! flight, at most `concurrency` of them, and its counts, and its span closes without them.
//!
//! It leaves no half-written record, provided the re-encryption writes a record's fields and its
//! [`EncryptionMarker`] in one conditional write: a cancelled write either committed, and the marker
//! moved, or did not, and the record is as it was. The keyring calls of a re-encryption, those of
//! its encryptor and `decrypt`, cache keys and write nothing to the store. The marker is the
//! sweep's progress: the records re-encrypted before the cancellation no longer match the query,
//! and the next run visits the rest.
//!
//! [`reencrypt_records_batched`] follows the same rules with batches: a cancelled run drops at most
//! `concurrency` batches in flight. A batch's write need not be atomic, as a Firestore
//! `BatchWrite` is not, provided each record's fields and marker go in one conditional write
//! within it: a cancellation then leaves every record of the batch re-encrypted or as it was.

use std::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;
use std::pin::pin;

use futures_util::future::OptionFuture;
use futures_util::{Stream, StreamExt};
use kms_aead::formats::Format;
use rsb_derive::Builder;
use tracing::Instrument;

use crate::errors::{KeyringError, KeyringResult};
use crate::{spans, KeyringId, Reencrypted};

#[cfg(feature = "postgres")]
mod postgres;
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// The re-encryption epoch of a keyring at the time a record's encrypted fields were encrypted,
/// stored beside those fields: the marker version `0x01`, then the epoch as a big-endian `u32`, 5
/// bytes in all.
///
/// Markers compare in the order of their epochs, and so do their bytes, in every store that
/// compares bytes as unsigned and from the first: a Firestore `bytes` value, a PostgreSQL `BYTEA`
/// and a BigQuery `BYTES`. The records a sweep still has to visit are then one range of one indexed
/// field, the markers below
/// [`KeyringRecord::encryption_marker`](crate::KeyringRecord::encryption_marker), and so are the
/// records that can hold a value under one version, the markers of its [`ReencryptRange`].
///
/// Epoch 0 is [`ENVELOPE`](Self::ENVELOPE), the marker of a record of envelope values, below the
/// marker of every keyring, whose epochs start at 1.
///
/// Stored bytes become a marker only through `TryFrom<Vec<u8>>`, which checks the version and
/// the length. `Debug` and `Display` show the epoch. serde serialises a marker as
/// bytes and deserialises it through `TryFrom<Vec<u8>>`, and the `postgres` and `sqlx` features
/// store it as `BYTEA` and read it through `TryFrom<Vec<u8>>` too.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EncryptionMarker([u8; 5]);

impl EncryptionMarker {
    /// The marker of a record whose fields are envelope values, written before the record had a
    /// marker: epoch 0, the bytes `01 00 00 00 00`.
    pub const ENVELOPE: Self = Self::of_epoch(0);

    /// The first byte of every marker, the version of its layout.
    const VERSION: u8 = 0x01;

    /// The marker of `epoch`.
    pub(crate) const fn of_epoch(epoch: u32) -> Self {
        let [first, second, third, fourth] = epoch.to_be_bytes();
        Self([Self::VERSION, first, second, third, fourth])
    }

    /// The epoch this marker names.
    pub(crate) fn epoch(self) -> u32 {
        let [_, epoch @ ..] = self.0;
        u32::from_be_bytes(epoch)
    }

    /// The marker of the epoch after this one, or `None` past 2^32 - 1.
    #[cfg(feature = "admin")]
    pub(crate) fn next(self) -> Option<Self> {
        self.epoch().checked_add(1).map(Self::of_epoch)
    }

    /// The bytes to store.
    pub fn value(&self) -> &[u8] {
        &self.0
    }

    /// The bytes to store, taking the marker.
    pub fn into_value(self) -> Vec<u8> {
        self.0.to_vec()
    }
}

/// Reads stored bytes as a marker.
///
/// # Errors
///
/// [`KeyringError::InvalidEncryptionMarker`] for bytes that are not 5 long or do not start with the
/// version `0x01`.
impl TryFrom<Vec<u8>> for EncryptionMarker {
    type Error = KeyringError;

    fn try_from(bytes: Vec<u8>) -> KeyringResult<Self> {
        match <[u8; 5]>::try_from(bytes) {
            Ok(bytes @ [Self::VERSION, ..]) => Ok(Self(bytes)),
            _ => Err(KeyringError::InvalidEncryptionMarker),
        }
    }
}

/// [`EncryptionMarker::ENVELOPE`], so that `#[serde(default)]` reads a record stored before it had a
/// marker as envelope values.
impl Default for EncryptionMarker {
    fn default() -> Self {
        Self::ENVELOPE
    }
}

/// The epoch, such as `EncryptionMarker { epoch: 3 }`.
impl Debug for EncryptionMarker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionMarker")
            .field("epoch", &self.epoch())
            .finish()
    }
}

/// The epoch, such as `3`.
impl Display for EncryptionMarker {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(&self.epoch(), f)
    }
}

/// The markers of the records that can hold values under one key version, from
/// [`KeyVersion::reencrypt_range`](crate::KeyVersion::reencrypt_range): from
/// [`start`](Self::start), the epoch at which the version became active, up to and without
/// [`end`](Self::end), the first epoch at which no process encrypts under it any more, or
/// open-ended while it may still be encrypted under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReencryptRange {
    start: EncryptionMarker,
    end: Option<EncryptionMarker>,
}

impl ReencryptRange {
    pub(crate) fn new(start: EncryptionMarker, end: Option<EncryptionMarker>) -> Self {
        Self { start, end }
    }

    /// The marker of the epoch at which the version became active: the lowest marker of a
    /// record that holds a value under it.
    pub fn start(&self) -> EncryptionMarker {
        self.start
    }

    /// The marker of the first epoch at which no process encrypts under the version, the epoch of
    /// the first write after it stopped being active that moved the epoch on, or `None` while
    /// no such write has happened: the active version, and a compromised one that nothing
    /// replaced yet.
    pub fn end(&self) -> Option<EncryptionMarker> {
        self.end
    }

    /// Whether a record stamped with `marker` can hold a value under the version.
    pub fn contains(&self, marker: EncryptionMarker) -> bool {
        self.start <= marker && self.end.is_none_or(|end| marker < end)
    }
}

/// What the re-encryption of one candidate did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReencryptOutcome {
    /// The record's fields were encrypted again under the active versions.
    Reencrypted {
        /// Whether any field the re-encryption read came from a compromised version, with
        /// [`KeyTrust::Compromised`](crate::KeyTrust::Compromised): `false` for a record of
        /// envelope values, which name no key version.
        from_compromised: bool,
    },
    /// No field of the record needed a re-encryption by the time it was read, and at most its
    /// marker was written, or a concurrent write won.
    Skipped,
}

/// The outcome of the `Option` that `Encryptor::reencrypt` returns: [`Reencrypted::outcome`] for a
/// value that was encrypted again, [`ReencryptOutcome::Skipped`] for one that was current.
impl<T, F: Format> From<&Option<Reencrypted<T, F>>> for ReencryptOutcome {
    fn from(reencrypted: &Option<Reencrypted<T, F>>) -> Self {
        reencrypted
            .as_ref()
            .map_or(ReencryptOutcome::Skipped, Reencrypted::outcome)
    }
}

/// The counts of a sweep. Every candidate is counted once in `scanned` and once in `reencrypted`,
/// `skipped` or `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct SweepReport {
    /// The candidates visited, those the stream returned as an error included.
    pub scanned: u64,
    /// The records re-encrypted.
    pub reencrypted: u64,
    /// The records among `reencrypted` with a field read from a compromised version.
    pub reencrypted_from_compromised: u64,
    /// The records the re-encryption skipped.
    pub skipped: u64,
    /// The candidates the stream returned as an error, and the records whose re-encryption returned
    /// an error or no outcome.
    pub failed: u64,
}

impl SweepReport {
    /// Counts the outcome of a candidate already counted in `scanned`, and logs a failure.
    fn count_outcome<E: Display>(
        &mut self,
        keyring_id: &KeyringId,
        candidate: &impl Display,
        outcome: Result<ReencryptOutcome, E>,
    ) {
        match outcome {
            Ok(ReencryptOutcome::Reencrypted { from_compromised }) => {
                self.reencrypted += 1;
                if from_compromised {
                    self.reencrypted_from_compromised += 1;
                }
            }
            Ok(ReencryptOutcome::Skipped) => self.skipped += 1,
            Err(error) => {
                self.failed += 1;
                spans::sweep_failed(keyring_id, candidate, &error);
            }
        }
    }

    /// Counts a candidate the stream returned as an error, and logs it.
    fn count_unread<E: Display>(&mut self, keyring_id: &KeyringId, error: &E) {
        self.scanned += 1;
        self.failed += 1;
        spans::sweep_candidate_failed(keyring_id, error);
    }
}

/// How [`reencrypt_records_batched`] cuts the candidates into batches, and how many batches it re-encrypts at
/// once.
#[derive(Debug, Clone, Builder)]
#[non_exhaustive]
pub struct BatchedSweepOptions {
    /// The candidates of a batch, all but the last: [`DEFAULT_BATCH_SIZE`](Self::DEFAULT_BATCH_SIZE)
    /// by default. A store's limit of writes per request bounds it, such as Firestore's 500 writes
    /// per `BatchWrite`.
    #[default = "Self::DEFAULT_BATCH_SIZE"]
    pub batch_size: NonZeroUsize,
    /// The batches in flight at once: [`DEFAULT_CONCURRENCY`](Self::DEFAULT_CONCURRENCY) by
    /// default.
    #[default = "Self::DEFAULT_CONCURRENCY"]
    pub concurrency: NonZeroUsize,
}

impl BatchedSweepOptions {
    /// The default [`batch_size`](Self::batch_size): 100 candidates.
    pub const DEFAULT_BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(100).expect("100 is not zero");
    /// The default [`concurrency`](Self::concurrency): 4 batches.
    pub const DEFAULT_CONCURRENCY: NonZeroUsize = NonZeroUsize::new(4).expect("4 is not zero");
}

/// Runs `reencrypt` over every candidate of `candidates`, with at most `concurrency` re-encryptions
/// in flight, and counts what they did. A candidate is whatever the application identifies a record
/// by, such as its id or its key columns, and the stream returns each as a `Result`, so that the
/// query that finds them can fail without ending the sweep in silence.
///
/// The stream and the re-encryption return the application's own error type `E`, so that an error
/// of its table is returned as it is. The keyring's calls inside the re-encryption, such as
/// [`Encryptor::reencrypt`](crate::Encryptor::reencrypt), return a [`KeyringError`], which `?`
/// converts into `E` through a `From` impl the application gives its error; `E` is `KeyringError`
/// itself for a re-encryption that has no other errors.
///
/// An error does not stop the sweep. A candidate the stream returned as an error is counted in
/// `scanned` and `failed`, and logged at `WARN` with the error's `Display`; a stream whose query
/// cannot go on returns its error and ends. A re-encryption that fails is counted in `failed` and
/// logged at `WARN` with the candidate's `Display` and the error's `Display`. The report keeps
/// counts only; an application that wants the errors themselves records them inside `reencrypt`.
/// Both texts are the application's own and go to the log as they are, so they name the record
/// and the failure and carry no value, secret or personal data. The sweep opens a `Keyring sweep`
/// span for `keyring_id`, which carries the counts once it ends.
///
/// [`reencrypt_records_batched`] drives a re-encryption that writes many records at once.
pub async fn reencrypt_records<T, C, F, Fut, E>(
    keyring_id: &KeyringId,
    candidates: C,
    concurrency: NonZeroUsize,
    mut reencrypt: F,
) -> SweepReport
where
    T: Display,
    C: Stream<Item = Result<T, E>>,
    F: FnMut(T) -> Fut,
    Fut: Future<Output = Result<ReencryptOutcome, E>>,
    E: Display,
{
    let span = spans::sweep(keyring_id);
    let report = async {
        let mut report = SweepReport::default();
        let mut outcomes = pin!(candidates
            .map(|candidate| {
                // Formatted before `reencrypt` takes the candidate, for the log line of a failure.
                let reencrypting =
                    candidate.map(|candidate| (candidate.to_string(), reencrypt(candidate)));
                async move {
                    let (candidate, outcome) = reencrypting?;
                    Ok::<_, E>((candidate, outcome.await))
                }
            })
            .buffer_unordered(concurrency.get()));
        while let Some(reencrypted) = outcomes.next().await {
            match reencrypted {
                Ok((candidate, outcome)) => {
                    report.scanned += 1;
                    report.count_outcome(keyring_id, &candidate, outcome);
                }
                Err(error) => report.count_unread(keyring_id, &error),
            }
        }
        report
    }
    .instrument(span.clone())
    .await;
    spans::record_sweep(&span, &report);
    report
}

/// Runs `reencrypt_batch` over the candidates of `candidates` cut into batches of
/// [`batch_size`](BatchedSweepOptions::batch_size), with at most
/// [`concurrency`](BatchedSweepOptions::concurrency) batches in flight, and counts what they did:
/// [`reencrypt_records`] for a store that writes many records in one request, such as a Firestore `BatchWrite`
/// or one PostgreSQL `UPDATE` over arrays. The last batch holds the candidates left over, fewer
/// than `batch_size` when they do not fill it.
///
/// A candidate the stream returned as an error takes its place in a batch, so that batch reaches
/// `reencrypt_batch` one candidate short; it is counted and logged as in [`reencrypt_records`], and a batch of
/// errors alone never reaches `reencrypt_batch`.
///
/// `reencrypt_batch` returns one outcome per candidate it was given, each beside its candidate, in
/// any order, or an error for the whole batch, which counts every candidate of the batch in
/// `failed` and logs one `WARN` with the error's `Display` and the size of the batch. The sweep
/// counts a batch by the candidates it was given: an outcome for a candidate outside the batch,
/// or a second one for the same candidate, can only take the place of one the batch left out, and
/// never adds to `scanned`. A batch that returns fewer outcomes than it was given counts the
/// difference in `failed`, since the sweep cannot tell which candidates they were. Either way the
/// sweep logs one `WARN` with both counts.
///
/// A failed outcome is counted and logged as in [`reencrypt_records`], and the sweep goes on. One
/// [`Encryptor`](crate::Encryptor) re-encrypts a whole batch and stamps its marker on every record
/// of the batch's write, so every record lies in the range of each version it is under.
pub async fn reencrypt_records_batched<T, C, F, Fut, E>(
    keyring_id: &KeyringId,
    candidates: C,
    options: BatchedSweepOptions,
    mut reencrypt_batch: F,
) -> SweepReport
where
    T: Display,
    C: Stream<Item = Result<T, E>>,
    F: FnMut(Vec<T>) -> Fut,
    Fut: Future<Output = Result<Vec<(T, Result<ReencryptOutcome, E>)>, E>>,
    E: Display,
{
    let span = spans::sweep(keyring_id);
    let report = async {
        let mut report = SweepReport::default();
        let mut batches = pin!(candidates
            .chunks(options.batch_size.get())
            .map(|batch| {
                let mut candidates: Vec<T> = Vec::with_capacity(batch.len());
                let mut unread: Vec<E> = Vec::new();
                for candidate in batch {
                    match candidate {
                        Ok(candidate) => candidates.push(candidate),
                        Err(error) => unread.push(error),
                    }
                }
                let given = candidates.len();
                let reencrypting = (given > 0).then(|| reencrypt_batch(candidates));
                async move { (unread, given, OptionFuture::from(reencrypting).await) }
            })
            .buffer_unordered(options.concurrency.get()));
        while let Some((unread, given, outcomes)) = batches.next().await {
            for error in &unread {
                report.count_unread(keyring_id, error);
            }
            let given_count = u64::try_from(given).unwrap_or(u64::MAX);
            match outcomes {
                Some(Ok(outcomes)) => {
                    let returned = outcomes.len();
                    if returned != given {
                        let returned_count = u64::try_from(returned).unwrap_or(u64::MAX);
                        spans::sweep_batch_outcomes_mismatched(
                            keyring_id,
                            given_count,
                            returned_count,
                        );
                    }
                    report.scanned += given_count;
                    report.failed +=
                        u64::try_from(given.saturating_sub(returned)).unwrap_or(u64::MAX);
                    for (candidate, outcome) in outcomes.into_iter().take(given) {
                        report.count_outcome(keyring_id, &candidate, outcome);
                    }
                }
                Some(Err(error)) => {
                    report.scanned += given_count;
                    report.failed += given_count;
                    spans::sweep_batch_failed(keyring_id, given_count, &error);
                }
                None => {}
            }
        }
        report
    }
    .instrument(span.clone())
    .await;
    spans::record_sweep(&span, &report);
    report
}

#[cfg(test)]
mod tests {
    use std::io;
    use std::sync::{Mutex, PoisonError};

    use futures_util::stream;
    use jiff::Timestamp;
    use kms_aead::formats::Randomized;
    use kms_aead::KmsAeadResult;
    use proptest::prelude::*;

    use super::*;
    use crate::test_support::{TestResult, TENANT};
    use crate::{Compromise, Encrypted, KeyTrust};

    /// Epochs on either side of every byte boundary of the big-endian layout.
    const BYTE_BOUNDARIES: [u32; 8] = [0, 1, 255, 256, 65_535, 65_536, 16_777_216, u32::MAX];

    fn epoch() -> impl Strategy<Value = u32> {
        prop_oneof![any::<u32>(), proptest::sample::select(&BYTE_BOUNDARIES[..])]
    }

    #[test]
    fn a_marker_is_the_version_byte_and_the_big_endian_epoch() {
        assert_eq!(EncryptionMarker::ENVELOPE.value(), [0x01, 0, 0, 0, 0]);
        assert_eq!(
            EncryptionMarker::of_epoch(0x0102_0304).value(),
            [0x01, 0x01, 0x02, 0x03, 0x04]
        );
    }

    proptest! {
        #[test]
        fn markers_and_their_bytes_order_as_their_epochs(earlier in epoch(), later in epoch()) {
            let (first, second) = (EncryptionMarker::of_epoch(earlier), EncryptionMarker::of_epoch(later));
            prop_assert_eq!(first.cmp(&second), earlier.cmp(&later));
            prop_assert_eq!(first.value().cmp(second.value()), earlier.cmp(&later));
        }
    }

    #[test]
    fn bytes_of_another_version_or_length_are_refused() -> TestResult {
        for malformed in [
            vec![],
            vec![0x01, 0, 0, 7],
            vec![0x01, 0, 0, 0, 7, 0],
            vec![0x00, 0, 0, 0, 7],
            vec![0x02, 0, 0, 0, 7],
        ] {
            assert!(matches!(
                EncryptionMarker::try_from(malformed),
                Err(KeyringError::InvalidEncryptionMarker)
            ));
        }
        assert_eq!(
            EncryptionMarker::try_from(vec![0x01, 0, 0, 1, 2])?,
            EncryptionMarker::of_epoch(258)
        );
        assert_eq!(
            EncryptionMarker::try_from(EncryptionMarker::ENVELOPE.into_value())?,
            EncryptionMarker::ENVELOPE
        );
        Ok(())
    }

    fn reencrypted_under(trust: KeyTrust) -> KmsAeadResult<Reencrypted<String, Randomized>> {
        // Tink's output prefix of key id 7, then a 12-byte nonce and a 16-byte tag.
        let mut bytes = vec![0x01, 0, 0, 0, 7];
        bytes.resize(5 + 12 + 16, 0);
        Ok(Reencrypted {
            value: Encrypted::try_from(bytes)?,
            trust,
        })
    }

    #[test]
    fn a_value_re_encrypted_from_a_compromised_version_is_reported_as_such() -> TestResult {
        let reencrypted = reencrypted_under(KeyTrust::Compromised(Compromise::new(
            Timestamp::UNIX_EPOCH,
            None,
        )))?;
        let expected = ReencryptOutcome::Reencrypted {
            from_compromised: true,
        };

        assert_eq!(reencrypted.outcome(), expected);
        assert_eq!(ReencryptOutcome::from(&Some(reencrypted)), expected);
        Ok(())
    }

    #[test]
    fn a_value_re_encrypted_from_a_trusted_version_is_not_reported_as_compromised() -> TestResult {
        let reencrypted = reencrypted_under(KeyTrust::Trusted)?;
        let expected = ReencryptOutcome::Reencrypted {
            from_compromised: false,
        };

        assert_eq!(reencrypted.outcome(), expected);
        assert_eq!(ReencryptOutcome::from(&Some(reencrypted)), expected);
        Ok(())
    }

    #[test]
    fn a_value_that_was_current_is_skipped() {
        let current: Option<Reencrypted<String, Randomized>> = None;

        assert_eq!(ReencryptOutcome::from(&current), ReencryptOutcome::Skipped);
    }

    /// The outcome the tests' re-encryptions give each candidate: `3` is skipped, `4` and `5` fail,
    /// `6` is re-encrypted from a compromised version, and every other candidate is re-encrypted.
    fn outcome_of(candidate: u32) -> Result<ReencryptOutcome, io::Error> {
        match candidate {
            3 => Ok(ReencryptOutcome::Skipped),
            4 => Err(io::Error::other("the users table is unavailable")),
            5 => Err(io::Error::other(KeyringError::RecordMissing(TENANT))),
            6 => Ok(ReencryptOutcome::Reencrypted {
                from_compromised: true,
            }),
            _ => Ok(ReencryptOutcome::Reencrypted {
                from_compromised: false,
            }),
        }
    }

    #[tokio::test]
    async fn reencrypt_records_counts_scanned_reencrypted_skipped_failed_with_the_applications_errors(
    ) {
        let report = reencrypt_records(
            &TENANT,
            stream::iter((1..=6).map(Ok)),
            NonZeroUsize::MIN.saturating_add(1),
            |candidate| async move { outcome_of(candidate) },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 6,
                reencrypted: 3,
                reencrypted_from_compromised: 1,
                skipped: 1,
                failed: 2,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_counts_a_candidate_the_stream_failed_to_read_as_scanned_and_failed()
    {
        let candidates = stream::iter([
            Ok(1),
            Err(io::Error::other("the users query failed")),
            Ok(2),
        ]);

        let report = reencrypt_records(
            &TENANT,
            candidates,
            NonZeroUsize::MIN,
            |candidate| async move { outcome_of(candidate) },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 3,
                reencrypted: 2,
                reencrypted_from_compromised: 0,
                skipped: 0,
                failed: 1,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_batched_counts_every_batch_and_the_short_last_one() {
        let batch_sizes = Mutex::new(Vec::new());

        let report = reencrypt_records_batched(
            &TENANT,
            stream::iter((1..=7).map(Ok)),
            BatchedSweepOptions::new().with_batch_size(NonZeroUsize::new(3).unwrap()),
            |batch: Vec<u32>| {
                batch_sizes
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(batch.len());
                async move {
                    Ok(batch
                        .into_iter()
                        .map(|candidate| (candidate, outcome_of(candidate)))
                        .collect())
                }
            },
        )
        .await;

        assert_eq!(
            batch_sizes
                .into_inner()
                .unwrap_or_else(PoisonError::into_inner),
            [3, 3, 1]
        );
        assert_eq!(
            report,
            SweepReport {
                scanned: 7,
                reencrypted: 4,
                reencrypted_from_compromised: 1,
                skipped: 1,
                failed: 2,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_batched_counts_the_outcomes_a_batch_left_out_as_failed() {
        let report = reencrypt_records_batched(
            &TENANT,
            stream::iter((1..=5).map(Ok)),
            BatchedSweepOptions::new().with_batch_size(NonZeroUsize::new(2).unwrap()),
            |batch: Vec<u32>| async move {
                Ok(batch
                    .into_iter()
                    .take(1)
                    .map(|candidate| (candidate, outcome_of(candidate)))
                    .collect())
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 5,
                reencrypted: 1,
                reencrypted_from_compromised: 0,
                skipped: 1,
                failed: 3,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_batched_counts_no_more_outcomes_than_a_batch_was_given() {
        let report = reencrypt_records_batched(
            &TENANT,
            stream::iter([Ok(1), Ok(2)]),
            BatchedSweepOptions::new().with_batch_size(NonZeroUsize::new(2).unwrap()),
            |batch: Vec<u32>| async move {
                Ok(batch
                    .into_iter()
                    .flat_map(|candidate| {
                        [candidate; 2].map(|candidate| (candidate, outcome_of(candidate)))
                    })
                    .collect())
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 2,
                reencrypted: 2,
                reencrypted_from_compromised: 0,
                skipped: 0,
                failed: 0,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_batched_counts_a_candidate_the_stream_failed_to_read_as_scanned_and_failed(
    ) {
        let candidates = stream::iter([
            Ok(1),
            Err(io::Error::other("the users query failed")),
            Ok(2),
            Err(io::Error::other("the users query failed")),
        ]);

        let report = reencrypt_records_batched(
            &TENANT,
            candidates,
            BatchedSweepOptions::new().with_batch_size(NonZeroUsize::new(2).unwrap()),
            |batch: Vec<u32>| async move {
                Ok(batch
                    .into_iter()
                    .map(|candidate| (candidate, outcome_of(candidate)))
                    .collect())
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 4,
                reencrypted: 2,
                reencrypted_from_compromised: 0,
                skipped: 0,
                failed: 2,
            }
        );
    }

    #[tokio::test]
    async fn reencrypt_records_batched_counts_every_candidate_of_a_failed_batch_as_failed() {
        let report = reencrypt_records_batched(
            &TENANT,
            stream::iter((1..=5).map(Ok)),
            BatchedSweepOptions::new().with_batch_size(NonZeroUsize::new(2).unwrap()),
            |batch: Vec<u32>| async move {
                if batch.contains(&3) {
                    return Err(io::Error::other("the users table is unavailable"));
                }
                Ok(batch
                    .into_iter()
                    .map(|candidate| (candidate, outcome_of(candidate)))
                    .collect())
            },
        )
        .await;

        assert_eq!(
            report,
            SweepReport {
                scanned: 5,
                reencrypted: 2,
                reencrypted_from_compromised: 0,
                skipped: 0,
                failed: 3,
            }
        );
    }

    #[cfg(all(
        feature = "admin",
        any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
    ))]
    mod with_backend {
        use std::collections::BTreeMap;
        use std::sync::{Mutex, PoisonError};

        use kms_aead::formats::Randomized;
        #[cfg(feature = "deterministic")]
        use kms_aead::DeterministicAlgorithm;
        use kms_aead::{
            AeadAlgorithm, BeaconAlgorithm, DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions,
        };

        use super::*;
        use crate::test_support::{
            email_of, TestAdmin, TestBackend, TestKeyring, TestProvider, TestRegistry,
        };
        use crate::testing::MemoryKeyringStore;
        use crate::{
            Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, KeyVersion,
            KeyringAlgorithms, KeyringRegistryOptions, Purpose,
        };

        const ALICE: &str = "alice@example.com";
        const ALICE_PHONE: &str = "+44 20 7946 0000";
        #[cfg(feature = "deterministic")]
        const EMAIL: FieldSpec = FieldSpec::new(
            EntityKind::from_static("user"),
            FieldName::from_static("email"),
        );
        const PHONE: FieldSpec = FieldSpec::new(
            EntityKind::from_static("user"),
            FieldName::from_static("phone"),
        );
        /// The AAD an application gave its envelope values.
        const ENVELOPE_AAD: &[u8] = b"users:42:email";

        async fn keyring_admin(
            provider: TestProvider,
        ) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
            TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(provider, TENANT, KeyringAlgorithms::new())
            .await
        }

        /// The users table of an application, by user id.
        type Users = Mutex<BTreeMap<&'static str, UserRow>>;

        #[derive(Clone)]
        struct UserRow {
            email: Encrypted<String, Randomized>,
            encryption_marker: EncryptionMarker,
        }

        /// Writes `user` as an application does: the email encrypted by one encryptor, and the
        /// marker of the encryptor's record.
        async fn write_user(
            keyring: &TestKeyring<MemoryKeyringStore>,
            users: &Users,
            user: &'static str,
        ) -> KeyringResult<()> {
            let encryptor = keyring.encryptor().await;
            let email = encryptor
                .encrypt(&email_of(user)?, &ALICE.to_string())
                .await?;
            let encryption_marker = encryptor.record().encryption_marker();
            users.lock().unwrap_or_else(PoisonError::into_inner).insert(
                user,
                UserRow {
                    email,
                    encryption_marker,
                },
            );
            Ok(())
        }

        fn row_of(users: &Users, user: &str) -> Option<UserRow> {
            users
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(user)
                .cloned()
        }

        /// The users whose marker is below the keyring's: the sweep's query.
        fn behind(keyring: &TestKeyring<MemoryKeyringStore>, users: &Users) -> Vec<&'static str> {
            let current = keyring.record().encryption_marker();
            users
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .filter(|(_, row)| row.encryption_marker < current)
                .map(|(user, _)| *user)
                .collect()
        }

        /// One sweep over the users [`behind`] finds, re-encrypting each email as an application
        /// does, with one encryptor per user, and writing the marker of the encryptor's record.
        async fn sweep(keyring: &TestKeyring<MemoryKeyringStore>, users: &Users) -> SweepReport {
            let candidates = behind(keyring, users);
            reencrypt_records(
                &TENANT,
                stream::iter(candidates.into_iter().map(Ok)),
                NonZeroUsize::MIN,
                |user| async move {
                    let Some(row) = row_of(users, user) else {
                        return Ok(ReencryptOutcome::Skipped);
                    };
                    let encryptor = keyring.encryptor().await;
                    let encryption_marker = encryptor.record().encryption_marker();
                    let reencrypted = encryptor.reencrypt(&email_of(user)?, &row.email).await?;
                    let outcome = ReencryptOutcome::from(&reencrypted);
                    let email = reencrypted.map_or(row.email, |reencrypted| reencrypted.value);
                    users.lock().unwrap_or_else(PoisonError::into_inner).insert(
                        user,
                        UserRow {
                            email,
                            encryption_marker,
                        },
                    );
                    Ok::<ReencryptOutcome, KeyringError>(outcome)
                },
            )
            .await
        }

        #[tokio::test]
        async fn reencrypt_records_writes_the_marker_alone_when_a_beacon_rotation_leaves_the_value_current(
        ) -> TestResult {
            let admin = TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
            )
            .await?;
            let keyring = admin.keyring();
            let users = Users::default();
            write_user(keyring, &users, "42").await?;
            let email = row_of(&users, "42").ok_or("the user is written")?.email;
            admin
                .promote_now(admin.rotate(Purpose::Beacon).await?)
                .await?;

            let report = sweep(keyring, &users).await;

            assert_eq!(
                report,
                SweepReport {
                    scanned: 1,
                    reencrypted: 0,
                    reencrypted_from_compromised: 0,
                    skipped: 1,
                    failed: 0,
                }
            );
            assert!(behind(keyring, &users).is_empty());
            let kept = row_of(&users, "42")
                .ok_or("the sweep keeps the user")?
                .email;
            assert_eq!(kept.value(), email.value());
            Ok(())
        }

        #[tokio::test]
        async fn reencrypt_records_reencrypts_a_value_under_a_decrypt_only_version_above_the_active_one(
        ) -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let users = Users::default();
            let first = keyring
                .record()
                .active(Purpose::Randomized)
                .map(|version| version.id())
                .ok_or("a new keyring has an active randomised version")?;
            let pending = admin.rotate(Purpose::Randomized).await?;
            let replacement = admin
                .mark_compromised(first, None)
                .await?
                .ok_or("the compromised active version is replaced")?
                .current;
            assert!(replacement.as_u32() > pending.as_u32());
            write_user(keyring, &users, "42").await?;
            admin.promote_now(pending).await?;

            let report = sweep(keyring, &users).await;

            assert_eq!(
                report,
                SweepReport {
                    scanned: 1,
                    reencrypted: 1,
                    reencrypted_from_compromised: 0,
                    skipped: 0,
                    failed: 0,
                }
            );
            assert!(behind(keyring, &users).is_empty());
            admin.retire(replacement).await?;
            let email = row_of(&users, "42")
                .ok_or("the sweep keeps the user")?
                .email;
            assert_eq!(email.key_id(), pending);
            assert_eq!(keyring.decrypt(&email_of("42")?, &email).await?, ALICE);
            Ok(())
        }

        /// The users whose marker `range` contains, and the users whose email is under `key_id`.
        fn found_and_under(
            users: &Users,
            range: ReencryptRange,
            key_id: KeyId,
        ) -> (Vec<&'static str>, Vec<&'static str>) {
            let users = users.lock().unwrap_or_else(PoisonError::into_inner);
            let found = users
                .iter()
                .filter(|(_, row)| range.contains(row.encryption_marker))
                .map(|(user, _)| *user)
                .collect();
            let under = users
                .iter()
                .filter(|(_, row)| row.email.key_id() == key_id)
                .map(|(user, _)| *user)
                .collect();
            (found, under)
        }

        #[tokio::test]
        async fn a_reencryption_range_finds_exactly_the_records_under_its_version() -> TestResult {
            let admin = TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
            )
            .await?;
            let keyring = admin.keyring();
            let users = Users::default();
            let first = keyring
                .record()
                .active(Purpose::Randomized)
                .map(KeyVersion::id)
                .ok_or("a new keyring has an active randomised version")?;
            write_user(keyring, &users, "41").await?;
            let second = admin
                .promote_now(admin.rotate(Purpose::Randomized).await?)
                .await?
                .current;
            write_user(keyring, &users, "42").await?;
            let third = admin
                .mark_compromised(second, None)
                .await?
                .ok_or("the compromised active version is replaced")?
                .current;
            write_user(keyring, &users, "43").await?;
            admin
                .promote_now(admin.rotate(Purpose::Beacon).await?)
                .await?;
            write_user(keyring, &users, "44").await?;

            let record = keyring.record();
            for (key_id, expected) in [
                (first, vec!["41"]),
                (second, vec!["42"]),
                (third, vec!["43", "44"]),
            ] {
                let range = record
                    .version(key_id)
                    .and_then(KeyVersion::reencrypt_range)
                    .ok_or("a version that was active has a range")?;
                assert_eq!(
                    found_and_under(&users, range, key_id),
                    (expected.clone(), expected),
                    "the range of key version {}",
                    key_id.as_u32()
                );
            }
            Ok(())
        }

        #[tokio::test]
        async fn a_process_that_has_not_seen_a_compromise_writes_inside_its_range() -> TestResult {
            let memory = MemoryKeyringStore::new();
            let provider = TestProvider::new("tenant-42-kek")?;
            let admin = TestRegistry::new(
                memory.clone(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(provider.clone(), TENANT, KeyringAlgorithms::new())
            .await?;
            // The application's process, which revalidates only once the default TTL is over.
            let stale = TestRegistry::new(memory, KeyringRegistryOptions::new().with_watch(false))?
                .open(provider, TENANT)
                .await?;
            let compromised = admin
                .keyring()
                .record()
                .active(Purpose::Randomized)
                .map(KeyVersion::id)
                .ok_or("a new keyring has an active randomised version")?;
            admin
                .mark_compromised(compromised, None)
                .await?
                .ok_or("the compromised active version is replaced")?;
            let users = Users::default();

            write_user(&stale, &users, "42").await?;

            let record = admin.keyring().record();
            let range = record
                .version(compromised)
                .and_then(KeyVersion::reencrypt_range)
                .ok_or("the compromised version has a range")?;
            let row = row_of(&users, "42").ok_or("the user is written")?;
            assert_eq!(row.email.key_id(), compromised);
            assert!(range.contains(row.encryption_marker));
            assert_eq!(range.end(), Some(record.encryption_marker()));

            stale.reload().await?;
            write_user(&stale, &users, "43").await?;
            let row = row_of(&users, "43").ok_or("the user is written")?;
            assert_ne!(row.email.key_id(), compromised);
            assert!(!range.contains(row.encryption_marker));
            Ok(())
        }

        #[tokio::test]
        async fn reencrypt_receives_the_trust_of_every_field() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let email_aad = email_of("42")?;
            let phone_aad = PHONE.aad(&EntityId::try_from("42")?);
            let email = keyring
                .encryptor()
                .await
                .encrypt(&email_aad, &ALICE.to_string())
                .await?;
            admin.mark_compromised(email.key_id(), None).await?;
            let phone = keyring
                .encryptor()
                .await
                .encrypt(&phone_aad, &ALICE_PHONE.to_string())
                .await?;
            let seen = Mutex::new(Vec::new());

            let report = reencrypt_records(
                &TENANT,
                stream::iter([Ok("42")]),
                NonZeroUsize::MIN,
                |_| async {
                    let email = keyring.decrypt_with_trust(&email_aad, &email).await?;
                    let phone = keyring.decrypt_with_trust(&phone_aad, &phone).await?;
                    let trusts = [email.trust, phone.trust];
                    seen.lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .extend(trusts.iter().cloned());
                    Ok::<ReencryptOutcome, KeyringError>(ReencryptOutcome::Reencrypted {
                        from_compromised: trusts
                            .iter()
                            .any(|trust| matches!(trust, KeyTrust::Compromised(_))),
                    })
                },
            )
            .await;

            let seen = seen.into_inner().unwrap_or_else(PoisonError::into_inner);
            assert!(matches!(
                seen.as_slice(),
                [KeyTrust::Compromised(_), KeyTrust::Trusted]
            ));
            assert_eq!(report.reencrypted, 1);
            assert_eq!(report.reencrypted_from_compromised, 1);
            Ok(())
        }

        #[tokio::test]
        async fn reencrypt_moves_only_a_value_behind_the_active_version() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let aad = email_of("42")?;
            let old = keyring
                .encryptor()
                .await
                .encrypt(&aad, &ALICE.to_string())
                .await?;
            assert!(keyring
                .encryptor()
                .await
                .reencrypt(&aad, &old)
                .await?
                .is_none());

            let rotation = admin
                .promote_now(admin.rotate(Purpose::Randomized).await?)
                .await?;
            let reencrypted = keyring
                .encryptor()
                .await
                .reencrypt(&aad, &old)
                .await?
                .ok_or("a value under the previous version is re-encrypted")?;

            assert_eq!(reencrypted.value.key_id(), rotation.current);
            assert_eq!(reencrypted.trust, KeyTrust::Trusted);
            assert_eq!(keyring.decrypt(&aad, &reencrypted.value).await?, ALICE);
            assert!(keyring
                .encryptor()
                .await
                .reencrypt(&aad, &reencrypted.value)
                .await?
                .is_none());
            Ok(())
        }

        #[tokio::test]
        async fn reencrypt_reports_the_trust_of_a_compromised_value() -> TestResult {
            let admin = keyring_admin(TestProvider::new("tenant-42-kek")?).await?;
            let keyring = admin.keyring();
            let aad = email_of("42")?;
            let old = keyring
                .encryptor()
                .await
                .encrypt(&aad, &ALICE.to_string())
                .await?;
            let rotation = admin
                .mark_compromised(old.key_id(), None)
                .await?
                .ok_or("the compromised active version is replaced")?;

            let reencrypted = keyring
                .encryptor()
                .await
                .reencrypt(&aad, &old)
                .await?
                .ok_or("a value under the compromised version is re-encrypted")?;

            assert!(matches!(reencrypted.trust, KeyTrust::Compromised(_)));
            assert_eq!(reencrypted.value.key_id(), rotation.current);
            Ok(())
        }

        #[cfg(feature = "deterministic")]
        #[tokio::test]
        async fn reencrypt_deterministic_moves_only_a_value_behind_the_active_version() -> TestResult
        {
            let admin = TestRegistry::new(
                MemoryKeyringStore::new(),
                KeyringRegistryOptions::new().with_watch(false),
            )?
            .create(
                TestProvider::new("tenant-42-kek")?,
                TENANT,
                KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
            )
            .await?;
            let keyring = admin.keyring();
            let aad = EMAIL.deterministic_aad();
            let old = keyring
                .encryptor()
                .await
                .encrypt_deterministic(&aad, &ALICE.to_string())
                .await?;
            assert!(keyring
                .encryptor()
                .await
                .reencrypt_deterministic(&aad, &old)
                .await?
                .is_none());

            let rotation = admin
                .promote_now(admin.rotate(Purpose::Deterministic).await?)
                .await?;
            let reencrypted = keyring
                .encryptor()
                .await
                .reencrypt_deterministic(&aad, &old)
                .await?
                .ok_or("a value under the previous version is re-encrypted")?;

            assert_eq!(reencrypted.trust, KeyTrust::Trusted);
            assert_eq!(
                reencrypted.value,
                keyring
                    .encryptor()
                    .await
                    .encrypt_deterministic(&aad, &ALICE.to_string())
                    .await?
            );
            assert_eq!(reencrypted.value.key_id(), rotation.current);
            Ok(())
        }

        #[tokio::test]
        async fn a_store_less_value_decrypts_through_the_keyring() -> TestResult {
            let provider = TestProvider::new("tenant-42-kek")?;
            let envelope = KmsAeadEnvelope::<TestProvider, TestBackend>::with_options(
                provider.clone(),
                KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
            )?;
            let values = [
                envelope.encrypt(ENVELOPE_AAD, &ALICE.to_string()).await?,
                envelope.encrypt(ENVELOPE_AAD, &ALICE.to_string()).await?,
            ];
            let admin = keyring_admin(provider).await?;
            let keyring = admin.keyring();

            for value in &values {
                let decrypted = keyring
                    .decrypt_envelope_for_migration(ENVELOPE_AAD, value, AeadAlgorithm::Aes256Gcm)
                    .await?;
                assert_eq!(decrypted, ALICE);
            }
            Ok(())
        }
    }
}
