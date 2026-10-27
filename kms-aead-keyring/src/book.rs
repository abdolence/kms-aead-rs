//! Compiles the code in the keyring chapters of the book as doctests, so an example cannot go
//! stale without a test failing. Only reachable through `cfg(doctest)`, which rustdoc sets while
//! collecting doctests and never while building the crate, so a packaged crate does not need the
//! chapters.

/// The keyring half of the getting started chapter, which mdBook includes into it, since
/// kms-aead's own doctests cannot use this crate.
#[doc = include_str!("../../docs/src/getting-started/with-a-keyring.md")]
mod getting_started {}

#[doc = include_str!("../../docs/src/keyring.md")]
mod keyring {}

#[doc = include_str!("../../docs/src/keyring/deployment.md")]
mod deployment {}

#[doc = include_str!("../../docs/src/keyring/lifecycle.md")]
mod lifecycle {}

#[doc = include_str!("../../docs/src/keyring/stores.md")]
mod stores {}

#[doc = include_str!("../../docs/src/keyring/record-cache.md")]
mod record_cache {}

#[doc = include_str!("../../docs/src/keyring/fields.md")]
mod fields {}

#[doc = include_str!("../../docs/src/keyring/deterministic.md")]
mod deterministic {}

#[doc = include_str!("../../docs/src/keyring/beacons.md")]
mod beacons {}

#[doc = include_str!("../../docs/src/keyring/bigquery.md")]
mod bigquery {}

#[doc = include_str!("../../docs/src/operations.md")]
mod operations {}

#[doc = include_str!("../../docs/src/operations/rotation.md")]
mod rotation {}

#[doc = include_str!("../../docs/src/operations/sweeps.md")]
mod sweeps {}

#[doc = include_str!("../../docs/src/operations/sweeps-firestore.md")]
mod sweeps_firestore {}

#[doc = include_str!("../../docs/src/operations/sweeps-postgres.md")]
mod sweeps_postgres {}

#[doc = include_str!("../../docs/src/operations/sweeps-bigquery.md")]
mod sweeps_bigquery {}

#[doc = include_str!("../../docs/src/operations/runbook.md")]
mod runbook {}

#[doc = include_str!("../../docs/src/use-cases/envelope-to-keyring.md")]
mod envelope_to_keyring {}

/// The streaming chapter, whose examples use both crates, so that this crate compiles them.
#[cfg(feature = "stream")]
#[doc = include_str!("../../docs/src/streaming.md")]
mod streaming {}

/// The use cases that stream, whose examples use both crates, so that this crate compiles them.
#[cfg(feature = "stream")]
#[doc = include_str!("../../docs/src/use-cases/large-files.md")]
mod large_files {}

/// The signing chapter, whose examples use both crates, so that this crate compiles them.
#[doc = include_str!("../../docs/src/signing.md")]
mod signing {}

/// The use cases of signed records and MACs, whose examples use both crates.
#[doc = include_str!("../../docs/src/use-cases/service-integrity.md")]
mod service_integrity {}

#[doc = include_str!("../../docs/src/use-cases/signed-records.md")]
mod signed_records {}

/// The README's quick start, compiled so it cannot drift from the API it demonstrates.
#[doc = include_str!("../README.md")]
mod readme {}
