//! Compiles the code in the keyring chapters of the book as doctests, so an example cannot go
//! stale without a test failing. Only reachable through `cfg(doctest)`, which rustdoc sets while
//! collecting doctests and never while building the crate, so a packaged crate does not need the
//! chapters.

#[doc = include_str!("../../docs/src/keyring.md")]
mod keyring {}

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

#[doc = include_str!("../../docs/src/keyring/key-binding.md")]
mod key_binding {}

#[doc = include_str!("../../docs/src/keyring/bigquery.md")]
mod bigquery {}

#[doc = include_str!("../../docs/src/operations.md")]
mod operations {}

/// The README's quick start, compiled so it cannot drift from the API it demonstrates.
#[doc = include_str!("../README.md")]
mod readme {}
