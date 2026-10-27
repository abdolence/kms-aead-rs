//! Compiles the code in the book chapters as doctests, so an example cannot go stale without a
//! test failing. Only reachable through `cfg(doctest)`, which rustdoc sets while collecting
//! doctests and never while building the crate.

#[doc = include_str!("../docs/src/intro.md")]
mod intro {}

#[doc = include_str!("../docs/src/getting-started.md")]
mod getting_started {}

#[doc = include_str!("../docs/src/stored-values.md")]
mod stored_values {}

#[doc = include_str!("../docs/src/providers.md")]
mod providers {}

#[doc = include_str!("../docs/src/providers/gcp.md")]
mod provider_gcp {}

#[doc = include_str!("../docs/src/providers/aws.md")]
mod provider_aws {}

#[doc = include_str!("../docs/src/providers/azure.md")]
mod provider_azure {}

#[doc = include_str!("../docs/src/providers/hc-vault-transit.md")]
mod provider_hc_vault_transit {}

#[doc = include_str!("../docs/src/providers/local.md")]
mod provider_local {}

#[doc = include_str!("../docs/src/envelope-encryption.md")]
mod envelope_encryption {}

#[doc = include_str!("../docs/src/dek-caching.md")]
mod dek_caching {}

#[doc = include_str!("../docs/src/crypto-backends.md")]
mod crypto_backends {}

#[doc = include_str!("../docs/src/deterministic.md")]
mod deterministic {}

#[doc = include_str!("../docs/src/beacons.md")]
mod beacons {}

#[doc = include_str!("../docs/src/asymmetric-kek.md")]
mod asymmetric_kek {}

#[doc = include_str!("../docs/src/formats.md")]
mod formats {}

#[doc = include_str!("../docs/src/errors.md")]
mod errors {}

#[doc = include_str!("../docs/src/observability.md")]
mod observability {}

#[doc = include_str!("../docs/src/security.md")]
mod security {}

#[doc = include_str!("../docs/src/migrating-from-0.29.md")]
mod migrating_from_0_29 {}

#[doc = include_str!("../docs/src/migrating-from-0.30.md")]
mod migrating_from_0_30 {}

#[doc = include_str!("../docs/src/use-cases/publish-verifiable.md")]
mod publish_verifiable {}

#[doc = include_str!("../docs/src/use-cases/write-only-producers.md")]
mod write_only_producers {}

#[doc = include_str!("../docs/src/use-cases/log-json-payloads.md")]
mod log_json_payloads {}

#[cfg(feature = "stream")]
#[doc = include_str!("../docs/src/use-cases/encrypted-http-streams.md")]
mod encrypted_http_streams {}

/// The README's quick start, compiled so it cannot drift from the API it demonstrates.
#[doc = include_str!("../README.md")]
mod readme {}
