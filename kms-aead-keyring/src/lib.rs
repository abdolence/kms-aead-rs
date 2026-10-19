//! Field encryption with a keyring, over [kms-aead](https://docs.rs/kms-aead).
//!
//! A keyring is the record of one scope's key versions, such as a tenant's, held in a
//! [`KeyringStore`](store::KeyringStore). Each version is a data encryption key (DEK) encrypted by
//! a key encryption key (KEK) in a KMS, with a lifecycle state. A [`Keyring`] encrypts fields
//! under the active versions, through a [`Sealer`] per write, and decrypts them under the version
//! each value names, without a call to the store or the KMS on the hot path: the record is cached
//! in the process, and the decrypted keys in kms-aead's [`DekCache`](kms_aead::cache::DekCache).
//!
//! An application opens its keyrings through one [`KeyringRegistry`] per store, which loads and
//! watches each keyring once, however many parts of the application open it, and whose
//! [`shutdown`](KeyringRegistry::shutdown) stops the work it runs.
//!
//! # Applications and administration
//!
//! A [`Keyring`] is the application's handle. It decrypts, and its [`Sealer`] encrypts, computes
//! beacons and re-seals, with the KMS's decrypt right and read access to the store, and it has no call that
//! encrypts a DEK or writes the record. Those calls, the creation of a keyring, its lifecycle and
//! the keyset exports, are on `KeyringAdmin`, which the `admin` feature adds together with the
//! registry's `create`, `open_or_create` and `admin`. An application builds without the feature
//! and runs under a principal without the rights those calls need; infrastructure automation, or
//! a service that provisions keyrings on purpose, builds with it. A keyring is created before an
//! application opens it: [`open`](KeyringRegistry::open) on a keyring the store does not hold
//! fails with [`KeyringError::RecordMissing`].
//!
//! # Values
//!
//! A value is in Tink's TINK-prefixed layout: the key id of the version that sealed it, then
//! what kms-aead's cipher of the version's algorithm writes. Under AES-256-GCM, the default of
//! a new keyring, the bytes are those Tink and BigQuery's `AEAD.DECRYPT_STRING` read. The key id
//! is not authenticated: a value relabelled with another id opens under no key. The bytes of
//! values, key ids and records are in the
//! [formats chapter](https://kms-aead-rust.abdolence.dev/formats.html) of the book.
//!
//! A value is kms-aead's [`Encrypted<T, Randomized>`](Encrypted), re-exported here, a value that
//! decrypts to a `T` and is checked when it is read from stored bytes. [`Plaintext`] fixes how
//! each `T` encodes, so that other readers decode it, and an application newtype such as `Email`
//! implements it to name what a field holds.
//!
//! A write seals every encrypted field of a record through one [`Sealer`], and stores the
//! [`SealMarker`](sweep::SealMarker) of the sealer's record beside them. The marker names the
//! versions the fields are under: a sweep finds the records behind the active versions by it, and
//! the records that can hold a value under one version by that version's
//! [`seal_range`](KeyVersion::seal_range), see [`sweep`].
//!
//! # Associated data
//!
//! The default associated data of a value is its place in the application's model,
//! `<kind>/<id>/<field>` such as `user/42/email`, built by [`FieldSpec::aad`]: a value opens only
//! in its own row and field, and moves between data stores without being encrypted again.
//! [`FieldSpec::custom_aad`] takes any bytes instead, on a field that BigQuery does not read.
//!
//! A field that BigQuery also decrypts is declared with
//! [`FieldSpec::with_interop`]`(`[`Interop::BigQuery`]`)`, and the keyring then refuses to seal
//! it under an algorithm or a KEK that BigQuery cannot read. With the `bigquery-export` feature,
//! `KeyringAdmin::export_bigquery_keyset` exports the keyset that BigQuery's `KEYS.KEYSET_CHAIN`
//! reads such fields with. A field that Tink also decrypts is declared with [`Interop::Tink`],
//! and `KeyringAdmin::export_tink_keyset` exports the encrypted keyset that Tink's keyset readers
//! take, on a KEK in Cloud KMS, AWS KMS or Vault Transit.
//!
//! # Deterministic fields
//!
//! A deterministic column leaks which rows hold equal values and how often each value occurs,
//! to anyone who reads it, and a leaked key lets its holder test guesses against the whole
//! column offline. Deterministic encryption fits fields that are queried and have high entropy,
//! such as emails and external ids, and never low-cardinality fields such as a status or a
//! country.
//!
//! With the `deterministic` feature, `Sealer::encrypt_deterministic` seals a value under the
//! active AES-SIV version, so that equal plaintexts give equal [`Encrypted<T,
//! Deterministic>`](formats::Deterministic) values, and `Keyring::deterministic_probes` seals a plaintext
//! under every version that still decrypts, for the `IN` list of an equality query across a
//! rotation. The AAD, [`FieldSpec::deterministic_aad`], is `<kind>/<field>` with no entity id,
//! so a value opens in any row of its kind and field, and a deterministic field never decides
//! identity or authorisation on its own.
//!
//! # Beacons
//!
//! A beacon, or blind index, is a truncated HMAC-SHA256 of a field's plaintext under a beacon
//! version, stored beside the field's randomised value so that a data store finds rows by
//! equality. A keyring created with a [`beacon`](KeyringAlgorithms::beacon) algorithm has beacon
//! versions:
//! [`Sealer::beacon`] computes the beacon of a value under the active one, and
//! [`Keyring::beacon_probes`] under every version a lookup matches across a rotation. A beacon
//! column leaks which rows are likely to hold equal values; [`FieldSpec::with_beacon_bits`] sets
//! how much of the HMAC it keeps, and so how many rows a lookup returns to decrypt and filter.
//! Normalising a value, such as lowercasing an email, is its `Plaintext` type's.
//!
//! # Lifecycle
//!
//! A version is `Pending`, `Active`, `DecryptOnly`, `Retired` or `Destroyed`, and any state past
//! `Active` may be compromised; see [`KeyVersionState`]. A rotation is staged:
//! `KeyringAdmin::rotate` adds a pending version, which every process decrypts under once its
//! record refreshes, and `KeyringAdmin::promote` makes it active, after the longest time any
//! process may run without a successful refresh; the old version keeps decrypting.
//! `KeyringAdmin::mark_compromised` flags a version for good, and replaces an active one with a
//! version that is active at once. Under the default [`CompromisedReadPolicy::Block`] values
//! under a compromised version stop decrypting through [`Keyring::decrypt`];
//! [`Keyring::decrypt_with_trust`] still opens them and reports them as untrusted.
//!
//! The record's integrity rests on the store's access control. The processes that serve
//! requests need the KMS's decrypt right and read access to the store; only a `KeyringAdmin`, in
//! an administrative job, encrypts DEKs and writes the record. A running process takes a record
//! from the store only
//! if it moves every version forward from the one it holds, and logs an `ERROR` otherwise.
//!
//! # Caching
//!
//! The record is revalidated with a conditional read once it is older than
//! [`record_ttl`](KeyringRegistryOptions::record_ttl), and early on a change signal from a store
//! with push. An unknown key id causes one reload per
//! [`reload_min_interval`](KeyringRegistryOptions::reload_min_interval). The DEK cache drops
//! expired keys only when it is called, so a process that can sit idle while it holds keys calls
//! [`DekCache::purge_expired`](kms_aead::cache::DekCache::purge_expired) on a timer of its own.
//!
//! # Stores
//!
//! | Store | Type | Feature |
//! |---|---|---|
//! | Memory, for tests and values that never outlive the process | [`MemoryKeyringStore`](testing::MemoryKeyringStore) | none |
//! | Firestore, with a listener for push | `store::FirestoreKeyringStore` | `firestore` |
//! | PostgreSQL, through tokio-postgres, with push by `NOTIFY` | `store::PostgresKeyringStore` | `postgres` |
//! | Cloud Storage, with generation preconditions and no push | `store::GcsKeyringStore` | `gcs` |
//! | Amazon S3 and S3-compatible servers, with ETag preconditions and no push | `store::S3KeyringStore` | `s3` |
//!
//! # Features
//!
//! | Feature | Enables |
//! |---|---|
//! | `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto` | the kms-aead backend of the same name |
//! | `admin` | `KeyringAdmin`, and the registry's `create`, `open_or_create` and `admin`: the calls that encrypt DEKs, write the record or export keysets |
//! | `deterministic` | deterministic key versions and every call on them: `encrypt_deterministic` and `reseal_deterministic` on a `Sealer`, `decrypt_deterministic`, `decrypt_deterministic_with_trust` and `deterministic_probes` on a `Keyring`; the deterministic types are in every build |
//! | `serde` | `Serialize` and `Deserialize` for [`Encrypted`] and [`SealMarker`](sweep::SealMarker), as bytes |
//! | `serde-json` | `serde`, and `Json`, a plaintext stored as its JSON |
//! | `firestore` | `store::FirestoreKeyringStore`, on firestore-rs |
//! | `postgres` | `store::PostgresKeyringStore` on tokio-postgres, with the TLS connector the application passes, and `ToSql` and `FromSql` for [`Encrypted`] and [`SealMarker`](sweep::SealMarker) as `BYTEA` |
//! | `sqlx` | sqlx's `Type`, `Encode` and `Decode` for [`Encrypted`] and [`SealMarker`](sweep::SealMarker) on PostgreSQL, as `BYTEA` |
//! | `gcs` | `store::GcsKeyringStore`, with no TLS root store: the application enables one of gcloud-sdk's |
//! | `gcs-tls-roots`, `gcs-tls-webpki` | `gcs`, with gcloud-sdk's `tls-roots` or `tls-webpki-roots` and its default crypto provider |
//! | `s3` | `store::S3KeyringStore`, on aws-sdk-s3 with the SDK's default HTTPS client, rustls on aws-lc-rs |
//! | `bigquery-export` | `admin`, and `KeyringAdmin::export_bigquery_keyset` on kms-aead's GCP provider with no TLS root store: the application enables kms-aead's `gcp-kms-encryption` |
//!
//! # Example
//!
//! A keyring on the memory store with a local KEK, on the ring backend, created and rotated
//! through its administrative handle, which also lends the application's handle:
//!
//! ```rust
//! # #[cfg(all(feature = "ring", feature = "admin"))]
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use kms_aead::backends::Ring;
//! use kms_aead::providers::{LocalKekId, LocalKmsProvider};
//! use kms_aead::KmsAeadResult;
//! use kms_aead_keyring::formats::Randomized;
//! use kms_aead_keyring::testing::MemoryKeyringStore;
//! use kms_aead_keyring::{
//!     Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
//!     KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Purpose,
//! };
//! use secret_vault_value::SecretValue;
//!
//! #[derive(Debug, Clone, PartialEq)]
//! struct Email(String);
//!
//! impl Plaintext for Email {
//!     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
//!         self.0.to_plaintext()
//!     }
//!
//!     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
//!         String::from_plaintext(plaintext).map(Email)
//!     }
//! }
//!
//! const TENANT: KeyringId = KeyringId::from_static("tenant-42");
//! const EMAIL: FieldSpec = FieldSpec::new(
//!     EntityKind::from_static("user"),
//!     FieldName::from_static("email"),
//! );
//!
//! let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
//!     MemoryKeyringStore::new(),
//!     KeyringRegistryOptions::new(),
//! )?;
//! let provider =
//!     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
//! let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
//!     .open_or_create(provider, TENANT, KeyringAlgorithms::new())
//!     .await?;
//! let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();
//!
//! let aad = EMAIL.aad(&EntityId::try_from("42")?);
//! let alice = Email("alice@example.com".to_string());
//! let value: Encrypted<Email, Randomized> = keyring.sealer().await.encrypt(&aad, &alice).await?;
//! let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
//! admin.promote(staged).await?;
//!
//! assert_eq!(keyring.decrypt(&aad, &value).await?, alice);
//! registry.shutdown().await?;
//! # Ok(())
//! # }
//! # #[cfg(not(all(feature = "ring", feature = "admin")))]
//! # fn main() {}
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aad;
pub use aad::*;

#[cfg(feature = "admin")]
pub mod encodings;

pub mod errors;
pub use errors::{KeyringError, KeyringResult};

mod keyring;
pub use keyring::*;

pub use kms_aead::formats;
#[cfg(feature = "serde-json")]
pub use kms_aead::Json;
pub use kms_aead::{Encrypted, KeyId, Plaintext};

mod purpose;
pub use purpose::Purpose;

mod record;
pub use record::*;

mod record_cache;

mod registry;
pub use registry::*;

// The book's code uses the administrative calls, the deterministic fields, serde, every store and
// the BigQuery export, so it compiles in the build with the docs.rs feature set only.
#[cfg(all(
    doctest,
    feature = "ring",
    feature = "admin",
    feature = "deterministic",
    feature = "serde-json",
    feature = "firestore",
    feature = "postgres",
    feature = "gcs",
    feature = "s3",
    feature = "bigquery-export"
))]
mod book;

mod spans;

pub mod store;

pub mod sweep;

pub mod testing;

#[cfg(test)]
mod test_support;
