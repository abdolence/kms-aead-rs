//! Field encryption with a keyring, over [kms-aead](https://docs.rs/kms-aead).
//!
//! A keyring is the record of one scope's key versions, such as a tenant's, held in a
//! [`KeyringStore`](store::KeyringStore). Each version is a data encryption key (DEK) encrypted by
//! a key encryption key (KEK) in a KMS, with a lifecycle state. A [`Keyring`] encrypts fields
//! under the active version and decrypts them under the version each value names, without a
//! call to the store or the KMS on the hot path: the record is cached in the process, and the
//! decrypted keys in kms-aead's [`DekCache`](kms_aead::cache::DekCache).
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
//! # Associated data
//!
//! The default associated data of a value is its place in the application's model,
//! `<kind>/<id>/<field>` such as `user/42/email`, built by [`FieldSpec::aad`]: a value opens only
//! in its own row and field, and moves between data stores without being encrypted again.
//! [`FieldAad::custom`] takes any bytes instead.
//!
//! A field that BigQuery also decrypts is declared with
//! [`FieldSpec::with_interop`]`(`[`Interop::BigQuery`]`)`, and the keyring then refuses to seal
//! it under an algorithm or a KEK that BigQuery cannot read. With the `bigquery-export` feature,
//! `Keyring::export_bigquery_keyset` exports the keyset that BigQuery's `KEYS.KEYSET_CHAIN` reads
//! such fields with. A field that Tink also decrypts is declared with [`Interop::Tink`], and
//! [`Keyring::export_tink_keyset`] exports the encrypted keyset that Tink's keyset readers take,
//! on a KEK in Cloud KMS, AWS KMS or Vault Transit.
//!
//! # Deterministic fields
//!
//! A deterministic column leaks which rows hold equal values and how often each value occurs,
//! to anyone who reads it, and a leaked key lets its holder test guesses against the whole
//! column offline. Deterministic encryption fits fields that are queried and have high entropy,
//! such as emails and external ids, and never low-cardinality fields such as a status or a
//! country.
//!
//! With the `deterministic` feature, `Keyring::encrypt_deterministic` seals a value under the
//! active AES-SIV version, so that equal plaintexts give equal [`Encrypted<T,
//! Deterministic>`](Deterministic) values, and `Keyring::equality_probes` seals a plaintext
//! under every version that still decrypts, for the `IN` list of an equality query across a
//! rotation. The AAD, [`FieldSpec::deterministic_aad`], is `<kind>/<field>` with no entity id,
//! so a value opens in any row of its kind and field, and a deterministic field never decides
//! identity or authorisation on its own.
//!
//! # Beacons
//!
//! A beacon, or blind index, is a truncated HMAC-SHA256 of a field's plaintext under a beacon
//! version, stored beside the field's randomised value so that a data store finds rows by
//! equality. A keyring whose policy names
//! [`with_beacon_algorithm`](KeyringPolicy::with_beacon_algorithm) has beacon versions:
//! [`Keyring::beacon`] computes the beacon of a value under the active one, and
//! [`Keyring::beacon_probes`] under every version a lookup matches across a rotation. A beacon
//! column leaks which rows are likely to hold equal values; [`FieldSpec::with_beacon_bits`] sets
//! how much of the HMAC it keeps, and so how many rows a lookup returns to decrypt and filter.
//! Normalising a value, such as lowercasing an email, is its `Plaintext` type's.
//!
//! # Lifecycle
//!
//! A version is `Pending`, `Active`, `DecryptOnly`, `Retired` or `Destroyed`, and any state past
//! `Active` may be compromised; see [`KeyVersionState`]. A rotation is staged:
//! [`Keyring::rotate`] adds a pending version, which every process decrypts under once its record
//! refreshes, and [`Keyring::promote`] makes it active, after the longest time any process may
//! run without a successful refresh; the old version keeps decrypting.
//! [`Keyring::mark_compromised`] flags a version for good, and replaces an active one with a
//! version that is active at once. Under the default [`CompromisedReadPolicy::Block`] values
//! under a compromised version stop decrypting through [`Keyring::decrypt`];
//! [`Keyring::decrypt_with_status`] still opens them and reports them as untrusted.
//!
//! The record's integrity rests on the store's access control. The processes that serve
//! requests need the KMS's decrypt right and read access to the store; only an administrative
//! job encrypts DEKs and writes the record. A running process takes a record from the store only
//! if it moves every version forward from the one it holds, and logs an `ERROR` otherwise.
//!
//! # Caching
//!
//! The record is revalidated with a conditional read once it is older than
//! [`record_ttl`](KeyringOptions::record_ttl), and early on a change signal from a store with
//! push. An unknown key id causes one reload per
//! [`reload_min_interval`](KeyringOptions::reload_min_interval). The DEK cache drops expired
//! keys only when it is called, so a process that can sit idle while it holds keys calls
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
//! | `deterministic` | creating deterministic key versions; the deterministic types are in every build |
//! | `serde` | `Serialize` and `Deserialize` for [`Encrypted`], as bytes |
//! | `serde-json` | `serde`, and `Json`, a plaintext stored as its JSON |
//! | `firestore` | `store::FirestoreKeyringStore`, on firestore-rs |
//! | `postgres` | `store::PostgresKeyringStore` on tokio-postgres, with the TLS connector the application passes, and kms-aead's `postgres` |
//! | `gcs` | `store::GcsKeyringStore`, with no TLS root store: the application enables one of gcloud-sdk's |
//! | `gcs-tls-roots`, `gcs-tls-webpki` | `gcs`, with gcloud-sdk's `tls-roots` or `tls-webpki-roots` and its default crypto provider |
//! | `s3` | `store::S3KeyringStore`, on aws-sdk-s3 with the SDK's default HTTPS client, rustls on aws-lc-rs |
//! | `bigquery-export` | `Keyring::export_bigquery_keyset`, on kms-aead's GCP provider with no TLS root store: the application enables kms-aead's `gcp-kms-encryption` |
//!
//! # Example
//!
//! A keyring on the memory store with a local KEK, on the ring backend:
//!
//! ```rust
//! # #[cfg(feature = "ring")]
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use kms_aead::providers::{LocalKekId, LocalKmsProvider};
//! use kms_aead::{KmsAeadResult, Ring};
//! use kms_aead_keyring::testing::MemoryKeyringStore;
//! use kms_aead_keyring::{
//!     Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
//!     KeyringPolicy, Plaintext, Purpose, Randomized,
//! };
//! use secret_vault_value::SecretValue;
//!
//! #[derive(Debug, PartialEq)]
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
//! let provider =
//!     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
//! let keyring = Keyring::<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>::open_or_create(
//!     MemoryKeyringStore::new(),
//!     provider,
//!     TENANT,
//!     KeyringPolicy::new(),
//!     KeyringOptions::new(),
//! )
//! .await?;
//!
//! let aad = EMAIL.aad(&EntityId::try_from("42")?);
//! let alice = Email("alice@example.com".to_string());
//! let value: Encrypted<Email, Randomized> = keyring.encrypt(&aad, &alice).await?;
//! let staged = keyring.rotate(Purpose::Randomized).await?;
//! keyring.promote(staged).await?;
//!
//! assert_eq!(keyring.decrypt(&aad, &value).await?, alice);
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "ring"))]
//! # fn main() {}
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aad;
pub use aad::*;

pub mod encodings;

pub mod errors;
pub use errors::{KeyringError, KeyringResult};

mod key_version_id;
pub use key_version_id::*;

mod keyring;
pub use keyring::*;

pub use kms_aead::formats::{Deterministic, Randomized};
#[cfg(feature = "serde-json")]
pub use kms_aead::Json;
pub use kms_aead::{Encrypted, Plaintext};

mod record;
pub use record::*;

mod record_cache;

// The book's code uses the deterministic fields, serde, every store and the BigQuery export, so it
// compiles in the build with the docs.rs feature set only.
#[cfg(all(
    doctest,
    feature = "ring",
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
pub use sweep::{SealFormat, SealMarker};

pub mod testing;

#[cfg(test)]
mod test_support;
