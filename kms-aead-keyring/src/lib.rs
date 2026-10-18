//! Field encryption with a keyring, over [kms-aead](https://docs.rs/kms-aead).
//!
//! A keyring is the record of one scope's key versions, such as a tenant's, held in a
//! [`KeyringStore`](store::KeyringStore). Each version is a data encryption key (DEK) wrapped by
//! a key encryption key (KEK) in a KMS, with a lifecycle state. A [`Keyring`] encrypts fields
//! under the active version and decrypts them under the version each value names, without a
//! call to the store or the KMS on the hot path: the record is cached in the process, and the
//! unwrapped keys in kms-aead's [`DekCache`](kms_aead::cache::DekCache).
//!
//! # Values
//!
//! A value is Tink's TINK-prefixed layout, `[0x01][key id: u32 BE][body]`, where the body is
//! what kms-aead's cipher of the version's algorithm writes. Under AES-256-GCM, the default of
//! a new keyring, the bytes are those Tink and BigQuery's `AEAD.DECRYPT_STRING` read. The key id
//! is not authenticated: a value relabelled with another id opens under no key.
//!
//! [`Encrypted<T>`](Encrypted) is a value that decrypts to a `T`, checked when it is read from
//! stored bytes. [`Plaintext`] fixes how each `T` encodes, so that other readers decode it.
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
//! it under an algorithm or a KEK that BigQuery cannot read.
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
//! identity or authorization on its own.
//!
//! # Lifecycle
//!
//! A version is `Active`, `DecryptOnly`, `Retired` or `Destroyed`, and any state past `Active`
//! may be compromised; see [`KeyVersionState`]. [`Keyring::rotate`] creates a new active version
//! and keeps the old one decrypting. [`Keyring::mark_compromised`] flags a version for good, and
//! under the default [`CompromisedReadPolicy::Block`] values under it stop decrypting through
//! [`Keyring::decrypt`]; [`Keyring::decrypt_with_status`] still opens them and reports them as
//! untrusted.
//!
//! The record's integrity rests on the store's access control. The processes that serve
//! requests need the KMS's decrypt right and read access to the store; only an administrative
//! job wraps keys and writes the record. A running process takes a record from the store only
//! if it moves every version forward from the one it holds, and logs an `ERROR` otherwise.
//!
//! Each version's DEK is wrapped bound to `<keyring id>/<key id>` through the KMS's associated
//! data, and every unwrap names the same binding, so the KMS refuses a wrapped DEK copied into
//! another version or another keyring: a writer of the store without the KMS's encrypt right
//! cannot bring a leaked DEK back into use under a new id. A KMS without associated data at wrap,
//! Azure Key Vault in this release, needs [`bind_keys`](KeyringOptions::bind_keys) off, and then
//! the record's integrity rests on the store's access control alone.
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
//! | Memory, for tests and single processes | [`MemoryKeyringStore`](store::MemoryKeyringStore) | none |
//! | Firestore, with a listener for push | `store::FirestoreKeyringStore` | `firestore` |
//! | PostgreSQL, through sqlx, with push by `NOTIFY` | `store::PostgresKeyringStore` | `postgres` |
//! | Cloud Storage, with generation preconditions and no push | `store::GcsKeyringStore` | `gcs` |
//!
//! # Features
//!
//! | Feature | Enables |
//! |---|---|
//! | `ring`, `aws-lc`, `aws-lc-fips`, `rustcrypto` | the kms-aead backend of the same name |
//! | `deterministic` | creating deterministic key versions; the deterministic types are in every build |
//! | `legacy-formats` | kms-aead's `legacy-formats`: [`Keyring::decrypt_envelope_value`] also reads the values kms-aead 0.28.1 and earlier wrote |
//! | `serde` | `Serialize` and `Deserialize` for [`Encrypted`], as bytes |
//! | `serde-json` | `serde`, and `Json`, a plaintext stored as its JSON |
//! | `firestore` | `store::FirestoreKeyringStore`, on firestore-rs |
//! | `postgres` | `store::PostgresKeyringStore`, and sqlx's `Type`, `Encode` and `Decode` for [`Encrypted`] as `BYTEA` |
//! | `postgres-tls-rustls`, `postgres-tls-rustls-ring`, `postgres-tls-native` | `postgres`, with sqlx's `tls-rustls-aws-lc-rs`, `tls-rustls-ring` or `tls-native-tls` |
//! | `gcs` | `store::GcsKeyringStore`, with no TLS root store: the application enables one of gcloud-sdk's |
//! | `gcs-tls-roots`, `gcs-tls-webpki` | `gcs`, with gcloud-sdk's `tls-roots` or `tls-webpki-roots` and its default crypto provider |
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
//! use kms_aead::AeadBackend;
//! use kms_aead_keyring::store::MemoryKeyringStore;
//! use kms_aead_keyring::{
//!     EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
//!     KeyringPolicy, Purpose,
//! };
//!
//! const TENANT: KeyringId = KeyringId::from_static("tenant-42");
//! const EMAIL: FieldSpec = FieldSpec::new(
//!     EntityKind::from_static("user"),
//!     FieldName::from_static("email"),
//! );
//!
//! let provider =
//!     LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?, AeadBackend::Ring)?;
//! let keyring = Keyring::open_or_create(
//!     MemoryKeyringStore::new(),
//!     provider,
//!     AeadBackend::Ring,
//!     TENANT,
//!     KeyringPolicy::new(),
//!     KeyringOptions::new(),
//! )
//! .await?;
//!
//! let aad = EMAIL.aad(&EntityId::try_from("42")?);
//! let value = keyring.encrypt(&aad, &"alice@example.com".to_string()).await?;
//! keyring.rotate(Purpose::Randomized).await?;
//!
//! assert_eq!(keyring.decrypt(&aad, &value).await?, "alice@example.com");
//! # Ok(())
//! # }
//! # #[cfg(not(feature = "ring"))]
//! # fn main() {}
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod aad;
pub use aad::*;

mod encrypted;
pub use encrypted::*;

pub mod errors;
pub use errors::{KeyringError, KeyringResult};

mod key_id;
pub use key_id::*;

mod keyring;
pub use keyring::*;

mod plaintext;
pub use plaintext::*;

mod record;
pub use record::*;

mod record_cache;

// The book's code uses the deterministic fields, serde and every store, so it compiles in the
// build with the docs.rs feature set only.
#[cfg(all(
    doctest,
    feature = "ring",
    feature = "deterministic",
    feature = "serde-json",
    feature = "firestore",
    feature = "postgres",
    feature = "gcs"
))]
mod book;

mod spans;

pub mod store;

pub mod sweep;
pub use sweep::{SealFormat, SealMarker};

#[cfg(test)]
mod testing;
