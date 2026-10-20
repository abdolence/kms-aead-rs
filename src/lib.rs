//! Envelope encryption with a key encryption key (KEK) held by a KMS, and AEAD without one.
//!
//! A value is sealed under a data encryption key (DEK) with an AEAD algorithm, and the DEK is
//! encrypted by the KEK. [`KmsAeadEnvelope`] does both and stores the encrypted DEK with the cipher
//! text, in Tink's KMS envelope format for every provider, so Tink's `KmsEnvelopeAead` reads the
//! values with the same KMS key and algorithm. [`AeadCipher`] seals with a DEK the caller holds,
//! without a KMS. [`formats`] has every byte layout.
//!
//! # Providers
//!
//! A provider encrypts and decrypts DEKs with one KEK. Each one is a type in [`providers`], enabled
//! by its feature where the table names one, and implements [`KmsAeadEncryptionProvider`], which an
//! application can also implement for a KMS of its own.
//!
//! | KMS | Type | Feature |
//! |---|---|---|
//! | Google Cloud KMS | `GcpKmsProvider` | `gcp-kms-encryption` |
//! | AWS KMS | `AwsKmsProvider` | `aws-kms-encryption` |
//! | Azure Key Vault and Managed HSM | `AzureKmsProvider` | `azure-kms-encryption` |
//! | HashiCorp Vault Transit | `HcVaultTransitProvider` | `hashicorp-vault-transit-kms-encryption` |
//! | A KEK the process holds | `LocalKmsProvider` | none, in every build |
//!
//! The GCP, Azure and HashiCorp Vault Transit features have variants that choose the TLS stack,
//! the root store or the crypto provider of their HTTP client; `Cargo.toml` lists them. A build
//! with a provider needs a backend.
//!
//! The threat model, a copied or relabelled encrypted DEK among it, is in the book's
//! [Security considerations](https://kms-aead-rust.abdolence.dev/security.html#threat-model).
//!
//! An AWS KMS decryption names the configured key. Configure the key ARN rather than an alias: a
//! key encrypted under an alias that later moves to another key fails to decrypt with
//! `IncorrectKeyException`. Outside the `aws` partition, such as in GovCloud or China, give the
//! full ARN, since a key id or an alias name becomes an `arn:aws:` ARN.
//!
//! # Backends
//!
//! The AEAD runs on a crypto library that a feature compiles in, named by a type in [`backends`]
//! that implements [`AeadBackend`](backends::AeadBackend): the `B` of [`AeadCipher<B>`] and [`KmsAeadEnvelope<P, B>`].
//! A build may enable any number of them, and there is no default one.
//!
//! | Feature | Type | Algorithms |
//! |---|---|---|
//! | `ring` | `Ring` | ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM |
//! | `aws-lc` | `AwsLc` | every [`AeadAlgorithm`] |
//! | `aws-lc-fips` | `AwsLc`, on the FIPS module | every [`AeadAlgorithm`] |
//! | `rustcrypto` | `RustCrypto` | every [`AeadAlgorithm`] |
//!
//! `aws-lc-fips` builds only the FIPS module, and does not need `aws-lc`. A build with both
//! compiles both C libraries, and aws-lc-rs runs on the FIPS module. The `aws-lc-rs` feature
//! both of them enable is not a backend choice: on its own, aws-lc-rs's build fails.
//!
//! A value sealed by one backend opens with any other that implements its algorithm.
//!
//! A build without a backend feature compiles, and
//! [`LocalKmsProvider`](providers::LocalKmsProvider) is in it, but nothing that seals or encrypts
//! can be constructed: no type implements [`AeadBackend`](backends::AeadBackend).
//!
//! # Store-less mode and the DEK cache
//!
//! A [`KmsAeadEnvelope`] built with a [`DekReusePolicy`] encrypts many values under one DEK and
//! renews it by age, by count, or once it has left the cache, so that a write calls the KMS only
//! to renew it. Its DEK, and the DEKs of the values it reads, live in a
//! [`cache::DekCache`], which serves each plaintext DEK for a TTL and zeroises it as it leaves the
//! cache: at the cache's next call after the TTL, or at
//! [`purge_expired`](cache::DekCache::purge_expired). The writer's DEK also leaves the cache when
//! the cache evicts it for capacity, so in a cache shared with readers, size
//! [`max_entries`](cache::DekCacheOptions::max_entries) above the number of distinct DEKs read
//! per TTL, or give the writer a cache of its own. The per-call envelope, the default, keeps
//! no DEK past the call. The KMS SDKs and HTTP clients the providers use keep copies of each
//! plaintext DEK in request and response buffers that kms-aead cannot zeroise.
//!
//! # Cipher texts
//!
//! Every call that encrypts returns an [`Encrypted<T, F>`](Encrypted), the bytes to store: `T` is
//! the [`Plaintext`] type the value decrypts to, such as an application newtype or
//! `SecretValue`, and `F` the [`Format`](formats::Format), its byte layout.
//! [`KmsAeadEnvelope::encrypt`] writes an `Encrypted<T, Envelope>`, Tink's KMS envelope, and
//! [`KmsAeadEnvelope::decrypt`] reads it back as a `T`. Stored bytes become an `Encrypted`
//! through `TryFrom<Vec<u8>>`, which checks them against the layout of its format. The `serde`
//! feature reads and writes it, and the `postgres` and `sqlx` features store it in a PostgreSQL
//! `BYTEA` column.
//!
//! [`AeadCipher::encrypt`] and `DeterministicCipher::encrypt` seal a value under a key the caller
//! holds, in Tink's layout of a key named by a [`KeyId`], so that Tink and BigQuery read it with a
//! keyset of that key. [`AeadCipher::encrypt_bare`] seals it with no framing, as an
//! `Encrypted<T, Bare>`.
//!
//! A [`Beacon<T>`](Beacon), or blind index, finds rows by a field's value without decrypting
//! the column: a truncated HMAC-SHA256 of the value under a beacon key, which
//! [`KmsAeadEnvelope::beacon`] computes with the key decrypted through the envelope's cache, and
//! [`BeaconMac`] with a key the caller holds. It is stored as `Encrypted` is.
//!
//! # Other features
//!
//! - `deterministic`: deterministic encryption with AES-SIV, [`DeterministicAlgorithm`];
//! - `legacy-formats`: reads the layouts written by 0.29 and earlier. Deprecated;
//! - `serde`: `Serialize` and `Deserialize` for [`Encrypted`], as bytes, for
//!   [`errors::KmsAeadErrorPublicGenericDetails`] and for `SecretValue`;
//! - `serde-json`: `Json`, a [`Plaintext`] of any serde type, stored as its JSON;
//! - `postgres`: `ToSql` and `FromSql` of postgres-types for [`Encrypted`], as `BYTEA`, and
//!   through them as `BYTEA[]` for `= ANY($1)`, for tokio-postgres and postgres;
//! - `sqlx`: sqlx's `Type`, `Encode`, `Decode` and `PgHasArrayType` for [`Encrypted`] on
//!   PostgreSQL, as `BYTEA` and `BYTEA[]`. It depends on sqlx-core and sqlx-postgres only, with
//!   no runtime and no TLS stack.
//!
//! # Examples
//!
//! Envelope encryption with AWS KMS, on the ring backend:
//!
//! ```rust,no_run
//! # #[cfg(all(feature = "aws-kms-encryption", feature = "ring"))]
//! # async fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::backends::Ring;
//! use kms_aead::formats::Envelope;
//! use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider};
//! use kms_aead::{Encrypted, KmsAeadEnvelope};
//! use secret_vault_value::SecretValue;
//!
//! let kms_ref = AwsKmsKeyRef::new(
//!     "123456789012".into(),
//!     "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab".into(),
//! );
//! let provider = AwsKmsProvider::new(&kms_ref).await?;
//! let envelope = KmsAeadEnvelope::<AwsKmsProvider, Ring>::new(provider)?;
//!
//! let secret_value = SecretValue::from("4111 1111 1111 1111");
//! let aad = b"orders/1042";
//!
//! let cipher_text: Encrypted<SecretValue, Envelope> =
//!     envelope.encrypt(aad, &secret_value).await?;
//! let decrypted: SecretValue = envelope.decrypt(aad, &cipher_text).await?;
//!
//! assert_eq!(decrypted, secret_value);
//! # Ok(())
//! # }
//! ```
//!
//! AEAD with a key the caller holds, on the ring backend:
//!
//! ```rust
//! # #[cfg(feature = "ring")]
//! # fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::backends::Ring;
//! use kms_aead::formats::Bare;
//! use kms_aead::{AeadAlgorithm, AeadCipher, Encrypted};
//! use secret_vault_value::SecretValue;
//!
//! let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
//! let dek = cipher.generate_dek()?;
//! let secret_value = SecretValue::from("4111 1111 1111 1111");
//! let aad = b"orders/1042";
//!
//! let cipher_text: Encrypted<SecretValue, Bare> =
//!     cipher.encrypt_bare(aad, &secret_value, &dek)?;
//! let stored: Vec<u8> = cipher_text.into_value();
//! let read_back = Encrypted::<SecretValue, Bare>::try_from(stored)?;
//! let decrypted: SecretValue = cipher.decrypt_bare(aad, &read_back, &dek)?;
//!
//! assert_eq!(decrypted, secret_value);
//! # Ok(())
//! # }
//! ```

#![cfg_attr(docsrs, feature(doc_cfg))]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-base",
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-roots"),
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-webpki")
))]
compile_error!(
    "You must enable either \"hashicorp-vault-transit-kms-encryption-tls-roots\" or \"hashicorp-vault-transit-kms-encryption-tls-webpki\" when using HashiCorp Vault Transit features"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-tls-roots",
    feature = "hashicorp-vault-transit-kms-encryption-tls-webpki"
))]
compile_error!(
    "You cannot enable both \"hashicorp-vault-transit-kms-encryption-tls-roots\" (enabled by \"hashicorp-vault-transit-kms-encryption\") and \"hashicorp-vault-transit-kms-encryption-tls-webpki\" at the same time"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-base",
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs"),
    not(feature = "hashicorp-vault-transit-kms-encryption-tls-ring")
))]
compile_error!(
    "You must enable either \"hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs\" or \"hashicorp-vault-transit-kms-encryption-tls-ring\" when using HashiCorp Vault Transit features"
);

#[cfg(all(
    feature = "hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs",
    feature = "hashicorp-vault-transit-kms-encryption-tls-ring"
))]
compile_error!(
    "You cannot enable both \"hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs\" (enabled by \"hashicorp-vault-transit-kms-encryption\") and \"hashicorp-vault-transit-kms-encryption-tls-ring\" at the same time"
);

#[cfg(all(
    any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "azure-kms-encryption-base",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ),
    not(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))
))]
compile_error!(
    "kms-aead needs a crypto backend for its KMS providers: enable \"ring\", \"aws-lc\", \"aws-lc-fips\" or \"rustcrypto\""
);

#[cfg(all(
    feature = "azure-kms-encryption-base",
    not(feature = "azure-kms-encryption-tls-aws-lc-rs"),
    not(feature = "azure-kms-encryption-tls-no-provider"),
    not(feature = "azure-kms-encryption-native-tls")
))]
compile_error!(
    "You must enable one of \"azure-kms-encryption-tls-aws-lc-rs\" (or \"azure-kms-encryption\"), \"azure-kms-encryption-tls-no-provider\" or \"azure-kms-encryption-native-tls\" when using Azure features"
);

#[cfg(any(
    all(
        feature = "azure-kms-encryption-tls-aws-lc-rs",
        feature = "azure-kms-encryption-tls-no-provider"
    ),
    all(
        feature = "azure-kms-encryption-tls-aws-lc-rs",
        feature = "azure-kms-encryption-native-tls"
    ),
    all(
        feature = "azure-kms-encryption-tls-no-provider",
        feature = "azure-kms-encryption-native-tls"
    )
))]
compile_error!(
    "You can enable only one of \"azure-kms-encryption-tls-aws-lc-rs\" (enabled by \"azure-kms-encryption\"), \"azure-kms-encryption-tls-no-provider\" and \"azure-kms-encryption-native-tls\""
);

/// The result of every fallible operation of the crate.
pub type KmsAeadResult<T> = std::result::Result<T, errors::KmsAeadError>;

mod api;
pub use api::*;

mod algorithm;
pub use algorithm::*;

pub mod backends;

mod aead_cipher;
pub use aead_cipher::*;

mod beacon;
pub use beacon::{Beacon, BeaconAlgorithm, BeaconBits, BeaconMac};

pub mod cache;

mod deterministic;
pub use deterministic::*;

mod encrypted;
pub use encrypted::Encrypted;

pub mod errors;

pub mod formats;

mod key_id;
pub use key_id::KeyId;

mod kms_envelope_encryption;
pub use kms_envelope_encryption::*;

mod plaintext;
pub use plaintext::*;

mod metrics;
#[cfg(feature = "opentelemetry")]
#[doc(hidden)]
pub use metrics::instruments as __instruments;

mod spans;

mod types;
pub use types::*;

pub mod providers;

// The book's code uses every provider, backend and optional feature, so it compiles in the build
// with the docs.rs feature set only.
#[cfg(all(
    doctest,
    feature = "ring",
    feature = "aws-lc",
    feature = "rustcrypto",
    feature = "deterministic",
    feature = "legacy-formats",
    feature = "serde",
    feature = "serde-json",
    feature = "postgres",
    feature = "sqlx",
    feature = "gcp-kms-encryption",
    feature = "aws-kms-encryption",
    feature = "azure-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption",
    feature = "opentelemetry"
))]
mod book;

#[cfg(test)]
mod test_provider;

#[cfg(test)]
#[cfg(any(
    feature = "aws-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption-base"
))]
mod test_http;
