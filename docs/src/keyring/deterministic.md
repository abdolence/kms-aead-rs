# Deterministic fields

This page covers how a keyring encrypts, queries and rotates deterministic fields. Feature
`deterministic`, to create deterministic key versions. The deterministic types exist in every
build, so values pass through a process without the feature.

The generic [Deterministic encryption](../deterministic.md) page owns the AES-SIV primitive and what
it leaks. Deterministic fields fit exact-match lookups where the leak of equality is acceptable;
to choose between them and a [beacon](./beacons.md), read
[Find a user by an encrypted email](../use-cases/equality-lookups.md).

## What they leak

What a deterministic column and a leaked deterministic DEK allow is in
[What it leaks](../deterministic.md#what-it-leaks). The keyring adds one rule: the AAD of a
deterministic field names its kind and field and no entity, see [AAD](#aad), so a deterministic
value also decrypts in any row of the same kind and field, and a deterministic field never decides
identity or authorisation on its own.

## Usage

A keyring with deterministic versions names their algorithm in its `KeyringAlgorithms`: AES-SIV,
the one `DeterministicAlgorithm` has:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{DeterministicAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::Deterministic;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    DeterministicAad, Encrypted, EntityKind, FieldName, FieldSpec, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .create(
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
    )
    .await?;
let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

let aad: DeterministicAad = EMAIL.deterministic_aad();
let alice = Email("alice@example.com".to_string());
let first: Encrypted<Email, Deterministic> =
    keyring.encryptor().await.encrypt_deterministic(&aad, &alice).await?;
let second: Encrypted<Email, Deterministic> =
    keyring.encryptor().await.encrypt_deterministic(&aad, &alice).await?;

// Equal plaintexts give equal values under one version
assert_eq!(first, second);
assert_eq!(keyring.decrypt_deterministic(&aad, &first).await?, alice);
registry.shutdown(None).await;
# Ok(())
# }
```

A deterministic value is an `Encrypted<T, Deterministic>`, a type of its own, so it is never
handed to `decrypt` by mistake. Unlike a randomised value it has `==` and `Hash`, which compare
the bytes. AES-SIV runs on the RustCrypto `aes-siv` crate whatever the
keyring's AEAD backend.

`decrypt_deterministic` applies the [compromised read policy](./lifecycle.md#reading-a-compromised-version),
and `decrypt_deterministic_with_trust` reports the version's trust, as their randomised
counterparts do.

## AAD

The AAD of a deterministic value is `<kind>/<field>`, such as `user/email`, built by
`FieldSpec::deterministic_aad()`. It holds no entity id, otherwise equal plaintexts in different
rows would give different values and an equality query would find nothing.

`DeterministicAad::with_context(bytes)` appends `/` and a context, such as a tenant id, to keep the
values of two scopes apart. A context that differs per row defeats equality across rows, so it is a
constant for the field. There is no constructor from arbitrary bytes: a deterministic value exists
to be queried, and the query rebuilds its AAD.

## Queries across rotations

A value encrypted under one deterministic version and the same plaintext under the next one differ.
So an equality query matches against every version that still decrypts, with
`deterministic_probes`:

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{DeterministicAlgorithm, KmsAeadResult};
# use kms_aead_keyring::formats::Deterministic;
# use kms_aead_keyring::testing::MemoryKeyringStore;
# use kms_aead_keyring::{
#     DeterministicAad, Encrypted, EntityKind, FieldName, FieldSpec, KeyId, Keyring, KeyringAdmin,
#     KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext, Purpose,
# };
# use secret_vault_value::SecretValue;
# #[derive(Debug, Clone, PartialEq)]
# struct Email(String);
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> { self.0.to_plaintext() }
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }
# const EMAIL: FieldSpec = FieldSpec::new(EntityKind::from_static("user"), FieldName::from_static("email"));
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .create(
#         provider,
#         KeyringId::from_static("tenant-42"),
#         KeyringAlgorithms::new().with_deterministic(DeterministicAlgorithm::Aes256Siv),
#     )
#     .await?;
# let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();
let aad: DeterministicAad = EMAIL.deterministic_aad();
let alice = Email("alice@example.com".to_string());
let before: Encrypted<Email, Deterministic> =
    keyring.encryptor().await.encrypt_deterministic(&aad, &alice).await?;

let staged: KeyId = admin.rotate(Purpose::Deterministic).await?;
admin.promote_now(staged).await?;

// One probe per version that still decrypts, newest first
let probes: Vec<Encrypted<Email, Deterministic>> = keyring.deterministic_probes(&aad, &alice).await?;
assert_eq!(probes.len(), 2);
assert!(probes.contains(&before));
# registry.shutdown(None).await;
# Ok(())
# }
```

`deterministic_probes` returns one probe per pending, active or decrypt-only deterministic version,
compromised ones included, so a query finds the rows encrypted under any of them, and a sweep the
rows encrypted under a compromised one. A staged version is probed before its promotion, so a
process that has not seen the promotion yet finds the values of the processes that have. Retired and
destroyed versions give no probe. The probes go into the query:

| Store | Query |
|---|---|
| PostgreSQL | `WHERE email_det = ANY($1)`, with the probes bound as a `BYTEA[]` |
| Firestore | an `in` filter on the field, which takes up to 30 values |
| BigQuery | `IN` over one `DETERMINISTIC_ENCRYPT` per version, each with that version's `Single` keyset, see [Queries](./bigquery.md#queries) |

After a promotion the list has two probes until a sweep re-encrypts every row and the old version is
retired. That is why deterministic versions are rotated rarely, and every rotation is followed by
a full sweep, see [Rotation cadence](../production/rotation.md#rotation-cadence).

Be aware a query with several probes puts the values of one plaintext under each version side by
side, so a reader of the query log links a value's history across a rotation.

A sweep re-encrypts a deterministic field with `reencrypt_deterministic`, as it re-encrypts a
randomised one with `reencrypt`, see [Re-encrypting a value](../production/sweeps.md#re-encrypting-a-value).

## BigQuery

BigQuery reads deterministic values with the keysets of `export_bigquery_keyset`, and a query
encrypts its probes in SQL with a `Single` keyset per version, see
[Exporting a keyset to BigQuery](./bigquery.md#exporting-a-keyset-to-bigquery).
