# Encrypted fields and AAD

## Encrypted values

A keyring value is kms-aead's [`Encrypted<T, Randomized>`](../stored-values.md#encryptedt-f),
re-exported by the keyring: the bytes to store, which decrypt to a `T`. `T` is any type that
implements `Plaintext`, usually an application newtype such as `Email`, so a field names what it
holds. Its layout is in [Formats of `Encrypted`](../formats.md#formats-of-encrypted). The keyring
encrypts and decrypts it with kms-aead's `AeadCipher::encrypt` and `decrypt` under the key of the
version, the calls an application with [one fixed key](../envelope-encryption.md#one-fixed-key)
makes itself.

- `value()` and `into_value()` return the bytes;
- `key_id()` returns the key id of the version that encrypted it;
- `Encrypted::try_from(bytes)`, serde and tokio-postgres check stored bytes against the layout
  when the value is made, and fail on bytes that are no keyring value before any decryption;
- `decrypt` checks the key id first, and fails with `ReservedKeyId` on a reserved id and with
  `KeyPurposeMismatch` on a deterministic one, before any store or KMS call;
- `Debug` shows the length only. A randomised value has no `==`: two values of one plaintext
  differ.

The plaintext types and their encodings are in [Stored values](../stored-values.md#plaintext).

## In application records

`Encrypted` is stored as bytes, with serde and the `postgres` and `sqlx` features, see
[Storing](../stored-values.md#storing). A field of a serde record:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringAlgorithms, KeyringId,
    KeyringRegistry, KeyringRegistryOptions, Plaintext,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    email: Encrypted<Email, Randomized>,
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# use kms_aead_keyring::KeyringAdmin;
# let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .create(provider, KeyringId::from_static("tenant-42"), KeyringAlgorithms::new())
#     .await?;
# let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();
let id = EntityId::try_from("42")?;
let alice = Email("alice@example.com".to_string());
let user = User {
    id: "42".to_string(),
    email: keyring.encryptor().await.encrypt(&EMAIL.aad(&id), &alice).await?,
};
let stored: Vec<u8> = serde_json::to_vec(&user)?;

let read: User = serde_json::from_slice(&stored)?;
let email: Email = keyring.decrypt(&EMAIL.aad(&id), &read.email).await?;
assert_eq!(email, alice);
# registry.shutdown(None).await;
# Ok(())
# }
```

### PostgreSQL

A `BYTEA` column, with tokio-postgres:

```rust,no_run
use kms_aead::backends::Ring;
use kms_aead::providers::LocalKmsProvider;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::{Encrypted, EntityId, FieldSpec, Keyring};
use tokio_postgres::{Client, NoTls};
# use kms_aead::KmsAeadResult;
# use kms_aead_keyring::Plaintext;
# use secret_vault_value::SecretValue;
# #[derive(Clone)]
# struct Email(String);
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> { self.0.to_plaintext() }
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }

type TenantKeyring = Keyring<PostgresKeyringStore<NoTls>, LocalKmsProvider<Ring>, Ring>;

async fn store_email(
    client: &Client,
    keyring: &TenantKeyring,
    field: &FieldSpec,
    id: &str,
    email: &Email,
) -> Result<(), Box<dyn std::error::Error>> {
    let value: Encrypted<Email, Randomized> = keyring
        .encryptor()
        .await
        .encrypt(&field.aad(&EntityId::try_from(id)?), email)
        .await?;
    client
        .execute("UPDATE users SET email = $1 WHERE id = $2", &[&value, &id])
        .await?;
    Ok(())
}

async fn email_of(
    client: &Client,
    keyring: &TenantKeyring,
    field: &FieldSpec,
    id: &str,
) -> Result<Email, Box<dyn std::error::Error>> {
    let row = client
        .query_one("SELECT email FROM users WHERE id = $1", &[&id])
        .await?;
    let value: Encrypted<Email, Randomized> = row.try_get("email")?;
    Ok(keyring.decrypt(&field.aad(&EntityId::try_from(id)?), &value).await?)
}
# fn main() {}
```

A column holding a value that is no keyring value fails in the decode, before any decryption. The
keyring's `sqlx` feature binds `Encrypted` and `EncryptionMarker` in sqlx the same way, as `BYTEA` on
PostgreSQL, and turns on kms-aead's `sqlx` feature, so the application needs no kms-aead dependency
line for it, see [Stored values](../stored-values.md#storing).

## AAD

The default AAD of a value is its place in the application's model, `<kind>/<id>/<field>`, such
as `user/42/email`:

- `EntityKind`, such as `user`;
- `EntityId`, the row's id, which binds the value to its row;
- `FieldName`, such as `email`.

Each part is 1 to 255 bytes of UTF-8 without `/`, NUL or another ASCII control character. An id
that holds `/` is encoded by the application first, with percent-encoding for example.

A `FieldSpec` names the kind and the field once, as a constant, and `FieldSpec::aad(&id)` builds
the AAD of one row. `from_static` checks a kind or field name at compile time when it
initialises a constant.

So a value decrypts only in its own row and field. A value copied into another row fails with
`KeyringError::KmsAead` with code `DECRYPT`. And since the AAD names the logical place, not the
physical one, a value moves between tables and data stores without being encrypted again.

An `EntityId` can be personal data, so no span, event or error of the crate carries it.

Deterministic fields have an AAD without the entity id, see
[Deterministic fields](./deterministic.md#aad), and beacons a context without it, see
[Beacons](./beacons.md).

## Why the AAD is structured

kms-aead's `AeadCipher` and `KmsAeadEnvelope` take the AAD as any `impl AsRef<[u8]>`: the
application chooses the bytes and rebuilds them itself on every read. The keyring's `encrypt` and
`decrypt` take a `FieldAad` instead, which only a `FieldSpec` builds:

- field binding: the default AAD names the kind and the field, so a value copied into another
  field of the same row fails to decrypt;
- row binding: it names the entity id, so a value copied into another row fails to decrypt. The
  application's own id, such as a user id, is the `EntityId`;
- deterministic fields: a deterministic AAD must not hold the row id, or equal plaintexts in
  different rows give different values and equality lookups never match. `DeterministicAad` is a
  separate type, with no entity id and no constructor from arbitrary bytes, see
  [Deterministic fields](./deterministic.md#aad);
- BigQuery: BigQuery decrypts in SQL, so the AAD has to be one SQL can rebuild from the row.
  `<kind>/<id>/<field>` is this crate's convention, which `CONCAT('user/', u.id, '/email')`
  rebuilds; BigQuery itself prescribes no format;
- Tink: Tink takes any AAD bytes. The requirements of a Tink field are on the algorithm and the
  KEK, not on the AAD;
- the interop requirement: a `FieldAad` carries the `Interop` of its `FieldSpec`, so encrypting
  checks the field's requirements whichever way the AAD was built. Free bytes would name no field
  and skip that check.

| AAD | Built by | Field binding | Row binding | BigQuery reads it | Interop checked |
|-----|----------|---------------|-------------|-------------------|-----------------|
| Free bytes | kms-aead's `AeadCipher`, `KmsAeadEnvelope` | if the bytes name the field | if the bytes name the row | if SQL rebuilds the bytes | no |
| Default | `spec.aad(&id)` | yes | yes | yes | yes |
| With a context | `spec.aad(&id).with_context(bytes)` | yes | yes | yes, with the same bytes appended in SQL | yes |
| Custom | `spec.custom_aad(bytes)` | if the bytes name the field | if the bytes name the row | no, refused | yes |
| Deterministic | `spec.deterministic_aad()` | yes | no, so that equal values match | yes | yes |

## The application's own context

There are three ways to put the application's own data, such as a user id or a tenant, into the
AAD:

- `spec.aad(&id)` with the application's id as the `EntityId`. The id follows the `EntityId`
  rules: 1 to 255 bytes of UTF-8 without `/`, NUL or another ASCII control character. It is
  treated as personal data and never logged;
- `FieldAad::with_context(bytes)` appends `/` and any bytes, such as a tenant or a schema version. A
  value encrypted with a context decrypts only with the same one. The context may itself hold `/`,
  so keep the contexts of one field apart yourself. A BigQuery reader appends the same bytes in SQL,
  `CONCAT('user/', u.id, '/email/tenant-7')`;
- `FieldSpec::custom_aad(bytes)` takes any bytes, with no structure, in place of the default AAD.
  It gives up field binding and row binding, unless the bytes name the field and the row
  themselves, and BigQuery readability: on a field declared with `Interop::BigQuery` it fails with
  `KeyringError::CustomAadUnsupported`, since SQL cannot rebuild such bytes. On a Tink field or a
  field without interop it keeps the field's algorithm and KEK checks.

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldAad, FieldName, FieldSpec, Interop, Keyring,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions,
};

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# use kms_aead_keyring::KeyringAdmin;
# let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .create(provider, KeyringId::from_static("tenant-42"), KeyringAlgorithms::new())
#     .await?;
# let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();
let user_id: u64 = 4711;
let id: EntityId = EntityId::try_from(user_id.to_string())?;
let email: String = "alice@example.com".to_string();

// user/4711/email
let default_aad: FieldAad = EMAIL.aad(&id);
// user/4711/email/tenant-7
let with_context: FieldAad = EMAIL.aad(&id).with_context(b"tenant-7");
// signup/4711, bound to neither the field nor the kind
let custom: FieldAad = EMAIL.custom_aad(format!("signup/{user_id}").as_bytes())?;

for aad in [default_aad, with_context, custom] {
    let value: Encrypted<String, Randomized> = keyring.encryptor().await.encrypt(&aad, &email).await?;
    assert_eq!(keyring.decrypt(&aad, &value).await?, email);
}

let bigquery_email: FieldSpec = EMAIL.with_interop(Interop::BigQuery);
assert!(matches!(
    bigquery_email.custom_aad(b"signup/4711"),
    Err(KeyringError::CustomAadUnsupported(Interop::BigQuery))
));
# registry.shutdown(None).await;
# Ok(())
# }
```
