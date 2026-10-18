# Encrypted fields and AAD

## Encrypted values

A keyring value is kms-aead's `Encrypted<T, Randomized>`, re-exported by the keyring: the bytes
to store, which decrypt to a `T`. `T` is any type that implements `Plaintext`, usually an
application newtype such as `Email`, so a field names what it holds. Its layout is in
[Typed fields](../formats.md#typed-fields). The keyring seals and opens it with kms-aead's
`AeadCipher::encrypt_field` and `decrypt_field` under the key of the version, the calls an
application with [one fixed key](../envelope-encryption.md#one-fixed-key) makes itself.

- `value()` and `into_value()`, of `kms_aead::ValueStruct`, return the bytes;
- `KeyVersionId::try_from(&value)` returns the version that sealed it;
- `Encrypted::try_from(bytes)`, serde and tokio-postgres check stored bytes against the layout
  when the value is made, and fail on bytes that are no keyring value before any decryption;
- `decrypt` checks the key id first, and fails with `ReservedKeyId` on a reserved id and with
  `KeyPurposeMismatch` on a deterministic one, before any store or KMS call;
- `Debug` shows the length only. A randomised value has no `==`: two values of one plaintext
  differ.

The plaintext types and how they encode, which is fixed so that other readers, such as BigQuery,
decode them:

| Type | Encoding |
|---|---|
| `String` | UTF-8 |
| `Vec<u8>`, `SecretValue` | the bytes themselves |
| `bool` | `true` or `false` |
| `i32`, `i64`, `u32`, `u64` | decimal ASCII, which SQL reads with `CAST` |
| `Json<T>`, feature `serde-json` | the compact JSON of any serde type |

An application type implements `Plaintext` by mapping to one of them, as `Email` maps to `String`.
The decrypted value belongs to the application. Only `SecretValue` as `T` is zeroised on drop;
`String` and `Vec<u8>` take over the decrypted buffer without a copy.

## In application records

With the `serde` feature `Encrypted` serialises as bytes: a Firestore `bytes` value, and in
serde_json an array of numbers.

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadResult, Ring};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, Plaintext, Randomized,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq)]
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
# let keyring = Keyring::<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>::open_or_create(
#     MemoryKeyringStore::new(),
#     provider,
#     KeyringId::from_static("tenant-42"),
#     KeyringPolicy::new(),
#     KeyringOptions::new(),
# )
# .await?;
let id = EntityId::try_from("42")?;
let alice = Email("alice@example.com".to_string());
let user = User {
    id: "42".to_string(),
    email: keyring.encrypt(&EMAIL.aad(&id), &alice).await?,
};
let stored: Vec<u8> = serde_json::to_vec(&user)?;

let read: User = serde_json::from_slice(&stored)?;
let email: Email = keyring.decrypt(&EMAIL.aad(&id), &read.email).await?;
assert_eq!(email, alice);
# Ok(())
# }
```

### PostgreSQL

With the `postgres` feature `Encrypted` binds and decodes in tokio-postgres as a `BYTEA`, and a
slice of values as a `BYTEA[]` for `= ANY($1)`:

```rust,no_run
use kms_aead::providers::LocalKmsProvider;
use kms_aead::Ring;
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::{Encrypted, EntityId, FieldSpec, Keyring, Randomized};
use tokio_postgres::{Client, NoTls};
# use kms_aead::KmsAeadResult;
# use kms_aead_keyring::Plaintext;
# use secret_vault_value::SecretValue;
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
    let value: Encrypted<Email, Randomized> =
        keyring.encrypt(&field.aad(&EntityId::try_from(id)?), email).await?;
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

A column holding a value that is no keyring value fails in the decode, before any decryption.
kms-aead's `sqlx` feature binds `Encrypted` in sqlx the same way, see
[Storing typed fields](../envelope-encryption.md#storing-typed-fields).

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

So a value opens only in its own row and field. A value copied into another row fails with
`KeyringError::Kms` with code `DECRYPT`. And since the AAD names the logical place, not the
physical one, a value moves between tables and data stores without being encrypted again.

An `EntityId` can be personal data, so no span, event or error of the crate carries it.

Other AADs:

- `FieldAad::with_context(bytes)` appends `/` and any bytes, such as a schema version. A value
  sealed with a context opens only with the same one. The context may itself hold `/`, so keep the
  contexts of one field apart yourself;
- `FieldAad::custom(bytes)` takes any bytes, with no structure. SQL cannot rebuild such an AAD, so
  a field [BigQuery reads](./bigquery.md) cannot use it.

Deterministic fields have an AAD without the entity id, see
[Deterministic fields](./deterministic.md#aad), and beacons a context without it, see
[Beacons](./beacons.md).
