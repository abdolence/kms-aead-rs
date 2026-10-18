# Encrypted fields and AAD

## Encrypted values

`Encrypted<T>` is a keyring value that decrypts to a `T`: the bytes to store, in
[Tink's wire format](./bigquery.md#wire-format). `key_id()` is the version that sealed it, and
`as_bytes()` the bytes.

A value read from storage is checked when it is made, with `Encrypted::try_from(bytes)`, by serde
or by sqlx: bytes that are no keyring value, or a value of the other purpose, fail there with
`ValueLayout` or `KeyPurposeMismatch`, before any store or KMS call. Its `Debug` shows the key id
only, and its equality compares the bytes in constant time.

The plaintext types and how they encode, which is fixed so that other readers, such as BigQuery,
decode them:

| Type | Encoding |
|---|---|
| `String` | UTF-8 |
| `Vec<u8>`, `SecretValue` | the bytes themselves |
| `bool` | `true` or `false` |
| `i32`, `i64`, `u32`, `u64` | decimal ASCII, which SQL reads with `CAST` |
| `Json<T>`, feature `serde-json` | the compact JSON of any serde type |

The decrypted value belongs to the application. Only `SecretValue` as `T` is zeroized on drop;
`String` and `Vec<u8>` take over the decrypted buffer without a copy.

## In application records

With the `serde` feature `Encrypted` serializes as bytes: a Firestore `bytes` value, and in
serde_json an array of numbers.

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy,
};
use serde::{Deserialize, Serialize};

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[derive(Serialize, Deserialize)]
struct User {
    id: String,
    email: Encrypted<String>,
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?, AeadBackend::Ring)?;
# let keyring = Keyring::open_or_create(
#     MemoryKeyringStore::new(),
#     provider,
#     AeadBackend::Ring,
#     KeyringId::from_static("tenant-42"),
#     KeyringPolicy::new(),
#     KeyringOptions::new(),
# )
# .await?;
let id = EntityId::try_from("42")?;
let user = User {
    id: "42".to_string(),
    email: keyring
        .encrypt(&EMAIL.aad(&id), &"alice@example.com".to_string())
        .await?,
};
let stored = serde_json::to_vec(&user)?;

let read: User = serde_json::from_slice(&stored)?;
let email = keyring.decrypt(&EMAIL.aad(&id), &read.email).await?;
assert_eq!(email, "alice@example.com");
# Ok(())
# }
```

### PostgreSQL

With the `postgres` feature `Encrypted` binds and decodes as a `BYTEA`, and a slice of values as a
`BYTEA[]` for `= ANY($1)`:

```rust,no_run
use kms_aead_keyring::{Encrypted, EntityId, FieldSpec, Keyring};
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead::providers::LocalKmsProvider;
use sqlx::postgres::PgPool;

async fn email_of(
    pool: &PgPool,
    keyring: &Keyring<PostgresKeyringStore, LocalKmsProvider>,
    email: &FieldSpec,
    id: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let value: Encrypted<String> =
        sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(id)
            .fetch_one(pool)
            .await?;
    Ok(keyring.decrypt(&email.aad(&EntityId::try_from(id)?), &value).await?)
}
# fn main() {}
```

A column holding a value that is no keyring value fails in the decode, before any decrypt.

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
initializes a constant.

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
[Deterministic fields](./deterministic.md#aad).
