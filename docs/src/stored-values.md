# Stored values

Three types carry what the library writes to a data store and reads back:

- `Encrypted<T, F>`: an encrypted value that decrypts to a `T`, in the layout of the format `F`;
- `Beacon<T>`: a blind index of a `T`, stored beside its encrypted value for lookups;
- `Plaintext`: the trait of every `T`, which fixes the bytes a value is sealed as.

The `T` is a type of the application, such as an `Email` newtype, so a column names what it
holds: `Encrypted<Email, Envelope>` and `Beacon<Email>`. Neither type holds a `T`, only the bytes
to store.

## `Encrypted<T, F>`

Every call that encrypts returns an `Encrypted<T, F>`. The format `F` comes from
`kms_aead::formats` and fixes the layout of the bytes:

| Format | Layout | Written by | Read by | `key_id()` | Equality |
|---|---|---|---|---|---|
| `Envelope` | [Tink's KMS envelope](./formats.md#tinks-kms-envelope), the encrypted DEK inside | `KmsAeadEnvelope::encrypt` | `KmsAeadEnvelope::decrypt` | no | none |
| `Bare` | `[nonce: 12][ciphertext][tag: 16]` | `KmsAeadEnvelope::encrypt_with_dek`, `AeadCipher::encrypt_bare` | `KmsAeadEnvelope::decrypt_with_dek`, `AeadCipher::decrypt_bare` | no | none |
| `Randomized` | `[0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]` | `AeadCipher::encrypt`, `Sealer::encrypt` | `AeadCipher::decrypt`, `Keyring::decrypt` | yes | none |
| `Deterministic` | `[0x01][key id: u32 BE][synthetic IV: 16][ciphertext]` | `DeterministicCipher::encrypt`, `Sealer::encrypt_deterministic` | `DeterministicCipher::decrypt`, `Keyring::decrypt_deterministic` | yes | `==` and `Hash`, in constant time |

- `key_id()` returns the `KeyId` that the TINK prefix names, the key to open the value with. The
  prefix is not authenticated: a changed key id fails to decrypt;
- an `Envelope` value carries its encrypted DEK instead of a key id, and a `Bare` value names no
  key: the application keeps track of the key that opens it;
- the randomised formats seal equal plaintexts into different values, so they have no `==`.
  Compare `value()` to tell whether two values are the same stored bytes;
- only `Deterministic` values are equal for equal plaintexts under one key and one AAD, which is
  what a lookup by the encrypted value needs, see [Deterministic encryption](./deterministic.md);
- `Debug` shows the length only.

See [Formats of `Encrypted`](./formats.md#formats-of-encrypted) for the shortest value of each
layout and the layouts of 0.29 and earlier.

### Bytes in and out

`value()` and `into_value()` return the bytes to store, and `to_hex_string()` returns them as
lowercase hex. The only ways back are `Encrypted::try_from` for bytes and
`Encrypted::try_from_hex_string` for hex in either case. Both check the bytes against the layout
of `F` before any KMS call, so a truncated or foreign value fails when it is read, with
`INVALID_CIPHER_TEXT_FORMAT`, `UNKNOWN_CIPHER_TEXT_LAYOUT`, `INVALID_HEX`, or `LEGACY_FORMAT` for
a layout of 0.29 or earlier without the `legacy-formats` feature. The check reads the framing
only: a changed value fails to decrypt with `DECRYPT`.

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Randomized;
use kms_aead::{AeadAlgorithm, AeadCipher, Encrypted, KeyId};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
let dek = cipher.generate_dek()?;
let encrypted: Encrypted<SecretValue, Randomized> =
    cipher.encrypt(KeyId::new(1), b"users/1042/token", &SecretValue::from("token"), &dek)?;

// The key the prefix names
assert_eq!(encrypted.key_id(), KeyId::new(1));

// Hex for a text column, bytes for a binary one
let stored_hex: String = encrypted.to_hex_string();
let stored: Vec<u8> = encrypted.into_value();

let from_bytes = Encrypted::<SecretValue, Randomized>::try_from(stored)?;
let from_hex = Encrypted::<SecretValue, Randomized>::try_from_hex_string(&stored_hex)?;
assert_eq!(from_bytes.value(), from_hex.value());

// A prefix with nothing after it is no randomised value
assert!(Encrypted::<SecretValue, Randomized>::try_from(vec![0x01, 0, 0, 0, 1]).is_err());
# Ok(())
# }
```

### Storing

Three features store `Encrypted` as bytes, and each one reads it back through `TryFrom`, so a
malformed stored value fails in the decode:

- `serde`: `Serialize` and `Deserialize`, a `bytes` value in Firestore and an array of numbers in
  serde_json;
- `postgres`: `ToSql` and `FromSql` of postgres-types, for tokio-postgres, as `BYTEA`, and a
  slice as `BYTEA[]` for `= ANY($1)`;
- `sqlx`: sqlx's `Type`, `Encode`, `Decode` and `PgHasArrayType` for PostgreSQL, as `BYTEA`. It
  depends on `sqlx-core` and `sqlx-postgres` only, so the application chooses sqlx's runtime and
  TLS stack.

A field of a serde record, here in JSON:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use serde::{Deserialize, Serialize};
# use kms_aead::{KmsAeadResult, Plaintext};
# use secret_vault_value::SecretValue;
# #[derive(Debug, Clone, PartialEq)]
# struct Email(String);
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> { self.0.to_plaintext() }
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }

#[derive(Serialize, Deserialize)]
struct User {
    id: i64,
    email: Encrypted<Email, Envelope>,
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let email = Email("alice@example.com".to_string());
let user = User {
    id: 1042,
    email: envelope.encrypt(b"users/1042/email", &email).await?,
};

let json: String = serde_json::to_string(&user)?;
let read_back: User = serde_json::from_str(&json)?;
let decrypted: Email = envelope.decrypt(b"users/1042/email", &read_back.email).await?;
assert_eq!(decrypted, email);
# Ok(())
# }
```

A `BYTEA` column, with sqlx:

```rust,no_run
use kms_aead::formats::Envelope;
use kms_aead::Encrypted;
use sqlx::PgPool;

# #[derive(Clone)]
# struct Email(String);
async fn store(pool: &PgPool, id: i64, email: &Encrypted<Email, Envelope>) -> sqlx::Result<()> {
    sqlx::query("INSERT INTO users (id, email) VALUES ($1, $2)")
        .bind(id)
        .bind(email)
        .execute(pool)
        .await?;
    Ok(())
}

async fn load(pool: &PgPool, id: i64) -> sqlx::Result<Encrypted<Email, Envelope>> {
    sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
}
```

A `TEXT` column, as hex, with tokio-postgres:

```rust,no_run
use kms_aead::formats::Envelope;
use kms_aead::Encrypted;
use tokio_postgres::Client;

# #[derive(Clone)]
# struct Email(String);
async fn store(
    client: &Client,
    id: i64,
    email: &Encrypted<Email, Envelope>,
) -> Result<(), tokio_postgres::Error> {
    let email_hex: String = email.to_hex_string();
    client
        .execute("UPDATE users SET email_hex = $1 WHERE id = $2", &[&email_hex, &id])
        .await?;
    Ok(())
}

async fn load(
    client: &Client,
    id: i64,
) -> Result<Encrypted<Email, Envelope>, Box<dyn std::error::Error>> {
    let row = client
        .query_one("SELECT email_hex FROM users WHERE id = $1", &[&id])
        .await?;
    let email_hex: String = row.try_get("email_hex")?;
    Ok(Encrypted::<Email, Envelope>::try_from_hex_string(&email_hex)?)
}
```

Hex takes twice the space of the bytes. Use it where the data store has no binary type, or where
the value travels as text.

## `Beacon<T>`

A beacon, or blind index, is a truncated HMAC-SHA256 of a `T`'s plaintext under a beacon key. It is
stored beside the field's encrypted value, which stays randomised, and a data store matches it
by equality without the plaintext or a decryption:

```text
[0x01][key id: u32 BE][HMAC-SHA256: the first ceil(bits / 8) bytes]
```

- `0x01` is the version of the beacon layout;
- `key_id()` returns the `KeyId` of the beacon key that calculated it, so that a column holds
  beacons of two keys during a re-index;
- `BeaconBits` sets how many bits of the HMAC a beacon keeps, 1 to 256, `BeaconBits::DEFAULT`,
  16, unless set. `BeaconBits::new` returns `None` outside that range;
- `value()` and `into_value()` return the bytes to store, and `Beacon::try_from` reads them back,
  failing with `INVALID_BEACON_FORMAT` on bytes of another layout;
- `==` and `Hash` compare the bytes, `==` in constant time, and `Debug` shows the key id only.

```rust
use kms_aead::backends::Ring;
use kms_aead::{Beacon, BeaconAlgorithm, BeaconBits, BeaconMac, KeyId};
# use kms_aead::{KmsAeadResult, Plaintext};
# use secret_vault_value::SecretValue;
# #[derive(Debug, Clone, PartialEq)]
# struct Email(String);
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> { self.0.to_plaintext() }
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }

# fn main() -> KmsAeadResult<()> {
let mac = BeaconMac::<Ring>::new(BeaconAlgorithm::HmacSha256)?;
let beacon_key = mac.generate_dek()?;

let email = Email("alice@example.com".to_string());
let beacon: Beacon<Email> =
    mac.beacon(KeyId::new(1), b"users/email", BeaconBits::DEFAULT, &email, &beacon_key)?;

// [0x01][key id: 4 bytes][16 bits of HMAC: 2 bytes]
assert_eq!(beacon.key_id(), KeyId::new(1));
assert_eq!(beacon.value().len(), 7);

let read_back = Beacon::<Email>::try_from(beacon.value().to_vec())?;
assert_eq!(read_back, beacon);
# Ok(())
# }
```

The bits trade lookups against leakage, see [Bits](./beacons.md#bits).

`Beacon<T>` is stored as `Encrypted` is, as bytes, with the `serde`, `postgres` and `sqlx`
features. A lookup matches the column by equality, so it gets an ordinary index:

```sql
CREATE TABLE users (
  id BIGINT PRIMARY KEY,
  email BYTEA NOT NULL,
  email_beacon BYTEA NOT NULL
);
CREATE INDEX users_email_beacon ON users (email_beacon);
```

```rust,no_run
use kms_aead::formats::Envelope;
use kms_aead::{Beacon, Encrypted};
use tokio_postgres::Client;

# #[derive(Clone)]
# struct Email(String);
// The candidates for one email, which the application decrypts and filters
async fn candidates(
    client: &Client,
    beacon: &Beacon<Email>,
) -> Result<Vec<Encrypted<Email, Envelope>>, tokio_postgres::Error> {
    let rows = client
        .query("SELECT email FROM users WHERE email_beacon = $1", &[beacon])
        .await?;
    rows.iter().map(|row| row.try_get("email")).collect()
}
```

See [Beacons](./beacons.md) for calculating beacons with a KMS-encrypted beacon key, the context,
normalisation and key rotation, and [Beacons](./keyring/beacons.md) in kms-aead-keyring for
beacons under key versions.

## `Plaintext`

`Plaintext` maps a type to the bytes it is sealed as, and back. Every `T` of `Encrypted<T, F>` and
`Beacon<T>` implements it. An application type implements it by mapping to one of the built-in
types, such as a newtype over `String` that is sealed as the same UTF-8 bytes:

```rust
use kms_aead::{KmsAeadResult, Plaintext};
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

# fn main() -> KmsAeadResult<()> {
let email = Email("alice@example.com".to_string());
assert_eq!(Email::from_plaintext(email.to_plaintext()?)?, email);
# Ok(())
# }
```

A newtype over `SecretValue` is written the same way:

```rust
use kms_aead::{KmsAeadResult, Plaintext};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(SecretValue);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(self.0.clone())
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        Ok(Email(plaintext))
    }
}

# fn main() -> KmsAeadResult<()> {
let email = Email(SecretValue::from("alice@example.com"));
let decrypted: Email = Email::from_plaintext(email.to_plaintext()?)?;
assert_eq!(decrypted.0.as_sensitive_str(), "alice@example.com");
# Ok(())
# }
```

It differs from the `String` newtype as follows:

- the decrypted value is zeroised on drop, and `Debug` prints `***` instead of it;
- text is sealed as the same bytes as through `String`, so `AEAD.DECRYPT_STRING` still reads it;
- there is no UTF-8 check on read, so bytes that are not UTF-8 decrypt without an error;
- the text is reached through `SecretValue`'s accessors rather than as a `&str`:
  `as_sensitive_str()`, which panics on bytes that are not UTF-8, or `sensitive_value_to_str()`,
  which returns an error.

`SecretValue` suits values that are secrets or personal data, and `String` values that are used as
text throughout.

The built-in types encode as follows. The encodings are fixed, so that other readers of the same
values, such as BigQuery's `AEAD.DECRYPT_STRING`, decode them:

| Type | Encoding |
|---|---|
| `String` | UTF-8 |
| `Vec<u8>`, `SecretValue` | the bytes themselves |
| `bool` | `true` or `false` |
| `i32`, `i64`, `u32`, `u64` | decimal ASCII, which SQL reads with `CAST` |
| `Json<T>`, feature `serde-json` | the compact JSON of any serde type |

- `decrypt` fails with `INVALID_PLAINTEXT` when the plaintext is not an encoding of `T`, and the
  error never quotes the bytes;
- the decrypted value belongs to the application, which protects it. Only `SecretValue` as `T` is
  zeroised on drop; `String` and `Vec<u8>` take over the decrypted buffer without a copy;
- a beacon is the HMAC of the encoded bytes, so normalisation, such as lowercasing an email, is
  the newtype's job, see [Beacons](./beacons.md).

`Json<T>` seals a structured value of any serde type as its compact JSON, which BigQuery reads with
`AEAD.DECRYPT_STRING` and its JSON functions:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, Json, KmsAeadEnvelope};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
struct Address {
    street: String,
    city: String,
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let address = Json(Address {
    street: "Mannerheimintie 1".to_string(),
    city: "Helsinki".to_string(),
});
let encrypted: Encrypted<Json<Address>, Envelope> =
    envelope.encrypt(b"users/1042/address", &address).await?;
let decrypted: Json<Address> = envelope.decrypt(b"users/1042/address", &encrypted).await?;
assert_eq!(decrypted, address);
# Ok(())
# }
```
