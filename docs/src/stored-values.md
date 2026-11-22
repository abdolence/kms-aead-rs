# Stored values

This page specifies the types that carry what the library writes to a data store and reads back,
and how they are stored. To encrypt the columns of a table, start with [Encrypt personal data and
secrets in your database](./use-cases/encrypt-fields.md). The bytes of each layout are in
[Values and DEKs](./formats/values.md).

Three types are involved:

- `Encrypted<T, F>`: an encrypted value that decrypts to a `T`, in the layout of the format `F`;
- `Beacon<T>`: a blind index of a `T`, stored beside its encrypted value for lookups;
- `Plaintext`: the trait of every `T`, which fixes the bytes a value is encrypted as.

The `T` is a type of the application, such as an `Email` newtype, so a column names what it
holds: `Encrypted<Email, Envelope>` and `Beacon<Email>`. Neither type holds a `T`, only the bytes
to store.

## `Encrypted<T, F>`

Every call that encrypts returns an `Encrypted<T, F>`. The format `F` comes from
`kms_aead::formats` and fixes the layout of the bytes:

| Format | Holds | Written by | Read by | `key_id()` | Equality |
|---|---|---|---|---|---|
| `Envelope` | the value and its encrypted DEK, in [Tink's KMS envelope](./formats/values.md#tinks-kms-envelope) | `KmsAeadEnvelope::encrypt` | `KmsAeadEnvelope::decrypt` | no | none |
| `Bare` | the AEAD output alone | `KmsAeadEnvelope::encrypt_with_dek`, `AeadCipher::encrypt_bare` | `KmsAeadEnvelope::decrypt_with_dek`, `AeadCipher::decrypt_bare` | no | none |
| `Randomized` | the AEAD output after a key id | `AeadCipher::encrypt`, `Encryptor::encrypt` | `AeadCipher::decrypt`, `Keyring::decrypt` | yes | none |
| `Deterministic` | the AES-SIV output after a key id | `DeterministicCipher::encrypt`, `Encryptor::encrypt_deterministic` | `DeterministicCipher::decrypt`, `Keyring::decrypt_deterministic` | yes | `==` and `Hash`, in constant time |

- `key_id()` returns the `KeyId` that the Tink output prefix names, the key to decrypt the value
  with. The prefix is the byte `0x01` and the key id, at the start of the value. It is not
  authenticated: a changed key id fails to decrypt;
- an `Envelope` value carries its encrypted DEK instead of a key id, and a `Bare` value names no
  key: the application keeps track of the key that decrypts it;
- the randomised formats encrypt equal plaintexts into different values, so they have no `==`.
  Compare `value()` to tell whether two values are the same stored bytes;
- only `Deterministic` values are equal for equal plaintexts under one key and one AAD, which is
  what a lookup by the encrypted value needs, see [Deterministic encryption](./deterministic.md);
- `Debug` shows the length only.

See [Formats of `Encrypted`](./formats/values.md#formats-of-encrypted) for the layout and the shortest
value of each format, and [Values written by 0.29 and
earlier](./migrating-from-0.29.md#values-written-by-029-and-earlier) for the legacy layouts, which
the library refuses.

### Bytes in and out

`value()` and `into_value()` return the bytes to store, and `to_hex_string()` returns them as
lowercase hex. The only ways back are `Encrypted::try_from` for bytes and
`Encrypted::try_from_hex_string` for hex in either case. Both check the bytes against the layout
of `F` before any KMS call, so a truncated or foreign value fails when it is read, with
`INVALID_CIPHER_TEXT_FORMAT`, `UNKNOWN_CIPHER_TEXT_LAYOUT`, `INVALID_HEX`, or `LEGACY_FORMAT` for
a legacy layout. The check reads the framing only: a changed value fails to decrypt with
`DECRYPT`.

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

`Encrypted` is stored as bytes, and read back through `TryFrom`, so a malformed stored value fails
in the decode:

- serde, in every build: `Serialize` and `Deserialize`, a `bytes` value in Firestore and an array
  of numbers in serde_json;
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
by equality without the plaintext or a decryption. The bytes are `0x01`, the key id and the
truncated HMAC, see [Beacons](./formats/values.md#beacons).

- `key_id()` returns the `KeyId` of the beacon key that calculated it, so that a column holds
  beacons of two keys during a re-index;
- `BeaconBits` sets how many bits of the HMAC a beacon keeps, see [Bits](./beacons.md#bits).
  `BeaconBits::new` returns `None` outside the range;
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

`Beacon<T>` is stored as `Encrypted` is, as bytes, with serde and the `postgres` and `sqlx`
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
beacons under key versions. [Find a user by an encrypted email](./use-cases/equality-lookups.md) puts
them to use.

## `Plaintext`

`Plaintext` maps a type to the bytes it is encrypted as, and back. Every `T` of `Encrypted<T, F>`
and `Beacon<T>` implements it. An application type implements it by mapping to one of the built-in
types, such as a newtype over `String` that is encrypted as the same UTF-8 bytes:

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
- text is encrypted as the same bytes as through `String`, so `AEAD.DECRYPT_STRING` still reads it;
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
| `i32`, `i64`, `u32`, `u64` | decimal ASCII, which SQL reads with `CAST` |
| `JsonEncoded<T>` | the compact JSON of any serde type |

A stored value is as long as its encoding plus a fixed overhead, so whoever reads the store reads
the length of the plaintext: the number of digits of an integer, the length of a string. There is
no impl for `bool` for this reason, since `true` and `false` differ in length. A type whose length
must not show pads its encoding to a fixed length in its own `Plaintext` impl.

- `decrypt` fails with `INVALID_PLAINTEXT` when the plaintext is not an encoding of `T`, and the
  error never quotes the bytes;
- the decrypted value belongs to the application, which protects it. Only `SecretValue` as `T` is
  zeroised on drop; `String` and `Vec<u8>` take over the decrypted buffer without a copy;
- a beacon is the HMAC of the encoded bytes, so normalisation, such as lowercasing an email, is
  the newtype's job, see [Beacons](./beacons.md).

`JsonEncoded<T>` encrypts a structured value of any serde type as its compact JSON, which BigQuery reads
with `AEAD.DECRYPT_STRING` and its JSON functions:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, JsonEncoded, KmsAeadEnvelope};
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

let address = JsonEncoded::new(Address {
    street: "Mannerheimintie 1".to_string(),
    city: "Helsinki".to_string(),
});
let encrypted: Encrypted<JsonEncoded<Address>, Envelope> =
    envelope.encrypt(b"users/1042/address", &address).await?;
let decrypted: JsonEncoded<Address> = envelope.decrypt(b"users/1042/address", &encrypted).await?;
assert_eq!(decrypted, address);
# Ok(())
# }
```

### JSON that does not decode

A plaintext that is not the JSON of its type, such as a record written by an older version of the
application, fails with `INVALID_PLAINTEXT` and logs a `WARN` event with an outline of the JSON.
By default the outline shows the shape: the type of every value, the nesting, and where serde_json
stopped reading. It shows no value and no length, since [a length gives away a hidden
boolean](https://docs.rs/kms-aead/latest/kms_aead/redaction/trait.JsonRedaction.html#associatedconstant.SIZES).

Finding the field that changed takes more. A type opts into it with a policy, the second type
parameter of `JsonEncoded`: a type of the application's own that implements
[`JsonRedaction`](https://docs.rs/kms-aead/latest/kms_aead/redaction/trait.JsonRedaction.html) and
sets the constants it needs. [Redaction policies](#redaction-policies) lists what each shows and
how [`FieldPaths`](https://docs.rs/kms-aead/latest/kms_aead/redaction/struct.FieldPaths.html) names a
field.

```rust
use kms_aead::redaction::{FieldPaths, JsonRedaction};
use kms_aead::JsonEncoded;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Customer {
    id: String,
    email: String,
    plan: String,
    renewal_date: String,
}

struct CustomerLog;

impl JsonRedaction for CustomerLog {
    const FIELD_NAMES: bool = true;
    const SIZES: bool = true;
    const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["id", "plan"]);
}

type CustomerJson = JsonEncoded<Customer, CustomerLog>;

let customer = CustomerJson::from(Customer {
    id: "cus_4821".to_string(),
    email: "ada.lovelace@example.com".to_string(),
    plan: "team".to_string(),
    renewal_date: "2027-03-01".to_string(),
});
```

`JsonEncoded::new` builds a value under the default policy, and `from` a value of a type with a
policy of its own. A record written when `plan` was a number logs this outline under the default
policy:

```text
{<key>: <string>, <key>: <string>, <key>: <number>, <key>: <string>}
```

and this under `CustomerLog`:

```text
89 bytes: {"id": "cus_4821", "email": <string, 24 chars>, "plan": 2, "renewal_date": <string, 10 chars>}
```

The outline names the field and the value that differs, and shows the length of the email and
nothing else of it. A plaintext is encrypted because it is secret, so a policy reveals codes and
identifiers only. A revealed value goes to the logs whenever the JSON does not decode: never reveal
personal data. `kms_aead::json=off` in an `EnvFilter` turns the event off. The event's fields are
in [Spans and events](./observability/spans-and-events.md#json-that-does-not-decode). `RedactedJson`
outlines any JSON the same way, with no encryption, see
[Log a webhook payload that failed to parse](./use-cases/log-json-payloads.md).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/encrypted_json.rs).

### Redaction policies

A policy `P` says what an outline shows. `JsonEncoded<T, P>` outlines the JSON that fails to decode
under it, and `RedactedJson::new::<P>(bytes)` outlines any bytes under it, with no encryption, see
[Log a webhook payload that failed to parse](./use-cases/log-json-payloads.md). A policy is a type of
the application's own that implements `JsonRedaction` and sets the constants it needs. Each
constant is off by default:

| Constant | Effect on the outline |
|---|---|
| `FIELD_NAMES` | shows the keys of objects, except the keys of `DATA_KEYED_MAPS` |
| `DATA_KEYED_MAPS` | lists the objects whose keys are data, such as a map from an email to a balance, so their keys stay hidden; `balances[]` names the values of the map `balances` |
| `SIZES` | shows the length of every hidden value and key, the length of the JSON and the line and column of the failure |
| `REVEALED_FIELDS` | shows the values of the listed fields, and the names of the fields on the way to each |

A path is the names of the fields joined by `.`, with `[]` after a field for every item of the array
it holds, such as `customer.plan` or `items[].sku`, and `[].id` for the items of an array at the top
level. A path takes in the whole value at its end. A field whose name has a `.`, `[` or `]` cannot
be named. A malformed path is a compile error in the build that uses the policy.

Bytes that do not start as JSON are outlined by their class: `empty`, `whitespace only`,
`hex digits`, `base64-like text`, `text` or `binary data`. The limits of an outline:

- the outline is one line of printable ASCII, 4 KiB at most, whatever the input;
- a revealed string is escaped, with `"`, `\`, `<`, `>` and every character outside printable ASCII
  written as JSON escapes, and cut after 64 bytes;
- the items of an array with the shape of the item before them print as a count, such as `<2 more
  of the same shape>`, and an array prints 8 items of different shapes at most;
- serde_json reads 128 levels of nesting at most.
