# Beacons

A beacon, or blind index, finds rows by a field's value without decrypting the column: an
HMAC-SHA256 of the value under a beacon key, truncated, stored beside the encrypted field. A
query calculates the beacon of the value it looks for and matches it by equality. `Beacon<T>` holds
the bytes to store, and the beacon key is a 32-byte key encrypted by the KMS, as a DEK is:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{
    Beacon, BeaconAlgorithm, BeaconBits, BeaconMac, Encrypted, KeyId, KmsAeadEnvelope,
    KmsAeadResult, KmsEncryptedDek, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

// The application's id of its beacon key, which every beacon names
const EMAIL_BEACON_KEY: KeyId = KeyId::new(1);

impl Email {
    // The beacon of an email matches regardless of case
    fn new(email: &str) -> Self {
        Email(email.to_lowercase())
    }
}

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

// Once, by an administrative job: the beacon key, stored beside the application's settings
let (_, KmsEncryptedDek { encrypted_dek, .. }) =
    BeaconMac::<Ring>::new(BeaconAlgorithm::HmacSha256)
        .generate_encrypted_dek(envelope.provider())
        .await?;

// On every write: the field and its beacon
let email = Email::new("Alice@Example.com");
let encrypted: Encrypted<Email, Envelope> =
    envelope.encrypt(b"users/1042/email", &email).await?;
let beacon: Beacon<Email> = envelope
    .beacon(EMAIL_BEACON_KEY, b"users/email", BeaconBits::DEFAULT, &email, &encrypted_dek)
    .await?;

// A lookup: the beacon of the value looked for, then a decryption of each matching row
let probe: Beacon<Email> = envelope
    .beacon(
        EMAIL_BEACON_KEY,
        b"users/email",
        BeaconBits::DEFAULT,
        &Email::new("alice@example.com"),
        &encrypted_dek,
    )
    .await?;
assert_eq!(probe, beacon);
let decrypted: Email = envelope.decrypt(b"users/1042/email", &encrypted).await?;
assert_eq!(decrypted, email);
# Ok(())
# }
```

- the context, `users/email` here, names the field and never a row, so that equal values in one
  field give equal beacons. A beacon of one field never matches a beacon of another;
- `BeaconBits` sets how much of the HMAC a beacon keeps, 1 to 256 bits, 16 by default. With `n`
  distinct values and `b` bits, about `n / 2^b` values share each beacon: a lookup returns that
  many rows, which the application decrypts and filters, and an equal beacon never proves an
  equal value. More bits leak more; fewer bits return more rows to filter;
- normalisation is the application's: the beacon of `Alice@Example.com` and of
  `alice@example.com` differ unless the type normalises the value before it is sealed, as
  `Email::new` does;
- the key id, a `KeyId`, is the application's number for the beacon key, written into every
  beacon so that a column can hold beacons of two keys at once;
- the beacon key is decrypted through the envelope's DEK cache, as a DEK is.

A beacon column leaks which rows are likely to hold equal values, and with them how often each
value occurs, to anyone who reads the column. A leaked beacon key lets its holder test guesses
against the whole column offline. Beacons fit fields that are looked up and have many distinct
values, such as emails and external ids, and never low-cardinality fields such as a status or a
country. BigQuery's SQL has no HMAC-SHA256 with a KMS-encrypted DEK, so a query in BigQuery
cannot calculate a beacon; it matches beacons the application calculated.

Rotating a beacon key in store-less mode is manual. Generate the new key and keep both, write
beacons under the new one, query with a beacon under each key until a re-index has rewritten
every stored beacon, then drop the old key. `Beacon::key_id` tells which key wrote a stored
beacon. kms-aead-keyring does this with key versions, see [Beacons](./keyring/beacons.md).

`Beacon<T>` is stored as `Encrypted` is, with the `serde`, `postgres` and `sqlx` features, and
read back through `TryFrom`, which checks its layout, see [Stored values](./stored-values.md#beacont).
See [Formats](./formats.md#beacons) for its bytes.

## Beacon or deterministic field

A [deterministic field](./deterministic.md) also finds rows by equality, by its cipher text:

| | Beacon | Deterministic field |
|---|---|---|
| Stored value | Randomised, so its AAD can name the row, and a value copied into another row fails to open | Equal for equal values, so its AAD names the field and never the row, and a value copied into another row opens there |
| Match | The truncated HMAC, with deliberate collisions | Always the exact value |
| Key | A beacon key, rotated separately from the data keys | The field's own key |
| Cost | An extra column, and a decryption and filter of the candidates on every lookup | Nothing beyond the field |
| BigQuery | SQL cannot calculate a beacon; it matches beacons the application calculated | SQL decrypts the field and searches it by equality |

With the default 16 bits, there are 65,536 possible beacons. A column of 1,000,000 distinct
emails gives about 1,000,000 / 65,536, or 15, emails per beacon, so a lookup of one email returns
about 15 rows. The application decrypts them and keeps the one equal to the email it looks for.
