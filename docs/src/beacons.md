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
    KmsAeadResult, Plaintext,
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
let (_, encrypted_dek) = BeaconMac::<Ring>::new(BeaconAlgorithm::HmacSha256)?
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
- the key id, a `KeyId`, is the application's number for the beacon key, written into every
  beacon so that a column can hold beacons of two keys at once;
- the beacon key is decrypted through the envelope's DEK cache, as a DEK is.

`Beacon<T>` is stored as `Encrypted` is, with serde and the `postgres` and `sqlx` features, and
read back through `TryFrom`, which checks its layout, see [Stored values](./stored-values.md#beacont).
See [Formats](./formats.md#beacons) for its bytes.

A message authentication code (MAC) over a value's bytes, which is not truncated and never serves
a lookup, is in [Beacons and MACs](./signing.md#beacons-and-macs).

## What a beacon leaks

A beacon column leaks to anyone who reads it, without any key:

- **Equality**: which rows are likely to hold the same value;
- **Frequency**: how often each value occurs, as far as the bits tell values apart.

And a leaked beacon key lets its holder test candidate values against the whole column offline.

So beacons fit fields that are looked up and have many distinct values, such as emails and
external ids. Do not use them for low-cardinality fields, such as a status, a country or a yes/no
answer, whose values the frequencies give away.

## Bits

`BeaconBits` sets how many bits of the HMAC a beacon keeps, 1 to 256; `BeaconBits::DEFAULT` is 16.
With `n` distinct values in a column and `b` bits, about `n / 2^b` values share each
beacon:

- fewer bits: more values share a beacon, so a lookup returns more rows, which the application
  decrypts and filters by the plaintext. A column of short beacons leaks less;
- more bits: fewer rows to filter, down to one per value once `2^b` is far above `n`, and the
  column then leaks which rows hold equal values as a deterministic column does.

An equal beacon never proves an equal value: a lookup always decrypts the rows it found and
compares the plaintexts. The bits enter the HMAC, so beacons of one value under different bits
never match: after a change of a column's bits, its stored beacons match no lookup until a
re-index computes them again. The numbers of the default for a column of 1,000,000 emails are in
[Find rows by an encrypted value](./use-cases/equality-lookups.md).

## Normalisation

A beacon is the HMAC of the bytes the `Plaintext` type encodes, so `Alice@Example.com` and
`alice@example.com` give different beacons unless the type normalises the value. Normalising is the
application's job: the newtype normalises when it is made, as `Email::new` lowercases above, and
every write and every lookup goes through it.

## BigQuery

BigQuery's SQL has no HMAC-SHA256 with a KMS-encrypted DEK, so a query in BigQuery cannot calculate
a beacon. It matches beacons the application calculated and passed in as query parameters.

## Rotating a beacon key

Rotating a beacon key in store-less mode is manual. Generate the new key and keep both, write
beacons under the new one, query with a beacon under each key until a re-index has rewritten
every stored beacon, then drop the old key. `Beacon::key_id` tells which key wrote a stored
beacon. kms-aead-keyring does this with key versions, see [Beacons](./keyring/beacons.md).
