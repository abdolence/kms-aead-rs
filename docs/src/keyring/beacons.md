# Beacons

A beacon, or blind index, finds rows by a field's value without decrypting the column: a
truncated HMAC-SHA256 of the value, stored beside the field's randomised value, which a data store
matches by equality. The keyring computes beacons under its beacon versions, of the purpose
`Purpose::Beacon`, which rotate like any other.

kms-aead's [Beacons](../envelope-encryption.md#beacons) describes the primitive, `Beacon<T>`
and `BeaconBits`, with keys the application keeps itself, and [Formats](../formats.md#beacons) its
bytes.

## What a beacon leaks

A beacon column leaks to anyone who reads it, without any key:

- **Equality**: which rows are likely to hold the same value;
- **Frequency**: how often each value occurs, as far as the bits tell values apart.

And a leaked beacon key lets its holder test candidate values against the whole column offline.

So beacons fit fields that are looked up and have many distinct values, such as emails and
external ids. Do not use them for low-cardinality fields, such as a status, a country or a yes/no
answer, whose values the frequencies give away.

A beacon is computed in a field's context, `<kind>/<field>` such as `user/email`, with no entity
id: equal values in different rows give equal beacons, which is what a lookup matches. A beacon of
one field never matches a beacon of another.

## Usage

A keyring with beacon versions names the algorithm in its policy, HMAC-SHA256, the one
`BeaconAlgorithm` has. `beacon` computes the beacon of a value under the active beacon version, and
`beacon_probes` the beacons of a value under every beacon version a lookup matches:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Beacon, BeaconAlgorithm, BeaconBits, KmsAeadResult, Ring};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, Plaintext, Randomized,
};
use secret_vault_value::SecretValue;

#[derive(Debug, PartialEq)]
struct Email(String);

impl Email {
    // Beacons of one address match regardless of case
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

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_beacon_bits(BeaconBits::DEFAULT);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let keyring = Keyring::<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>::open_or_create(
    MemoryKeyringStore::new(),
    provider,
    KeyringId::from_static("tenant-42"),
    KeyringPolicy::new().with_beacon_algorithm(BeaconAlgorithm::HmacSha256),
    KeyringOptions::new(),
)
.await?;

// On every write: the field and its beacon
let aad = EMAIL.aad(&EntityId::try_from("42")?);
let email = Email::new("Alice@Example.com");
let encrypted: Encrypted<Email, Randomized> = keyring.encrypt(&aad, &email).await?;
let beacon: Beacon<Email> = keyring.beacon(&EMAIL, &email).await?;

// A lookup: the probes of the value looked for, then a decrypt of each matching row
let probes: Vec<Beacon<Email>> = keyring
    .beacon_probes(&EMAIL, &Email::new("alice@example.com"))
    .await?;
assert!(probes.contains(&beacon));
assert_eq!(keyring.decrypt(&aad, &encrypted).await?, email);
# Ok(())
# }
```

The probes go into the query as the probes of a deterministic field do:

| Store | Query |
|---|---|
| PostgreSQL | `WHERE email_beacon = ANY($1)`, with the probes bound as a `BYTEA[]` |
| Firestore | an `in` filter on the field, which takes up to 30 values |

With the `postgres` feature, `Beacon` binds and decodes in tokio-postgres as a `BYTEA`, and with
the `serde` feature it serialises as bytes, as `Encrypted` does.

## Bits

`FieldSpec::with_beacon_bits` sets how many bits of the HMAC the field's beacons keep, 1 to 256,
`BeaconBits::DEFAULT`, 16, unless set. With `n` distinct values in a column and `b` bits, about
`n / 2^b` values share each beacon:

- fewer bits: more values share a beacon, so a lookup returns more rows, which the application
  decrypts and filters by the plaintext. A column of short beacons leaks less;
- more bits: fewer rows to filter, down to one per value once `2^b` is far above `n`, and the
  column then leaks which rows hold equal values as a deterministic column does.

An equal beacon never proves an equal value: a lookup always decrypts the rows it found and
compares the plaintexts. The bits enter the HMAC, so beacons of one value under different bits
never match: after a change of a field's bits, its stored beacons match no probe until a re-index
computes them again.

## Normalisation

A beacon is the HMAC of the bytes the `Plaintext` type encodes, so `Alice@Example.com` and
`alice@example.com` give different beacons unless the type normalises the value. Normalising is the
application's job: the newtype normalises when it is made, as `Email::new` lowercases above, and
every write and every lookup goes through it.

## BigQuery

BigQuery's SQL has no HMAC-SHA256 with a KMS-wrapped key, so a query in BigQuery cannot compute a
beacon, and the keyring never exports beacon keys to it: `export_bigquery_keyset` of the beacon
purpose fails with `ExportAlgorithmUnsupported`. A BigQuery query matches beacons the application
computed and passed in as query parameters.

## Rotating beacon versions

A beacon version rotates as the other purposes do, see [Staged
rotation](./lifecycle.md#staged-rotation), and a column holds beacons of several versions while it
is re-indexed:

1. `rotate(Purpose::Beacon)` stages the version. `beacon_probes` returns a probe under it from the
   next refresh of each process, so lookups find the beacons computed under it before every
   process has seen the promotion;
2. after the wait, `promote` it. Writes compute beacons under it from each process's next refresh;
3. lookups use `beacon_probes` throughout: one probe per pending, active or decrypt-only beacon
   version, compromised ones included, newest first;
4. a re-index sweep computes each row's beacon again under the active version, and writes the
   row's `SealMarker` with the key ids of its values and beacons, see
   [Sweeps](../operations.md#sweeps). `SealMarker::beacon` is the oldest beacon version among the
   row's beacons, so the rows still to visit are those whose `seal.beacon` is below the new
   version's key id;
5. once the sweep reports no failure and that query returns nothing, `retire` the old version, and
   its probe drops out of every lookup.

`KeyId::try_from(&beacon)` reads the key id of a stored beacon, for the marker. Beacon versions
are rotated by policy and on compromise only: each one adds a probe to every lookup until the
re-index is done.
