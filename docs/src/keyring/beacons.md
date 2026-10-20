# Beacons

A beacon, or blind index, finds rows by a field's value without decrypting the column: a
truncated HMAC-SHA256 of the value, stored beside the field's randomised value, which a data store
matches by equality. The keyring computes beacons under its beacon versions, of the purpose
`Purpose::Beacon`, which rotate like any other.

kms-aead's [Beacons](../beacons.md) describes the primitive, `Beacon<T>`
and `BeaconBits`, with keys the application keeps itself, and [Formats](../formats.md#beacons) its
bytes.

A [deterministic field](./deterministic.md) also finds rows by equality, by its encrypted value,
see [Beacon or deterministic field](../beacons.md#beacon-or-deterministic-field).

## What a beacon leaks

A beacon column leaks likely equality and frequency to anyone who reads it, and a leaked beacon
key lets its holder test candidate values offline, see
[What a beacon leaks](../beacons.md#what-a-beacon-leaks) in kms-aead.

A beacon is computed in a field's context, `<kind>/<field>` such as `user/email`, with no entity
id: equal values in different rows give equal beacons, which is what a lookup matches. A beacon of
one field never matches a beacon of another.

## Usage

A keyring with beacon versions names their algorithm in its `KeyringAlgorithms`: HMAC-SHA256, the
one `BeaconAlgorithm` has. A sealer's `beacon` computes the beacon of a value under the active
beacon version, in the same write as the field's value, and `Keyring::beacon_probes` the beacons of
a value under every beacon version a lookup matches:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Beacon, BeaconAlgorithm, BeaconBits, KmsAeadResult};
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringAdmin, KeyringAlgorithms,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
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
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .create(
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
    )
    .await?;
let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

// On every write: the field and its beacon, through one sealer
let aad = EMAIL.aad(&EntityId::try_from("42")?);
let email = Email::new("Alice@Example.com");
let sealer = keyring.sealer().await;
let encrypted: Encrypted<Email, Randomized> = sealer.encrypt(&aad, &email).await?;
let beacon: Beacon<Email> = sealer.beacon(&EMAIL, &email).await?;

// A lookup: the probes of the value looked for, then a decryption of each matching row
let probes: Vec<Beacon<Email>> = keyring
    .beacon_probes(&EMAIL, &Email::new("alice@example.com"))
    .await?;
assert!(probes.contains(&beacon));
assert_eq!(keyring.decrypt(&aad, &encrypted).await?, email);
registry.shutdown().await?;
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

`FieldSpec::with_beacon_bits` sets how many bits of the HMAC the field's beacons keep,
`BeaconBits::DEFAULT`, 16, unless set; what the bits trade is in [Bits](../beacons.md#bits). The
bits enter the HMAC, so after a change of a field's bits, its stored beacons match no probe until a
re-index computes them again. A beacon is the HMAC of the bytes the `Plaintext` type encodes, so
the field's newtype normalises the value, as `Email::new` lowercases above, see
[Normalisation](../beacons.md#normalisation).

## BigQuery

The keyring never exports beacon keys to BigQuery: `export_bigquery_keyset` of the beacon purpose
fails with `ExportAlgorithmUnsupported`, see
[Exporting a keyset to BigQuery](./bigquery.md#exporting-a-keyset-to-bigquery). A BigQuery query
matches beacons the application computed, see [BigQuery](../beacons.md#bigquery) in kms-aead.

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
4. the promotion moved the keyring's seal epoch on, so every row written before it has a
   `SealMarker` below the current one, and a re-index sweep visits them, see
   [Sweeps](../operations/sweeps.md). It computes each row's beacon again under the active version
   of its sealer and writes the sealer's marker; a row without a beacon gets the marker alone;
5. once the sweep reports no failure and that query returns nothing, `retire` the old version, and
   its probe drops out of every lookup.

`beacon.key_id()` reads the key id of a stored beacon, so that the sweep recomputes only the beacons
under an older version. Beacon versions are rotated by policy and on compromise only: each one adds
a probe to every lookup until the re-index is done.
