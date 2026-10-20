# Find rows by an encrypted value

A randomised value is different every time it is sealed, so a data store cannot find a row by it.
Two ways make a field searchable by equality: a deterministic field, whose stored value is equal
for equal plaintexts, and a beacon, a truncated HMAC stored beside a field that stays randomised.
Both leak which rows hold the same value, see
[What it leaks](../deterministic.md#what-it-leaks) and
[What a beacon leaks](../beacons.md#what-a-beacon-leaks). Neither suits a field with few distinct
values, such as a status or a country.

## Beacon or deterministic field

| | Beacon | Deterministic field |
|---|---|---|
| Stored value | Randomised, so its AAD can name the row, and a value copied into another row fails to open | Equal for equal values, so its AAD names the field and never the row, and a value copied into another row opens there |
| Match | The truncated HMAC, with deliberate collisions | Always the exact value |
| Key | A beacon key, rotated separately from the data keys | The field's own key |
| Cost | An extra column, and a decryption and filter of the candidates on every lookup | Nothing beyond the field |
| BigQuery | SQL cannot calculate a beacon; it matches beacons the application calculated | SQL decrypts the field and searches it by equality |
| FIPS | HMAC-SHA256 on the configured backend | AES-SIV, which is not FIPS-approved |

With the default 16 bits, there are 65,536 possible beacons. A column of 1,000,000 distinct
emails gives about 1,000,000 / 65,536, or 15, emails per beacon, so a lookup of one email returns
about 15 rows. The application decrypts them and keeps the one equal to the email it looks for.
How the bits trade rows to filter against what the column leaks is in
[Bits](../beacons.md#bits).

## With kms-aead alone

The application keeps the key itself, as a key id and the key encrypted by the KMS, such as in its
settings, and rotates it by hand:

- a deterministic field: `DeterministicCipher` with a key the KMS encrypts once, see
  [Deterministic encryption](../deterministic.md#keys-encrypted-by-a-kms);
- a beacon: `KmsAeadEnvelope::beacon` or `BeaconMac`, see [Beacons](../beacons.md). A rotation
  keeps both keys and queries with a beacon under each until a re-index, see
  [Rotating a beacon key](../beacons.md#rotating-a-beacon-key).

## With a keyring

Each purpose has its own key versions, rotated centrally, and a lookup matches every version that
still decrypts:

- a deterministic field: a sealer's `encrypt_deterministic` on every write, and
  `Keyring::deterministic_probes` for a lookup, under the `deterministic` feature, see
  [Deterministic fields](../keyring/deterministic.md);
- a beacon: a sealer's `encrypt` and `beacon` in the same write, and `Keyring::beacon_probes` for a
  lookup, see [Beacons](../keyring/beacons.md).

Each rotation of a deterministic or beacon version adds a probe to every lookup until a sweep, see
[Rotation cadence](../operations/rotation.md#rotation-cadence).

## A lookup

1. Normalise the value in its newtype, such as a lowercased email, so that the write and the lookup
   encode the same bytes, see [Normalisation](../beacons.md#normalisation);
2. compute the probes of the value looked for, one per key that still decrypts: with kms-aead
   alone one, or two during a rotation by hand until the re-index; with a keyring one per version;
3. query by them: `WHERE email_beacon = ANY($1)` on PostgreSQL with the probes bound as a
   `BYTEA[]`, an `in` filter on Firestore, which takes up to 30 values, see
   [Queries across rotations](../keyring/deterministic.md#queries-across-rotations);
4. for a beacon, decrypt every row found and keep the ones whose plaintext equals the value: an
   equal beacon never proves an equal value.

A deterministic field in BigQuery is queried in SQL, with one `DETERMINISTIC_ENCRYPT` per version,
see [Queries](../keyring/bigquery.md#queries).
