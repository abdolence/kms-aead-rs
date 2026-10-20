# Formats

Every byte layout the library reads or writes is on this page.

The library writes one envelope format for every provider, Tink's KMS envelope. A value encrypted
by `KmsAeadEnvelope::encrypt` opens with Tink's `KmsEnvelopeAead` on the same KMS key and
algorithm, and a value Tink encrypts opens with `KmsAeadEnvelope::decrypt`.

| Layout | Type | Bytes | Read by | Written by |
|---|---|---|---|---|
| Tink KMS envelope | `Encrypted<T, Envelope>` | `[w: u32 BE][encrypted DEK: w][nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | 0.30.0 and later |
| Bare value | `Encrypted<T, Bare>` | `[nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | every release |
| Encrypted DEK | `EncryptedDataEncryptionKey` | the provider's bytes, see [Encrypted DEKs](#encrypted-deks) | kms-aead, Tink for GCP and AWS keys | 0.30.0 and later |
| Serialised DEK | the plaintext of an encrypted DEK, but Azure's | Tink's key message, see [Serialised DEKs](#serialised-deks) | kms-aead, Tink | 0.30.0 and later |
| TINK-prefixed value | `Encrypted<T, Randomized>`, `Encrypted<T, Deterministic>`, named by a `KeyId` | `[0x01][key id: u32 BE][value]` | kms-aead, Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| Tink keyset | `TinkKeyset` | `google.crypto.tink.Keyset` | Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| Tink encrypted keyset | `TinkKeyset::into_encrypted_bytes` | `google.crypto.tink.EncryptedKeyset`, `[0x12][w: varint][encrypted keyset: w]` | Tink with a GCP, AWS or Vault Transit key | 0.30.0 and later, and kms-aead-keyring through it |
| Envelope layout v1 | `Encrypted<T, Envelope>` with `legacy-formats` | `[0x01][k: u8][key version: k][w: u16 BE][encrypted DEK: w][cipher text]` | kms-aead with `legacy-formats` | 0.29 |
| Encrypted DEK layout v1 | stored `EncryptedDataEncryptionKey` | `[0xFF][0x01][k: u8][key version: k][encrypted DEK]` | kms-aead with `legacy-formats` | 0.29 |
| Length-prefixed envelope | `Encrypted<T, Envelope>` with `legacy-formats` | `[w: u64 BE][encrypted DEK: w][cipher text]`, and `[w: u32 BE]` from 32-bit targets before 0.24.0 | kms-aead with `legacy-formats` | 0.8.0 to 0.28.1 |
| Raw encrypted DEK | `EncryptedDataEncryptionKey` | the KMS ciphertext of the DEK's 16 or 32 raw bytes | kms-aead with `legacy-formats` | up to 0.29 |

`k = 0` records no key version. A key version is 1 to 255 ASCII alphanumeric characters. The Azure
provider encrypts the raw DEK in every release, see [Encrypted DEKs](#encrypted-deks).

## Tink's KMS envelope

`KmsAeadEnvelope::encrypt` writes Tink's KMS envelope, and `Encrypted::join` writes it from a
bare value and an encrypted DEK. `separate` reads it back:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let encrypted: Encrypted<SecretValue, Envelope> =
    envelope.encrypt(b"aad", &SecretValue::from("secret")).await?;

let (bare, encrypted_dek) = encrypted.separate()?;
let joined = Encrypted::<SecretValue, Envelope>::join(&bare, &encrypted_dek)?;
assert_eq!(joined.value(), encrypted.value());
# Ok(())
# }
```

- `w` is 1 to 4,096 bytes, the limit of every Tink implementation, on write and on read;
- the encrypted DEK is the provider's [`EncryptedDataEncryptionKey`](#encrypted-deks), the KMS
  ciphertext of the [serialised DEK](#serialised-deks), or of the raw DEK for Azure;
- the AAD goes to the DEK's AEAD only. The KMS encryption of the DEK has no AAD, as in Tink, so
  Tink's AWS client sends no encryption context and its GCP client no additional authenticated data;
- the rest is a [`Bare` value](#formats-of-encrypted).

The envelope records neither the algorithm nor the KEK version, so the writer and the reader,
kms-aead or Tink, are configured with the same algorithm. Tink calls it the DEK template:

| Algorithm | Tink key type | Tink for Java and Go | Tink for C++ and Python |
|---|---|---|---|
| ChaCha20-Poly1305 | `ChaCha20Poly1305Key` | reads and writes | no |
| AES-128-GCM, AES-256-GCM | `AesGcmKey` | reads and writes | reads and writes |
| AES-256-GCM-SIV | `AesGcmSivKey` | reads and writes | reads and writes |

AES-256-GCM is the default of `KmsAeadEnvelope::new`, so every Tink implementation reads the
values of an envelope that names no algorithm. The default of 0.29 and earlier was
ChaCha20-Poly1305, see [Migrating from 0.29](./migrating-from-0.29.md#default-algorithm).

Tink for Python reads a kms-aead value with the key URI of the provider's key:

```python
from tink import aead
from tink.integration import gcpkms

aead.register()
key_uri = 'gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k'
remote = gcpkms.GcpKmsClient(key_uri).get_aead(key_uri)
envelope = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, remote)
plain_text = envelope.decrypt(value, aad)
```

Checked on a Cloud KMS key and an AWS KMS key, both ways: AES-128-GCM, AES-256-GCM and
AES-256-GCM-SIV with Tink 1.16.1 for Python, and ChaCha20-Poly1305 with Tink 1.24.0 for Java on
the Cloud KMS key. `tests/tink_interop.py` and `examples/tink_interop.rs` repeat the Python check.

## Encrypted DEKs

`EncryptedDataEncryptionKey` is the bytes the provider returned from an encryption, which are also
the bytes to store and the bytes it decrypts. Each provider's bytes name the KEK version that
encrypted the DEK where the KMS needs one to decrypt:

| Provider | Bytes | Key version |
|---|---|---|
| GCP | the Cloud KMS ciphertext, starting with `0x0a` | inside the ciphertext |
| AWS | the AWS KMS ciphertext blob, starting with `0x01` | not exposed |
| Azure | `[0x01][k: u8][key version: k][Key Vault encrypted DEK]` | in the layout |
| Vault Transit | the Transit ciphertext, `vault:vN:…` | the `N` |
| local | `[0x01][i: u8][KEK id: i][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]` | in the layout |
| an application's own | whatever it returns | |

The Azure layout is the library's own: Key Vault decrypts only with the key version that encrypted,
and no Tink client exists for Azure. For the same reason, the Key Vault encrypted DEK is the KMS
ciphertext of the raw DEK of 16, 32 or 64 bytes, as in 0.29, not of the serialised DEK: AES key
wrap, `A128KW` to `A256KW`, takes only multiples of 8 bytes, which no serialised DEK is. The local
KMS seals the DEK with AES-256-GCM under the KEK version, with its header up to the version as the
AAD, so neither the id nor the version can be changed without the decryption failing.

Store `value()` or `to_hex_string()`, and read them back with `EncryptedDataEncryptionKey::from`
or `try_from_hex_string`. Neither holds the KEK version of `kek_version()`, see
[Storing encrypted DEKs](./envelope-encryption.md#storing-encrypted-deks).

## Serialised DEKs

The plaintext a provider encrypts is the DEK serialised as Tink serialises a key, the message of its
Tink key type with `version` 0, which protobuf leaves out. The Azure provider encrypts the raw DEK
instead, see [Encrypted DEKs](#encrypted-deks):

| Algorithm | Message | Bytes |
|---|---|---|
| ChaCha20-Poly1305 | `ChaCha20Poly1305Key` | `[0x12][0x20][key: 32]` |
| AES-128-GCM | `AesGcmKey` | `[0x1a][0x10][key: 16]` |
| AES-256-GCM | `AesGcmKey` | `[0x1a][0x20][key: 32]` |
| AES-256-GCM-SIV | `AesGcmSivKey` | `[0x1a][0x20][key: 32]` |
| AES-256-SIV, deterministic | `AesSivKey` | `[0x12][0x40][key: 64]` |

A beacon key of HMAC-SHA256 is serialised as `[0x1a][0x20][key: 32]`, its 32 bytes in
`key_value`, field 3, as in Tink's `HmacPrfKey` without its parameters: the bytes of a 32-byte
`AesGcmKey`. It is encrypted as a DEK is, raw under an Azure key.

`KmsAeadEnvelope::generate_encrypted_dek`, `generate_encrypted_deterministic_dek` and the
`generate_encrypted_dek` of both ciphers and of `BeaconMac` encrypt their keys the same way. The
message does not name its type, and AES-256-GCM and AES-256-GCM-SIV keys are written alike, so the
algorithm of the reader decides how the key is used, as in Tink.

A decrypted DEK that is no serialised Tink key, or under an Azure key no raw DEK, fails with
`INVALID_KEY_FORMAT`. An encrypted Tink
keyset decrypts under the same KEK too, and this is what keeps it out of the DEK cache.

## Tink keysets and the TINK prefix

Two items describe the TINK-prefixed values:

- `kms_aead::KeyId`: the key id of Tink's output prefix of type TINK, `[0x01][key id: u32 BE]`,
  the start of every `Randomized` and `Deterministic` value and of every beacon. It picks the key
  that opens the value, and Tink and BigQuery pick the key of a keyset by it. It is not
  authenticated;
- `kms_aead::formats::TinkKeyset`: a serialised `google.crypto.tink.Keyset` of enabled, symmetric,
  TINK-prefixed keys, the bytes `tinkey` writes for the same keys. Encrypted by a Cloud KMS key, it
  is the keyset of BigQuery's `KEYS.KEYSET_CHAIN`: an application writes it for its one key, see
  [One fixed key](./envelope-encryption.md#one-fixed-key), and a keyring exports it for its
  versions.

`TinkKeyset::into_encrypted_bytes` writes the keyset encrypted by a KMS key, as Tink writes an
encrypted keyset: a `google.crypto.tink.EncryptedKeyset` whose `encrypted_keyset`, field 2, is the
KMS ciphertext of the serialised keyset, encrypted with no associated data. Tink's binary keyset
writers leave out `keyset_info`, field 3, and so does the library. Tink's `KeysetHandle.read`
reads it with the KMS client of `KekRef::tink_key_uri`, which Tink has for GCP and AWS keys, and
Tink for Go for Vault Transit keys too. A keyring exports it for its versions, see
[Exporting a keyset to Tink](./keyring/bigquery.md#exporting-a-keyset-to-tink).

## Formats of `Encrypted`

Every value the library encrypts is an `Encrypted<T, F>`: the bytes of one layout, named by its
format `F` from `kms_aead::formats`. `Encrypted::try_from` and `Encrypted::try_from_hex_string`
check stored bytes against it:

| Format | Layout | Shortest value | `key_id()` | Written by |
|---|---|---|---|---|
| `Envelope` | [Tink's KMS envelope](#tinks-kms-envelope) | an encrypted DEK of 1 to 4,096 bytes, then 28 bytes | none | `KmsAeadEnvelope::encrypt`, `Encrypted::join` |
| `Bare` | `[nonce: 12][ciphertext][tag: 16]` | 28 bytes | none | `AeadCipher::encrypt_bare`, `KmsAeadEnvelope::encrypt_with_dek` and `encrypt_with_encrypted_dek`, `Encrypted::separate` |
| `Randomized` | `[0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]` | 33 bytes | `KeyId` | `AeadCipher::encrypt`, and kms-aead-keyring through it |
| `Deterministic` | `[0x01][key id: u32 BE][synthetic IV: 16][ciphertext]` | 21 bytes | `KeyId` | `DeterministicCipher::encrypt`, and kms-aead-keyring through it |

A `Bare` value is Tink's AEAD output under a key with the output prefix RAW, and the part of every
`Envelope` value after the encrypted DEK. It names no key: the application keeps track of the key
that opens it.

The check reads the framing only, and whether the bytes are authentic is known when they are
decrypted. With `legacy-formats`, an `Envelope` value also holds the envelope layout v1 of 0.29 and
the length-prefixed envelope, checked by their lengths, so a column decodes its old rows into the
same type until they are upgraded, see [Upgrading stored values](#upgrading-stored-values).
Without the feature, `Encrypted::try_from` refuses them with `LEGACY_FORMAT`. `separate` refuses
them in every build. The layout of 32-bit targets before 0.24.0 has Tink's framing, so it reads as
an `Envelope` value in every build, and `KmsAeadEnvelope::decrypt` opens it with `legacy-formats`.

The plaintext inside is the encoding of the value's `Plaintext` type: UTF-8 for `String`, the
bytes themselves for `Vec<u8>` and `SecretValue`, `true` or `false` for `bool`, decimal ASCII for
the integers, and compact JSON for `Json<T>`. See
[Stored values](./stored-values.md#plaintext).

## Beacons

A `Beacon<T>` is a prefix and a truncated HMAC-SHA256:

```text
[0x01][key id: u32 BE][HMAC-SHA256: the first ceil(bits / 8) bytes]
```

- `0x01` is the version of the beacon layout. A later layout takes another first byte, so that
  beacons of both layouts can share a column during a re-index;
- the key id names the beacon key that calculated the beacon;
- the HMAC keeps its first `bits` bits, and the unused low bits of the last byte are zero. A
  beacon is 6 to 37 bytes.

The HMAC covers the bits, the context and the plaintext, as the `Plaintext` type encodes it:

```text
HMAC-SHA256(key, [bits: u16 BE][context length: u32 BE][context][plaintext])
```

so that beacons of two fields, or of two bit counts, never match. `Beacon::try_from` checks the
prefix and that 1 to 32 bytes of HMAC follow, and fails with `INVALID_BEACON_FORMAT` otherwise.

## Keyring key ids

kms-aead-keyring writes the key id of a version into the TINK prefix of every value and beacon
under it. The two high bits of the id are the purpose, and the rest is the ordinal:

| Bits | Meaning |
|---|---|
| 31 | set for deterministic versions |
| 30 | set for beacon versions |
| 0 to 29 | the ordinal, from 1, counted per purpose |

So the ids of each purpose are:

- randomised: `1`, `2`, `3`, …;
- deterministic: `2147483649`, `2147483650`, …;
- beacon: `1073741825`, `1073741826`, ….

An id whose ordinal is 0, such as `0`, `2^30` and `2^31`, and an id with both high bits set are
reserved: a value that carries one fails with `ReservedKeyId`. A value whose id is of another
purpose than the call fails with `KeyPurposeMismatch`. Both fail before any store or KMS call. Ids
are never reused: a destroyed version keeps its id in the record. A key id goes up to 2^32 - 1, so
a SQL column holding one is a `BIGINT`.

## Keyring records

kms-aead-keyring keeps a keyring record as one JSON document, the same in every keyring store. A
record with deterministic and beacon versions, after one randomised rotation and with another one
staged, with the encrypted DEKs shortened:

```json
{
  "schema": 1,
  "id": "tenant-42",
  "kek": { "provider": "local", "key": "tenant-kek" },
  "algorithms": {
    "randomized": "aes-256-gcm",
    "deterministic": "aes-256-siv",
    "beacon": "hmac-sha256"
  },
  "seal_epoch": 2,
  "versions": [
    {
      "key_id": 1,
      "algorithm": "aes-256-gcm",
      "state": "decrypt_only",
      "compromised": null,
      "seal_epochs": { "start": 1, "end": 2 },
      "created_at": "2026-10-18T12:18:31.053483320Z",
      "state_changed_at": "2026-10-18T12:18:31.054258061Z",
      "encrypted_dek": "AQp0ZW5hbnQta2VrAAAAAV6OYLYtnCqk...",
      "kek_version": "1"
    },
    {
      "key_id": 2147483649,
      "algorithm": "aes-256-siv",
      "state": "active",
      "compromised": null,
      "seal_epochs": { "start": 1, "end": null },
      "created_at": "2026-10-18T12:18:31.053483320Z",
      "state_changed_at": "2026-10-18T12:18:31.053483320Z",
      "encrypted_dek": "AQp0ZW5hbnQta2VrAAAAAeY4U51ScBd+...",
      "kek_version": "1"
    },
    {
      "key_id": 1073741825,
      "algorithm": "hmac-sha256",
      "state": "active",
      "compromised": null,
      "seal_epochs": { "start": 1, "end": null },
      "created_at": "2026-10-18T12:18:31.053483320Z",
      "state_changed_at": "2026-10-18T12:18:31.053483320Z",
      "encrypted_dek": "AQp0ZW5hbnQta2VrAAAAAWYRS+ENPZF7...",
      "kek_version": "1"
    },
    {
      "key_id": 2,
      "algorithm": "aes-256-gcm",
      "state": "active",
      "compromised": null,
      "seal_epochs": { "start": 2, "end": null },
      "created_at": "2026-10-18T12:18:31.053897100Z",
      "state_changed_at": "2026-10-18T12:18:31.054258061Z",
      "encrypted_dek": "AQp0ZW5hbnQta2VrAAAAASNGwiIu93uT...",
      "kek_version": "1"
    },
    {
      "key_id": 3,
      "algorithm": "aes-256-gcm",
      "state": "pending",
      "compromised": null,
      "seal_epochs": null,
      "created_at": "2026-10-18T12:18:31.054603074Z",
      "state_changed_at": "2026-10-18T12:18:31.054603074Z",
      "encrypted_dek": "AQp0ZW5hbnQta2VrAAAAAWVYn2R7AWay...",
      "kek_version": "1"
    }
  ],
  "created_at": "2026-10-18T12:18:31.053483320Z",
  "updated_at": "2026-10-18T12:18:31.054603074Z"
}
```

- `schema` is `1`;
- `kek` names the provider and the KEK the keyring was created with;
- `algorithms` holds the algorithm new versions of each purpose use. `deterministic` and `beacon`
  are `null` for a keyring without versions of that purpose;
- `seal_epoch` counts the writes that made a version active, from 1 at the creation, see
  [Seal markers](#seal-markers);
- `versions` holds every version ever created, in creation order, each under its
  [key id](#keyring-key-ids);
- `state` is `pending`, `active`, `decrypt_only`, `retired` or `destroyed`. For a pending version,
  `state_changed_at` is the time it was staged;
- `compromised` is `null`, or `{"at": "<time>", "note": "<the operator's note, or null>"}`;
- `seal_epochs` is the version's seal range as epochs, `{"start": <epoch>, "end": <epoch or
  null>}`: the epoch of the write that made it active, and the epoch of the first write after it
  stopped being active that moved the epoch on, `null` until then. It is `null` for a version that
  was never active, see [Seal markers](#seal-markers);
- `encrypted_dek` is the standard base64 of the [encrypted DEK](#encrypted-deks), the bytes the
  provider returned, here the local KMS layout. It is `null` for a destroyed version;
- `kek_version` is the version of the KEK that encrypted `encrypted_dek`, as the KMS reported it,
  here the local KEK version. It is `null` for a destroyed version, and under a KMS that reports
  none, such as AWS KMS;
- the times are RFC 3339, in UTC.

A reader parses at most 1 MiB of JSON. The size of a version is mostly its encrypted DEK, so the
number of versions that fit depends on the KMS:

| KEK | Bytes per version | Versions in 1 MiB |
|---|---|---|
| local KMS | 359 | about 2,900 |
| Vault Transit | 380 | about 2,750 |
| GCP Cloud KMS | 412 | about 2,550 |
| AWS KMS | 504 | about 2,050 |
| Azure, RSA 2048-bit key | 674 | about 1,550 |
| Azure, RSA 4096-bit key | 1,014 | about 1,050 |

The local KMS row was measured on a record the crate wrote after 500 randomised rotations, each
version AES-256-GCM, decrypt-only with a seal range. The other rows are the same record with each
encrypted DEK replaced by one of that KMS's length, and a KEK version of that KMS's form: none for
AWS, two digits for GCP and Vault, 32 hex digits for Azure.

A reader fails with `RecordInvalid` on a document that breaks any of:

- at most one active and one pending version per purpose, neither of them compromised;
- an encrypted DEK on every version but the destroyed ones, and a `kek_version`, when there is
  one, of 1 to 255 ASCII alphanumerics beside it;
- unique key ids of the purpose of their algorithm, increasing within a purpose in creation order;
- a `seal_epoch` of 1 or more;
- `seal_epochs` on every active, decrypt-only and retired version and on no pending one, open on
  the active version, starting at 1 or more and below its end, and within the `seal_epoch`.

## Seal markers

A seal marker is the seal epoch of the keyring record a write sealed a record's fields under,
which the application stores beside them:

```text
[0x01][seal epoch: u32 BE]
```

5 bytes in all, so that markers compare as their epochs do, and so do their bytes as Firestore,
PostgreSQL and BigQuery compare them. `SealMarker::ENVELOPE`, `01 00 00 00 00`, is epoch 0, the
marker of a record of envelope values. `SealMarker::try_from` fails with `InvalidSealMarker` on
bytes of any other length or first byte. The `serde` feature stores a marker as bytes, an array of
numbers in serde_json, and the `postgres` and `sqlx` features as `BYTEA`. See
[Sweeps](./operations/sweeps.md) for the query it serves.

`KeyVersion::seal_range()` returns the markers of a version's `seal_epochs` as a `SealRange`:
`start()`, and `end()`, `None` while the range is open. A record whose fields were sealed through
one `Sealer`, and which stores the marker of the sealer's record, lies in the range of every
version its fields are under. See
[Records under a version](./operations/sweeps.md#records-under-a-version) for the query it serves.

## Telling layouts apart

The first bytes of a stored value:

| First bytes | Layout |
|---|---|
| `00 00 00 00` | the length-prefixed envelope of 0.28.1 and earlier |
| `00`, then a length of 1 to 4,096 | Tink's KMS envelope, or the 4-byte length prefix of 32-bit targets before 0.24.0 |
| `01` | envelope layout v1 of 0.29, or a TINK-prefixed value |
| `FF 01` | encrypted DEK layout v1 of 0.29 |

Only the decrypted DEK tells a Tink envelope from the 32-bit layout before 0.24.0: a raw key of
16 or 32 bytes against a serialised Tink key, whose lengths differ. An encrypted DEK of AWS, Azure
or the local KMS also starts with `0x01`, and Tink's LEGACY and CRUNCHY output prefixes with `0x00`.

A column that holds two layouts:

- Tink envelopes and TINK-prefixed values: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.29 envelopes: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.28.1 envelopes: the first four bytes;
- 0.29 envelopes and TINK-prefixed values: no byte tells them apart, so the layout is recorded
  outside the value, such as in another column;
- bare values and any other layout: a bare value has no framing, and its random nonce can start
  with any byte, so a column of bare values holds no other layout;
- encrypted DEKs of 0.29 and of 0.30: `0xFF 0x01` starts no encrypted DEK of a built-in provider, so
  the library tells them apart for those. It never inspects the bytes of an application's own
  provider: strip the header `[0xFF][0x01][k][key version]` of its 0.29 keys before reading them.

## Values written by 0.29 and earlier

The layouts of 0.29 and earlier are read only with the deprecated `legacy-formats` feature:

- `KmsAeadEnvelope::decrypt` reads the three envelope layouts, which `Encrypted<T, Envelope>`
  holds with the feature;
- the `*_with_encrypted_dek` calls and the DEK cache read the encrypted DEK layout v1 of 0.29 and
  raw encrypted DEKs.

`Encrypted::separate` never reads the older envelope layouts: for Azure, the encrypted DEK they
hold needs the provider to become its bytes.

Without the feature, reading them fails with `KmsAeadError::LegacyFormat`, the code
`LEGACY_FORMAT`, and one of:

- `KmsAeadLegacyFormat::EnvelopeV1`;
- `KmsAeadLegacyFormat::LengthPrefixedEnvelope`;
- `KmsAeadLegacyFormat::EncryptedDekV1`;
- `KmsAeadLegacyFormat::RawEncryptedDek`, for an encrypted DEK that decrypts to the raw key. The
  values of 32-bit targets before 0.24.0 fail with it, since their framing is Tink's.

The error never echoes the bytes read. With the feature, the first read of each layout in a
process logs one `WARN` event that names the upgrade methods. Without it, the `KMS AEAD decrypt`
spans of such values record `error_code=LEGACY_FORMAT`, see [Observability](./observability.md).

## Upgrading stored values

With `legacy-formats`, two methods of `KmsAeadEnvelope` rewrite a stored value in Tink's format,
and return `None` when it already is in it, so a sweep writes only the rows that change:

- `upgrade_legacy_value`, for envelope values;
- `upgrade_legacy_encrypted_dek`, for encrypted DEKs stored apart, such as the bytes of 0.29's
  `to_bytes`.

Each decrypts the DEK with the provider, without the DEK cache, and encrypts it again as a
serialised Tink key when it was in an older layout: one KMS call for a current value, two for an old
one. A value in Tink's framing needs the decryption to be told from the 32-bit layout before 0.24.0.
The AEAD bytes stay as they are.

An upgraded DEK is encrypted under the KEK's current version, so the upgrade also does what
`reencrypt_dek` and `reencrypt_encrypted_dek` do for a value or a DEK already in Tink's format, see
[Re-encrypting DEKs after a KEK rotation](./envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).
Those two refuse a layout of 0.29 or earlier with `LEGACY_FORMAT`, so a sweep after a KEK rotation
upgrades a value in an old layout and re-encrypts the DEK of a value in Tink's format.

The envelope's algorithm is the one the values were sealed with: ChaCha20-Poly1305 for values that
0.29 and earlier sealed under their default. A raw DEK does not record its algorithm, and the
encrypted DEK of the upgrade records it as a Tink key type, so `upgrade_legacy_value` takes the
value's AAD and opens the value before it writes anything. Under another algorithm or another AAD
it fails with `DECRYPT`. `upgrade_legacy_encrypted_dek` has no value to open, so it records the
envelope's algorithm for any key of its length. Be aware not to upgrade a DEK stored apart under
another algorithm than its values were sealed with: use `upgrade_legacy_value` wherever the values
are at hand.

A sweep over stored rows:

```rust
use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult};
use secret_vault_value::SecretValue;

/// A stored envelope value and the AAD it was sealed under.
struct Row {
    aad: Vec<u8>,
    value: Vec<u8>,
}

/// Rewrites the envelope values of `rows` in Tink's format, and returns how many changed.
#[allow(deprecated)]
async fn upgrade_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &mut [Row],
) -> KmsAeadResult<usize>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut upgraded = 0;
    for row in rows.iter_mut() {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.value.clone())?;
        if let Some(value) = envelope.upgrade_legacy_value(&row.aad, &stored).await? {
            row.value = value.into_value();
            upgraded += 1;
        }
    }
    Ok(upgraded)
}
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{AeadAlgorithm, AeadCipher, KmsAeadEnvelopeOptions};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# // A value as 0.28.1 wrote it: [w: u64 BE][encrypted raw key][cipher text]
# let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
# let dek = cipher.generate_dek()?;
# let bare = cipher.encrypt_bare(b"aad", &SecretValue::from("secret"), &dek)?;
# let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;
# let mut legacy = u64::try_from(encrypted_dek.value().len()).unwrap().to_be_bytes().to_vec();
# legacy.extend_from_slice(encrypted_dek.value());
# legacy.extend_from_slice(bare.value());
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     provider,
#     KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
# )?;
# let mut rows = vec![Row { aad: b"aad".to_vec(), value: legacy }];
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 1);
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 0);
# let upgraded = Encrypted::<SecretValue, Envelope>::try_from(rows[0].value.clone())?;
# let decrypted: SecretValue = envelope.decrypt(b"aad", &upgraded).await?;
# assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

Upgrade every reader to 0.30 before the sweep writes: 0.29 and earlier cannot read Tink's format.

## Deprecation

Reading the layouts of 0.29 and earlier is deprecated since 0.30.0 and will be removed in a later
breaking release, together with the `legacy-formats` feature and the upgrade methods, which carry
`#[deprecated]` from their first release, so every call site warns. Without the feature, the
older layouts keep failing with `LEGACY_FORMAT`.
