# Formats

Every byte layout the library reads or writes is on this page.

The library writes one envelope format for every provider, Tink's KMS envelope. A value encrypted
by `KmsAeadEnvelope::encrypt` decrypts with Tink's `KmsEnvelopeAead` on the same KMS key and
algorithm, and a value Tink encrypts decrypts with `KmsAeadEnvelope::decrypt`.

| Layout | Type | Bytes | Read by | Written by |
|---|---|---|---|---|
| Tink KMS envelope | `Encrypted<T, Envelope>` | `[w: u32 BE][encrypted DEK: w][nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | 0.30.0 and later |
| Bare value | `Encrypted<T, Bare>` | `[nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | every release |
| Encrypted DEK | `EncryptedDataEncryptionKey` | the provider's bytes, see [Encrypted DEKs](#encrypted-deks) | kms-aead, Tink for GCP and AWS keys | 0.30.0 and later |
| Serialised DEK | the plaintext of an encrypted DEK, but Azure's | Tink's key message, see [Serialised DEKs](#serialised-deks) | kms-aead, Tink | 0.30.0 and later |
| TINK-prefixed value | `Encrypted<T, Randomized>`, `Encrypted<T, Deterministic>`, named by a `KeyId` | `[0x01][key id: u32 BE][value]` | kms-aead, Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| Streamed value | `StreamEncryptor` and `StreamDecryptor` of `AeadCipher::stream_encryptor` and `stream_decryptor`, and of the keyring's `Encryptor::stream_encryptor` and `Keyring::stream_decryptor` | see [Streamed values](#streamed-values) | kms-aead with `stream`; a C2SP chunked-encryption reader from byte 5 | 0.31.0 and later, and kms-aead-keyring through it |
| Envelope streamed value | `StreamEncryptor` and `StreamDecryptor` of `KmsAeadEnvelope::stream_encryptor` and `stream_decryptor` | see [Streamed values](#streamed-values) | kms-aead with `stream`; a C2SP chunked-encryption reader from byte `4 + w` | 0.31.0 and later |
| Bare streamed value | `StreamEncryptor` and `StreamDecryptor` of the `stream_encryptor_bare` and `stream_decryptor_bare` calls of `AeadCipher` and `KmsAeadEnvelope` | see [Streamed values](#streamed-values) | kms-aead with `stream`, any C2SP chunked-encryption reader | 0.31.0 and later |
| Detached signature | `Signature<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead | 0.31.0 and later |
| Attached signature | `Signed<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead | 0.31.0 and later |
| Detached MAC | `Mac<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |
| Attached MAC | `WithMac<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |
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
| local | `[0x01][i: u8][KEK id: i][KEK version: u32 BE][nonce: 12][encrypted DEK][tag: 16]` | in the layout |
| any, encrypted with a public key | `[0x02][a: u8][i: u8][KEK id: i][k: u8][KEK version: k][RSA block]`, see [DEKs encrypted with a public key](#deks-encrypted-with-a-public-key) | in the layout |
| an application's own | whatever it returns | |

The Azure layout is the library's own: Key Vault decrypts only with the key version that encrypted,
and no Tink client exists for Azure. For the same reason, the Key Vault encrypted DEK is the KMS
ciphertext of the raw DEK of 16, 32 or 64 bytes, as in 0.29, not of the serialised DEK: AES key
wrap, `A128KW` to `A256KW`, takes only multiples of 8 bytes, which no serialised DEK is. The local
KMS encrypts the DEK with AES-256-GCM under the KEK version, with its header up to the version as
the AAD, so neither the id nor the version can be changed without the decryption failing.

The `0x02` layout is the same for every KMS: a producer holding the public half of an RSA key
encrypts the DEK in its own process, and the provider of the KMS that holds the private half
decrypts it. The providers of 0.31 read it beside their own bytes, and no earlier release reads it,
see [DEKs encrypted with a public key](#deks-encrypted-with-a-public-key) and [Asymmetric
KEKs](./asymmetric-kek.md).

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
| HMAC-SHA256, MAC key | `HmacKey` | `[0x1a][0x20][key: 32]` |
| HMAC-SHA512, MAC key | `HmacKey` | `[0x1a][0x40][key: 64]` |

A beacon key of HMAC-SHA256 is serialised as `[0x1a][0x20][key: 32]`, its 32 bytes in
`key_value`, field 3, as in Tink's `HmacPrfKey` without its parameters: the bytes of a 32-byte
`AesGcmKey`. It is encrypted as a DEK is, raw under an Azure key. A MAC key of a keyring is serialised the same
way, in field 3 and never in field 2, since `[0x12][0x40][key: 64]` is byte for byte an AES-SIV key,
see [MACs in a keyring](./signing.md#macs-in-a-keyring).

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
  that decrypts the value, and Tink and BigQuery pick the key of a keyset by it. It is not
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
that decrypts it.

The check reads the framing only, and whether the bytes are authentic is known when they are
decrypted. With `legacy-formats`, an `Envelope` value also holds the envelope layout v1 of 0.29 and
the length-prefixed envelope, checked by their lengths, so a column decodes its old rows into the
same type until they are upgraded, see [Upgrading stored values](#upgrading-stored-values). Without
the feature, `Encrypted::try_from` refuses them with `LEGACY_FORMAT`. `separate` refuses them in
every build. The layout of 32-bit targets before 0.24.0 has Tink's framing, so it reads as an
`Envelope` value in every build, and `KmsAeadEnvelope::decrypt` decrypts it with `legacy-formats`.

The plaintext inside is the encoding of the value's `Plaintext` type: UTF-8 for `String`, the
bytes themselves for `Vec<u8>` and `SecretValue`, `true` or `false` for `bool`, decimal ASCII for
the integers, and compact JSON for `JsonEncoded<T>`. See
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
| 31 | set for deterministic versions, alone |
| 30 | set for beacon versions, alone |
| 31 and 30 | set for MAC versions |
| 0 to 29 | the ordinal, from 1, counted per purpose |

So the ids of each purpose are:

- randomised: `1`, `2`, `3`, …;
- deterministic: `2147483649`, `2147483650`, …;
- beacon: `1073741825`, `1073741826`, …;
- MAC: `3221225473`, `3221225474`, ….

An id whose ordinal is 0 is reserved: `0`, `2^30`, `2^31` and `2^31 + 2^30`. A value that carries
one fails with `ReservedKeyId`. A value whose id is of another
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
    "beacon": "hmac-sha256",
    "mac": null
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
- `algorithms` holds the algorithm new versions of each purpose use. `deterministic`, `beacon` and
  `mac` are `null` for a keyring without versions of that purpose. `mac` is `mac-hmac-sha256` or
  `mac-hmac-sha512`, distinct from the beacon's `hmac-sha256`, since the algorithm name fixes a
  version's purpose;
- `signature` is an optional top-level member, absent from the record above:
  `"signature": "<standard base64 of the detached Signature bytes>"`, written where the
  administration signs its records, see
  [The signed keyring record](#the-signed-keyring-record). A reader of 0.30 ignores it;
- `seal_epoch` is the record's re-encryption epoch: it counts the writes that made a version active,
  from 1 at the creation, see [Encryption markers](#encryption-markers);
- `versions` holds every version ever created, in creation order, each under its
  [key id](#keyring-key-ids);
- `state` is `pending`, `active`, `decrypt_only`, `retired` or `destroyed`. For a pending version,
  `state_changed_at` is the time it was staged;
- `compromised` is `null`, or `{"at": "<time>", "note": "<the operator's note, or null>"}`;
- `seal_epochs` is the version's re-encryption range as epochs, `{"start": <epoch>, "end": <epoch or
  null>}`: the epoch of the write that made it active, and the epoch of the first write after it
  stopped being active that moved the epoch on, `null` until then. It is `null` for a version that
  was never active, see [Encryption markers](#encryption-markers);
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
| Cloud KMS, RSA 2048-bit key, public-key encryption (computed) | 608 | about 1,700 |
| Cloud KMS, RSA 3072-bit key, public-key encryption (computed) | 776 | about 1,350 |
| Cloud KMS, RSA 4096-bit key, public-key encryption (computed) | 948 | about 1,100 |
| AWS KMS, RSA 2048-bit key, public-key encryption (computed) | 602 | about 1,750 |
| AWS KMS, RSA 4096-bit key, public-key encryption (computed) | 942 | about 1,100 |
| Azure, RSA 2048-bit key, public-key encryption (computed) | 678 | about 1,550 |
| Azure, RSA 4096-bit key, public-key encryption (computed) | 1,018 | about 1,000 |
| Vault Transit, RSA 2048-bit key, public-key encryption (computed) | 608 | about 1,700 |
| local KMS, RSA 2048-bit key, 10-byte KEK id, public-key encryption (computed) | 619 | about 1,700 |

The local KMS row was measured on a record the crate wrote after 500 randomised rotations, each
version AES-256-GCM, decrypt-only with a re-encryption range. The other rows are the same record
with each encrypted DEK replaced by one of that KMS's length, and a KEK version of that KMS's form:
none for AWS, two digits for GCP and Vault, 32 hex digits for Azure. The rows marked computed were
not measured: they are the same record with the encrypted DEK of the `0x02` layout, the header and
one RSA block, see [DEKs encrypted with a public key](#deks-encrypted-with-a-public-key).

A reader fails with `RecordInvalid` on a document that breaks any of:

- at most one active and one pending version per purpose, neither of them compromised;
- an encrypted DEK on every version but the destroyed ones, and a `kek_version`, when there is
  one, of 1 to 255 ASCII alphanumerics beside it;
- unique key ids of the purpose of their algorithm, increasing within a purpose in creation order;
- no two versions with the same `encrypted_dek` bytes (`DuplicateEncryptedDek`), so that a key
  filed under a second id is refused where the record is read;
- a `seal_epoch` of 1 or more;
- `seal_epochs` on every active, decrypt-only and retired version and on no pending one, open on
  the active version, starting at 1 or more and below its end, and within the `seal_epoch`.

## Encryption markers

An encryption marker is the re-encryption epoch of the keyring record a write encrypted a
record's fields under, which the application stores beside them:

```text
[0x01][re-encryption epoch: u32 BE]
```

5 bytes in all, so that markers compare as their epochs do, and so do their bytes as Firestore,
PostgreSQL and BigQuery compare them. `EncryptionMarker::ENVELOPE`, `01 00 00 00 00`, is epoch 0, the
marker of a record of envelope values. `EncryptionMarker::try_from` fails with
`InvalidEncryptionMarker` on bytes of any other length or first byte. Serde stores a marker as bytes,
an array of numbers in serde_json, and the `postgres` and `sqlx` features as `BYTEA`. See
[Sweeps](./operations/sweeps.md) for the query it serves.

The record's JSON members for the epoch and the ranges keep the names `seal_epoch` and
`seal_epochs`. `KeyVersion::reencrypt_range()` returns the markers of a version's `seal_epochs` as a
`ReencryptRange`: `start()`, and `end()`, `None` while the range is open. A record whose fields were
encrypted through one `Encryptor`, and which stores the marker of the encryptor's record, lies in
the range of every version its fields are under. See [Records under a
version](./operations/sweeps.md#records-under-a-version) for the query it serves.

## DEKs encrypted with a public key

An encrypted DEK that a public key encrypted has one layout for every KMS:

```text
[0x02][a: u8][i: u8][KEK id: i bytes][k: u8][KEK version: k ASCII alphanumerics][RSA block]
```

- `0x02` is the layout. No encrypted DEK of a built-in provider starts with it before 0.31, see
  [Telling layouts apart](#telling-layouts-apart);
- `a` is the algorithm: `0x01` for RSA-OAEP with SHA-256 as the OAEP hash and the MGF1 hash, and an
  empty label. A later algorithm is another value;
- `i` and the KEK id are the local KEK's `LocalKekId`. `i` is 0 for a cloud KEK;
- `k` and the KEK version are the version the public key carried, as the reader names it to its KMS:
  1 to 255 ASCII alphanumerics. `k` is 0 under AWS KMS, which has no versions, and the version is the
  decimal `LocalKekVersion` under the local KMS;
- the RSA block is as long as the modulus: 256, 384 or 512 bytes for a key of 2048, 3072 or 4096
  bits. The encrypted DEK is the header and the block, 260 bytes under AWS KMS with a 2048-bit key.

The block is the OAEP encryption of the DEK in the form its KEK's provider encrypts it: the
[serialised DEK](#serialised-deks), or the raw DEK under Key Vault. The seed of OAEP is random, so
two encryptions of one DEK differ.

A reader checks the header against its own shape before any KMS call, and refuses the encrypted DEK
with `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` otherwise: a known algorithm byte; a header within the bytes;
`i` of 0 for a cloud KEK; `k` of 0 under AWS KMS and 1 or more elsewhere; a block of 256, 384 or 512
bytes. Nothing in the header is authenticated: a changed version or KEK id names a key that fails to
decrypt the block, and no change decrypts a value.

How each KMS decrypts the block:

| KMS | Request |
|---|---|
| Google Cloud KMS | `AsymmetricDecrypt` on `<key>/cryptoKeyVersions/<version>`, `ciphertext` the block |
| AWS KMS | `Decrypt` with `KeyId` the key, `EncryptionAlgorithm` `RSAES_OAEP_SHA_256` and `CiphertextBlob` the block |
| Azure Key Vault | `unwrapKey` on the key and the version with `alg` `RSA-OAEP-256` |
| Vault Transit | `decrypt` on the key with `ciphertext` `vault:v<version>:` and the standard base64 of the block, `padding_scheme` `oaep` and `hash_algorithm` `sha2-256` |
| Local KMS | RSA-OAEP decryption with the version's private key |

None of the four KMS decryptions takes a label or an AAD. What binds a value to its place is its own
AAD.

## Streamed values

A streamed value is a header and chunks. Every length is in bytes and integers are big-endian. The
prefixed form, the one of `AeadCipher::stream_encryptor` and of the keyring:

```text
offset          len     field
     0            1     0x01, Tink's output prefix of type TINK
     1            4     key id, u32: the keyring version that encrypted the value, or the caller's KeyId
     5           24     salt, random per value
    29           32     key commitment
    61       16,400     chunk 0: 16,384 bytes of ciphertext and a 16-byte tag
    61 + k × 16,400     chunk k
```

The bare form is a Cobblestone-256 message as [C2SP chunked encryption](https://c2sp.org/chunked-encryption)
writes it, with the caller's AAD as its *context* and the DEK as its *input key*:

```text
offset          len     field
     0           24     salt
    24           32     key commitment
    56       16,400     chunk 0
    56 + k × 16,400     chunk k
```

The envelope form, the one `KmsAeadEnvelope::stream_encryptor` writes, puts the encrypted DEK in
front of the bare form, as [Tink's KMS envelope](#tinks-kms-envelope) puts it in front of a bare
value:

```text
offset          len     field
     0            4     w, u32: the length of the encrypted DEK, 1 to 4,096
     4            w     encrypted DEK, the provider's EncryptedDataEncryptionKey
 4 + w           24     salt
28 + w           32     key commitment
60 + w       16,400     chunk 0
60 + w + k × 16,400     chunk k
```

- the header `H` is 61 bytes in the prefixed form, 56 in the bare form and `60 + w` in the
  envelope form. From the Cobblestone header on, the forms are the same;
- every chunk but the last is 16,400 bytes as stored. The last chunk is 16 to 16,399 bytes, the tag
  and 0 to 16,383 bytes of ciphertext, so a plaintext of a multiple of 16,384 bytes ends with a
  tag alone. An empty plaintext is the header and one tag, 77 bytes prefixed, 72 bare and `76 + w`
  in the envelope form. There is one chunking for each length;
- only the first byte of a prefixed header is checked when it is read. The key id is not
  authenticated: it names the key that decrypts the value;
- a reader of the envelope form reads `w` from the first 4 bytes, refuses a `w` outside 1 to 4,096
  before it fetches or allocates anything, then reads the `60 + w` bytes of the header. The
  encrypted DEK is not authenticated either: another value's encrypted DEK decrypts to another DEK,
  which fails the key commitment;
- no byte tells the bare form from the others, since a bare value starts with its random salt. The
  call names the form.

The keys come from the DEK `K` of 32 bytes, the salt and the AAD `A`:

```text
key || base nonce || commitment = HKDF-Expand(SHA-512, PRK = K,
    info = "c2sp.org/chunked-encryption@v1+" || "AEAD_AES_256_GCM" || 0x00 || salt || A,
    length = 32 + 12 + 32)
```

With a 32-byte PRK, HKDF-Expand is two HMAC-SHA-512 calls: `T1 = HMAC(K, info || 0x01)` gives the key
(`T1[0..32]`), the base nonce (`T1[32..44]`) and `commitment[0..20]` (`T1[44..64]`), and
`T2 = HMAC(K, T1 || info || 0x02)` gives `commitment[20..32]` (`T2[0..12]`). A reader derives all
three and compares the commitment in constant time before it decrypts a chunk. The AAD is bound here
and nowhere else: each chunk's GCM associated data is empty.

Chunk `k` holds plaintext bytes `[k × 16,384, (k + 1) × 16,384)` and is
`AES-256-GCM(key, N_k, aad = "", M_k)`, with the nonce `N_k = base nonce XOR k`, `k` as a 96-bit
big-endian integer. There is no final flag: the final chunk is the one that is shorter than a full
one.

For a plaintext of `L` bytes the stored length is `Z = H + L + 16 × n` with `n = L div 16,384 + 1`
chunks. From a stored length `Z`, with `body = Z - H`:

```text
Z < H + 16          refused: shorter than the header and one tag
n = body div 16,400 + 1
r = body - (n - 1) × 16,400     the final chunk as stored
r < 16              refused: r = 0 is a value cut at a chunk boundary, 1 to 15 no encryptor writes
n > 2^38            refused
L = body - 16 × n
```

A value holds at most 2^38 chunks, 4 PiB less one byte of plaintext. The refusals are
`STREAM_LENGTH`. `Z` is what the store reports: until the final chunk has been decrypted, `L` is the
store's word. A reader that reads the value to its end needs no `Z`: the bytes after the last full
chunk are the final chunk, and the rules above hold for the length it read.

For a plaintext range `[a, b)` with `a <= b <= L`, the chunks to decrypt and the bytes to fetch are
below. A range open at the start has `a = 0` and one open at the end has `b = L`, so `..` is `[0, L)`:

```text
first = a div 16,384
end   = n                      if b == L: the final chunk, even when it holds no plaintext
        first                  if a == b < L
        (b - 1) div 16,384 + 1 otherwise
ciphertext = [H + first × 16,400, min(Z, H + end × 16,400))
```

The reader cuts the decrypted plaintext to `[a - first × 16,384, b - first × 16,384)`. For
`a = 1,000,000` and `b = 1,064,512` the chunks are `61..65` and the bytes `[1,000,461, 1,066,061)`
prefixed or `[1,000,456, 1,066,056)` bare, and `4 + w` bytes further in the envelope form.

The two shortest vectors of the C2SP test file as prefixed values under key id 7, with the key
`59454c4c4f57205355424d4152494e452059454c4c4f57205355424d4152494e` and an empty AAD:

```text
vector 1, an empty plaintext, 77 bytes:
0100000007 43a2e39431cbae0389d3fc86adf46f7c3a24de88d9311617
e53f3164cc1d5dc738a66b97f0bf786565c31799c2f463d50a7e10046011dc6f
c3c939e3a5db7affb6191551669554fb

vector 2, a plaintext of 7 bytes, 84 bytes:
0100000007 a1a1b56f6db58cd1ede0c5c9db62aef20d3f96a6c594bb92
52bb38122de91236502b42a1d7fcab820ffa292940d2f86add212cfa42c38df1
9d3cc9139ee61a5990d3db57433514229beea49a8a72bd
```

The lines are the prefix and the salt, the commitment, and the final chunk. In the bare form the
vectors' `ct` are the stored values as they are.

Vector 2 in the envelope form, with the 7 bytes `wrapped` as the encrypted DEK, 90 bytes:

```text
0000000777726170706564 a1a1b56f6db58cd1ede0c5c9db62aef20d3f96a6c594bb92
52bb38122de91236502b42a1d7fcab820ffa292940d2f86add212cfa42c38df1
9d3cc9139ee61a5990d3db57433514229beea49a8a72bd
```

The first line is `w`, the encrypted DEK and the salt. A real encrypted DEK is the provider's, see
[Encrypted DEKs](#encrypted-deks). Its bytes play no part in the key derivation, which takes the
DEK.

## Signatures and MACs

Detached and attached signatures and MACs are Tink-prefixed values:

| Layout | Type | Bytes | Length |
|---|---|---|---|
| Detached signature | `Signature<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead | 0.31.0 and later |
| Attached signature | `Signed<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead | 0.31.0 and later |
| Detached MAC | `Mac<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |
| Attached MAC | `WithMac<T>` | see [Signatures and MACs](#signatures-and-macs) | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |

- `0x01` is the version of the layout. A later layout takes another first byte;
- the key id names the key that signed or computed the tag. It is not authenticated and is a hint
  only: a value whose id is changed verifies under no key;
- the signature is the raw signature of the key's algorithm: 64 bytes for Ed25519 (RFC 8032) and
  `r || s` with each scalar left-padded to 32 bytes for P-256. The algorithm is not in the value:
  the verifying key fixes it;
- the tag is the full HMAC output, never truncated: 32 bytes under HMAC-SHA256, 64 under
  HMAC-SHA512. The key version's algorithm fixes the length;
- `w` is the signature or tag length, 1 to 65,535, so a reader finds the payload at offset `7 + w`
  without knowing the key.

`TryFrom<Vec<u8>>` checks a value against its layout and fails with `INVALID_SIGNATURE_FORMAT` or
`INVALID_MAC_FORMAT`.

Every signature and every MAC is computed over the pre-image, never over the payload itself. It is
the Pre-Authentication Encoding (PAE) of
[DSSE](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md), the Dead Simple Signing
Envelope, with the SHA-256 of the payload as its body:

```text
pre-image = "DSSEv1" SP DEC(len(type)) SP type SP "32" SP SHA-256(payload)
```

- `SP` is one byte `0x20`;
- `DEC(n)` is `n` in ASCII decimal with no leading zeros;
- `type` is the payload type: 1 to 255 bytes of visible ASCII, `0x21` to `0x7E`, such as
  `application/vnd.example.invoice+json`;
- `SHA-256(payload)` is the 32-byte digest of the payload bytes.

The pre-image is 46 to 302 bytes long. Ed25519 signs it as it is, and ECDSA P-256 signs its SHA-256.
A MAC is the HMAC of the pre-image. The payload is the bytes `Signable::to_payload` returns, which
the library neither parses nor re-serialises.

The key id of a signing key is derived from its public key:

```text
thumbprint input = {"crv":"Ed25519","kty":"OKP","x":"<base64url of the 32 bytes>"}
                 | {"crv":"P-256","kty":"EC","x":"<base64url of x>","y":"<base64url of y>"}
digest           = SHA-256(thumbprint input)
kid              = base64url(digest), without padding, 43 characters
key id           = the first four bytes of digest, as a big-endian u32
```

The thumbprint input is the JWK thumbprint of [RFC 7638](https://www.rfc-editor.org/rfc/rfc7638): the
required members of the key in lexicographic order, with no whitespace. A publisher with a numbering
of its own sets the id instead, and the published key carries it as the integer member
`kms_aead_key_id`. The key id of a MAC key is the keyring's id of the version, see
[Keyring key ids](#keyring-key-ids).

A set of public keys is a JWK Set ([RFC 7517](https://www.rfc-editor.org/rfc/rfc7517)). Each key has
`kty`, `crv`, `x` (and `y`), `kid` the full thumbprint, `use` `sig` and `alg` `EdDSA` or `ES256`,
and `kms_aead_key_id` where the publisher set the id:

```json
{"keys":[
  {"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
   "kid":"kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k","use":"sig","alg":"EdDSA"},
  {"kty":"EC","crv":"P-256","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y",
   "y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk",
   "kid":"DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0","use":"sig","alg":"ES256"}
]}
```

### The signed keyring record

A keyring record carries its signature as the top-level member `signature`, the standard base64 of
a detached `Signature` over the record's canonical document:

```text
canonical = JCS(record document without its "signature" member)
pre-image = PAE("application/vnd.kms-aead.keyring-record+json", SHA-256(canonical))
```

JCS is the JSON Canonicalization Scheme of [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785):
members sorted by name, no whitespace, standard string escaping with non-ASCII kept as UTF-8 and
control characters as `\u00XX`. It is computed over the parsed JSON document with every member
kept, including members this release does not know, so a later release may add members and sign
records that carry them. A record holds strings, integers, booleans, `null`, arrays and objects; a
fraction, an exponent or an integer beyond 2^53 anywhere in it is `RECORD_INVALID`. The canonical
document of a record with a `null`, a nested `compromised`, a note holding `é` and the control
character `0x07`, and a member `future` this release does not define, on one line of 579 bytes
without the line breaks shown here:

```text
{"algorithms":{"beacon":null,"deterministic":null,"mac":null,"randomized":"aes-256-gcm"},
"created_at":"2026-10-25T09:00:00Z","future":{"a":[true,null],"b":1},"id":"tenant-42",
"kek":{"key":"tenant-kek","provider":"local"},"schema":1,"seal_epoch":1,
"updated_at":"2026-10-25T09:00:00Z","versions":[{"algorithm":"aes-256-gcm",
"compromised":{"at":"2026-10-25T09:00:00Z","note":"clé \u0007"},
"created_at":"2026-10-25T09:00:00Z","encrypted_dek":"AQ==","kek_version":"1","key_id":1,
"seal_epochs":{"end":null,"start":1},"state":"decrypt_only",
"state_changed_at":"2026-10-25T09:00:00Z"}]}
```

Its SHA-256 is `195ad529d5ec1beec7f6d806169d598723bf067c6abd6b522ab330310f2d79d2`, with `é` as the two
bytes `c3 a9`. The pre-image is `DSSEv1 44 application/vnd.kms-aead.keyring-record+json 32 ` and that
digest, 90 bytes. Under the Ed25519 key of the vectors below the stored member is
`"signature": "AZD6yv6RAlxJsp1uzsdIQxlvyawlD282Dfrtg3QthYeSPnQ02B6jbpOBFA65Y2Zq5lILiXyyTCxj9bv36JGSWC2H2UAG"`.

### Signature and MAC test vectors

Generated with Python's `cryptography` 50.0.2 from published keys, so that nothing in them is
secret. Payload type `application/vnd.example.invoice+json`, payload
`{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","total_cents":12500}`:

```text
SHA-256(payload)       7b43154b748a12c6909cba38acd83fff12a11b6345effb807b21c7ce465e4cd1
pre-image (82 bytes)   445353457631203336206170706c69636174696f6e2f766e642e6578616d706c652e
                       696e766f6963652b6a736f6e203332207b43154b748a12c6909cba38acd83fff12a1
                       1b6345effb807b21c7ce465e4cd1
SHA-256(pre-image)     4617fb02679fc4831b071fb2a064a33c2999e5f6a3c2fb65a96474d5663950be
```

Ed25519, the RFC 8032 section 7.1 test 1 key, seed
`9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60`:

```text
public key             d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
SubjectPublicKeyInfo   302a300506032b6570032100 || public key
PKCS#8                 302e020100300506032b657004220420 || seed
thumbprint input       {"crv":"Ed25519","kty":"OKP","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
kid                    kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k
key id                 90facafe = 2432355070
signature              21c5f4d55977b19640f25f0e248d4c9765aa0d210f9c781b61b46dece74d4dec
                       b950acf3947659a9fff322b88ad8562e2c9ee4392440a4da901b7fec385f1102
detached (69 bytes)    0190facafe || signature
attached (160 bytes)   0190facafe0040 || signature || payload
```

ECDSA P-256, the RFC 6979 A.2.5 key, private scalar
`c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721`. ECDSA signing is randomised,
so the signature verifies and is not reproduced:

```text
x                      60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6
y                      7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299
SubjectPublicKeyInfo   3059301306072a8648ce3d020106082a8648ce3d030107034200 || 04 || x || y
thumbprint input       {"crv":"P-256","kty":"EC","x":"YP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Y","y":"eQP-EAi4vJmkGunpVii8ZPLxsgwtfp9Rd6PClNRGIpk"}
kid                    DOvxvJiAdIqVWIkFt5hDtCunXLF0BV4-JGv4f-ALSm0
key id                 0cebf1bc = 216789436
signature as DER       30450220409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7
                       022100af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976
r || s                 409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7
                       af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976
detached (69 bytes)    010cebf1bc || r || s
```

HMAC-SHA256 under the key of 32 bytes `0x42`, key id `3221225473`, the first MAC version of a
keyring:

```text
tag                    a2ca416600c31c19620b0b021986b1116ef1186318b32d819659093c125737f9
detached (37 bytes)    01c0000001 || tag
attached (128 bytes)   01c00000010020 || tag || payload
```

HMAC-SHA512 under the key of 64 bytes `0x42`, key id `3221225474`, the second MAC version:

```text
tag                    620e50560d4f30c943664d8671c2788db8a1165c742ab379afaf9047dfa3610a
                       ca85a98e462c791f19d966e04b90748ce397755de7dc86a49f511a9021331ac3
detached (69 bytes)    01c0000002 || tag
attached (160 bytes)   01c00000020040 || tag || payload
```

The primitives are checked against [Wycheproof](https://github.com/C2SP/wycheproof/tree/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1)
on every backend, and these vectors on ring, aws-lc-rs, RustCrypto and, with
`tests/webcrypto_vectors.mjs`, WebCrypto under Node.

## Telling layouts apart

The first bytes of a stored value:

| First bytes | Layout |
|---|---|
| `00 00 00 00` | the length-prefixed envelope of 0.28.1 and earlier |
| `00`, then a length of 1 to 4,096 | Tink's KMS envelope, an envelope streamed value, or the 4-byte length prefix of 32-bit targets before 0.24.0 |
| `01` | envelope layout v1 of 0.29, or a TINK-prefixed value |
| `02` | a DEK encrypted with the public half of an asymmetric KEK |
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
- streamed values and bare streamed values: no byte tells them apart, since a bare one starts
  with its random salt, so the call names the form, as `decrypt_bare` does for a bare value, see
  [Streamed values](#streamed-values);
- envelope streamed values and Tink envelopes: both start with `[w][encrypted DEK]`, so the
  layout is recorded outside the value, as for bare values;
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

The envelope's algorithm is the one the values were encrypted with: ChaCha20-Poly1305 for values
that 0.29 and earlier encrypted under their default. A raw DEK does not record its algorithm, and
the encrypted DEK of the upgrade records it as a Tink key type, so `upgrade_legacy_value` takes the
value's AAD and decrypts the value before it writes anything. Under another algorithm or another AAD
it fails with `DECRYPT`. `upgrade_legacy_encrypted_dek` has no value to decrypt, so it records the
envelope's algorithm for any key of its length. Be aware not to upgrade a DEK stored apart under
another algorithm than its values were encrypted with: use `upgrade_legacy_value` wherever the
values are at hand.

A sweep over stored rows:

```rust
use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{Encrypted, KmsAeadDecryptionProvider, KmsAeadEnvelope, KmsAeadResult};
use secret_vault_value::SecretValue;

/// A stored envelope value and the AAD it was encrypted under.
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
    P: KmsAeadDecryptionProvider,
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
# use kms_aead::{AeadAlgorithm, AeadCipher, KmsAeadEncryptionProvider, KmsAeadEnvelopeOptions};
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
