# Keyring records and keysets

This page has the key ids, the stored record and the encryption markers of kms-aead-keyring, and
the Tink keysets that carry keys to Tink and BigQuery. Read it to write a keyring store, to
read a record outside the library, or to query encryption markers. The layouts of every kind of
value are listed on [Formats](../formats.md).

## Tink keysets and the TINK prefix

Two items describe the TINK-prefixed values:

- `kms_aead::KeyId`: the key id of Tink's output prefix of type TINK, `[0x01][key id: u32 BE]`,
  the start of every `Randomized` and `Deterministic` value and of every beacon. It picks the key
  that decrypts the value, and Tink and BigQuery pick the key of a keyset by it. It is not
  authenticated;
- `kms_aead::formats::TinkKeyset`: a serialised `google.crypto.tink.Keyset` of enabled, symmetric,
  TINK-prefixed keys, the bytes `tinkey` writes for the same keys. Encrypted by a Cloud KMS key, it
  is the keyset of BigQuery's `KEYS.KEYSET_CHAIN`: an application writes it for its one key, see
  [One fixed key](../one-fixed-key.md), and a keyring exports it for its
  versions.

`TinkKeyset::into_encrypted_bytes` writes the keyset encrypted by a KMS key, as Tink writes an
encrypted keyset: a `google.crypto.tink.EncryptedKeyset` whose `encrypted_keyset`, field 2, is the
KMS ciphertext of the serialised keyset, encrypted with no associated data. Tink's binary keyset
writers leave out `keyset_info`, field 3, and so does the library. Tink's `KeysetHandle.read`
reads it with the KMS client of `KekRef::tink_key_uri`, which Tink has for GCP and AWS keys, and
Tink for Go for Vault Transit keys too. A keyring exports it for its versions, see
[Exporting a keyset to Tink](../keyring/bigquery.md#exporting-a-keyset-to-tink).

## Keyring key ids

kms-aead-keyring writes the key id of a version into the TINK prefix of every value and beacon
under it. The two high bits of the id are the purpose, and the rest is the ordinal:

| Bits | Meaning |
|---|---|
| 31 | set for deterministic versions, alone |
| 30 | set for beacon versions, alone |
| 31 and 30 | set for MAC versions |
| 24 to 29 | reserved: clear in the id of every version |
| 0 to 23 | the ordinal, from 1, counted per purpose |

So the ids of each purpose are:

- randomised: `1`, `2`, `3`, …;
- deterministic: `2147483649`, `2147483650`, …;
- beacon: `1073741825`, `1073741826`, …;
- MAC: `3221225473`, `3221225474`, ….

Two kinds of id are reserved, and no version has one:

- an id whose ordinal is 0: `0`, `2^30`, `2^31` and `2^31 + 2^30`;
- an id with any of bits 24 to 29 set. These bits are kept for purposes a later release may add,
  so a reader refuses such an id rather than take it for a version of one of the four purposes.

A value that carries a reserved id fails with `ReservedKeyId`, and a value whose id is of another
purpose than the call fails with `KeyPurposeMismatch`. Both fail before any store or KMS call. A
record that holds a reserved id fails with `RecordInvalid` and the reason `ReservedKeyId`. Each
purpose has 2^24 - 1 ordinals, and ids are never reused: a destroyed version keeps its id in the
record. A key id goes up to 2^32 - 1, so a SQL column holding one is a `BIGINT`.

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
  [The signed keyring record](./signatures-and-macs.md#the-signed-keyring-record). A reader that predates record signing ignores it;
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
- `encrypted_dek` is the standard base64 of the [encrypted DEK](./values.md#encrypted-deks), the bytes the
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
one RSA block, see [DEKs encrypted with a public key](./values.md#deks-encrypted-with-a-public-key).

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

A reader reads past a member it does not know, at any depth, and keeps it in the canonical digest
that a signature covers. An administrative write refuses a record that holds one, with
`RecordInvalid` and the reason `UnknownMembers`, before it writes anything: the record it writes
holds only the members its release knows, so the others would be lost, and a signing
administration would sign what is left. Once a later release writes a member into a record, an
administrative binary of an earlier release still reads the record and no longer writes it, until
it moves to that release.

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
[Sweeps](../production/sweeps.md) for the query it serves.

The record's JSON members for the epoch and the ranges keep the names `seal_epoch` and
`seal_epochs`. `KeyVersion::reencrypt_range()` returns the markers of a version's `seal_epochs` as a
`ReencryptRange`: `start()`, and `end()`, `None` while the range is open. A record whose fields were
encrypted through one `Encryptor`, and which stores the marker of the encryptor's record, lies in
the range of every version its fields are under. See [Records under a
version](../production/sweeps.md#records-under-a-version) for the query it serves.
