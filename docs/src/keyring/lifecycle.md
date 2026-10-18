# Key versions and lifecycle

## The record

A keyring record holds:

- the keyring id, the scope it encrypts for: 1 to 128 ASCII alphanumerics, `-`, `_` and `.`,
  except `.` and `..` and ids that start and end with `__`. Such an id is a Firestore document
  id, a PostgreSQL key, a part of a GCS object name or an S3 object key, and a BigQuery string
  without escaping. It is an identifier, not a secret, and appears in spans and errors;
- the KEK of the provider the keyring was created with;
- the algorithms new versions use, one per purpose;
- every key version ever created, in creation order.

Every store keeps it as the same JSON document. A keyring with a deterministic version, after one
randomized rotation, with the wrapped DEKs shortened:

```json
{
  "schema": 1,
  "id": "tenant-42",
  "kek": { "provider": "local", "key": "tenant-kek" },
  "algorithms": { "randomized": "aes-256-gcm", "deterministic": "aes-256-siv" },
  "versions": [
    {
      "key_id": 1,
      "algorithm": "aes-256-gcm",
      "state": "decrypt_only",
      "compromised": null,
      "created_at": "2026-10-18T04:47:14.882949235Z",
      "state_changed_at": "2026-10-18T04:47:14.883340479Z",
      "wrapped_dek": "/wEBMQEKdGVuYW50LWtlawAAAAGT/DUOrGI1..."
    },
    {
      "key_id": 2147483649,
      "algorithm": "aes-256-siv",
      "state": "active",
      "compromised": null,
      "created_at": "2026-10-18T04:47:14.882949235Z",
      "state_changed_at": "2026-10-18T04:47:14.882949235Z",
      "wrapped_dek": "/wEBMQEKdGVuYW50LWtlawAAAAEm/upkqN/Z..."
    },
    {
      "key_id": 2,
      "algorithm": "aes-256-gcm",
      "state": "active",
      "compromised": null,
      "created_at": "2026-10-18T04:47:14.883340479Z",
      "state_changed_at": "2026-10-18T04:47:14.883340479Z",
      "wrapped_dek": "/wEBMQEKdGVuYW50LWtlawAAAAFnfb1urGjc..."
    }
  ],
  "created_at": "2026-10-18T04:47:14.882949235Z",
  "updated_at": "2026-10-18T04:47:14.883340479Z"
}
```

`wrapped_dek` is the standard base64 of the [encrypted key layout v1](../formats.md#encrypted-key-layout-v1),
so the KEK version travels with each wrapped DEK. The `kek` field is informational: it catches a
keyring opened with the wrong provider, with `KekMismatch`, and is no security control, since a
writer of the record sets it as freely as any other field. What refuses a DEK wrapped under
another KEK is the KMS, since every unwrap names the configured KEK.

A record holds at most 1 MiB of JSON, about 2,600 versions at about 400 bytes per version. Every
read checks the document and its invariants:

- at most one active version per purpose, and never a compromised one;
- a wrapped DEK on every version but the destroyed ones;
- unique key ids of their algorithm's purpose, increasing within a purpose.

A record that breaks one fails with `RecordInvalid`, naming the rule and never the bytes.

`Keyring::record()` returns the cached record, to inspect versions and states.

## Key ids

Every value carries the key id of the version that sealed it. Bit 31 of the id is the purpose,
set for deterministic versions, and bits 0 to 30 are the ordinal, from 1, counted per purpose:

- randomized versions are `1`, `2`, `3`, …;
- deterministic versions are `2147483649`, `2147483650`, ….

So a randomized value never opens under a deterministic version, and the purpose of a value is
known from its bytes. Ids are never reused: a destroyed version keeps its id in the record.

## States

```text
                     rotate                 retire               destroy
  (new) ──create──▶ Active ──────▶ DecryptOnly ──────▶ Retired ──────▶ Destroyed
                      │                 ▲    │            ▲
                      │ mark_compromised│    └─reinstate──┘
                      └─────────────────┘
```

- `Active`: encrypts new values and decrypts. At most one per purpose;
- `DecryptOnly`: decrypts only. Every version a rotation replaced;
- `Retired`: refused on read with `KeyVersionRetired`. The wrapped DEK stays in the record, so
  `reinstate` can undo it;
- `Destroyed`: the wrapped DEK is removed from the record, and reads fail with
  `KeyVersionDestroyed`.

Any state past `Active` may also be compromised. The flag is set by `mark_compromised`, with a
time and an optional note, and never clears. A compromised active version is moved to
`DecryptOnly` and replaced in the same write.

The calls:

| Call | Does |
|---|---|
| `rotate(purpose)` | creates a new active version with the record's algorithm for the purpose; the previous active one becomes `DecryptOnly` |
| `change_algorithm(algorithm)` | makes `algorithm` the one new versions of its purpose use, and rotates that purpose |
| `mark_compromised(key_id, note)` | flags the version; for the active version also rotates in the same write |
| `retire(key_id)` | `DecryptOnly` to `Retired`, once a sweep found no value left under it |
| `reinstate(key_id)` | `Retired` back to `DecryptOnly`, for a value that turned up after all; a compromised flag stays |
| `destroy(key_id)` | `Retired` to `Destroyed` |
| `rewrap()` | unwraps and wraps again every DEK in the record, under the KEK's current version; no value changes |

A call that does not apply to the version's state fails with `InvalidTransition`. Each call reads
the record, applies the change and writes it with a compare-and-swap, reading again after a
conflict up to `KeyringOptions::cas_retries` times, 5 by default, before `RecordConflict`.

`mark_compromised` on the active version needs to wrap a new DEK. When the KMS cannot, in an
outage or without the encrypt right, the flag is written alone, a `WARN` is logged, and the call
returns `Ok(None)`: the purpose then has no active version, and `encrypt` fails with
`NoActiveVersion` until `rotate` succeeds. A compromised flag is never held back by the KMS.

`destroy` removes the wrapped DEK from this record only. A backup of the record still holds it,
and the KMS still unwraps it as long as the KEK version that wrapped it exists, see
[Crypto-shredding](../operations.md#crypto-shredding).

## Reading a compromised version

`KeyringOptions::compromised_reads` decides what `decrypt` does with a value under a compromised
version:

- `CompromisedReadPolicy::Block`, the default: fails with `KeyVersionCompromised`, decided on the
  cached record before any unwrap;
- `CompromisedReadPolicy::Allow`: decrypts, with one `WARN` event per value. Use it for the time
  of a sweep when availability matters more, and be aware the leaked DEK can forge values under
  that id meanwhile.

`decrypt_with_status` opens the value whatever the policy, and returns a `Decrypted` with the
value, the key id that opened it and its `KeyTrust`, `Trusted` or `Compromised`. It is the call
for a [sweep](../operations.md#sweeps). A compromised version's DEK is unwrapped by the provider
for that call only and never returns to the DEK cache.
