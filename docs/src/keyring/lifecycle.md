# Key versions and lifecycle

## The record

A keyring record holds:

- the keyring id, the scope it encrypts for: 1 to 128 ASCII alphanumerics, `-`, `_` and `.`,
  except `.` and `..` and ids that start and end with `__`. Such an id is a Firestore document
  id, a PostgreSQL key, a part of a GCS object name or an S3 object key, and a BigQuery string
  without escaping. It is an identifier, not a secret, and appears in spans and errors;
- the KEK of the provider the keyring was created with;
- the algorithms new versions use, one per purpose;
- every key version ever created, in creation order, each with its encrypted DEK and its state.

Every store keeps it as the same JSON document, see [Keyring records](../formats.md#keyring-records)
for the document and the rules every read checks. A record that breaks one fails with
`RecordInvalid`, naming the rule and never the bytes.

The `kek` field is informational: it catches a keyring opened with the wrong provider, with
`KekMismatch`, and is no security control, since a writer of the record sets it as freely as any
other field. What refuses a DEK encrypted under another KEK is the KMS, since every decryption names
the configured KEK.

`Keyring::record()` returns the cached record, to inspect versions and states, such as
`record.pending(Purpose::Randomized)` for the version a rotation staged. An administrative job
reads it as `admin.keyring().record()`.

## Key ids

Every value carries the key id of the version that sealed it, and the id names the version's
purpose: randomised, deterministic or beacon. So a value of one purpose never opens under a
version of another, and the purpose of a value is known from its bytes, see
[Keyring key ids](../formats.md#keyring-key-ids). The keyring numbers the versions of each purpose
from its first id: randomised versions are `1`, `2`, `3`, …, deterministic ones `2147483649`,
`2147483650`, … and beacon ones `1073741825`, `1073741826`, …. Ids are never reused: a destroyed
version keeps its id in the record.

A key id is a `kms_aead::KeyId`, which the keyring re-exports. `value.key_id()` reads the key id
of a stored value, and `version.algorithm().purpose()` the purpose of a version. An operation that
names a reserved key id fails with `ReservedKeyId` before any store call.

## States

```text
                       promote                          retire           destroy
  rotate ──▶ Pending ──────────▶ Active ──▶ DecryptOnly ──────▶ Retired ─────────▶ Destroyed
                │                   ▲            ▲                 │                   ▲
                │       create ─────┘            └────reinstate────┘                   │
                └───────────────────────────────destroy────────────────────────────────┘
```

- `Pending`: staged by a rotation. Decrypts, and never encrypts until it is promoted. At most one
  per purpose;
- `Active`: encrypts new values and decrypts. At most one per purpose;
- `DecryptOnly`: decrypts only. Every version a promotion replaced;
- `Retired`: refused on read with `KeyVersionRetired`. The encrypted DEK stays in the record, so
  `reinstate` can undo it;
- `Destroyed`: the encrypted DEK is removed from the record, and reads fail with
  `KeyVersionDestroyed`.

A promotion moves the previous active version to `DecryptOnly`, and so does `mark_compromised` on an
active version. Any state right of `Active` may also be compromised. The flag is set by
`mark_compromised`, with a time and an optional note, and never clears. `Pending` and `Active` are
never compromised: a compromised active version moves to `DecryptOnly` in the same write that flags
it.

`KeyringRegistry::create` starts each purpose with an active version. Every later version starts
as pending, except the replacement `mark_compromised` adds for an active version, which is active
at once.

The calls, on a `KeyringAdmin`, with the `admin` feature, see
[Applications and administration](../keyring.md#applications-and-administration):

| Call | Does |
|---|---|
| `rotate(purpose)` | stages a pending version with the record's algorithm for the purpose, and returns its key id |
| `promote(key_id)` | makes the pending version active; the previous active one becomes `DecryptOnly`. Returns a `Rotation` with both ids |
| `change_algorithm(algorithm)` | makes `algorithm` the one new versions of its purpose use, and stages a version of it as `rotate` does |
| `mark_compromised(key_id, note)` | flags the version; for the active version also adds an active replacement in the same write |
| `retire(key_id)` | `DecryptOnly` to `Retired`, once a sweep found no value left under it |
| `reinstate(key_id)` | `Retired` back to `DecryptOnly`, for a value that turned up after all; a compromised flag stays |
| `destroy(key_id)` | `Retired` or `Pending` to `Destroyed` |
| `dangerously_destroy_all_versions()` | every version of every purpose to `Destroyed`, in any state, in one write: the keyring encrypts and decrypts nothing from then on |
| `reencrypt_deks()` | decrypts and encrypts again every DEK in the record, under the KEK's current version; no value changes |

A call that does not apply to the version's state fails with `InvalidTransition`, which names the
version, its state and the `Transition`:

- `rotate` and `change_algorithm` while the purpose has a pending version fail with
  `Transition::Rotate`, naming that version. Promote or destroy it first;
- `retire`, `mark_compromised` and `reinstate` refuse a pending version, which never sealed a
  value. `destroy` it instead.

Each call reads the record, applies the change and writes it with a compare-and-swap, reading
again after a conflict up to `KeyringOptions::cas_retries` times,
`KeyringOptions::DEFAULT_CAS_RETRIES` by default, before `RecordConflict`.

States move forward only: nothing returns to `Pending`, and `Pending` moves only to `Active` or
`Destroyed`. A running process refuses a record that moves a version backwards, see
[Record cache](./record-cache.md#when-the-store-fails-or-misbehaves).

## Staged rotation

A rotation is two calls, so that no process meets a value under a version it does not know yet:

1. `rotate(purpose)` stages the version. Every process decrypts under it once its record
   refreshes, and none encrypts under it;
2. after a wait, `promote(key_id)` makes it active. Processes seal under it from their next
   refresh, and every process that reads those values already has the version.

Promote only after the longest time any process may run without a successful refresh of its
record, counted from `KeyVersion::staged_at()`. For a healthy process that time is at most
`record_ttl`, `KeyringRegistryOptions::DEFAULT_RECORD_TTL` by default. A process whose
revalidations fail keeps its cached record for as long as they fail, and logs a `WARN` on each
failure: "The keyring record could not be revalidated; the cached record stays in use". A
deployment whose instances can take hours to update or to reach the store waits as long. Alert on
that `WARN`: an instance that logs it is one a promotion can leave behind. The library has no
guard that holds a promotion back.

An instance that has not seen the version when it reads a value under it treats the key id as
unknown and reloads its record once, at most once per `reload_min_interval`. When the store
answers, the read succeeds after the reload; when it does not, the read fails with
`KeyVersionUnknown`. The wait before `promote` is what keeps that path rare.

```rust
use std::sync::Arc;

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    KeyId, KeyVersionState, KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRecord,
    KeyringRegistry, KeyringRegistryOptions, Purpose, Rotation,
};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .open_or_create(provider, KeyringId::from_static("tenant-42"), KeyringAlgorithms::new())
    .await?;

// The administrative job stages the version
let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
let record: Arc<KeyringRecord> = admin.keyring().record();
let pending = record
    .pending(Purpose::Randomized)
    .ok_or("no pending version")?;
assert_eq!(pending.state(), KeyVersionState::Pending);

// Once the wait from `pending.staged_at()` is over, the job promotes it
let rotation: Rotation = admin.promote(staged).await?;
assert_eq!(rotation.current, staged);
assert_eq!(rotation.previous, Some(KeyId::new(1)));
registry.shutdown().await?;
# Ok(())
# }
```

## Compromised versions

`mark_compromised` on the active version replaces it with a version that is active at once, not
pending. Sealing under a compromised key has to stop at each process's next refresh, and a wait
before the replacement takes over would leave the leaked key sealing new values for that long. The
cost is the one staged rotation avoids: a process that has not seen the replacement yet reloads its
record once, rate-limited, when it meets a value under it. A pending version of the purpose stays
pending, to be promoted or destroyed as planned.

The replacement needs a new DEK encrypted. When the KMS cannot encrypt it, in an outage or without
the encrypt right, the flag is written alone, a `WARN` is logged, and the call returns `Ok(None)`:
the purpose then has no active version, and `encrypt` fails with `NoActiveVersion` until a version
is promoted. A compromised flag is never held back by the KMS.

`destroy` and `dangerously_destroy_all_versions` remove encrypted DEKs from this record only. A
backup of the record still holds them, and the KMS still decrypts them as long as the KEK version
that encrypted them exists, see
[Crypto-shredding](../operations.md#crypto-shredding).

## Reading a compromised version

`KeyringOptions::compromised_reads` decides what `decrypt` does with a value under a compromised
version:

- `CompromisedReadPolicy::Block`, `KeyringOptions::DEFAULT_COMPROMISED_READS`: fails with
  `KeyVersionCompromised`, decided on the cached record before any decryption;
- `CompromisedReadPolicy::Allow`: decrypts, with one `WARN` event per value. Use it for the time
  of a sweep when availability matters more, and be aware the leaked DEK can forge values under
  that id meanwhile.

`decrypt_with_trust` opens the value whatever the policy, and returns a `Decrypted` with the
value, the key id of the version that opened it and its `KeyTrust`, `Trusted` or
`Compromised`. It is the call for a [sweep](../operations.md#sweeps). A compromised version's DEK
is decrypted by the provider for that call only and never returns to the DEK cache.
