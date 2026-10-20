# Sweeps

A sweep re-seals stored values under the active versions: after a rotation, to retire the old
version, after a compromise, and to migrate envelope values. It is a job the application runs, a
CLI or a Kubernetes Job, never a task inside the library: only the application knows its tables,
its queries and its write rules. The job runs on a schedule, and again until its `SweepReport`
shows nothing scanned. A run that stops part-way or fails on some records needs no checkpoint: the
next run's marker query returns exactly the records it did not write. Retiring the old version is
a separate step of the administrative job, see [Retiring the old version](#retiring-the-old-version).

## The seal marker

A keyring record counts a seal epoch, which moves on by one with every administrative write that
makes a version active:

| Call | Seal epoch |
|---|---|
| `create`, and `open_or_create` when it creates | 1 |
| `promote` | moves on by one |
| `mark_compromised` of the active version, with its replacement | moves on by one |
| `mark_compromised` that writes the flag alone, or of any other version | unchanged |
| `rotate`, `change_algorithm` | unchanged: the version they add is pending |
| `retire`, `reinstate`, `destroy`, `reencrypt_deks`, `dangerously_destroy_all_versions` | unchanged |

A write moves the epoch once, however many versions it makes active. `KeyringRecord::seal_marker()`
returns it as a `SealMarker`:

```text
[0x01][seal epoch: u32 BE]
```

Markers compare as their epochs do, and so do their bytes, in Firestore, PostgreSQL and BigQuery
alike. `SealMarker::ENVELOPE` is epoch 0, `01 00 00 00 00`, the marker of a record of envelope
values, below the marker of every keyring.

Each record of the application keeps the marker in one field beside its encrypted fields. A write
that touches any encrypted field of a record takes one `Sealer` from `keyring.sealer()`, seals all
of the record's encrypted fields again through it, computes its beacons again, and stores
`sealer.record().seal_marker()` in the same write, as `write_user` does in
[Running a sweep](#running-a-sweep). The sealer keeps the record it took from the cache, so the
marker names the epoch whose active versions the fields are under, also when the cache refreshes
during the write.

A marker read from `keyring.record()` names whichever record the cache held when it was read. Read
before the sealing, it can name an older epoch than the versions the fields are under, which puts
the record outside the [range](#records-under-a-version) of those versions. Read after, it can name
a newer one, and the record then drops out of every sweep.

## Finding records behind

The records a sweep still has to visit are those whose marker is below the current one:

- `seal < $1` with the marker of `keyring.record().seal_marker()`, on one indexed field, in every
  store;
- `row.seal < current` in Rust, on a record read back before its re-seal.

The query also matches a record with nothing to re-seal: after a rotation of a purpose the record
holds no value of, such as a beacon rotation for a record without beacons, its marker is below the
current one all the same. The re-seal then writes the sealer's marker alone, without decrypting
anything or calling the KMS, and the record matches once.

Each process stamps the epoch of the record it caches. A process that has not refreshed its record
since a promotion seals under the previous version and stamps the previous epoch, so its writes stay
in the query and the next sweep visits them. So the final check that the query returns nothing runs
once the longest time any process may run without a successful refresh of its record has passed
since the promotion.

The marker comes from the cached record, so a job that starts right after a promotion in another
process calls `reload()` first.

## Records under a version

`KeyVersion::seal_range()` returns the markers of the records that can hold a value under the
version, as a `SealRange`:

- `start()`, the epoch of the write that made the version active;
- `end()`, the epoch of the first write after it stopped being active that moved the epoch on, or
  `None` while there was none: the active version, and a version flagged compromised while it was
  active, until a version is next made active.

A version that was never active, pending or destroyed while pending, has no range, and neither has
an unknown key id: `record.version(key_id)` is `None`. The queries:

| Store | Query |
|---|---|
| Firestore | two range filters on `seal`, as below |
| PostgreSQL | `WHERE seal >= $1 AND ($2::BYTEA IS NULL OR seal < $2)` with `&range.start()` and `&range.end()` |
| BigQuery | `WHERE seal >= @start AND (@end IS NULL OR seal < @end)`, with `@end` a `NULL` of type `BYTES` for an open range |
| Rust | `range.contains(row.seal)` |

Firestore takes both bounds on the one field and serves them from its ascending index on `seal`,
and an open range is one filter:

```rust,no_run
use firestore::{FirestoreDb, FirestoreResult};
use futures_util::stream::{self, BoxStream, StreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{SealMarker, SealRange};
use kms_aead_keyring::{KeyId, KeyVersion, Keyring};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id", skip_serializing)]
    id: String,
    #[serde(default)]
    seal: SealMarker,
}

/// The users that can hold a value under `key_id`, as a stream: a range can hold millions.
async fn users_under<'a>(
    db: &'a FirestoreDb,
    keyring: &Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>,
    key_id: KeyId,
) -> Result<BoxStream<'a, FirestoreResult<UserDoc>>, Box<dyn std::error::Error>> {
    // The store's record: a compromise or promotion in another process is in it
    let range: Option<SealRange> = keyring
        .reload()
        .await?
        .version(key_id)
        .and_then(KeyVersion::seal_range);
    let Some(range) = range else {
        // Never active: no record holds a value under it
        return Ok(stream::empty().boxed());
    };
    let users: BoxStream<'a, FirestoreResult<UserDoc>> = db
        .fluent()
        .select()
        .from("users")
        .filter(|q| {
            q.for_all([
                q.field("seal").greater_than_or_equal(range.start()),
                range.end().and_then(|end| q.field("seal").less_than(end)),
            ])
        })
        .obj()
        .stream_query_with_errors()
        .await?;
    Ok(users)
}
#
# fn main() {}
```

The range serves two decisions:

- after `mark_compromised`, the range of the compromised version returns every record to re-seal
  and decide on, see [The trust of re-sealed values](#the-trust-of-re-sealed-values). The writes
  of processes that have not seen the compromise yet are in it too: they seal under the version and
  stamp an epoch below the range's end. Run the query again once the longest time any process may
  run without a successful refresh of its record has passed since the compromise, for the writes
  of the last of them. A version flagged compromised after it stopped being active moves no epoch,
  and keeps the range it had;
- before `retire`, and again before `destroy`, the query of the version returning nothing shows
  that no record holds a value under it, see [Retiring the old version](#retiring-the-old-version).
  That check needs one record at most: `limit(1)` in Firestore, `EXISTS` in SQL.

One epoch counts the activations of every purpose of the keyring, so a range can match a record
with no field of the version's purpose, such as a record without beacons in the range of a beacon
version. Its re-seal finds every value current and writes the marker alone. No range holds
`SealMarker::ENVELOPE`, since every range starts at epoch 1 or later. Records of several keyrings
in one table add the keyring's id to the query, as the sweep's query does, see
[Sweeps by store](#sweeps-by-store).

## Re-sealing a value

`Sealer::reseal(aad, value)` returns `None` for a value under the active randomised version of the
sealer's record, without decrypting it or calling the KMS. A value under an older version the
sealer's record holds, a decrypt-only version with a higher key id than the active one included, is
read with `decrypt_with_trust` and sealed again under the active version. The `Resealed` it returns
holds the new `value` and the `trust` of the version the old value was read under, so the
compromised-value decision stays with the caller, see
[The trust of re-sealed values](#the-trust-of-re-sealed-values). `reseal_deterministic` does the
same for deterministic values, under the `deterministic` feature.

A sealer never seals a value back under an older version. A value under a version that is pending
in the sealer's record, or missing from it, was sealed by a process with a newer record, and a
sealer taken before a `mark_compromised` would otherwise move it back under the compromised
version. The re-seal fails with `KeyringError::SealerOutdated`, after reloading the cached record
when it lacks the version or holds it as pending, under the same rate limit as `decrypt`'s reload
for a key id it lacks. The sealer keeps its own record, so that its marker still names every
version the write seals under. The write is safe to retry: it takes a new sealer and runs again,
and the new sealer, taken from the reloaded record, finds the value current or seals it under its
active version. Inside `reload_min_interval` of another such reload the cached record may not have
moved yet, and the retry fails the same way until it does. When the store's record itself holds the
version as pending, as for a value from another keyring whose key id is pending here or after a
restore from an older backup, every retry fails with `SEALER_OUTDATED`, at no more than one store
read per `reload_min_interval`. A key id the reloaded record lacks too fails with
`KeyVersionUnknown`.

A beacon cannot be re-sealed: it is a MAC of the plaintext. `sealer.is_current(beacon.key_id())`
applies the same rule to it: `true` under the active beacon version of the sealer's record, and the
beacon stays as it is; `false` under an older one, and the field is read with `decrypt_with_trust`,
whose plaintext gives both the value under the active version, through the sealer's `encrypt`, and
the beacon under the active beacon version, through its `beacon(field, &plaintext)`; and
`SealerOutdated` under a version newer than the sealer's record.

When nothing needs a re-seal, the write still stores the sealer's marker, conditional on the record
as the sweep read it, and the re-seal returns `ResealOutcome::Skipped`.

## Running a sweep

`sweep::run` drives the application's re-seal over a stream of candidates, with at most
`concurrency` in flight, and counts what happened. `sweep::run_batched` cuts the same stream into
batches, re-sealed and written back one batch per call, as `BatchedSweepOptions` sets: 100
candidates a batch and 4 batches in flight by default, `DEFAULT_BATCH_SIZE` and
`DEFAULT_CONCURRENCY`. The stream returns each candidate as a
`Result`, so that the query that finds them can fail into the report rather than end the sweep in
silence. A sweep is data plane: it takes a `Keyring`
and needs the application's rights only, since a re-seal encrypts under a DEK the record already
holds. The rotation before it and the `retire` after it are the administrative job's, on a
`KeyringAdmin`. Here over an in-memory table, with both in one process:

```rust
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::providers::LocalKmsProvider;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringResult,
    Resealed,
};
# use kms_aead::providers::LocalKekId;
# use kms_aead::KmsAeadResult;
# use kms_aead_keyring::{
#     KeyId, KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
#     Plaintext, Purpose,
# };
# use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
# const TENANT: KeyringId = KeyringId::from_static("tenant-42");
#
# #[derive(Clone)]
# struct Email(String);
#
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }

#[derive(Clone)]
struct UserRow {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// The users table, by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

/// Re-seals the row of `user` under the active version, with the marker of the sealer's record.
async fn reseal(keyring: &UsersKeyring, table: &Table, user: &str) -> KeyringResult<ResealOutcome> {
    let Some(row) = table.lock().unwrap().get(user).cloned() else {
        return Ok(ResealOutcome::Skipped);
    };
    let read: Vec<u8> = row.email.value().to_vec();
    let sealer = keyring.sealer().await;
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &row.email).await?;
    let (email, outcome) = match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the rotation was of a purpose this row holds no value of
        None => (row.email, ResealOutcome::Skipped),
    };
    let seal: SealMarker = sealer.record().seal_marker();
    // Conditional on the row as it was read: a row the application rewrote meanwhile keeps its
    // own value, which it sealed under the active versions anyway.
    let mut table = table.lock().unwrap();
    match table.get_mut(user) {
        Some(stored) if stored.email.value() == read.as_slice() => {
            *stored = UserRow { email, seal };
            Ok(outcome)
        }
        _ => Ok(ResealOutcome::Skipped),
    }
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .create(provider, TENANT, KeyringAlgorithms::new())
#     .await?;
# let keyring: &UsersKeyring = admin.keyring();
# let table = Table::default();
# for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
#     let sealer = keyring.sealer().await;
#     let email = sealer
#         .encrypt(&EMAIL.aad(&EntityId::try_from(user)?), &Email(email.to_string()))
#         .await?;
#     let seal: SealMarker = sealer.record().seal_marker();
#     table.lock().unwrap().insert(user.to_string(), UserRow { email, seal });
# }
# let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
# admin.promote_now(staged).await?;
// Every row whose marker is below the keyring's
let current: SealMarker = keyring.record().seal_marker();
let candidates = table
    .lock()
    .unwrap()
    .iter()
    .filter(|(_, row)| row.seal < current)
    .map(|(user, _)| user.clone())
    .collect::<Vec<String>>();

let report: SweepReport = sweep::run(
    keyring.id(),
    stream::iter(candidates.into_iter().map(Ok)),
    NonZeroUsize::new(8).unwrap(),
    |candidate| {
        let table = &table;
        async move { reseal(keyring, table, &candidate).await }
    },
)
.await;
println!("{report:?}");
# assert_eq!(report.resealed, 2);
# registry.shutdown(None).await;
# Ok(())
# }
```

The `SweepReport` counts every candidate once in `scanned`, and once in `resealed`, `skipped` or
`failed`. A candidate the stream returns as an error is counted in `scanned` and `failed`, and
logged at `WARN` with the error's `Display`; a stream whose query cannot go on returns its error
and ends. A re-seal that fails does not stop the sweep either: it is counted in `failed` and logged at
`WARN` with the candidate's `Display` and the error's `Display`. A re-seal that fails with
`SealerOutdated` is one of them: a process with a newer record rewrote the record after the query
returned it. The record is counted as failed, and the next run's query no longer returns it,
because the process that sealed it stamped a newer marker. A value under a version the store's
record itself holds as pending, such as a value from another keyring whose key id is pending here,
fails in every run instead. A candidate is the application's own type, such as a record id, a
struct of key columns or the record itself, and its `Display` names the record and nothing else. A
record id is often an entity id, so read the sweep's log as an administrative log.

The stream returns `Result<T, E>` and the re-seal `Result<ResealOutcome, E>`, with the
application's own error type, any type that implements `Display`. The keyring's calls inside it
return a `KeyringError`, and a `From` impl on the application's error lets `?` convert it, as the
examples on [Firestore](./sweeps-firestore.md), [PostgreSQL](./sweeps-postgres.md) and
[BigQuery](./sweeps-bigquery.md) do with an error of their data store; a re-seal with no errors of
its own returns `KeyringResult<ResealOutcome>`, as above. The error's `Display` is the application's text and goes to the log as it is, so it carries
no value, secret or personal data. The report counts failures and keeps no error: an application
that wants the errors themselves records them inside its re-seal.

## Retiring the old version

Once the sweep is done, the administrative job retires the version a promotion replaced, and later
destroys it, on its `KeyringAdmin`:

1. wait, from the promotion, the longest time any process may run without a successful refresh of
   its record, see [Staged rotation](../keyring/lifecycle.md#staged-rotation), and check that no
   process logged "The keyring record could not be revalidated" meanwhile. Until then a process
   on the old record seals under the old version and stamps the old epoch, see
   [Finding records behind](#finding-records-behind);
2. run the sweep until a run reports nothing scanned and nothing failed;
3. run the old version's [range query](#records-under-a-version). When it returns nothing,
   `retire(key_id)`. Reads under the version fail with `KeyVersionRetired` from then on, logged at
   `WARN`;
4. export the `Readable` BigQuery and Tink keysets again, which leave a retired version out, and
   write them where the old ones are kept, see
   [BigQuery and Tink interop](../keyring/bigquery.md). A keyset exported before keeps reading
   values under the retired version in SQL and in Tink;
5. keep the version retired for as long as the backups of the stored values taken before the
   sweep are kept. A destroyed version makes the values in them unreadable, as a destroyed KEK
   version does, see
   [Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
   and only a backup of the record from before the destroy still opens them, see below.
   A value the sweep missed fails with `KeyVersionRetired`: `reinstate(key_id)`, export the
   keysets again, sweep again, and go back to step 3;
6. run the range query again. When it still returns nothing, delete every copy of the keysets
   whose `key_ids()` include the retired version, then `destroy(key_id)`. The other keysets, such
   as the `Single` keyset of the active deterministic version and the `Readable` keysets of other
   purposes, keep reading their values in SQL and in Tink. No call brings a destroyed version
   back.

`destroy` removes the encrypted DEK from the record only. A backup of the record still holds it,
and so does every copy of a keyset exported while the version decrypted, both opened by the KMS as
long as the KEK version that encrypted them exists, see
[Crypto-shredding](./runbook.md#crypto-shredding).

## Sweeps by store

At millions of records a sweep streams its candidates from the store in one query and never holds
its result in memory, and it writes them back in batches. Every example, on
[Firestore](./sweeps-firestore.md), [PostgreSQL](./sweeps-postgres.md) and
[BigQuery](./sweeps-bigquery.md), has the same five properties:

- it resumes without a checkpoint: the query is the checkpoint, since a re-sealed record no longer
  matches it, so a cancelled or failed run is started again over the same query;
- a concurrent writer wins: the write is conditional on the record the sweep read, and a record
  that changed in between is `Skipped`. The application's own write re-seals every field under
  the active versions anyway;
- `concurrency` bounds the batches in flight, and with them the load on both the store and the
  KMS. The DEK cache keeps each version's key, so a sweep makes one KMS decrypt per key version
  and cache TTL, never one per record. The keys of a compromised version are the exception: they are decrypted
  for every value and never cached;
- each write stores the marker of the sealer that re-sealed the record, so the record lies in the
  range of every version it is under;
- it runs on a schedule until a run reports nothing scanned. The `retire`, and later the
  `destroy`, of the old version are the administrative job's, see
  [Retiring the old version](#retiring-the-old-version).

The examples keep one keyring's records in a collection or table. Each keyring counts its own
epochs, so records of several keyrings in one table keep their keyring's id beside the marker, and
the query compares within one keyring, `tenant = $2 AND seal < $1`, on an index over both fields: a
composite index in Firestore.

## The trust of re-sealed values

A sweep reads every field with `decrypt_with_trust`, and reports in `ResealOutcome::Resealed`
whether the `KeyTrust` of any of them is compromised. A value read under a compromised version is untrusted data: whoever holds the
leaked DEK can have forged it. Re-sealing it under a new version makes it read as trusted
everywhere afterwards.

So after a compromise the application decides per record before it re-seals:

- a quarantine field beside the marker, for a person to review;
- a comparison against a backup taken before the compromise;
- or acceptance, when forged values do no harm.

`SweepReport::resealed_from_compromised` counts the records that went through that decision, or
fewer on the [BigQuery `MERGE` path](./sweeps-bigquery.md), whose batches with a conflict count as skipped.
