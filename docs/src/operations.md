# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

A rotation is staged: `rotate(purpose)` adds a pending version, which every process decrypts under
once its record refreshes, and `promote(key_id)` makes it active once every process has had time
to see it, see [Staged rotation](./keyring/lifecycle.md#staged-rotation). The previous version keeps
decrypting. Nothing is lost while the change propagates: processes on the old record seal under
the previous version until their record refreshes, and those values decrypt.

The administrative job runs a rotation in steps, on its `KeyringAdmin`, see
[Applications and administration](./keyring.md#applications-and-administration):

1. `rotate(purpose)`;
2. export the `Readable` BigQuery keysets again, which then hold the pending version;
3. wait the longest time any process may run without a successful refresh of its record, counted
   from `staged_at()`, and check that no process logged "The keyring record could not be
   revalidated" meanwhile;
4. `promote(key_id)`. Until `record_ttl` has passed since `staged_at()` it fails with
   `PromotionTooEarly`, whose `remaining` is the time left. `promote_now(key_id)` skips that
   guard, for a fleet known to have refreshed since the rotation or a compromise that cannot wait.

The [`rotate` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/rotate.rs)
runs the whole cycle, and a KEK re-encryption after it, on the memory store and the local KMS:
`cargo run -p kms-aead-keyring --example rotate --features ring,admin`.

How often:

- A randomised DEK with random 96-bit nonces is good for about 2^32 values, see
  [Nonces](./security.md#nonces). The library cannot count the values a fleet seals, so estimate
  them: at 550 values per second a version reaches 2^32 in 90 days. Rotate every 30 to 90 days,
  sooner at higher rates. AES-128-GCM, AES-256-GCM, AES-256-GCM-SIV and ChaCha20-Poly1305 all
  take a 12-byte nonce, so the same cadence applies to each;
- AES-GCM also bounds the data sealed under one key: RFC 8446, section 5.5, allows 2^38.5 bytes
  for an AE advantage of about 2^-57. The keyring does not count bytes, since its DEKs are shared
  across processes, so schedule rotation to stay below 2^38 bytes per version under AES-GCM, the
  default [`max_bytes`](./dek-caching.md#volume-limit) of a store-less envelope. AES-256-GCM-SIV
  and ChaCha20-Poly1305 need no volume bound beyond the count of values;
- a deterministic version has no nonce, so it is rotated by policy and on compromise only. Every
  deterministic rotation adds a probe to each equality query until a full sweep re-seals every
  row, see [Queries across rotations](./keyring/deterministic.md#queries-across-rotations), so
  rotate deterministic versions rarely;
- a beacon version likewise, since every beacon rotation adds a probe to each lookup until a
  re-index, see [Rotating beacon versions](./keyring/beacons.md#rotating-beacon-versions).

After a promotion, export the `Single` BigQuery keysets of the new deterministic version, since
a pending version has none.

Rotation does not touch values already written. To stop reading them under the old version, run a
[sweep](#sweeps), then `retire` the version.

## Rotating the KEK

The KEK rotates in the KMS on its own schedule. After a rotation, `reencrypt_deks()` decrypts every
DEK in the record and encrypts it again under the KEK's current version. No value changes. A keyring
that is not re-encrypted keeps working as long as the old KEK versions stay enabled in the KMS.

`reencrypt_deks` is a `KeyringAdmin` call and runs in the administrative job, like every call that
encrypts a DEK.

The record keeps the KEK version of each encrypted DEK, as the KMS reported it when it encrypted the
DEK: `KeyVersion::kek_version`. `reencrypt_deks` returns one `DekReencryption` per version, with the
KEK version its DEK was under and the one the KMS encrypted it with now, and `kek_versions_in_use`
of the record lists every KEK version the record's DEKs are under. Before the old KEK version is
disabled, the record that `Keyring::reload` returns must list the new version alone, which needs no
KMS call. Once the old version is disabled, `reencrypt_deks` runs again: it decrypts every DEK
through the KMS and fails on one the KMS no longer decrypts. Here with the local KMS, rotated from
version 1 to version 2, where dropping version 1 from the provider stands for disabling it:

```rust
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::providers::{
    KekVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider,
};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    DekReencryption, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let kek_id = LocalKekId::try_from("tenant-kek".to_string())?;
let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
# let before_rotation = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
# )?;
# registry
#     .create(before_rotation, TENANT, KeyringAlgorithms::new())
#     .await?;

// The administrative job after the rotation, with the new version encrypting
let rotated = LocalKmsProvider::<Ring>::new(
    kek_id.clone(),
    vec![
        LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
        LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
    ],
)?;
let admin = registry.admin(rotated, TENANT).await?;

// One entry per version: the KEK version its DEK was under, and the one it is under now
let moved: Vec<DekReencryption> = admin.reencrypt_deks().await?;
let new_kek_version = KekVersion::from(v2);
assert!(moved
    .iter()
    .all(|reencryption| reencryption.kek_version.as_ref() == Some(&new_kek_version)));

// The check before the old version is disabled: every DEK is under the new version
let record = admin.keyring().reload().await?;
assert_eq!(record.kek_versions_in_use(), [Some(&new_kek_version)]);

// The check once the old version is disabled: every DEK still decrypts
let disabled = LocalKmsProvider::<Ring>::new(
    kek_id,
    vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
)?;
registry.admin(disabled, TENANT).await?.reencrypt_deks().await?;
# Ok(())
# }
```

Under Cloud KMS, a `reencrypt_deks` that ran before the new primary version had propagated reports
the old version as the one the DEK is under now, and the record keeps listing it: run
`reencrypt_deks` again once the rotation has propagated. Under Vault Transit,
`min_decryption_version` disables every version below it at once, which is why the check asks for
the new version alone.

The whole procedure, with the application's own DEKs and keysets, is in
[Re-encrypting DEKs after a KEK rotation](./envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).

### A KEK version the KMS did not report

A `None` among the versions in use stands for the DEKs whose KMS reported no version: every DEK
under AWS KMS, and under a KMS with versions, a version that is unknown, as with an application's
own provider that returns none. `reencrypt_deks` keeps such a DEK at `None`, so the check before the
disable never passes, and the check once the old version is disabled is the only one:

1. run `reencrypt_deks` after the rotation;
2. disable the old version in the KMS;
3. run `reencrypt_deks` again. It decrypts every DEK through the KMS, so an error is a DEK the KMS
   no longer decrypts: enable the old version again, and go back to step 1.

Between steps 2 and 3, a DEK still under the old version fails in the application too, once its
DEK cache entry has expired. Under AWS KMS only imported key material can be removed, see
[AWS KMS](./providers/aws.md#key-versions-and-rotation).

## Sweeps

A sweep re-seals stored values under the active versions: after a rotation, to retire the old
version, after a compromise, and to migrate envelope values. It is a job the application runs, a
CLI or a Kubernetes Job, never a task inside the library: only the application knows its tables,
its pages and its write rules.

### The seal marker

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

### Finding records behind

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

### Records under a version

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
use firestore::FirestoreDb;
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

/// The users that can hold a value under `key_id`.
async fn users_under(
    db: &FirestoreDb,
    keyring: &Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>,
    key_id: KeyId,
) -> Result<Vec<UserDoc>, Box<dyn std::error::Error>> {
    // The store's record: a compromise or promotion in another process is in it
    let range: Option<SealRange> = keyring
        .reload()
        .await?
        .version(key_id)
        .and_then(KeyVersion::seal_range);
    let Some(range) = range else {
        // Never active: no record holds a value under it
        return Ok(Vec::new());
    };
    let users: Vec<UserDoc> = db
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
        .query()
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
  that no record holds a value under it.

One epoch counts the activations of every purpose of the keyring, so a range can match a record
with no field of the version's purpose, such as a record without beacons in the range of a beacon
version. Its re-seal finds every value current and writes the marker alone. No range holds
`SealMarker::ENVELOPE`, since every range starts at epoch 1 or later. Records of several keyrings
in one table add the keyring's id to the query, as the sweep's query does, see
[Sweeps by store](#sweeps-by-store).

### Re-sealing a value

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

### Running a sweep

`sweep::run` drives the application's re-seal over a stream of candidates, with at most
`concurrency` in flight, and counts what happened. A sweep is data plane: it takes a `Keyring`
and needs the application's rights only, since a re-seal encrypts under a DEK the record already
holds. The rotation before it and the `retire` after it are the administrative job's, on a
`KeyringAdmin`. Here over an in-memory table, with both in one process:

```rust
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SealRange, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, KeyVersion, Keyring,
    KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeyringResult, Plaintext, Purpose, Resealed, Rotation,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[derive(Clone)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

#[derive(Clone)]
struct UserRow {
    email: Encrypted<Email, Randomized>,
    seal: SealMarker,
}

/// The users table, by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

/// The application's write of a user: every field sealed through one sealer, and the marker of
/// the sealer's record.
async fn write_user(
    keyring: &UsersKeyring,
    table: &Table,
    user: &str,
    email: &Email,
) -> KeyringResult<()> {
    let sealer = keyring.sealer().await;
    let email = sealer
        .encrypt(&EMAIL.aad(&EntityId::try_from(user)?), email)
        .await?;
    let seal: SealMarker = sealer.record().seal_marker();
    table
        .lock()
        .unwrap()
        .insert(user.to_string(), UserRow { email, seal });
    Ok(())
}

/// Re-seals the row of `user` under the active version, with the marker of the sealer's record.
async fn reseal(keyring: &UsersKeyring, table: &Table, user: &str) -> KeyringResult<ResealOutcome> {
    let Some(row) = table.lock().unwrap().get(user).cloned() else {
        return Ok(ResealOutcome::Skipped);
    };
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
    table
        .lock()
        .unwrap()
        .insert(user.to_string(), UserRow { email, seal });
    Ok(outcome)
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
let table = Table::default();
for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
    write_user(keyring, &table, user, &Email(email.to_string())).await?;
}

// The administrative job stages a version, and promotes it after the wait for every process to
// see it; `promote_now` stands in for the wait here
let staged: KeyId = admin.rotate(Purpose::Randomized).await?;
let rotation: Rotation = admin.promote_now(staged).await?;

// The sweep, on the data-plane handle: every row whose marker is below the keyring's
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
    stream::iter(candidates),
    NonZeroUsize::new(8).unwrap(),
    |candidate| {
        let table = &table;
        async move { reseal(keyring, table, &candidate).await }
    },
)
.await;

// Nothing left in the old version's range: the administrative job retires it
if let Some(previous) = rotation.previous {
    let range: SealRange = keyring
        .record()
        .version(previous)
        .and_then(KeyVersion::seal_range)
        .ok_or("a replaced version was active")?;
    let left = table.lock().unwrap().values().any(|row| range.contains(row.seal));
    if report.failed == 0 && !left {
        admin.retire(previous).await?;
    }
}
# assert_eq!(report.resealed, 2);
# registry.shutdown().await?;
# Ok(())
# }
```

The `SweepReport` counts every candidate once in `scanned`, and once in `resealed`, `skipped` or
`failed`. A re-seal that fails does not stop the sweep: it is counted in `failed` and logged at
`WARN` with the candidate's `Display` and the error's `Display`. A re-seal that fails with
`SealerOutdated` is one of them: a process with a newer record rewrote the record after the query
returned it. The record is counted as failed, and the next run's query no longer returns it,
because the process that sealed it stamped a newer marker. A value under a version the store's
record itself holds as pending, such as a value from another keyring whose key id is pending here,
fails in every run instead. A candidate is the application's own type, such as a record id, a
struct of key columns or the record itself, and its `Display` names the record and nothing else. A
record id is often an entity id, so read the sweep's log as an administrative log.

The re-seal returns `Result<ResealOutcome, E>` with the application's own error type, any type
that implements `Display`. The keyring's calls inside it return a `KeyringError`, and a `From`
impl on the application's error lets `?` convert it, as the examples below do with an error of
their data store; a re-seal with no errors of its own returns `KeyringResult<ResealOutcome>`, as
above. The error's `Display` is the application's text and goes to the log as it is, so it carries
no value, secret or personal data. The report counts failures and keeps no error: an application
that wants the errors themselves records them inside its re-seal.

Once a sweep reports `failed == 0` and the range query of the old version returns nothing, `retire`
it. Keep it retired for a while before `destroy`: `reinstate` brings a retired version back for a value that
turned up after all, while a destroyed one is gone.

### Sweeps by store

At millions of records a sweep streams its candidates from the store and never holds the result
of its query in memory. Every example below has the same five properties:

- it resumes without a checkpoint: the query is the checkpoint, since a re-sealed record no longer
  matches it, so a cancelled or failed run is started again over the same query;
- a concurrent writer wins: the write is conditional on the record the sweep read, and a record
  that changed in between is `Skipped`. The application's own write re-seals every field under
  the active versions anyway;
- `concurrency` bounds the re-seals in flight, and with them the load on both the store and the
  KMS. The DEK cache keeps each version's key, so a sweep makes one KMS decrypt per key version
  and cache TTL, never one per record. The keys of a compromised version are the exception: they are decrypted
  for every value and never cached;
- each write stores the marker of the sealer that re-sealed the record, so the record lies in the
  range of every version it is under;
- it ends with `retire`, then later `destroy`, once a run reports `failed == 0` and the range query
  of the old version returns nothing.

The examples keep one keyring's records in a collection or table. Each keyring counts its own
epochs, so records of several keyrings in one table keep their keyring's id beside the marker, and
the query compares within one keyring, `tenant = $2 AND seal < $1`, on an index over both fields: a
composite index in Firestore.

#### Firestore

The marker is a `bytes` field, `seal`, and the query is one range filter on it. Firestore indexes a
field ascending and descending by default, and the query needs the ascending index only, so an
exemption keeps just that one:

```sh
gcloud firestore indexes fields update seal --collection-group=users --index=order=ASCENDING
```

The query streams with `stream_query_with_errors()`, so that a document that does not read is a
failed candidate, and the sweep never ends early on it. The write carries the document's update time
as its precondition, and Firestore refuses it once anything changed the document since the query
read it:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use firestore::errors::FirestoreError;
use firestore::{
    paths, FirestoreDb, FirestoreResult, FirestoreTimestamp, FirestoreWritePrecondition,
};
use futures_util::StreamExt;
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, KeyringResult, Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;
use serde::{Deserialize, Serialize};

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, FirestoreKeyringStore, GcpKmsProvider, Ring>;

const USERS: &str = "users";
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// The algorithm of the store-less envelope that wrote the values before the migration.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

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
#
#[derive(Serialize, Deserialize)]
struct UserDoc {
    #[serde(rename = "_firestore_id", skip_serializing)]
    id: String,
    #[serde(rename = "_firestore_updated", skip_serializing)]
    updated: FirestoreTimestamp,
    /// An envelope value under `SealMarker::ENVELOPE`, a keyring value under any other marker.
    #[serde(with = "serde_bytes")]
    email: Vec<u8>,
    #[serde(default)]
    seal: SealMarker,
}

/// A document the query returned, or the error of reading it, which the sweep counts as failed.
struct Candidate(FirestoreResult<UserDoc>);

/// The document id, and nothing of its fields.
impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Ok(doc) => write!(f, "{USERS}/{}", doc.id),
            Err(_) => write!(f, "an unreadable document of {USERS}"),
        }
    }
}

/// Why the re-seal of a document failed: an error of the keyring or of the users collection.
enum SweepError {
    Keyring(KeyringError),
    Users(FirestoreError),
}

impl From<KeyringError> for SweepError {
    fn from(error: KeyringError) -> Self {
        SweepError::Keyring(error)
    }
}

impl From<FirestoreError> for SweepError {
    fn from(error: FirestoreError) -> Self {
        SweepError::Users(error)
    }
}

/// The text the sweep logs: codes, never Firestore's messages, since a deserialisation error can
/// quote the field it could not read.
impl Display for SweepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SweepError::Keyring(error) => write!(f, "the keyring failed with {}", error.code()),
            SweepError::Users(FirestoreError::DatabaseError(error)) => {
                write!(f, "the users collection failed with {}", error.public.code)
            }
            SweepError::Users(FirestoreError::DeserializeError(_)) => {
                f.write_str("a document of users did not deserialise")
            }
            SweepError::Users(_) => f.write_str("the users collection failed"),
        }
    }
}

/// The AAD the application gave its envelope values.
fn envelope_aad(id: &str) -> Vec<u8> {
    format!("users:{id}:email").into_bytes()
}

/// `email`, the stored bytes of user `id` under the marker `seal`, under the active version of
/// `sealer`, and the outcome of its re-seal. A keyring value under that version comes back as it
/// is, with `ResealOutcome::Skipped`.
async fn reseal_email(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    id: &str,
    seal: SealMarker,
    email: &[u8],
) -> KeyringResult<(Encrypted<Email, Randomized>, ResealOutcome)> {
    let aad = EMAIL.aad(&EntityId::try_from(id)?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Email, Envelope>::try_from(email.to_vec())?;
        let opened: Email = keyring
            .decrypt_envelope_for_migration(&envelope_aad(id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let email = Encrypted::<Email, Randomized>::try_from(email.to_vec())?;
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &email).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the record gets the marker alone
        None => (email, ResealOutcome::Skipped),
    })
}

/// Re-seals a document under the active version and writes the marker of the sealer's record.
async fn reseal(
    keyring: &UsersKeyring,
    db: &FirestoreDb,
    candidate: Candidate,
) -> Result<ResealOutcome, SweepError> {
    let doc = candidate.0?;
    let sealer: UsersSealer<'_> = keyring.sealer().await;
    let (email, outcome) = reseal_email(keyring, &sealer, &doc.id, doc.seal, &doc.email).await?;
    let update = UserDoc {
        email: email.into_value(),
        seal: sealer.record().seal_marker(),
        ..doc
    };
    let written: FirestoreResult<UserDoc> = db
        .fluent()
        .update()
        .fields(paths!(UserDoc::{email, seal}))
        .in_col(USERS)
        .precondition(FirestoreWritePrecondition::UpdateTime(update.updated.into()))
        .document_id(&update.id)
        .object(&update)
        .execute()
        .await;
    match written {
        Ok(_) => Ok(outcome),
        // A write since the query: the writer re-sealed the document itself
        Err(FirestoreError::DatabaseError(error)) if error.public.code == "FailedPrecondition" => {
            Ok(ResealOutcome::Skipped)
        }
        Err(error) => Err(SweepError::Users(error)),
    }
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let db = FirestoreDb::new("my-project").await?;
let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
    FirestoreKeyringStore::new(db.clone()),
    KeyringRegistryOptions::new(),
)?;
let keyring: UsersKeyring = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;

let current: SealMarker = keyring.record().seal_marker();
let candidates = db
    .fluent()
    .select()
    .from(USERS)
    .filter(|q| q.field("seal").less_than(current))
    .obj::<UserDoc>()
    .stream_query_with_errors()
    .await?
    .map(Candidate);
let report: SweepReport = sweep::run(keyring.id(), candidates, CONCURRENCY, |candidate| {
    let (keyring, db) = (&keyring, &db);
    async move { reseal(keyring, db, candidate).await }
})
.await;
println!("{report:?}");
registry.shutdown().await?;
# Ok(())
# }
```

A range filter never matches a document without the field. `#[serde(default)]` reads a document
written before the marker as `SealMarker::ENVELOPE`, and the query finds it only once its `seal`
holds those bytes, see [Migrating from envelope values](#migrating-from-envelope-values).

`partition_query()` splits a collection into cursors that separate workers run in parallel, for a
sweep faster than one stream reads. Firestore partitions only a query with no filter, so each worker
compares `doc.seal < current` and skips the current documents before the re-seal.

The marker takes 10 bytes of a document: the field name as a 5-byte string and the 5 bytes of the
value. Its entry in the ascending index takes the size of the document's name, of its parent's
name, of the field name and of the value, plus 32 bytes, by Firestore's storage size rules: about
70 bytes for a short document id in a top-level collection. 10 million documents hold about 0.1 GB
of markers and 0.7 GB of index, about $0.13 a month at about $0.18 per GiB.

The [`sweep_firestore` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_firestore.rs)
runs this sweep end to end, from the writes to the `retire`, on the Firestore emulator. It re-seals
a page of 500 documents through one sealer and writes it back in one batch, one precondition per
document, instead of one write per document.

#### PostgreSQL

The marker is a `BYTEA` column with a btree index. Its default, the bytes of
`SealMarker::ENVELOPE`, gives the rows written before the column a marker too:

```sql
ALTER TABLE users ADD COLUMN seal BYTEA NOT NULL DEFAULT '\x0100000000';
CREATE INDEX users_seal ON users (seal);
```

The candidates stream in pages by keyset pagination on the primary key, with
`futures_util::stream::unfold`: each page is one short query, so no transaction stays open across
the sweep, and memory holds one page. The `UPDATE` is conditional on the bytes it read, which a write
of any other process changes, since every randomised value has its own nonce. A process that has
not seen the promotion yet still seals under the old version and stamps the old epoch, which the
row holds already, so the marker alone does not detect its write:

```rust,no_run
use std::fmt::{self, Display, Formatter};
use std::num::NonZeroUsize;

use futures_util::{stream, Stream, StreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::PostgresKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, KeyringResult, Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;
use tokio_postgres::{Client, Config, NoTls, Row};

type UsersKeyring = Keyring<PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, PostgresKeyringStore<NoTls>, GcpKmsProvider, Ring>;

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);
const PAGE_SIZE: u16 = 1000;
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(16).unwrap();
/// The algorithm of the store-less envelope that wrote the values before the migration.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

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
#
/// A row the query returned, or the error of reading its page, which the sweep counts as failed.
enum Candidate {
    /// `email` is an envelope value under `SealMarker::ENVELOPE`, a keyring value under any other
    /// marker.
    Row {
        id: i64,
        email: Vec<u8>,
        seal: SealMarker,
    },
    Unread(tokio_postgres::Error),
}

/// The row id, and nothing of its columns.
impl Display for Candidate {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Candidate::Row { id, .. } => write!(f, "users/{id}"),
            Candidate::Unread(_) => f.write_str("a row or page of users that did not read"),
        }
    }
}

impl TryFrom<Row> for Candidate {
    type Error = tokio_postgres::Error;

    fn try_from(row: Row) -> Result<Self, Self::Error> {
        Ok(Candidate::Row {
            id: row.try_get("id")?,
            email: row.try_get("email")?,
            seal: row.try_get("seal")?,
        })
    }
}

/// Why the re-seal of a row failed: an error of the keyring or of the users table.
enum SweepError {
    Keyring(KeyringError),
    Users(tokio_postgres::Error),
}

impl From<KeyringError> for SweepError {
    fn from(error: KeyringError) -> Self {
        SweepError::Keyring(error)
    }
}

impl From<tokio_postgres::Error> for SweepError {
    fn from(error: tokio_postgres::Error) -> Self {
        SweepError::Users(error)
    }
}

/// The text the sweep logs: codes, never the server's message, whose detail can quote a row's
/// values.
impl Display for SweepError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            SweepError::Keyring(error) => write!(f, "the keyring failed with {}", error.code()),
            SweepError::Users(error) => match error.code() {
                Some(state) => write!(f, "the users table failed with SQLSTATE {}", state.code()),
                None => f.write_str("the users table failed"),
            },
        }
    }
}

/// The rows whose marker is below `current`, a page at a time in the order of `id`.
fn candidates(client: &Client, current: SealMarker) -> impl Stream<Item = Candidate> + '_ {
    stream::unfold(Some(i64::MIN), move |after| async move {
        let rows = client
            .query(
                "SELECT id, email, seal FROM users WHERE seal < $1 AND id > $2 ORDER BY id LIMIT $3",
                &[&current, &after?, &i64::from(PAGE_SIZE)],
            )
            .await;
        let page = match rows {
            Ok(rows) => rows
                .into_iter()
                .map(|row| Candidate::try_from(row).unwrap_or_else(Candidate::Unread))
                .collect::<Vec<Candidate>>(),
            Err(error) => return Some((vec![Candidate::Unread(error)], None)),
        };
        let last = page.iter().rev().find_map(|candidate| match candidate {
            Candidate::Row { id, .. } => Some(*id),
            Candidate::Unread(_) => None,
        });
        let next = match last {
            Some(last) if page.len() == usize::from(PAGE_SIZE) => Some(last),
            _ => None,
        };
        (!page.is_empty()).then_some((page, next))
    })
    .flat_map(stream::iter)
}

/// The AAD the application gave its envelope values.
fn envelope_aad(id: i64) -> Vec<u8> {
    format!("users:{id}:email").into_bytes()
}

/// `email`, the stored bytes of user `id` under the marker `seal`, under the active version of
/// `sealer`, and the outcome of its re-seal. A keyring value under that version comes back as it
/// is, with `ResealOutcome::Skipped`.
async fn reseal_email(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    id: i64,
    seal: SealMarker,
    email: &[u8],
) -> KeyringResult<(Encrypted<Email, Randomized>, ResealOutcome)> {
    let aad = EMAIL.aad(&EntityId::try_from(id.to_string())?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Email, Envelope>::try_from(email.to_vec())?;
        let opened: Email = keyring
            .decrypt_envelope_for_migration(&envelope_aad(id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let email = Encrypted::<Email, Randomized>::try_from(email.to_vec())?;
    let resealed: Option<Resealed<Email, Randomized>> = sealer.reseal(&aad, &email).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the row gets the marker alone
        None => (email, ResealOutcome::Skipped),
    })
}

/// Re-seals a row under the active version and writes the marker of the sealer's record.
async fn reseal(
    keyring: &UsersKeyring,
    client: &Client,
    candidate: Candidate,
) -> Result<ResealOutcome, SweepError> {
    let (id, email, row_seal) = match candidate {
        Candidate::Row { id, email, seal } => (id, email, seal),
        Candidate::Unread(error) => return Err(SweepError::Users(error)),
    };
    let sealer: UsersSealer<'_> = keyring.sealer().await;
    let (new_email, outcome) = reseal_email(keyring, &sealer, id, row_seal, &email).await?;
    let seal: SealMarker = sealer.record().seal_marker();
    let updated: u64 = client
        .execute(
            "UPDATE users SET email = $2, seal = $3 WHERE id = $1 AND email = $4",
            &[&id, &new_email, &seal, &email],
        )
        .await?;
    Ok(match updated {
        // A write since the query: the writer re-sealed the row itself
        0 => ResealOutcome::Skipped,
        _ => outcome,
    })
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let config: Config = "postgres://app@localhost/app".parse()?;
let (client, connection) = config.connect(NoTls).await?;
tokio::spawn(connection);
let registry = KeyringRegistry::<PostgresKeyringStore<NoTls>, Ring>::new(
    PostgresKeyringStore::new(config, NoTls),
    KeyringRegistryOptions::new(),
)?;
let keyring: UsersKeyring = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;

let current: SealMarker = keyring.record().seal_marker();
let report: SweepReport = sweep::run(
    keyring.id(),
    candidates(&client, current),
    CONCURRENCY,
    |candidate| {
        let (keyring, client) = (&keyring, &client);
        async move { reseal(keyring, client, candidate).await }
    },
)
.await;
println!("{report:?}");
registry.shutdown().await?;
# Ok(())
# }
```

`SealMarker` is a `BYTEA` parameter and column through tokio-postgres with the `postgres` feature,
and through sqlx with the `sqlx` feature. One tokio-postgres `Client` pipelines the page queries and
the concurrent `UPDATE`s on one connection. The primary key serves every page while most rows are
behind, and the index on `seal` serves the sweep that leaves most rows current, such as the final
check that the query returns nothing.

A single query read through a portal is the alternative to pages: `Transaction::bind` and
`query_portal_raw` fetch the rows of one `SELECT` in batches. A portal lives only inside its
transaction, so that transaction stays open for the whole sweep, hours at millions of rows. Its
snapshot keeps vacuum from removing the dead row versions the `UPDATE`s leave behind, and the
`UPDATE`s run on a second connection, since the first holds the portal.

The marker takes 6 bytes of a row: its 5 bytes and a 1-byte length header. A btree on a column of a
few distinct epochs stores each one once per page with the list of its rows: measured on
PostgreSQL 18 over 1 million rows of 7 epochs, the column took 6 bytes per row and its index about 7.
10 million rows hold about 130 MB of markers and index.

The [`sweep_postgres` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_postgres.rs)
runs this sweep end to end, from the writes to the `retire`, on a local PostgreSQL. It re-seals a
page of 1000 rows through one sealer and writes it back in one `UPDATE` over arrays of the ids, the
new values and the values it read, instead of one statement per row.

#### BigQuery

The marker is a `BYTES` column. BigQuery gives a column added to a table `NULL` in the rows already
there, so the column's default goes with a write of `SealMarker::ENVELOPE` into them:

```sql
ALTER TABLE users ADD COLUMN seal BYTES;
ALTER TABLE users ALTER COLUMN seal SET DEFAULT b'\x01\x00\x00\x00\x00';
UPDATE users SET seal = b'\x01\x00\x00\x00\x00' WHERE seal IS NULL;
```

A field BigQuery reads, declared with `Interop::BigQuery`, is re-sealed by one `UPDATE` in SQL,
with no Rust loop and no value leaving BigQuery. With `keyset` standing for the
`KEYS.KEYSET_CHAIN(…)` expression of a `Readable(Purpose::Randomized)` export, see
[Exporting a keyset to BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery), and
`@seal` for the bytes of the export's marker, `keyset.seal_marker().value()`:

```sql
UPDATE users
SET
  email = AEAD.ENCRYPT(
    keyset,
    AEAD.DECRYPT_BYTES(keyset, email, CAST(CONCAT('user/', id, '/email') AS BYTES)),
    CAST(CONCAT('user/', id, '/email') AS BYTES)),
  seal = @seal
WHERE seal < @seal AND seal > b'\x01\x00\x00\x00\x00';
```

`AEAD.DECRYPT_BYTES`, and `AEAD.ENCRYPT` of bytes, take the AAD as `BYTES`, the UTF-8 of the
same text. `AEAD.ENCRYPT` seals under the keyset's primary, which a `Readable` export sets to the
active version of the record it reads from the store, and `EncryptedKeyset::seal_marker()` is that
record's marker. So every row the statement re-seals lies in the
[range](#records-under-a-version) of the primary, as a row written through a `Sealer` does. A
keyset exported before a promotion has the previous version as its primary and the previous
epoch's marker, and the rows it re-seals stay in the next sweep's query, so the sweep exports its
keyset after the promotion. The export is a `KeyringAdmin` call of the administrative job.

The statement re-seals every encrypted field of the row, since the marker it writes covers all of
them. Fields of several purposes are sealed under one `Readable` keyset each, and the statement
stamps the marker only when their `seal_marker()` is the same; otherwise it exports them again. A
row with a beacon, which SQL does not compute, goes through the Rust path below, and so does a row
under `SealMarker::ENVELOPE`, the lowest marker, which the statement leaves out: an envelope value
does not open under a keyring's keyset.

This sweep:

- resumes without a checkpoint: the statement is atomic, and a failed one changed nothing;
- loses no concurrent write: BigQuery runs DML under snapshot isolation, and of two conflicting
  statements on the same rows one fails and runs again, and its `WHERE` then sees the other's
  marker;
- makes no KMS call per record: BigQuery opens the keyset through Cloud KMS for the statement;
- ends with `retire`, then later `destroy`, once the range query of the old version,
  `SELECT COUNT(*) FROM users WHERE seal >= @start AND (@end IS NULL OR seal < @end)`, returns 0.

A `Readable` keyset leaves a compromised version out, so the values under it fail
`AEAD.DECRYPT_BYTES` and the whole statement with them. After a compromise those rows go through
the Rust path below, where the sealer's `reseal` reports their trust.

Other fields, such as ChaCha20-Poly1305 values or values under a custom AAD, are re-sealed in
Rust. BigQuery runs only a few DML statements on one table at a time, so the write is one `MERGE`
per page of rows rather than one `UPDATE` per row, conditional on the bytes each row held:

```sql
MERGE users u
USING UNNEST(@pages) p
ON u.id = p.id AND u.phone = p.old_phone
WHEN MATCHED THEN UPDATE SET phone = p.phone, seal = @seal;
```

The pages stream from the application's BigQuery client, a query of `SELECT id, phone, seal FROM
users WHERE seal < @current` with the current marker, read a page at a time. Each page is re-sealed
through one sealer, and the client runs the `MERGE` with `@seal` bound to the marker of the
sealer's record. Every row of a page goes into `@pages`, the current ones with their bytes as they
are, so that each gets the marker. The candidate is then a page, and the report counts pages:

```rust
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;

use futures_util::Stream;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringResult, Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, FirestoreKeyringStore, GcpKmsProvider, Ring>;

const PHONE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("phone"),
);
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(2).unwrap();
/// The algorithm of the store-less envelope that wrote the values before the migration.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

# #[derive(Clone)]
# struct Phone(String);
#
# impl Plaintext for Phone {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Phone)
#     }
# }
#
/// A row of `SELECT id, phone, seal FROM users WHERE seal < @current`.
struct UserRow {
    id: String,
    /// An envelope value under `SealMarker::ENVELOPE`, a keyring value under any other marker.
    phone: Vec<u8>,
    seal: SealMarker,
}

/// A page of rows, as the application's BigQuery client reads the query result.
struct UsersPage {
    /// The page token the client read the page with, which names the page and no row.
    token: String,
    rows: Vec<UserRow>,
}

impl Display for UsersPage {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users page {}", self.token)
    }
}

/// One element of `@pages`: a row with the bytes it held and the bytes to write.
struct PhoneUpdate {
    id: String,
    old_phone: Vec<u8>,
    phone: Encrypted<Phone, Randomized>,
}

/// The AAD the application gave its envelope values.
fn envelope_aad(id: &str) -> Vec<u8> {
    format!("users:{id}:phone").into_bytes()
}

/// `phone`, the stored bytes of user `id` under the marker `seal`, under the active version of
/// `sealer`, and the outcome of its re-seal. A keyring value under that version comes back as it
/// is, with `ResealOutcome::Skipped`.
async fn reseal_phone(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    id: &str,
    seal: SealMarker,
    phone: &[u8],
) -> KeyringResult<(Encrypted<Phone, Randomized>, ResealOutcome)> {
    let aad = PHONE.aad(&EntityId::try_from(id)?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Phone, Envelope>::try_from(phone.to_vec())?;
        let opened: Phone = keyring
            .decrypt_envelope_for_migration(&envelope_aad(id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let phone = Encrypted::<Phone, Randomized>::try_from(phone.to_vec())?;
    let resealed: Option<Resealed<Phone, Randomized>> = sealer.reseal(&aad, &phone).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the row gets the marker alone
        None => (phone, ResealOutcome::Skipped),
    })
}

/// Re-seals the `pages` of the query, one sealer per page, and writes each through `merge`, which
/// runs the `MERGE` with `@seal` bound to the marker it is given, the marker of the page's
/// sealer, and returns its number of affected rows. `ClientError` is the error of the
/// application's BigQuery client, which a `KeyringError` converts into, and its `Display` is the
/// text the sweep logs for a failed page.
async fn sweep_phones<Pages, Merge, Merged, ClientError>(
    keyring: &UsersKeyring,
    pages: Pages,
    merge: Merge,
) -> SweepReport
where
    Pages: Stream<Item = UsersPage>,
    Merge: Fn(Vec<PhoneUpdate>, SealMarker) -> Merged,
    Merged: Future<Output = Result<u64, ClientError>>,
    ClientError: From<KeyringError> + Display,
{
    sweep::run(keyring.id(), pages, CONCURRENCY, |page| {
        let merge = &merge;
        async move {
            let sealer: UsersSealer<'_> = keyring.sealer().await;
            let mut updates = Vec::with_capacity(page.rows.len());
            let mut resealed_any = false;
            let mut from_compromised = false;
            for row in page.rows {
                let (phone, outcome) =
                    reseal_phone(keyring, &sealer, &row.id, row.seal, &row.phone).await?;
                if let ResealOutcome::Resealed {
                    from_compromised: compromised,
                } = outcome
                {
                    resealed_any = true;
                    from_compromised |= compromised;
                }
                updates.push(PhoneUpdate {
                    id: row.id,
                    old_phone: row.phone,
                    phone,
                });
            }
            let merged: u64 = merge(updates, sealer.record().seal_marker()).await?;
            Ok::<ResealOutcome, ClientError>(if merged > 0 && resealed_any {
                ResealOutcome::Resealed { from_compromised }
            } else {
                ResealOutcome::Skipped
            })
        }
    })
    .await
}
#
# fn main() {}
```

A page is re-sealed sequentially inside its re-seal, and `concurrency` bounds the pages in flight,
which BigQuery's limit on concurrent DML per table sets low. The five properties hold per page: a
row that a concurrent writer changed fails the `ON` condition and stays in the query for the next
run.

The marker takes 7 bytes of a row: its 5 bytes and the 2 BigQuery counts for every `BYTES` value.
Measured on BigQuery, 100,000 markers held 700,000 bytes, and the sweep's query processed
700,000 bytes, the `seal` column alone. BigQuery does not cluster a `BYTES` column, so the query
reads the whole column: about 70 MB at 10 million rows, about $0.0004 per query at $6.25 per TiB
on demand, and its storage about $0.0013 a month at $0.02 per GiB.

The [`sweep_bigquery` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_bigquery.rs)
runs the `UPDATE` above end to end, from the writes to the `retire`, against Cloud KMS and BigQuery.

### The trust of re-sealed values

A sweep reads every field with `decrypt_with_trust`, and reports in `ResealOutcome::Resealed`
whether the `KeyTrust` of any of them is compromised. A value read under a compromised version is untrusted data: whoever holds the
leaked DEK can have forged it. Re-sealing it under a new version makes it read as trusted
everywhere afterwards.

So after a compromise the application decides per record before it re-seals:

- a quarantine field beside the marker, for a person to review;
- a comparison against a backup taken before the compromise;
- or acceptance, when forged values do no harm.

`SweepReport::resealed_from_compromised` counts the records that went through that decision.

## Migrating from envelope values

Values that kms-aead's `KmsAeadEnvelope` wrote, per call or store-less, move to keyring values in
five steps:

1. the model gains `seal: SealMarker`, and every record without one reads as
   `SealMarker::ENVELOPE`: through `#[serde(default)]`, or a column default of its bytes,
   `'\x0100000000'`;
2. the field keeps its stored bytes, whose layout the marker names: envelope values under
   `ENVELOPE`, epoch 0, and keyring values under any other marker, since the epochs of a keyring
   start at 1;
3. reads go through the marker: `Keyring::decrypt_envelope_for_migration` opens an envelope value,
   with the AAD and the algorithm the application used for it, and `Keyring::decrypt` a keyring
   value;
4. the sweep's query, `seal < $1` with the current marker, finds every envelope record too, and the
   re-seal seals it as keyring values through a sealer and writes the marker of the sealer's
   record;
5. once no record holds `ENVELOPE`, the read path drops its envelope branch.

A range query never matches a record whose marker is missing: Firestore skips a document without the
field, and `<` in SQL is never true on `NULL`. A PostgreSQL column added with a default holds it in
every existing row. A BigQuery column holds `NULL` there until an `UPDATE` writes `ENVELOPE`, see
[BigQuery](#bigquery). Firestore documents written before the marker get `ENVELOPE` written into
them first, or the migration's first sweep scans the whole collection and tests `doc.seal < current`
on each, since `#[serde(default)]` reads a missing marker as `ENVELOPE`.

The keyring's provider decrypts the envelope values, so they must have been encrypted by the
keyring's KEK. `decrypt_envelope_for_migration` reads Tink's KMS envelope, the layout kms-aead 0.30 writes.
Values written by kms-aead 0.29 or earlier are upgraded in place first, with
`KmsAeadEnvelope::upgrade_legacy_value(aad, value)` under kms-aead's `legacy-formats` feature, see
[Upgrading stored values](./formats.md#upgrading-stored-values). The layout of a value is always
the marker's, never inferred from its bytes.

`decrypt_envelope_for_migration` decrypts whatever encrypted DEK an envelope value carries, under the
keyring's KEK. It knows no key version, and so no compromised flag and no destroyed state: keep its
branch in the read path for the migration only.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/migrate.rs),
run it with `cargo run -p kms-aead-keyring --example migrate --features ring,admin,serde`.

## Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

### A plaintext DEK leaked

Or is suspected to have.

1. `mark_compromised(key_id, note)`: the version is flagged and, if active, replaced in one write
   by a version that is active at once. The replacement skips the staged wait on purpose: sealing
   under the leaked key stops at each process's next refresh, and a process that has not seen the
   replacement yet reloads its record once, rate-limited, when it meets a value under it. When the
   KMS cannot encrypt a new DEK, the flag lands alone and `encrypt` fails with `NoActiveVersion`;
   once the KMS answers, `rotate` and `promote_now` at once, since nothing seals under the purpose
   meanwhile, or `promote_now` the pending version if the purpose has one. `promote` would refuse
   with `PromotionTooEarly` for up to `record_ttl` from the staging. A pending version itself is
   never compromised: `destroy` it instead;
2. every process stops using the key within the bound of the
   [record cache](./keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep the records in the compromised version's range, see
   [Records under a version](#records-under-a-version), reading them with `decrypt_with_trust`,
   and decide per record on the values read through the compromised version, see
   [The trust of re-sealed values](#the-trust-of-re-sealed-values). Run the range query again once
   every process has had time to refresh its record, for the writes of processes that had not seen
   the flag yet;
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. `retire` the version once the sweep is done and its range query returns nothing.

Rotation protects nothing already copied: backups, point-in-time recovery and data exports still
hold values the leaked DEK opens. Treat them as exposed and revoke the secrets inside them.

### A KMS IAM over-grant

1. Fix the IAM binding, back to the split in
   [Keyring deployment](./security.md#keyring-deployment);
2. rotate the KEK in the KMS and `reencrypt_deks()`;
3. with KMS data-access logs enabled in advance, list the `Decrypt` calls the wrong principal
   made: every encrypted DEK they decrypted is a leaked DEK, see above. Without those logs, every
   version is a leaked DEK.

### An encrypted DEK or the keyring record leaked

Harmless by itself, since decrypting needs the KMS. If the attacker may also gain `Decrypt` on the
KEK, follow the IAM over-grant steps. If the attacker may also write the keyring store, see
[the next case](#a-version-the-administrative-job-did-not-create) and the store-writer threat in
[Keyring deployment](./security.md#keyring-deployment).

### A version the administrative job did not create

This case starts from the `ERROR` event of a refused record that moves backwards, or from a version
in the record that the administrative job's log does not show. The event's `rule` names the version
that moved backwards, except `the seal epoch moved back`, which names none: compare the versions of
the record in the store with the job's log to find the one it did not create. Either means that
something other than the job wrote the record: a restore, which
[the next case](#the-keyring-record-was-deleted-or-corrupted) covers, or a writer of the
store.

1. If the version is active, `mark_compromised` it, so that nothing new is sealed under it from
   each process's next refresh. If it is pending, `destroy` it;
2. `retire` and then `destroy` the version, after a sweep if values were sealed under it;
3. check the KMS audit log for the `Encrypt` call that encrypted its DEK. None means its encrypted
   DEK was copied or relabelled from another version, of this keyring or of another under the
   same KEK, which the KMS decrypts as it would the original; one from a principal other than the
   administrative job is an IAM over-grant, see above;
4. audit who can write the keyring store: the application has no write, and only the
   administrative job should.

### The keyring record was deleted or corrupted

Running processes keep their cached record and log a `WARN`; new processes fail at `open` with
`RecordMissing` or `RecordInvalid`.

1. Restore the record from the store's backup: Firestore point-in-time recovery, a PostgreSQL
   backup, or a noncurrent version of the Cloud Storage or S3 object. The encrypted DEKs inside are
   still valid under the KEK;
2. repeat on the restored record every administrative call made after the copy was taken, from
   the administrative job's log, before starting new processes.

A running process refuses a restored copy that is older than its cached record and logs an
`ERROR`, while new processes take it. Values are never lost with the record as long as a copy of
it exists. Without any copy they are gone, so keep versioning on the bucket and back up the
table.

### Crypto-shredding

To make a scope's values unrecoverable:

- with a KEK per scope: destroy the KEK's versions in the KMS. Every encrypted DEK of the scope is
  then unrecoverable, backups included;
- with a shared KEK: `dangerously_destroy_all_versions`, which destroys every version of the
  keyring in one write, so that it encrypts and decrypts nothing from then on. A backup of the
  record still holds the encrypted DEKs, which the KMS opens as long as the KEK version that
  encrypted them exists, so then either delete the record and every backup of it, or destroy that
  KEK version: on GCP, Vault Transit and the local KMS, rotate the KEK, `reencrypt_deks` every
  other keyring under it, then destroy the previous KEK version. On AWS rotated key material is
  never destroyed, so only the deletion of the KMS key itself shreds.

A deployment that needs shredding guarantees uses a KEK per scope.

### A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.
