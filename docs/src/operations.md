# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

`rotate(purpose)` creates a new active version, and the previous one keeps decrypting. Nothing
is lost while the change propagates: processes on the old record seal under the previous version
until their record refreshes, and those values decrypt.

- A randomized DEK with random 96-bit nonces is good for about 2^32 values, see
  [Nonces](./security.md#nonces). The library cannot count the values a fleet seals, so estimate
  them: at 550 values per second a version reaches 2^32 in 90 days. Rotate every 30 to 90 days,
  sooner at higher rates. AES-256-GCM, AES-256-GCM-SIV and ChaCha20-Poly1305 all take a 12-byte
  nonce, so the same cadence applies to each;
- a deterministic version has no nonce, so it is rotated by policy and on compromise only. Every
  deterministic rotation adds a probe to each equality query until a full sweep re-seals every
  row, see [Queries across rotations](./keyring/deterministic.md#queries-across-rotations), so
  rotate deterministic versions rarely.

After a rotation, export the BigQuery keysets again, since a keyset is a copy of the record at
the time of the export.

Rotation does not touch values already written. To stop reading them under the old version, run a
[sweep](#sweeps), then `retire` the version.

## Rotating the KEK

The KEK rotates in the KMS on its own schedule. After a rotation, `rewrap()` unwraps every DEK in
the record and wraps it again under the KEK's current version. No value changes. A keyring that is
not rewrapped keeps working as long as the old KEK versions stay enabled in the KMS.

`rewrap` runs in the administrative job, like every call that wraps.

## Sweeps

A sweep re-seals stored values under the active versions: after a rotation, to retire the old
version, after a compromise, and to migrate envelope values. It is a job the application runs, a
CLI or a Kubernetes Job, never a task inside the library: only the application knows its tables,
its pages and its write rules.

### The seal marker

Each record of the application keeps a `SealMarker` beside its encrypted fields, as plain fields
an index covers:

```json
{"format": "keyring", "randomized": 3, "deterministic": null}
```

- `format` is `keyring` or `envelope`, the layout of the record's encrypted fields;
- `randomized` and `deterministic` are the oldest key version of each purpose among them.

A write that touches any encrypted field of a record re-seals all of them under the active
versions and writes `SealMarker::keyring` of their key ids. Then one query finds every record a
sweep still has to visit: after a randomized rotation to key id `n`, the records whose
`seal.randomized < n`, and likewise for deterministic versions. A key id goes up to 2^32 - 1, so
a SQL column holding one is a `BIGINT`.

### Running a sweep

`sweep::run` drives the application's re-seal over the records a query found, with a bounded
number in flight, and counts what happened:

```rust
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use futures_util::stream;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::sweep::{self, Outcome};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringId, KeyringOptions,
    KeyringPolicy, KeyringResult, Purpose, SealMarker,
};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
);

#[derive(Clone)]
struct UserRow {
    email: Encrypted<String>,
    seal: SealMarker,
}

/// The users table, by user id.
type Table = Mutex<BTreeMap<String, UserRow>>;

/// Re-seals the row of `user` under the active version.
async fn reseal(
    keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider>,
    table: &Table,
    user: &str,
) -> KeyringResult<Outcome> {
    let Some(row) = table.lock().unwrap().get(user).cloned() else {
        return Ok(Outcome::Skipped);
    };
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let decrypted = keyring.decrypt_with_status(&aad, &row.email).await?;
    let email = keyring.encrypt(&aad, &decrypted.value).await?;
    let seal = SealMarker::keyring([email.key_id()]);
    table
        .lock()
        .unwrap()
        .insert(user.to_string(), UserRow { email, seal });
    // A record with any field from a compromised version counts as one
    Ok(Outcome::Resealed([decrypted.trust].iter().collect()))
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?, AeadBackend::Ring)?;
# let keyring = Keyring::open_or_create(MemoryKeyringStore::new(), provider, AeadBackend::Ring,
#     TENANT, KeyringPolicy::new(), KeyringOptions::new()).await?;
# let table = Table::default();
# for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
#     let email = keyring.encrypt(&EMAIL.aad(&EntityId::try_from(user)?), &email.to_string()).await?;
#     let seal = SealMarker::keyring([email.key_id()]);
#     table.lock().unwrap().insert(user.to_string(), UserRow { email, seal });
# }
let rotation = keyring.rotate(Purpose::Randomized).await?;

// The query: every row whose oldest randomized version is below the new one
let candidates = table
    .lock()
    .unwrap()
    .iter()
    .filter(|(_, row)| row.seal.randomized < Some(rotation.current))
    .map(|(user, _)| user.clone())
    .collect::<Vec<_>>();

let report = sweep::run(
    &TENANT,
    stream::iter(candidates),
    NonZeroUsize::new(8).unwrap(),
    |candidate| {
        let (keyring, table) = (&keyring, &table);
        async move { reseal(keyring, table, &candidate).await }
    },
)
.await;

// Nothing left under the old version: retire it
if report.failed == 0 {
    if let Some(previous) = rotation.previous {
        keyring.retire(previous).await?;
    }
}
# assert_eq!(report.resealed, 2);
# Ok(())
# }
```

The `SweepReport` counts every candidate once in `scanned`, and once in `resealed`, `skipped` or
`failed`. A re-seal that fails does not stop the sweep: it is counted in `failed` and logged at
`WARN` with the candidate's `Display` and the error's code, never a value. A candidate is the
application's own type, such as a record id or a struct of key columns, and its `Display` names
the record and nothing else. A record id is often an entity id, so read the sweep's log as an
administrative log.

In a real data store the re-seal is a transaction per record or per batch:

- Firestore: a transaction per document, which reads the document, re-seals every field and writes
  it with the marker. A concurrent application write wins, and the candidate is `Skipped`;
- PostgreSQL: `SELECT … WHERE seal_randomized < $1 ORDER BY id LIMIT $2 FOR UPDATE SKIP LOCKED` in a
  transaction per batch, then the `UPDATE` and the commit.

Once a sweep reports `failed == 0` and the query returns nothing, `retire` the old version. Keep it
retired for a while before `destroy`: `reinstate` brings a retired version back for a value that
turned up after all, while a destroyed one is gone.

### The trust of re-sealed values

A sweep reads every field with `decrypt_with_status`, and builds its `Outcome::Resealed` from the
`KeyTrust` of each. A value read under a compromised version is untrusted data: whoever holds the
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

1. the model gains `seal: SealMarker` with `#[serde(default)]`, or a column default, so every
   record without one reads as `SealMarker::ENVELOPE`;
2. the field keeps its stored bytes, whose layout the marker names;
3. reads go through the marker: `Keyring::decrypt_envelope_value` opens an envelope value, with
   the AAD and the algorithm the application used for it, and `Keyring::decrypt` a keyring value;
4. a sweep over `seal.format = 'envelope'` re-seals each record as keyring values and writes its
   keyring marker;
5. once that query returns nothing, the read path drops its envelope branch.

The keyring's provider unwraps the envelope values, so they must have been wrapped by the
keyring's KEK. Values written by kms-aead 0.28.1 or earlier need the `legacy-formats` feature. The
layout of a value is always the marker's, never guessed from its bytes.

`decrypt_envelope_value` refuses, with `EnvelopeKeyOfKeyVersion` and before any KMS call, an
envelope value that carries the wrapped DEK of one of the keyring's versions: a version's DEK never
opens through the envelope path, which knows no key version and so no compromised flag.

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/migrate.rs),
run it with `cargo run -p kms-aead-keyring --example migrate --features ring`.

## Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

### A plaintext DEK leaked

Or is suspected to have.

1. `mark_compromised(key_id, note)`: the version is flagged and, if active, replaced in one write.
   When the KMS cannot wrap a new DEK, the flag lands alone and `encrypt` fails with
   `NoActiveVersion`; run `rotate` once the KMS answers;
2. every process stops using the key within the bound of the
   [record cache](./keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep with `decrypt_with_status`, and decide per record on the values read through the
   compromised version, see [The trust of re-sealed values](#the-trust-of-re-sealed-values);
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. `retire` the version once the sweep is done.

Rotation protects nothing already copied: backups, point-in-time recovery and data exports still
hold values the leaked DEK opens. Treat them as exposed and revoke the secrets inside them.

### A KMS IAM over-grant

1. Fix the IAM binding, back to the split in
   [Keyring deployment](./security.md#keyring-deployment);
2. rotate the KEK in the KMS and `rewrap()`;
3. with KMS data-access logs enabled in advance, list the `Decrypt` calls the wrong principal
   made: every wrapped DEK they unwrapped is a leaked DEK, see above. Without those logs, every
   version is a leaked DEK.

### A wrapped DEK or the keyring record leaked

Harmless by itself, since unwrapping needs the KMS. If the attacker may also gain `Decrypt` on the
KEK, follow the IAM over-grant steps.

### The keyring record was deleted or corrupted

Running processes keep their cached record and log a `WARN`; new processes fail at `open`.

1. Restore the record from the store's backup: Firestore point-in-time recovery, a PostgreSQL
   backup, or a noncurrent version of the Cloud Storage object. The wrapped DEKs inside are still
   valid under the KEK;
2. repeat on the restored record every administrative call made after the copy was taken, from
   the administrative job's log, before starting new processes.

A running process refuses a restored copy that is older than its cached record and logs an
`ERROR`, while new processes take it. Values are never lost with the record as long as a copy of
it exists. Without any copy they are gone, so keep versioning on the bucket and back up the
table.

### Crypto-shredding

To make a scope's values unrecoverable:

- with a KEK per scope: destroy the KEK's versions in the KMS. Every wrapped DEK of the scope is
  then unrecoverable, backups included;
- with a shared KEK: `retire` and `destroy` every version of the keyring. A backup of the record
  still holds the wrapped DEKs, which the KMS opens as long as the KEK version that wrapped them
  exists. On GCP, Vault Transit and the local KMS, rotate the KEK, `rewrap`, then destroy the
  previous KEK version. On AWS rotated key material is never destroyed, so only the deletion of
  the KMS key itself shreds.

A deployment that needs shredding guarantees uses a KEK per scope.

### A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No unwrap, wrap or rotation succeeds until the
KMS returns, and errors carry the provider's message. `mark_compromised` still lands the flag.
