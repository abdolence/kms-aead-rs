# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

A rotation is staged: `rotate(purpose)` adds a pending version, which every process decrypts under
once its record refreshes, and `promote(key_id)` makes it active once every process has had time
to see it, see [Staged rotation](./keyring/lifecycle.md#staged-rotation). The previous version keeps
decrypting. Nothing is lost while the change propagates: processes on the old record seal under
the previous version until their record refreshes, and those values decrypt.

The administrative job runs a rotation in steps:

1. `rotate(purpose)`;
2. export the `Readable` BigQuery keysets again, which then hold the pending version;
3. wait the longest time any process may run without a successful refresh of its record, counted
   from `staged_at()`, and check that no process logged "The keyring record could not be
   revalidated" meanwhile;
4. `promote(key_id)`.

How often:

- A randomised DEK with random 96-bit nonces is good for about 2^32 values, see
  [Nonces](./security.md#nonces). The library cannot count the values a fleet seals, so estimate
  them: at 550 values per second a version reaches 2^32 in 90 days. Rotate every 30 to 90 days,
  sooner at higher rates. AES-256-GCM, AES-256-GCM-SIV and ChaCha20-Poly1305 all take a 12-byte
  nonce, so the same cadence applies to each;
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

`reencrypt_deks` runs in the administrative job, like every call that encrypts.

## Sweeps

A sweep re-seals stored values under the active versions: after a rotation, to retire the old
version, after a compromise, and to migrate envelope values. It is a job the application runs, a
CLI or a Kubernetes Job, never a task inside the library: only the application knows its tables,
its pages and its write rules.

### The seal marker

Each record of the application keeps a `SealMarker` beside its encrypted fields, as plain fields
an index covers:

```json
{"format": "keyring", "randomized": 3, "deterministic": null, "beacon": 1073741825}
```

- `format` is `keyring` or `envelope`, the layout of the record's encrypted fields;
- `randomized`, `deterministic` and `beacon` are the oldest key version of each purpose among its
  values and beacons.

A write that touches any encrypted field of a record re-seals all of them under the active
versions, computes its beacons again, and writes `SealMarker::keyring` of their key ids, which
`value.key_id()` reads. Then one query finds every record a sweep still has to
visit: after the promotion of randomised key id `n`, the records whose `seal.randomized < n`, and
likewise for deterministic and beacon versions. A key id goes up to 2^32 - 1, so a SQL column
holding one is a `BIGINT`.

### Running a sweep

`sweep::run` drives the application's re-seal over the records a query found, with a bounded
number in flight, and counts what happened:

```rust
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

use futures_util::stream;
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::sweep::{self, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Decrypted, Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyId, KeyTrust, Keyring,
    KeyringAlgorithms, KeyringId, KeyringOptions, KeyringResult, Plaintext, Purpose, Rotation,
};
use secret_vault_value::SecretValue;

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

/// Re-seals the row of `user` under the active version.
async fn reseal(
    keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>,
    table: &Table,
    user: &str,
) -> KeyringResult<ResealOutcome> {
    let Some(row) = table.lock().unwrap().get(user).cloned() else {
        return Ok(ResealOutcome::Skipped);
    };
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let decrypted: Decrypted<Email> = keyring.decrypt_with_trust(&aad, &row.email).await?;
    let email: Encrypted<Email, Randomized> = keyring.encrypt(&aad, &decrypted.value).await?;
    let seal = SealMarker::keyring([email.key_id()])?;
    table
        .lock()
        .unwrap()
        .insert(user.to_string(), UserRow { email, seal });
    Ok(ResealOutcome::Resealed {
        from_compromised: matches!(decrypted.trust, KeyTrust::Compromised(_)),
    })
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let keyring = Keyring::<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>::open_or_create(
#     MemoryKeyringStore::new(), provider, TENANT, KeyringAlgorithms::new(), KeyringOptions::new(),
# )
# .await?;
# let table = Table::default();
# for (user, email) in [("41", "ada@example.com"), ("42", "alice@example.com")] {
#     let email = keyring
#         .encrypt(&EMAIL.aad(&EntityId::try_from(user)?), &Email(email.to_string()))
#         .await?;
#     let seal = SealMarker::keyring([email.key_id()])?;
#     table.lock().unwrap().insert(user.to_string(), UserRow { email, seal });
# }
let staged: KeyId = keyring.rotate(Purpose::Randomized).await?;
// After the wait for every process to see the staged version
let rotation: Rotation = keyring.promote(staged).await?;

// The query: every row whose oldest randomised version is below the new one
let candidates = table
    .lock()
    .unwrap()
    .iter()
    .filter(|(_, row)| {
        row.seal.randomized.map(KeyId::as_u32) < Some(rotation.current.as_u32())
    })
    .map(|(user, _)| user.clone())
    .collect::<Vec<String>>();

let report: SweepReport = sweep::run(
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
  transaction per batch, then the `UPDATE` and the commit. `$1` is the new version's
  `KeyId::as_u32()`, bound as a `BIGINT`.

Once a sweep reports `failed == 0` and the query returns nothing, `retire` the old version. Keep it
retired for a while before `destroy`: `reinstate` brings a retired version back for a value that
turned up after all, while a destroyed one is gone.

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

1. the model gains `seal: SealMarker` with `#[serde(default)]`, or a column default, so every
   record without one reads as `SealMarker::ENVELOPE`;
2. the field keeps its stored bytes, whose layout the marker names;
3. reads go through the marker: `Keyring::decrypt_envelope` opens an envelope value, with
   the AAD and the algorithm the application used for it, and `Keyring::decrypt` a keyring value;
4. a sweep over `seal.format = 'envelope'` re-seals each record as keyring values and writes its
   keyring marker;
5. once that query returns nothing, the read path drops its envelope branch.

The keyring's provider decrypts the envelope values, so they must have been encrypted by the
keyring's KEK. `decrypt_envelope` reads Tink's KMS envelope, the layout kms-aead 0.30 writes.
Values written by kms-aead 0.29 or earlier are upgraded in place first, with
`KmsAeadEnvelope::upgrade_legacy_value(aad, value)` under kms-aead's `legacy-formats` feature, see
[Upgrading stored values](./formats.md#upgrading-stored-values). The layout of a value is always
the marker's, never inferred from its bytes.

`decrypt_envelope` decrypts whatever encrypted DEK an envelope value carries, under the
keyring's KEK. It knows no key version, and so no compromised flag and no destroyed state: keep its
branch in the read path for the migration only.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/migrate.rs),
run it with `cargo run -p kms-aead-keyring --example migrate --features ring`.

## Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

### A plaintext DEK leaked

Or is suspected to have.

1. `mark_compromised(key_id, note)`: the version is flagged and, if active, replaced in one write
   by a version that is active at once. The replacement skips the staged wait on purpose: sealing
   under the leaked key stops at each process's next refresh, and a process that has not seen the
   replacement yet reloads its record once, rate-limited, when it meets a value under it. When the
   KMS cannot encrypt a new DEK, the flag lands alone and `encrypt` fails with `NoActiveVersion`;
   once the KMS answers, `rotate` and `promote` at once, since nothing seals under the purpose
   meanwhile, or `promote` the pending version if the purpose has one. A pending version itself
   is never compromised: `destroy` it instead;
2. every process stops using the key within the bound of the
   [record cache](./keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep with `decrypt_with_trust`, and decide per record on the values read through the
   compromised version, see [The trust of re-sealed values](#the-trust-of-re-sealed-values);
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. `retire` the version once the sweep is done.

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

This case starts from the `ERROR` event of a refused record that moves backwards, whose `rule`
names the version, or from a version in the record that the administrative job's log does not
show. Either means that something other than the job wrote the record: a restore, which
[the next case](#the-keyring-record-was-deleted-or-corrupted) covers, or a writer of the
store.

1. If the version is active, `mark_compromised` it, so that nothing new is sealed under it from
   each process's next refresh. If it is pending, `destroy` it;
2. `retire` and then `destroy` the version, after a sweep if values were sealed under it;
3. check the KMS audit log for the `Encrypt` call that encrypted its DEK. None means its encrypted
   DEK was copied or relabelled from another version, of this keyring or of another under the
   same KEK, which the KMS decrypts as it would the original; one from a principal other than the
   administrative job is an IAM over-grant, see above;
4. audit who can write the keyring store: the serving principal has no write, and only the
   administrative job should.

### The keyring record was deleted or corrupted

Running processes keep their cached record and log a `WARN`; new processes fail at `open`.

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
- with a shared KEK: `retire` and `destroy` every version of the keyring. A backup of the record
  still holds the encrypted DEKs, which the KMS opens as long as the KEK version that encrypted them
  exists. On GCP, Vault Transit and the local KMS, rotate the KEK, `reencrypt_deks`, then destroy
  the previous KEK version. On AWS rotated key material is never destroyed, so only the deletion of
  the KMS key itself shreds.

A deployment that needs shredding guarantees uses a KEK per scope.

### A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.
