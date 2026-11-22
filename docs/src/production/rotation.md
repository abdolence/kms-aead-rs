# Rotate keys and re-encrypt values

Two keys rotate, on their own schedules:

- a DEK encrypts values. A new DEK changes nothing already written, so the values under the old one
  are re-encrypted by a sweep before the old DEK is retired;
- the KEK encrypts DEKs in the KMS. A new KEK version changes no value: the DEKs are encrypted
  again under it before the old version is disabled.

Both run without downtime, since the old key keeps decrypting until one of the last steps
retires or disables it, and a check runs before that step. This page walks through each rotation
and links to the procedure of each step. How often to rotate is in
[Rotation cadence](#rotation-cadence).

## DEK rotation

On a keyring, a DEK rotation is a new key version of a purpose, staged before it encrypts anything.
The administrative job runs every call on its `KeyringAdmin`, and the application runs the sweep,
see [Permissions: applications and administration](./permissions.md). In order:

1. **stage and promote** the new version: `rotate`, export the keysets again, wait until every
   process has the pending version, `promote`. The steps and the waits are in
   [Rotation cadence](#rotation-cadence), and why the wait is needed in
   [Staged rotation](../keyring/lifecycle.md#staged-rotation);
2. **sweep** the records whose encryption marker is below the keyring's current one. They are the
   records that can hold a value under an older version, and records with no value of the rotated
   purpose, whose re-encryption writes the marker alone, see [Sweeps](./sweeps.md). A sweep is a job
   that runs on a schedule until its `SweepReport` shows nothing scanned. The query and the write per
   database:
   - [Firestore](./sweeps/firestore.md);
   - [PostgreSQL](./sweeps/postgres.md);
   - [BigQuery](./sweeps/bigquery.md), in SQL;
   - beacons and deterministic fields: [Rotating beacon versions](../keyring/beacons.md#rotating-beacon-versions)
     and [Queries across rotations](../keyring/deterministic.md#queries-across-rotations);
3. **retire, then destroy** the old version, once every process has refreshed since the promotion
   and no record is left under it, see
   [Retiring the old version](./sweeps.md#retiring-the-old-version).

### Rotation cadence

A rotation is staged: `rotate(purpose)` adds a pending version, which every process decrypts under
once its record refreshes, and `promote(key_id)` makes it active once every process has had time
to see it, see [Staged rotation](../keyring/lifecycle.md#staged-rotation). The previous version keeps
decrypting. Nothing is lost while the change propagates: processes on the old record encrypt under
the previous version until their record refreshes, and those values decrypt.

The administrative job runs a rotation in steps, on its `KeyringAdmin`, see
[Permissions: applications and administration](./permissions.md):

1. `rotate(purpose)`;
2. export the `Readable` BigQuery and Tink keysets again, which then hold the pending version;
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

- a randomised version is good for about 2^32 values, see [Nonces](../security.md#nonces), and an
  AES-GCM version for about 2^38 bytes, see [Data volume](../security.md#data-volume). The keyring
  stops at neither, since its DEKs are shared across processes: estimate the values and bytes a
  fleet encrypts, or measure them, see [Alerting on volume](./monitoring.md#alerting-on-volume). At 550 values per
  second a version reaches 2^32 in 90 days, so rotate every 30 to 90 days, sooner at higher rates;
- a deterministic version has no nonce, so it is rotated by policy and on compromise only. Every
  deterministic rotation adds a probe to each equality query until a full sweep re-encrypts every
  row, see [Queries across rotations](../keyring/deterministic.md#queries-across-rotations), so
  rotate deterministic versions rarely;
- a beacon version likewise, since every beacon rotation adds a probe to each lookup until a
  re-index, see [Rotating beacon versions](../keyring/beacons.md#rotating-beacon-versions).

After a promotion, export the `Single` BigQuery keysets of the new deterministic version, since
a pending version has none.

### Why nothing stops

- A pending version decrypts in every process that has seen it and encrypts nothing, so by the
  promotion every process that reads a value under it already knows it;
- a process that has not taken the promotion yet encrypts under the previous version, which stays
  `DecryptOnly`, so its values decrypt everywhere;
- the sweep reads a value under the old version and writes it under the new one, conditional on
  the record as it read it, so a write of the application in between is never overwritten;
- `retire` is the first step that refuses a read, and `reinstate` undoes it.

### What can go wrong

- **A process left behind** by a promotion meets a value under the new version and reloads its
  record, see [Staged rotation](../keyring/lifecycle.md#staged-rotation);
- **a re-encryption that fails** is counted and logged, and some failures repeat in every run, see
  [Running a sweep](./sweeps.md#running-a-sweep);
- **a retire too early** refuses a value the sweep missed, see
  [Retiring the old version](./sweeps.md#retiring-the-old-version);
- **a stale keyset** misses the values under the new version in SQL, see
  [Read values in BigQuery or Tink](../use-cases/bigquery-and-tink.md#with-a-keyring);
- **a destroy** is final, apart from the copies of the DEK that backups of the record and earlier
  keyset exports keep, see [What survives a shred](../use-cases/erase-a-tenant.md#what-survives-a-shred).

### What to alert on

The alerts of a DEK rotation are in [During a DEK rotation](./monitoring.md#during-a-dek-rotation).

## KEK rotation

A KEK rotation is a new version of the key in the KMS. In order:

1. **rotate the KEK in the KMS**, as its provider page describes under "Key versions and
   rotation": [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation),
   [AWS KMS](../providers/aws.md#key-versions-and-rotation),
   [Azure Key Vault](../providers/azure.md#key-versions-and-rotation),
   [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation) or the
   [local KMS](../providers/local.md#key-versions-and-rotation);
2. **re-encrypt, check, disable, check again and destroy**, as in
   [Re-encrypt DEKs after a KEK rotation](./reencrypt-deks.md).
   A keyring's part, `reencrypt_deks` and `kek_versions_in_use`, is in
   [Re-encrypting a keyring's DEKs](#re-encrypting-a-keyrings-deks), with a sample.

### Why nothing stops

No value changes, and the old KEK version decrypts every DEK until it is disabled. The disable
waits until no process holds an encrypted DEK from before the re-encryption, so by then every
process reads through DEKs under the new version. A DEK the re-encryption missed fails in the
application from the disable on, once its DEK cache entry expires, and the check after the disable
finds it. Enabling the old version again restores every DEK under it, at once under Cloud KMS, see
[Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation).

### Re-encrypting a keyring's DEKs

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
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{
    KmsKeyVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider,
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
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?],
# )?;
# registry
#     .create(before_rotation, TENANT, KeyringAlgorithms::new())
#     .await?;

// The administrative job after the rotation, with the new version encrypting
let rotated = LocalKmsProvider::<Ring>::new(
    kek_id.clone(),
    vec![
        LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?,
        LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?,
    ],
)?;
let admin = registry.admin(rotated, TENANT).await?;

// One entry per version: the KEK version its DEK was under, and the one it is under now
let moved: Vec<DekReencryption> = admin.reencrypt_deks().await?;
let new_kek_version = KmsKeyVersion::from(v2);
assert!(moved
    .iter()
    .all(|reencryption| reencryption.kek_version.as_ref() == Some(&new_kek_version)));

// The check before the old version is disabled: every DEK is under the new version
let record = admin.keyring().reload().await?;
assert_eq!(record.kek_versions_in_use(), [Some(&new_kek_version)]);

// The check once the old version is disabled: every DEK still decrypts
let disabled = LocalKmsProvider::<Ring>::new(
    kek_id,
    vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?],
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
[Re-encrypt DEKs after a KEK rotation](./reencrypt-deks.md).

### A KEK version the KMS did not report

A `None` among the versions in use stands for the DEKs whose KMS reported no version: every DEK
under AWS KMS, and under a KMS with versions, a version that is unknown, as with an application's
own provider that returns none. A Cloud KMS or Vault Transit response without a key version is
logged at `WARN`, see [Events](../observability/spans-and-events.md#events). `reencrypt_deks` keeps such a DEK at
`None`, so the check before the disable never passes. The procedure in
[Re-encrypt DEKs after a KEK rotation](./reencrypt-deks.md)
then goes from step 2 to step 4, and the check after the disable, step 6, is the only one.

Between the disable and that check, a DEK still under the old version fails in the application too,
once its DEK cache entry has expired. Under AWS KMS only imported key material can be removed, see
[AWS KMS](../providers/aws.md#key-versions-and-rotation).

### The KMS decrypt burst

`reencrypt_deks` gives every DEK new encrypted bytes, and the DEK cache keys its entries by those
bytes. Each process that takes the refreshed record evicts the old entries, so its next call under
each version decrypts that version's DEK through the KMS again: one KMS decryption per process, per
keyring and per version in use, within the bound of
[How late a change is seen](../keyring/record-cache.md#how-late-a-change-is-seen) after each
`reencrypt_deks`. With a keyring per tenant, re-encrypt the keyrings in batches below the KMS's
request quota, with room for that burst, see [Pacing](./reencrypt-deks.md#pacing). A sweep or
an application over the quota fails with the KMS's error, such as `ResourceExhausted` on Google
Cloud KMS or `ThrottlingException` on AWS KMS, both a `NetworkError`.

### What can go wrong

- **An early re-encryption or check** under Cloud KMS, inside the propagation of the new primary
  version or of the disable, see [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
- **a pinned Azure version** re-encrypts under the old version, see
  [Azure Key Vault](../providers/azure.md#key-versions-and-rotation);
- **an early disable** fails the reads of a process that still holds the old encrypted DEKs, see
  [The check](./reencrypt-deks.md#the-check);
- **Vault Transit's `min_decryption_version`** disables every version below it at once, see
  [Re-encrypting a keyring's DEKs](#re-encrypting-a-keyrings-deks);
- **AWS KMS key material** cannot be disabled when generated, and leaves the key unusable when
  imported material is deleted or expires, see [AWS KMS](../providers/aws.md#key-versions-and-rotation);
- **a destroyed old version** makes every backup taken before the re-encryption unreadable.

### What to alert on

The alerts of a KEK rotation are in [During a KEK rotation](./monitoring.md#during-a-kek-rotation).

## With kms-aead alone

### DEKs

Without a keyring there is no version to stage, and the DEK rotates with the mode:

- **per-call envelope**: every value has a DEK of its own, so there is no DEK to rotate;
- **store-less DEK reuse**: the envelope renews its DEK by age, count and bytes, as its
  `DekReusePolicy` sets, and the values keep their encrypted DEK, so the renewal is the rotation
  and needs no sweep, see [Store-less DEK reuse](../dek-caching.md#store-less-dek-reuse);
- **one fixed key**, a deterministic key or a beacon key the application keeps: a second key under
  a second key id, both kept for reads, and a re-index of the values or beacons under the old one,
  see [One fixed key](../one-fixed-key.md) and
  [Rotating a beacon key](../beacons.md#rotating-a-beacon-key).

A DEK that leaked keeps decrypting every value encrypted under it, whatever the KEK, so it is
retired by the steps of
[A DEK of envelope values leaked](./runbook.md#a-dek-of-envelope-values-leaked), not by a routine
rotation.

### The KEK

The KEK rotates in the KMS, and before the old version is disabled, the DEKs stored in the values
and apart from them are encrypted again under its new version with `reencrypt_encrypted_dek`, once
per distinct encrypted DEK, and the application's own encrypted keysets through the provider. No
value is decrypted. The procedure, when the sweep starts, its pacing, the checks and a rollback are
in [Re-encrypt DEKs after a KEK rotation](./reencrypt-deks.md), and the alerts are those of
[During a KEK rotation](./monitoring.md#during-a-kek-rotation), on `kms_aead.kms.duration`.
