# Rotate keys and re-encrypt values

Two keys rotate, on their own schedules:

- a DEK seals values. A new DEK changes nothing already written, so the values under the old one
  are re-sealed by a sweep before the old DEK is retired;
- the KEK encrypts DEKs in the KMS. A new KEK version changes no value: the DEKs are encrypted
  again under it before the old version is disabled.

Both run without downtime, since the old key keeps decrypting until one of the last steps
retires or disables it, and a check runs before that step. This page walks through each rotation
and links to the procedure of each step. How often to rotate is in
[Rotation cadence](../operations/rotation.md#rotation-cadence).

## DEK rotation

On a keyring, a DEK rotation is a new key version of a purpose, staged before it seals anything.
The administrative job runs every call on its `KeyringAdmin`, and the application runs the sweep,
see [Applications and administration](../keyring/deployment.md). In order:

1. **stage and promote** the new version: `rotate`, export the keysets again, wait until every
   process has the pending version, `promote`. The steps and the waits are in
   [Rotation cadence](../operations/rotation.md#rotation-cadence), and why the wait is needed in
   [Staged rotation](../keyring/lifecycle.md#staged-rotation);
2. **sweep** the records whose seal marker is below the keyring's current one. They are the records
   that can hold a value under an older version, and records with no value of the rotated purpose,
   whose re-seal writes the marker alone, see [Sweeps](../operations/sweeps.md). The query and the
   write per database:
   - [Firestore](../operations/sweeps-firestore.md);
   - [PostgreSQL](../operations/sweeps-postgres.md);
   - [BigQuery](../operations/sweeps-bigquery.md), in SQL;
   - beacons and deterministic fields: [Rotating beacon versions](../keyring/beacons.md#rotating-beacon-versions)
     and [Queries across rotations](../keyring/deterministic.md#queries-across-rotations);
3. **retire, then destroy** the old version, once every process has refreshed since the promotion
   and no record is left under it, see
   [Retiring the old version](../operations/sweeps.md#retiring-the-old-version).

The [`rotate` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/rotate.rs)
runs the whole cycle on the memory store and the local KMS:
`cargo run -p kms-aead-keyring --example rotate --features ring,admin`.

### Why nothing stops

- A pending version decrypts in every process that has seen it and seals nothing, so by the
  promotion every process that reads a value under it already knows it;
- a process that has not taken the promotion yet seals under the previous version, which stays
  `DecryptOnly`, so its values decrypt everywhere;
- the sweep reads a value under the old version and writes it under the new one, conditional on
  the record as it read it, so a write of the application in between is never overwritten;
- `retire` is the first step that refuses a read, and `reinstate` undoes it.

### What can go wrong

- **A process left behind** by a promotion meets a value under the new version and reloads its
  record, see [Staged rotation](../keyring/lifecycle.md#staged-rotation);
- **a re-seal that fails** is counted and logged, and some failures repeat in every run, see
  [Running a sweep](../operations/sweeps.md#running-a-sweep);
- **a retire too early** refuses a value the sweep missed, see
  [Retiring the old version](../operations/sweeps.md#retiring-the-old-version);
- **a stale keyset** misses the values under the new version in SQL, see
  [Read values in BigQuery or Tink](./bigquery-and-tink.md#with-a-keyring);
- **a destroy** is final, apart from the copies of the DEK that backups of the record and earlier
  keyset exports keep, see [Crypto-shredding](../operations/runbook.md#crypto-shredding).

### What to alert on

- "The keyring record could not be revalidated", from the rotation until the old version is
  retired: a process that logs it is one a promotion can leave behind, and one that can still seal
  under the old version;
- `error.type` `KEY_VERSION_UNKNOWN` on `kms_aead.operation.duration`, a read that met a version
  its process could not load, and `KEY_VERSION_RETIRED` once the old version is retired;
- `SweepReport::failed` above zero, and the sweep's `WARN` per record;
- the values and bytes per version, which say when the next rotation is due, see
  [Alerting on volume](../operations/rotation.md#alerting-on-volume).

The metrics need the `opentelemetry` feature, see [Metrics](../observability.md#metrics).

## KEK rotation

A KEK rotation is a new version of the key in the KMS. In order:

1. **rotate the KEK in the KMS**, as its provider page describes under "Key versions and
   rotation": [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation),
   [AWS KMS](../providers/aws.md#key-versions-and-rotation),
   [Azure Key Vault](../providers/azure.md#key-versions-and-rotation),
   [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation) or the
   [local KMS](../providers/local.md#key-versions-and-rotation);
2. **re-encrypt, check, disable, check again and destroy**, as in
   [Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).
   A keyring's part, `reencrypt_deks` and `kek_versions_in_use`, is in
   [Rotating the KEK](../operations/rotation.md#rotating-the-kek), with a sample.

### Why nothing stops

No value changes, and the old KEK version decrypts every DEK until it is disabled. The disable
waits until no process holds an encrypted DEK from before the re-encryption, so by then every
process reads through DEKs under the new version. A DEK the re-encryption missed fails in the
application from the disable on, once its DEK cache entry expires, and the check after the disable
finds it. Enabling the old version again restores every DEK under it, at once under Cloud KMS, see
[Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation).

### The KMS decrypt burst

`reencrypt_deks` gives every DEK new encrypted bytes, and the DEK cache keys its entries by those
bytes. Each process that takes the refreshed record evicts the old entries, so its next call under
each version decrypts that version's DEK through the KMS again: one KMS decryption per process, per
keyring and per version in use, within the bound of
[How late a change is seen](../keyring/record-cache.md#how-late-a-change-is-seen) after each
`reencrypt_deks`. With a keyring per tenant, re-encrypt the keyrings in batches below the KMS's
request quota, with room for that burst, see [Pacing](../envelope-encryption.md#pacing). A sweep or
an application over the quota fails with the KMS's error, such as `ResourceExhausted` on Google
Cloud KMS or `ThrottlingException` on AWS KMS, both a `NetworkError`.

### What can go wrong

- **An early re-encryption or check** under Cloud KMS, inside the propagation of the new primary
  version or of the disable, see [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
- **a pinned Azure version** re-encrypts under the old version, see
  [Azure Key Vault](../providers/azure.md#key-versions-and-rotation);
- **an early disable** fails the reads of a process that still holds the old encrypted DEKs, see
  [The check](../envelope-encryption.md#the-check);
- **Vault Transit's `min_decryption_version`** disables every version below it at once, see
  [Rotating the KEK](../operations/rotation.md#rotating-the-kek);
- **AWS KMS key material** cannot be disabled when generated, and leaves the key unusable when
  imported material is deleted or expires, see [AWS KMS](../providers/aws.md#key-versions-and-rotation);
- **a destroyed old version** makes every backup taken before the re-encryption unreadable.

### What to alert on

- "The keyring record could not be revalidated", from the re-encryption until the disable: a
  process that logs it keeps the old encrypted DEKs, and its reads fail after the disable once its
  DEK cache entries expire;
- `error.type` on `kms_aead.kms.duration` with `kms_aead.operation` `decrypt_dek`, after the
  disable: a DEK the re-encryption missed, or a process that still holds old bytes;
- the rate of `kms_aead.kms.duration` with `decrypt_dek`, and `ResourceExhausted` or
  `ThrottlingException` in its `error.type`, during the burst;
- an `error_code` on the `Keyring re-encrypt DEKs` span of the administrative job.

## With kms-aead alone

### DEKs

Without a keyring there is no version to stage, and the DEK rotates with the mode:

- **per-call envelope**: every value has a DEK of its own, so there is no DEK to rotate;
- **store-less DEK reuse**: the envelope renews its DEK by age, count and bytes, as its
  `DekReusePolicy` sets, and the values keep their encrypted DEK, so the renewal is the rotation
  and needs no sweep, see [Store-less DEK reuse](../dek-caching.md#store-less-dek-reuse);
- **one fixed key**, a deterministic key or a beacon key the application keeps: a second key under
  a second key id, both kept for reads, and a re-index of the values or beacons under the old one,
  see [One fixed key](../envelope-encryption.md#one-fixed-key) and
  [Rotating a beacon key](../beacons.md#rotating-a-beacon-key).

A DEK that leaked keeps opening every value sealed under it, whatever the KEK. To retire it:

1. stop sealing under it: a store-less writer renews its DEK after `invalidate` of that DEK, or
   `clear`, on its envelope's DEK cache, in every process, see
   [The DEK lives in the cache](../dek-caching.md#the-dek-lives-in-the-cache);
2. read each value under it with `decrypt` and seal it again with `encrypt`, which takes a new
   DEK, and write it back only where the stored bytes are still the ones read;
3. treat backups and exports that hold the old values as exposed, see
   [What rotation does not protect](../security.md#what-rotation-does-not-protect).

### The KEK

The KEK rotates in the KMS, and before the old version is disabled, the DEKs stored in the values
and apart from them are encrypted again under its new version with `reencrypt_encrypted_dek`, once
per distinct encrypted DEK, and the application's own encrypted keysets through the provider. No
value is opened. The procedure, when the sweep starts, its pacing, the checks and a rollback are in
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
and the alerts are those of the keyring's KEK rotation above, on `kms_aead.kms.duration`.
