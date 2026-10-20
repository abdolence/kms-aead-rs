# Rotate keys and re-encrypt values

Two keys rotate, on their own schedules:

- a DEK seals values. A new DEK changes nothing already written, so the values under the old one
  are re-sealed by a sweep before the old DEK is retired;
- the KEK encrypts DEKs in the KMS. A new KEK version changes no value: the DEKs are encrypted
  again under it before the old version is disabled.

Both run without downtime, since the old key keeps decrypting until one of the last steps
retires or disables it, and a check runs before that step. The runbooks below are for a keyring,
then for kms-aead alone. How often to rotate is in
[Rotation cadence](../operations/rotation.md#rotation-cadence).

## DEK rotation

On a keyring, a DEK rotation is a new key version of a purpose, staged before it seals anything.
The administrative job runs every call on its `KeyringAdmin`, and the application runs the sweep,
see [Applications and administration](../keyring/deployment.md).

1. **Rotate.** `rotate(purpose)` stages a pending version and returns its key id. Export the
   BigQuery and Tink keysets again, which then hold the pending version, see
   [Read values in BigQuery or Tink](./bigquery-and-tink.md#with-a-keyring);
2. **wait** until every process decrypts under the pending version. How long a healthy process
   takes depends on the store, see
   [How late a change is seen](../keyring/record-cache.md#how-late-a-change-is-seen):
   - Firestore and PostgreSQL, with `watch` on: within `reload_min_interval` of the store's
     signal, about 5 seconds by default;
   - Cloud Storage and S3, with `watch` off, or while a listener is disconnected: within
     `record_ttl`, 5 minutes by default.

   A process whose revalidations fail keeps its old record for as long as they fail, and logs
   "The keyring record could not be revalidated; the cached record stays in use". Check that no
   process logged it since `staged_at()`;
3. **promote.** `promote(key_id)` makes the version active. Until `record_ttl` has passed since
   `staged_at()` it fails with `PromotionTooEarly`, whose `remaining` is the time left, so the job
   sleeps that long and calls it again. `promote_now(key_id)` skips the guard, for a fleet known to
   have the version, such as one restarted since the rotation, see
   [Staged rotation](../keyring/lifecycle.md#staged-rotation). After the promotion, export the
   `Single` BigQuery keyset of a new deterministic version;
4. **sweep.** Every record whose seal marker is below the keyring's current one holds a value
   under an older version. A sweep re-seals them under the active version, and runs on a schedule
   until its `SweepReport` shows nothing scanned, see [Sweeps](../operations/sweeps.md). The query
   and the write per database:
   - [Firestore](../operations/sweeps-firestore.md);
   - [PostgreSQL](../operations/sweeps-postgres.md);
   - [BigQuery](../operations/sweeps-bigquery.md), in SQL;
   - beacons and deterministic fields: [Rotating beacon versions](../keyring/beacons.md#rotating-beacon-versions)
     and [Queries across rotations](../keyring/deterministic.md#queries-across-rotations);
5. **retire.** Once the old version's range query returns nothing, see
   [Records under a version](../operations/sweeps.md#records-under-a-version), `retire(key_id)`.
   Reads under it fail with `KeyVersionRetired` from then on, and `reinstate(key_id)` brings it
   back for a value that turned up after all;
6. **destroy.** After a time retired, `destroy(key_id)` removes its encrypted DEK from the record,
   and no call brings it back.

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

- **A process left behind.** A process that missed the pending version, because its store was
  unreachable or `promote_now` ran too early, meets a value under the new version, reloads its
  record once, rate-limited, and reads it when the store answers. When the store does not answer,
  the read fails with `KeyVersionUnknown`;
- **a short guard.** `promote` waits the `record_ttl` of the administrative job's registry, so that
  registry needs the longest `record_ttl` in the fleet. A clock skew between the host that staged
  the version and the one that promotes it shortens or lengthens the wait by as much;
- **a re-seal that fails.** A sweep counts each failure and logs it at `WARN`. A `SealerOutdated`
  is a record another process rewrote meanwhile, and the next run no longer finds it. A value under
  a version the store's record holds as pending, such as a value from another keyring, fails in
  every run, see [Running a sweep](../operations/sweeps.md#running-a-sweep);
- **a retire too early.** A value the sweep missed fails with `KeyVersionRetired`, logged at
  `WARN`. `reinstate` the version, sweep again and retire again;
- **a stale keyset.** A BigQuery keyset exported before the rotation has no key for values sealed
  under the new version, so SQL fails to decrypt them;
- **a destroy.** A destroyed version's values are gone, except in backups of the record, which
  still hold its encrypted DEK, see [Crypto-shredding](../operations/runbook.md#crypto-shredding).

### What to alert on

- the revalidation `WARN` above, from the rotation to the promotion: a process that logs it is one
  a promotion can leave behind;
- `error.type` `KEY_VERSION_UNKNOWN` on `kms_aead.operation.duration`, a read that met a version
  its process could not load, and `KEY_VERSION_RETIRED` once the old version is retired;
- `SweepReport::failed` above zero, and the sweep's `WARN` per record;
- the values and bytes per version, which say when the next rotation is due, see
  [Alerting on volume](../operations/rotation.md#alerting-on-volume).

The metrics need the `opentelemetry` feature, see [Metrics](../observability.md#metrics).

## KEK rotation

A KEK rotation is a new version of the key in the KMS. On a keyring:

1. **Rotate the KEK in the KMS**, as its provider page describes under "Key versions and rotation":
   - [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation): wait until the new primary
     version has propagated before the next step;
   - [AWS KMS](../providers/aws.md#key-versions-and-rotation): AWS KMS keeps every earlier key
     material decrypting, and reports no version;
   - [Azure Key Vault](../providers/azure.md#key-versions-and-rotation): move a version pinned in
     `AzureKmsKeyRef` to the new one;
   - [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation): the new version
     encrypts at once;
   - [Local KMS](../providers/local.md#key-versions-and-rotation): two deploys, first listing the
     new version, then encrypting under it;
2. **re-encrypt the DEKs.** `reencrypt_deks()` on each keyring under the KEK decrypts every DEK of
   the record and encrypts it again under the KEK's current version, two KMS calls per DEK. Then
   export the keyrings' BigQuery and Tink keysets again, see
   [Encrypted keysets](../envelope-encryption.md#encrypted-keysets);
3. **check before the disable.** `kek_versions_in_use()` of the record that `Keyring::reload`
   returns must be `[Some(&new)]`, the new version alone, which needs no KMS call. Under Cloud KMS a
   `reencrypt_deks` that ran before the new primary version had propagated leaves the old version
   listed: run it again. A `None` is a DEK whose KMS reported no version, every DEK under AWS KMS:
   this check never passes then, and the check after the disable is the only one, see
   [A KEK version the KMS did not report](../operations/rotation.md#a-kek-version-the-kms-did-not-report);
4. **wait one `record_ttl`** after the last `reencrypt_deks`. A process keeps the encrypted DEKs of
   the record it holds until the record refreshes, and decrypts those bytes through the KMS once its
   DEK cache entry expires;
5. **disable the old KEK version** in the KMS, then run `reencrypt_deks` again: it decrypts every
   DEK through the KMS and fails on one the KMS no longer decrypts. On a failure, enable the old
   version again and go back to step 2;
6. **keep the old version disabled** for as long as the backups of the keyring records are kept,
   since they hold DEKs under it, then destroy it.

The whole procedure, with an application's own DEKs and keysets beside the keyrings, is in
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
and the keyring's part with a sample in [Rotating the KEK](../operations/rotation.md#rotating-the-kek).

### Why nothing stops

No value changes, and the old KEK version decrypts every DEK until step 5. The check in step 3
runs before anything is disabled, and the one in step 5 right after, so a missed DEK is found by
the job and not by a read. Enabling the old version again restores every DEK under it, at once
under Cloud KMS, where enabling is strongly consistent.

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

- **An early re-encryption.** Under Cloud KMS, before the new primary version has propagated,
  `reencrypt_deks` re-encrypts under the old version, and step 3 shows it;
- **a pinned Azure version.** A provider pinned to the old version re-encrypts under the old
  version;
- **an early disable.** A process that still holds the old encrypted DEKs fails to decrypt them
  once its DEK cache entry expires. Under Cloud KMS a disabled version typically stays usable for
  up to a minute, and for hours in exceptional cases, so a check inside that window passes on DEKs
  still under it, see [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
- **Vault Transit's `min_decryption_version`** disables every version below it at once, which is
  why step 3 asks for the new version alone;
- **AWS KMS key material.** Generated key material cannot be disabled, so there is nothing to
  disable and the rotation needs no check. Imported key material that is deleted or expires leaves
  the key unusable for every DEK until it is imported again, see
  [AWS KMS](../providers/aws.md#key-versions-and-rotation);
- **a destroyed old version** makes every backup of a record taken before step 2 unreadable.

### What to alert on

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
value is opened. The sweep, its pacing, the check before and after the disable, and a rollback are
in [Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).

A store-less writer keeps sealing under its current DEK, encrypted under the old version, until it
renews it, and every DEK cache serves the DEKs it holds until their entries expire, at the cache's
TTL of 15 minutes by default. The sweep starts once every writer has renewed its DEK after the
rotation, and the alerts are those of the keyring's KEK rotation, on `kms_aead.kms.duration`.
