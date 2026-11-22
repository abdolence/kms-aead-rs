# Erase one customer's data for good

A customer closes its account and asks for its data to be erased, or a retention rule requires it.
Deleting its rows leaves the values in backups, exports and every other copy of the store, and
those cannot all be found and rewritten. Destroying the keys that decrypt the values makes every
copy unreadable at once.

## Crypto-shredding

A scope's values become unreadable once nothing can decrypt their DEKs. With kms-aead alone, the
DEKs are encrypted by the KEK, so shredding is the destruction of the KEK's versions that encrypted
them, backups included. Per KMS:

- **Google Cloud KMS**: destroy the key versions. Cloud KMS schedules the destruction, and until
  then a version can be restored, see
  [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
- **AWS KMS**: delete the key. Rotated key material is never destroyed on its own, see
  [AWS KMS](../providers/aws.md#key-versions-and-rotation);
- **Azure Key Vault**: delete the key, which deletes it with all its versions: Key Vault never
  deletes one version alone, see [Azure Key Vault](../providers/azure.md#key-versions-and-rotation).
  Soft delete and purge protection delay the shredding, see
  [What survives a shred](#what-survives-a-shred);
- **Vault Transit**: `min_available_version` and a trim of the key delete the versions below it, see
  [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation), and a deletion of
  the key, once its configuration sets `deletion_allowed`, deletes every version;
- **local KMS**: destroy every copy of the KEK version, backups included, see
  [Local KMS](../providers/local.md#key-versions-and-rotation).

Under a keyring, the KEK encrypts the record's DEKs and every keyset exported from the keyring, so
destroying the KEK's versions makes the backups of the record and the exported keysets
unrecoverable too.

Since a deletion of the key takes every version, shredding one scope under AWS KMS or Azure Key
Vault needs a key per scope. With a keyring, a shared KEK has a second route, `dangerously_shred()`.
It destroys every version of the keyring and deletes its record from the store, with the earlier
versions the store keeps. The keys stay in every copy the store keeps beyond its API, such as a
backup, and in every keyset exported from the keyring, see
[What survives a shred](#what-survives-a-shred). A deployment that needs shredding guarantees uses
a KEK per scope, see [Give each customer of a SaaS its own keys](./keyring-per-tenant.md).

## Shredding a tenant with `dangerously_shred()`

Under a shared KEK, `KeyringAdmin::dangerously_shred()` ends the tenant's keyring in one call: it
destroys every version of the keyring in one write, as `dangerously_destroy_all_versions` does,
then deletes the record from the store with every earlier version of it the store keeps. The
keyring encrypts and decrypts nothing from then on, except through a stream encryptor or decryptor
already made, see below, and the id is free for a new keyring.

- the write is signed as every lifecycle write is: an administration without a record signer is
  refused with `RecordSignerMissing` over a signed record, and a signing one with `RecordUnsigned`
  over an unsigned record, both before any store write;
- a conflict of the write or of the delete starts again from a new read, up to `cas_retries`, then
  `RecordConflict`;
- a shred that fails is run again. A record whose every version is destroyed already, as a failure
  between the write and the delete leaves it, is deleted without a write, and a record already
  gone returns `Ok`. The record left between the two steps holds no encrypted DEK, and every
  process that reads it destroys its versions;
- `KeyringRegistry::admin` on a keyring already gone fails with `RecordMissing`, which an erasure
  treats as done;
- a copy of the record from before the shred is refused by a process that took the deletion, with
  `RecordRegressed` and an `ERROR`, because it revives versions the process holds destroyed. A
  store writer who restores an old record gains nothing against that process;
- after a deliberate restore, such as one that undoes an accidental deletion, restart every process
  that took the deletion. A process that starts after the restore takes the record.

Every process that holds the keyring takes the shred as a deleted record, see
[The keyring record was deleted or corrupted](../production/runbook.md#the-keyring-record-was-deleted-or-corrupted).
Its handles fail with `NoActiveVersion` for a write and `KeyVersionDestroyed` for a read. How late:

- with push, within `reload_min_interval` of the store's signal;
- without push, on Cloud Storage and S3 or with `watch` off, once the cached record is older than
  `record_ttl`, at the next call.

The plaintext DEK leaves the process's memory at that revalidation. A process that makes no call
keeps it until the DEK cache drops it: its TTL, with `purge_expired` on a timer, see
[DEK eviction](../keyring/record-cache.md#dek-eviction). A stream decryptor or encryptor already
made keeps the key derived for its value, and goes on decrypting or encrypting with it, until it is
dropped. Build a decryptor per request and do not cache it across requests, so that a shred takes
effect for new requests, see [Streaming encryption](../streaming.md#limits).

## What to watch for

- `dangerously_shred()` never calls the KMS and leaves every KMS key version as it was. Values
  encrypted under the keyring stay where they are and decrypt under nothing;
- the store's backups, its history and every exported keyset stay where they are too, and still
  decrypt while a KEK version that encrypted their DEKs exists, see
  [What survives a shred](#what-survives-a-shred).

### What survives a shred

Every copy of the record outside the store's API still holds the encrypted DEKs, which the KMS
decrypts as long as a KEK version that encrypted them exists. The operator deletes them or ends the
KEK versions:

- **Firestore**: serves a deleted document to reads at an earlier time for one hour, and for seven days
  with point-in-time recovery on, which keeps the versions of every document for that window.
  Backups and exports hold the record until they are deleted;
- **PostgreSQL**: the row's earlier versions until a vacuum reclaims them, and backups, WAL archives
  and replicas. The WAL is the write-ahead log, which holds every committed change;
- **Cloud Storage**: `dangerously_shred()` deletes every generation of the object, noncurrent ones
  included. Soft delete keeps every deleted generation restorable for the bucket's retention, 7 days
  by default, so a bucket of keyring records turns soft delete off, or counts the retention into the
  time a shred takes;
- **S3**: `dangerously_shred()` deletes every version and delete marker of the object. Replication
  to another bucket and backups hold copies it does not reach;
- **exported keysets**: every BigQuery and Tink keyset exported from the keyring holds the keys of
  the versions it was exported with, under the same KEK, see
  [Keyring limits](../security.md#keyring-limits).

Per store, what `dangerously_shred()` deletes is in [Keyring stores](../keyring/stores.md).

So after a shred, either delete the record's backups and every copy of the keysets exported from
the keyring, or destroy every KEK version that encrypted them. On GCP, Vault Transit and the local
KMS, rotate the KEK, re-encrypt every other keyring under it as in
[Re-encrypt DEKs after a KEK rotation](../production/reencrypt-deks.md),
then destroy every previous KEK version, the ones an earlier rotation left disabled included. On
AWS rotated key material is never destroyed, so only the deletion of the KMS key itself shreds.
Azure Key Vault deletes a key with all its versions and never one version alone, so there too only
the deletion of the key shreds. A vault with soft delete keeps a deleted key recoverable until it
is purged, and with purge protection on, no purge is possible until the vault's retention period of
7 to 90 days has passed, see
[Azure Key Vault soft-delete](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/shred.rs).
