# Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

## A plaintext DEK leaked

Or is suspected to have.

1. `mark_compromised(key_id, note)`: the version is flagged and, if active, replaced in one write by
   a version that is active at once. The replacement skips the staged wait on purpose: encrypting
   under the leaked key stops at each process's next refresh, and a process that has not seen the
   replacement yet reloads its record once, rate-limited, when it meets a value under it. When the
   KMS cannot encrypt a new DEK, the flag lands alone and `encrypt` fails with `NoActiveVersion`;
   once the KMS answers, `rotate` and `promote_now` at once, since nothing encrypts under the
   purpose meanwhile, or `promote_now` the pending version if the purpose has one. `promote` would
   refuse with `PromotionTooEarly` for up to `record_ttl` from the staging. A pending version itself
   is never compromised: `destroy` it instead;
2. every process stops using the key within the bound of the
   [record cache](../keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep the records in the compromised version's range, see [Records under a
   version](./sweeps.md#records-under-a-version), reading them with `decrypt_with_trust`, and decide
   per record on the values read through the compromised version, see [The trust of re-encrypted
   values](./sweeps.md#the-trust-of-re-encrypted-values). Run the range query again once every
   process has had time to refresh its record, for the writes of processes that had not seen the
   flag yet;
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. retire and later destroy the version as in
   [Retiring the old version](./sweeps.md#retiring-the-old-version).

Rotation protects nothing already copied: backups, point-in-time recovery and data exports still
hold values the leaked DEK decrypts. Treat them as exposed and revoke the secrets inside them.

## A KMS IAM over-grant

1. Fix the IAM binding, back to the split in
   [KMS rights](../keyring/deployment.md#kms-rights);
2. rotate the KEK in the KMS and `reencrypt_deks()`;
3. with KMS data-access logs enabled in advance, list the `Decrypt` calls the wrong principal
   made: every encrypted DEK they decrypted is a leaked DEK, see above. Without those logs, every
   version is a leaked DEK.

## An encrypted DEK or the keyring record leaked

Harmless by itself, since decrypting needs the KMS. If the attacker may also gain `Decrypt` on the
KEK, follow the IAM over-grant steps. If the attacker may also write the keyring store, see
[the next case](#a-version-the-administrative-job-did-not-create) and the store-writer threat in
[Keyring deployment](../security.md#keyring-deployment).

## A version the administrative job did not create

This case starts from the `ERROR` event of a refused record that moves backwards, or from a version
in the record that the administrative job's log does not show. The event's `rule` names the version
that moved backwards, except `the re-encryption epoch moved back`, which names none: compare the
versions of the record in the store with the job's log to find the one it did not create. Either
means that something other than the job wrote the record: a restore, which [the next
case](#the-keyring-record-was-deleted-or-corrupted) covers, or a writer of the store.

1. If the version is active, `mark_compromised` it, so that nothing new is encrypted under it from
   each process's next refresh. If it is pending, `destroy` it;
2. retire and destroy the version as in
   [Retiring the old version](./sweeps.md#retiring-the-old-version), after a sweep if values were
   encrypted under it;
3. check the KMS audit log for the `Encrypt` call that encrypted its DEK. None means its encrypted
   DEK was copied or relabelled from another version, of this keyring or of another under the
   same KEK, which the KMS decrypts as it would the original; one from a principal other than the
   administrative job is an IAM over-grant, see above;
4. audit who can write the keyring store: the application has no write, and only the
   administrative job should.

## The keyring record was deleted or corrupted

A running process takes a record gone from the store as a shredded keyring, see
[Record cache](../keyring/record-cache.md#when-the-store-fails-or-misbehaves). At its next
revalidation, forced `reload` or administrative call it destroys every version of its cached record
in memory, evicts the keyring's keys from the DEK cache and logs a `WARN`, "The keyring store no
longer holds the keyring record; every version is destroyed in this process". A
[shred](#shredding-a-keyring) writes the record with every version destroyed before it deletes it:
a process that read that record logs an `INFO` for the deletion instead, and the process that ran
the shred logs nothing. A process that first reads the store after the delete, such as one without
push, logs the `WARN` for a shred too, so the `WARN` does not tell an accidental deletion from an
erasure by itself. Its handles then
fail: `encrypt` with `NoActiveVersion`, `decrypt` with `KeyVersionDestroyed`, and `reload` with
`RecordMissing`. Within the bound of
[how late a change is seen](../keyring/record-cache.md#how-late-a-change-is-seen), an accidental
deletion stops every process that holds the keyring. New processes fail at `open` with
`RecordMissing`. A record that fails to parse or validate is a failed read instead: a running
process keeps its cached record and logs the `WARN` of a failed revalidation, and new processes
fail at `open` with `RecordInvalid`.

1. Restore the record from the store's backup: Firestore point-in-time recovery, a PostgreSQL
   backup, or a noncurrent version of the Cloud Storage or S3 object. The encrypted DEKs inside are
   still valid under the KEK;
2. repeat on the restored record every administrative call made after the copy was taken, from
   the administrative job's log, before any process opens the keyring again;
3. restart every process that took the deletion. It keeps the deleted record as the baseline of
   the id, and refuses the restored copy with `RecordRegressed` and an `ERROR`, because the copy
   revives versions the process holds destroyed. A process that starts after the restore has no
   baseline and takes the record.

A process that never saw the deletion, such as one whose revalidations were failing meanwhile,
refuses an older copy as well, and logs an `ERROR`. Values are never lost with the record as long
as a copy of it exists. Without any copy they are gone, so keep versioning on the bucket and back
up the table.

## Crypto-shredding

Crypto-shredding makes values unrecoverable by destroying the keys that decrypt them, so no copy of
the values has to be found. To make a scope's values unrecoverable:

- with a KEK per scope: destroy the KEK's versions in the KMS. Every encrypted DEK of the scope is
  then unrecoverable, backups of the record and keysets exported from it included, since the KEK
  encrypts both;
- with a shared KEK: `KeyringAdmin::dangerously_shred()`, see [Shredding a
  keyring](#shredding-a-keyring).

A deployment that needs shredding guarantees uses a KEK per scope.

### Shredding a keyring

`dangerously_shred()` destroys every version of the keyring in one write, as
`dangerously_destroy_all_versions` does, then deletes the record from the store with every earlier
version of it the store keeps. The keyring encrypts and decrypts nothing from then on, except
through a stream encryptor or decryptor already made, see below, and the id is free for a new
keyring.

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
  treats as done.

Every process that holds the keyring takes the shred as a deleted record, see above. How late:

- with push, within `reload_min_interval` of the store's signal;
- without push, on Cloud Storage and S3 or with `watch` off, once the cached record is older than
  `record_ttl`, at the next call.

The plaintext DEK leaves the process's memory at that revalidation. A process that makes no call
keeps it until the DEK cache drops it: its TTL, with `purge_expired` on a timer, see
[DEK eviction](../keyring/record-cache.md#dek-eviction). A stream decryptor or encryptor already
made keeps the key derived for its value, and goes on decrypting or encrypting with it, until it is
dropped. Build a decryptor per request and do not cache it across requests, so that a shred takes
effect for new requests, see [Streaming encryption](../streaming.md#limits).

`dangerously_shred()` never calls the KMS and leaves every KMS key version as it was. Values
encrypted under the keyring stay where they are and decrypt under nothing.

#### What survives a shred

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
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
then destroy every previous KEK version, the ones an earlier rotation left disabled included. On
AWS rotated key material is never destroyed, so only the deletion of the KMS key itself shreds.
Azure Key Vault deletes a key with all its versions and never one version alone, so there too only
the deletion of the key shreds. A vault with soft delete keeps a deleted key recoverable until it
is purged, and with purge protection on, no purge is possible until the vault's retention period of
7 to 90 days has passed, see
[Azure Key Vault soft-delete](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).

## A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.
