# Incident runbook

A key leaked, or may have: a service account key in a repository, a DEK in a log, a backup in the
wrong bucket. Each scenario starts with the steps that contain it, and explains the case after them.
Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

## Which scenario

| What happened, or what the alert says | Scenario |
|---|---|
| A plaintext DEK leaked, or may have, under a keyring | [A plaintext DEK leaked](#a-plaintext-dek-leaked) |
| A DEK of values encrypted without a keyring leaked | [A DEK of envelope values leaked](#a-dek-of-envelope-values-leaked) |
| A principal got KMS rights it should not have, or the KMS audit log shows an `Encrypt` or a `Decrypt` by one that should not | [A KMS IAM over-grant](#a-kms-iam-over-grant) |
| An encrypted DEK or a keyring record leaked | [An encrypted DEK or the keyring record leaked](#an-encrypted-dek-or-the-keyring-record-leaked) |
| An `ERROR` for a refused record that moves backwards, or a version the job did not create | [A version the administrative job did not create](#a-version-the-administrative-job-did-not-create) |
| A keyring record was deleted or corrupted, or a `WARN` about a record gone from the store | [The keyring record was deleted or corrupted](#the-keyring-record-was-deleted-or-corrupted) |
| The KMS is down | [A KMS outage](#a-kms-outage) |
| A tenant's values must become unreadable | [A scope's values must become unreadable](#a-scopes-values-must-become-unreadable) |

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

## A DEK of envelope values leaked

Without a keyring. A DEK that leaked decrypts every value encrypted under it, and a KEK rotation
does not change that. With a per-call envelope it is the DEK of one value, and with store-less DEK
reuse of every value the writer encrypted until it renewed the DEK.

1. stop encrypting under it: a store-less writer renews its DEK after `invalidate` of that DEK, or
   `clear`, on its envelope's DEK cache, in every process, and the DEK is invalidated in every DEK
   cache that holds it, see [The DEK lives in the cache](../dek-caching.md#the-dek-lives-in-the-cache);
2. read each value under it with `decrypt` and encrypt it again with `encrypt`, which takes a new
   DEK, and write it back only where the stored bytes are still the ones read;
3. a DEK the application keeps itself, such as the key of
   [One fixed key](../one-fixed-key.md) or a beacon key, is replaced by a key
   under a new key id, and the values or beacons under the old one are encrypted or computed again;
4. treat backups, point-in-time recovery and data exports as exposed: they still hold the values
   the leaked DEK decrypts, see
   [What rotation does not protect](../security.md#what-rotation-does-not-protect).

## A KMS IAM over-grant

1. Fix the IAM binding, back to the split in
   [KMS rights](./permissions.md#kms-rights);
2. rotate the KEK in the KMS and `reencrypt_deks()`;
3. with KMS data-access logs enabled in advance, list the `Decrypt` calls the wrong principal
   made: every encrypted DEK they decrypted is a leaked DEK, see
   [A plaintext DEK leaked](#a-plaintext-dek-leaked). Without those logs, every
   version is a leaked DEK.

## An encrypted DEK or the keyring record leaked

Harmless by itself, since decrypting needs the KMS. If the attacker may also gain `Decrypt` on the
KEK, follow the IAM over-grant steps. If the attacker may also write the keyring store, see
[A version the administrative job did not create](#a-version-the-administrative-job-did-not-create) and the store-writer threat in
[Keyring deployment](../security.md#keyring-deployment).

## A version the administrative job did not create

A version in the keyring record that the administrative job did not create.

1. If the version is active, `mark_compromised` it, so that nothing new is encrypted under it from
   each process's next refresh. If it is pending, `destroy` it;
2. retire and destroy the version as in
   [Retiring the old version](./sweeps.md#retiring-the-old-version), after a sweep if values were
   encrypted under it;
3. check the KMS audit log for the `Encrypt` call that encrypted its DEK. None means its encrypted
   DEK was copied or relabelled from another version, of this keyring or of another under the
   same KEK, which the KMS decrypts as it would the original; one from a principal other than the
   administrative job is an IAM over-grant, see
   [A KMS IAM over-grant](#a-kms-iam-over-grant);
4. audit who can write the keyring store: the application has no write, and only the
   administrative job should.

### How the case shows

This case starts from the `ERROR` event of a refused record that moves backwards, or from a version
in the record that the administrative job's log does not show. The event's `rule` names the version
that moved backwards, except `the re-encryption epoch moved back`, which names none: compare the
versions of the record in the store with the job's log to find the one it did not create. Either
means that something other than the job wrote the record: a restore, which [The keyring record was deleted or
corrupted](#the-keyring-record-was-deleted-or-corrupted) covers, or a writer of the store.

## The keyring record was deleted or corrupted

The record is gone from the store, or unreadable.

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

### What the processes do

A running process takes a record gone from the store as a shredded keyring, see
[Record cache](../keyring/record-cache.md#when-the-store-fails-or-misbehaves). At its next
revalidation, forced `reload` or administrative call it destroys every version of its cached record
in memory, evicts the keyring's keys from the DEK cache and logs a `WARN`, "The keyring store no
longer holds the keyring record; every version is destroyed in this process". Its handles then
fail: `encrypt` with `NoActiveVersion`, `decrypt` with `KeyVersionDestroyed`, and `reload` with
`RecordMissing`. Within the bound of
[how late a change is seen](../keyring/record-cache.md#how-late-a-change-is-seen), an accidental
deletion stops every process that holds the keyring. New processes fail at `open` with
`RecordMissing`.

A [shred](../use-cases/erase-a-tenant.md#shredding-a-tenant-with-dangerously_shred) writes the
record with every version destroyed before it deletes it. A process that read that record logs an
`INFO` for the deletion instead, and the process that ran the shred logs nothing. A process that
first reads the store after the delete, such as one without push, logs the `WARN` for a shred too,
so the `WARN` does not tell an accidental deletion from an erasure by itself.

A record that fails to parse or validate is a failed read instead: a running process keeps its
cached record and logs the `WARN` of a failed revalidation, and new processes fail at `open` with
`RecordInvalid`.

## A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.

## A scope's values must become unreadable

To make a scope's values unrecoverable on purpose, destroy the keys that decrypt them: the KEK's
versions with a KEK per scope, or `KeyringAdmin::dangerously_shred()` under a shared KEK. The
procedure, what a shred leaves behind and how late each process takes it are in
[Erase one customer's data for good](../use-cases/erase-a-tenant.md#crypto-shredding).
