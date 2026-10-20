# Emergency runbook

Rehearse each on a staging keyring, on a schedule, and record how long propagation took.

## A plaintext DEK leaked

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
   [record cache](../keyring/record-cache.md#how-late-a-change-is-seen), and its DEK is evicted from
   the DEK cache. With the default `Block` policy values under the version stop decrypting
   through `decrypt`. Set `Allow` for the time of the sweep if availability matters more, and be
   aware the leaked DEK can forge values under its id meanwhile;
3. sweep the records in the compromised version's range, see
   [Records under a version](./sweeps.md#records-under-a-version), reading them with `decrypt_with_trust`,
   and decide per record on the values read through the compromised version, see
   [The trust of re-sealed values](./sweeps.md#the-trust-of-re-sealed-values). Run the range query again once
   every process has had time to refresh its record, for the writes of processes that had not seen
   the flag yet;
4. export the BigQuery keysets again: a `Readable` keyset leaves the compromised version out.
   Delete the `Single` keyset of the compromised version once the sweep is done;
5. `retire` the version once the sweep is done and its range query returns nothing.

Rotation protects nothing already copied: backups, point-in-time recovery and data exports still
hold values the leaked DEK opens. Treat them as exposed and revoke the secrets inside them.

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

## The keyring record was deleted or corrupted

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

## Crypto-shredding

To make a scope's values unrecoverable:

- with a KEK per scope: destroy the KEK's versions in the KMS. Every encrypted DEK of the scope is
  then unrecoverable, backups of the record and keysets exported from it included, since the KEK
  encrypts both;
- with a shared KEK: `dangerously_destroy_all_versions`, which destroys every version of the
  keyring in one write, so that it encrypts and decrypts nothing from then on. Two copies outside
  the record still hold its keys, and the KMS opens both as long as the KEK version that encrypted
  them exists: every backup of the record, and every BigQuery and Tink keyset exported from the
  keyring, see [Keyring limits](../security.md#keyring-limits). So then either delete the record,
  every backup of it and every copy of those keysets, or destroy that KEK version: on GCP, Vault
  Transit and the local KMS, rotate the KEK, re-encrypt every other keyring under it as in
  [Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
  then destroy the previous KEK version. On AWS rotated key material is never destroyed, so only
  the deletion of the KMS key itself shreds. Azure Key Vault deletes a key with all its versions
  and never one version alone, so there too only the deletion of the key shreds. A vault with soft
  delete keeps a deleted key recoverable until it is purged, and with purge protection on, no purge
  is possible until the vault's retention period of 7 to 90 days has passed, see
  [Azure Key Vault soft-delete](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview).

A deployment that needs shredding guarantees uses a KEK per scope.

## A KMS outage

DEKs in the cache serve reads and writes until their TTL. A longer DEK cache TTL buys time at the
cost of a longer life of plaintext keys in memory. No decryption, encryption or rotation succeeds
until the KMS returns, and errors carry the provider's message. `mark_compromised` still lands the
flag.
