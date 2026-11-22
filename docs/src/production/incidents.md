# Respond to a leaked key

A key leaked, or may have: a service account key in a repository, a DEK in a log, a backup in the
wrong bucket. The [emergency runbook](../operations/runbook.md) has the steps for a keyring. This
page is the entry point, with the cases kms-aead alone adds. To make a tenant's values unreadable
on purpose, see [Erase one customer's data for good](../use-cases/erase-a-tenant.md).

## With a keyring

| What happened | Runbook |
|---|---|
| A plaintext DEK leaked, or may have | [A plaintext DEK leaked](../operations/runbook.md#a-plaintext-dek-leaked) |
| A principal got KMS rights it should not have | [A KMS IAM over-grant](../operations/runbook.md#a-kms-iam-over-grant) |
| An encrypted DEK or a keyring record leaked | [An encrypted DEK or the keyring record leaked](../operations/runbook.md#an-encrypted-dek-or-the-keyring-record-leaked) |
| A refused record moving backwards, logged at `ERROR`, or a version the job did not create | [A version the administrative job did not create](../operations/runbook.md#a-version-the-administrative-job-did-not-create) |
| A keyring record was deleted or corrupted | [The keyring record was deleted or corrupted](../operations/runbook.md#the-keyring-record-was-deleted-or-corrupted) |
| The KMS is down | [A KMS outage](../operations/runbook.md#a-kms-outage) |
| A tenant's values must become unreadable | [Erase one customer's data for good](../use-cases/erase-a-tenant.md), with [`dangerously_shred()`](../use-cases/erase-a-tenant.md#shredding-a-tenant-with-dangerously_shred) under a shared KEK |

## A leaked DEK of envelope values

A DEK that leaked decrypts every value encrypted under it, and a KEK rotation does not change that.
With a per-call envelope it is the DEK of one value, and with store-less DEK reuse of every value
the writer encrypted until it renewed the DEK. The values are re-encrypted under new DEKs, as in
[With kms-aead alone](./rotation.md#deks), and the DEK is invalidated in every DEK cache that holds
it.

A DEK the application keeps itself, such as the key of [One fixed key](../envelope-encryption.md#one-fixed-key)
or a beacon key, is replaced by a key under a new key id, and the values or beacons under the old
one are encrypted or computed again.

Backups, point-in-time recovery and data exports still hold the values the leaked DEK decrypts:
treat them as exposed.
