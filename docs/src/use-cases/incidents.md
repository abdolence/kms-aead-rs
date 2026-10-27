# A leaked key or a shredded tenant

The [emergency runbook](../operations/runbook.md) has the steps for a keyring. This page is the
entry point, with the cases kms-aead alone adds.

## With a keyring

| What happened | Runbook |
|---|---|
| A plaintext DEK leaked, or may have | [A plaintext DEK leaked](../operations/runbook.md#a-plaintext-dek-leaked) |
| A principal got KMS rights it should not have | [A KMS IAM over-grant](../operations/runbook.md#a-kms-iam-over-grant) |
| An encrypted DEK or a keyring record leaked | [An encrypted DEK or the keyring record leaked](../operations/runbook.md#an-encrypted-dek-or-the-keyring-record-leaked) |
| A refused record moving backwards, logged at `ERROR`, or a version the job did not create | [A version the administrative job did not create](../operations/runbook.md#a-version-the-administrative-job-did-not-create) |
| A keyring record was deleted or corrupted | [The keyring record was deleted or corrupted](../operations/runbook.md#the-keyring-record-was-deleted-or-corrupted) |
| The KMS is down | [A KMS outage](../operations/runbook.md#a-kms-outage) |
| A tenant's values must become unreadable | [Crypto-shredding](#crypto-shredding), and [`dangerously_shred()`](#shredding-a-tenant-with-dangerously_shred) under a shared KEK |

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

## Crypto-shredding

A scope's values become unreadable once nothing can decrypt their DEKs. With kms-aead alone, the
DEKs are encrypted by the KEK, so shredding is the destruction of the KEK's versions that encrypted
them, backups included. Per KMS:

- **Google Cloud KMS**: destroy the key versions. Cloud KMS schedules the destruction, 30 days
  later by default, and until then a version can be restored, see
  [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
- **AWS KMS**: delete the key. Rotated key material is never destroyed on its own, see
  [AWS KMS](../providers/aws.md#key-versions-and-rotation);
- **Azure Key Vault**: delete the key, which deletes it with all its versions: Key Vault never
  deletes one version alone, see [Azure Key Vault](../providers/azure.md#key-versions-and-rotation).
  Soft delete and purge protection delay the shredding, see
  [Crypto-shredding](../operations/runbook.md#crypto-shredding);
- **Vault Transit**: `min_available_version` and a trim of the key delete the versions below it, see
  [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation), and a deletion of
  the key, once its configuration sets `deletion_allowed`, deletes every version;
- **local KMS**: destroy every copy of the KEK version, backups included, see
  [Local KMS](../providers/local.md#key-versions-and-rotation).

Since a deletion of the key takes every version, shredding one scope under AWS KMS or Azure Key
Vault needs a key per scope. With a keyring, a shared KEK has a second route, `dangerously_shred()`:
it destroys every version of the keyring and deletes its record from the store, with the earlier
versions the store keeps. The keys stay in every copy the store keeps beyond its API, such as a
backup, and in every keyset exported from the keyring, see
[Crypto-shredding](../operations/runbook.md#crypto-shredding). A deployment that needs shredding
guarantees uses a KEK per scope, see [A keyring per tenant](./keyring-per-tenant.md).

### Shredding a tenant with `dangerously_shred()`

Under a shared KEK, `KeyringAdmin::dangerously_shred()` ends the tenant's keyring in one call: it
destroys every version and deletes the record from the store. The call can be repeated after a
failure, and returns `Ok` on a keyring that is gone already. The keyring id is free for a new
keyring afterwards.

- Every process that holds the keyring takes the deletion at its next revalidation, within seconds
  with push. Its handles fail with `NoActiveVersion` for a write and `KeyVersionDestroyed` for a
  read, and the plaintext DEK leaves its memory with that revalidation;
- a copy of the record from before the shred is refused by a process that took the deletion, with
  `RecordRegressed` and an `ERROR`, because it revives versions the process holds destroyed. A
  store writer who restores an old record gains nothing against that process;
- after a deliberate restore, such as one that undoes an accidental deletion, restart every process
  that took the deletion. A process that starts after the restore takes the record;
- `dangerously_shred()` leaves the store's backups, its history and every exported keyset where
  they are, and the KMS untouched. They still decrypt while a KEK version that encrypted their DEKs
  exists, see [What survives a shred](../operations/runbook.md#what-survives-a-shred).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/shred.rs).
