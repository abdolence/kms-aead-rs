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
| A tenant's values must become unreadable | [Crypto-shredding](#crypto-shredding) |

## A leaked DEK of envelope values

A DEK that leaked opens every value sealed under it, and a KEK rotation does not change that. With
a per-call envelope it is the DEK of one value, and with store-less DEK reuse of every value the
writer sealed until it renewed the DEK. The values are re-sealed under new DEKs, as in
[With kms-aead alone](./rotation.md#deks), and the DEK is invalidated in every DEK cache that holds
it.

A DEK the application keeps itself, such as the key of [One fixed key](../envelope-encryption.md#one-fixed-key)
or a beacon key, is replaced by a key under a new key id, and the values or beacons under the old
one are sealed or computed again.

Backups, point-in-time recovery and data exports still hold the values the leaked DEK opens:
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
  A vault with soft delete keeps a deleted key recoverable until it is purged, and with purge
  protection on, no purge is possible until the vault's retention period of 7 to 90 days has
  passed, see [Azure Key Vault soft-delete](https://learn.microsoft.com/en-us/azure/key-vault/general/soft-delete-overview);
- **Vault Transit**: `min_available_version` and a trim of the key delete the versions below it, see
  [Vault Transit](../providers/hc-vault-transit.md#key-versions-and-rotation), and a deletion of
  the key, once its configuration sets `deletion_allowed`, deletes every version;
- **local KMS**: destroy every copy of the KEK version, backups included, see
  [Local KMS](../providers/local.md#key-versions-and-rotation).

Since a deletion of the key takes every version, shredding one scope under AWS KMS or Azure Key
Vault needs a key per scope. With a keyring, a shared KEK has a second route,
`dangerously_destroy_all_versions`, which leaves the keys in every backup of the record and in every
keyset exported from it, see [Crypto-shredding](../operations/runbook.md#crypto-shredding). A deployment that needs shredding
guarantees uses a KEK per scope, see [A keyring per tenant](./keyring-per-tenant.md).
