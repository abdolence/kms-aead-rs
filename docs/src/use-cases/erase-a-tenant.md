# Erase one customer's data for good

A customer closes its account and asks for its data to be erased, or a retention rule requires it.
Deleting its rows leaves the values in backups, exports and every other copy of the store, and
those cannot all be found and rewritten. Destroying the keys that decrypt the values makes every
copy unreadable at once.

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
guarantees uses a KEK per scope, see [A keyring per tenant](../use-cases/keyring-per-tenant.md).

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
