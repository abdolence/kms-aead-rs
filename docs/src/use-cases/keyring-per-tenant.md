# A keyring per tenant

A multi-tenant application gives each tenant a keyring of its own: its own key versions, rotated,
flagged and destroyed apart from the others, in one keyring store such as Firestore or
PostgreSQL. The keyring id names the tenant, see
[The record](../keyring/lifecycle.md#the-record) for the ids it takes.

## One KEK per tenant or one shared KEK

| | A KEK per tenant | One shared KEK |
|---|---|---|
| A DEK copied into another tenant's record | fails at the KMS, which decrypts with the tenant's own KEK | decrypts, since the KMS decrypts it for any principal allowed to decrypt with the KEK |
| KMS rights | per tenant, so a principal can be limited to some tenants | one grant covers every tenant |
| Crypto-shredding a tenant | destroying its KEK, backups of the record and exported keysets included | `dangerously_shred()`, and then deleting the record's backups, the store's other copies and the exported keysets, or a KEK rotation for every other keyring |
| KMS keys to manage | one per tenant | one |

The first row is the store-writer threat of [Keyring deployment](../security.md#keyring-deployment),
and the third the two routes of [Crypto-shredding](./incidents.md#crypto-shredding). A deployment
that needs either guarantee uses a KEK per tenant.

## Creating the keyrings

An application opens only keyrings that exist, so each tenant's keyring is created first:

- by the administrative job, as part of onboarding a tenant, with `create` or `open_or_create`;
- or by the application on the tenant's first request, with `open_or_create`. Such an application
  builds with the `admin` feature and runs with the administrative rights, so it is trusted as the
  administration is, see [Applications and administration](../keyring/deployment.md) and
  [Keyring limits](../security.md#keyring-limits).

## The path through the API

1. One `KeyringRegistry` per process and store, with the store and the backend, see
   [The registry and its handles](../keyring.md#the-registry-and-its-handles);
2. `registry.open(provider, keyring_id)` for each tenant the process serves. A second open of an
   open keyring reads nothing from the store and shares the first one's record and watch. The call
   takes the provider by value: `GcpKmsProvider` and `HcVaultTransitProvider` are `Clone`, and the
   other providers are built once per keyring;
3. a `FieldSpec` constant per encrypted field, the same for every tenant, since each keyring
   has DEKs of its own, see [Encrypted fields and AAD](../keyring/fields.md);
4. on every write, `keyring.encryptor()` and its `encrypt`, and the encryption marker it gives,
   see [The encryption marker](../operations/sweeps.md#the-encryption-marker); on every read,
   `keyring.decrypt`;
5. `registry.shutdown(None)` before the process exits, see
   [The registry and its handles](../keyring.md#the-registry-and-its-handles).

Rotations and sweeps run per keyring: the administrative job loops over the tenants, see
[Rotate keys and re-encrypt values](./rotation.md).

## What many keyrings cost

A keyring stays open until the registry shuts down, so a process holds every keyring it opened:

- **store reads**: one at the first `open`, and one revalidation per keyring per `record_ttl`, or
  per change signal, see [How the record is refreshed](../keyring/record-cache.md#how-the-record-is-refreshed);
- **connections**: on Firestore, one listen stream per store, with a target on each keyring's
  document; on PostgreSQL, at most two connections per store, however many keyrings, see
  [Keyring stores](../keyring/stores.md);
- **the DEK cache**: one per registry, shared by its keyrings, with an entry per version in use per
  keyring. It holds `DekCacheOptions::DEFAULT_MAX_ENTRIES`, 1024, by default, and an entry evicted
  for capacity is decrypted through the KMS again on its next use, so size it above the tenants a
  process serves times the versions each uses, see [Sizing](../dek-caching.md#sizing);
- **KMS calls**: one decryption per version per DEK cache TTL in every process, and two per version
  in each `reencrypt_deks`. A KEK rotation re-encrypts every keyring under the KEK, see
  [The KMS decrypt burst](./rotation.md#the-kms-decrypt-burst);
- **metrics**: the plaintext size histogram has a series per keyring and version, see
  [Metrics](../observability.md#metrics) for its cardinality limit.
