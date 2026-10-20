# Keyring and field encryption

The `kms-aead-keyring` crate encrypts fields of application records under a keyring: the record
of one scope's key versions, such as a tenant's, kept in a keyring store. Each key version is a
data encryption key (DEK) encrypted by a KEK in the KMS, with a lifecycle state.

Compared to an envelope, a keyring value carries a 4-byte key id instead of its encrypted DEK:

- no KMS encryption on write, and one KMS decryption per key version per DEK cache TTL, on write
  and read;
- 33 bytes of overhead per value, 21 for deterministic values, see
  [Formats of `Encrypted`](./formats.md#formats-of-encrypted);
- central staged rotation, retirement, destruction and a compromised flag, for every process
  that uses the keyring;
- deterministic fields that a data store finds by equality, across rotations;
- beacons, blind indexes that a data store matches by equality beside randomised fields;
- values in Tink's wire format, which Tink and BigQuery read too.

The price is one more piece of infrastructure, the keyring store, which holds one small JSON
document per keyring. See [Choosing a mode](./intro.md#choosing-a-mode) for the comparison with
the envelope modes of kms-aead.

## Applications and administration

See [Applications and administration](./keyring/deployment.md).

## The registry and its handles

A first keyring, on the memory store with a local KEK, is in
[With a keyring](./getting-started.md#with-a-keyring).

`KeyringRegistry::create` creates the record, with one active version of each purpose its
`KeyringAlgorithms` name, and fails with `RecordExists` when there is one already.
`open_or_create` creates it on the first start and opens it on every later one, and `admin` only
opens it. The three return a `KeyringAdmin`. `KeyringRegistry::open` returns a `Keyring`, and
fails with `RecordMissing` when there is no record; it is the application's call:

```rust,no_run
use firestore::FirestoreDb;
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::{Keyring, KeyringId, KeyringRegistry, KeyringRegistryOptions};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let key_ref = GcpKmsKeyRef::new(
#     "my-project".to_string(),
#     "europe-north1".to_string(),
#     "my-key-ring".to_string(),
#     "my-key".to_string(),
# );
let registry = KeyringRegistry::<FirestoreKeyringStore, Ring>::new(
    FirestoreKeyringStore::new(FirestoreDb::new("my-project").await?),
    KeyringRegistryOptions::new(),
)?;
let keyring: Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring> = registry
    .open(GcpKmsProvider::new(&key_ref).await?, KeyringId::from_static("tenant-42"))
    .await?;
registry.shutdown().await?;
# Ok(())
# }
```

The registry takes the store and the backend as the type parameters of `KeyringRegistry<S, B>`,
and each call takes the provider, so that the handles are `Keyring<S, P, B>` and
`KeyringAdmin<S, P, B>`.

A `Keyring` and a `KeyringAdmin` of one keyring in one registry share its cached record and its
watch, so a write through the `KeyringAdmin` is seen by every `Keyring` at once.
`KeyringAdmin::keyring()` returns the `Keyring` it holds, for `id`, `record`, `reload`, encryption
and sweeps inside an administrative job. The example in
[With a keyring](./getting-started.md#with-a-keyring) takes its `Keyring` there too, since the
ephemeral local KEK has no second copy to `open` the keyring with: `LocalKmsProvider` is not
`Clone`.

`Keyring::sealer` takes the cached record, and the `Sealer` seals under that record's active
versions; `decrypt` opens under the version the value names. A write takes one sealer and seals
every encrypted field of the record through it, so that the seal marker it stores beside them
names the versions they are under, see [The seal marker](./operations/sweeps.md#the-seal-marker).
Neither calls the store while the cached record is fresh, nor the KMS while the version's DEK is
in the DEK cache, see [Record cache](./keyring/record-cache.md).

A keyring stays open until the registry shuts down. Where the store has push, the registry follows
the change signals of each open keyring with a task on the current tokio runtime.
`registry.shutdown()` stops those tasks and the store's listener and waits for them:

- a revalidation read in flight finishes and is taken; waits, retry delays and connection attempts
  stop at once;
- the open keyrings' keys are evicted from the DEK cache, and no other key is;
- the handles keep serving from their cached records, which their TTL revalidates without push,
  and later opens work too, with no watch.

Await it before the last clone of the registry is dropped: a registry dropped while its tasks run
aborts them and logs a `WARN`. `shutdown_with_timeout(timeout)` aborts what still runs after
`timeout`, with a `WARN` that counts the aborted tasks, and an abort leaves no half-written state.
Both return `Ok` whatever the tasks did.

The bytes of values, key ids and records are in [Formats](./formats.md).
