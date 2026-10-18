# Record cache

Each `Keyring` keeps its record in the process, and the decrypted DEKs of its versions in
kms-aead's [DEK cache](../dek-caching.md). `encrypt`, `decrypt` and `beacon` read both, so the hot
path calls neither the store nor the KMS.

## Options

`KeyringRegistryOptions` configures the record cache of every keyring a registry opens, and its
`keyring` field holds the `KeyringOptions` of the handles it returns. Each default is a public
constant of the type that holds the option:

| Option | Default | What it does |
|---|---|---|
| `record_ttl` | `DEFAULT_RECORD_TTL`, 5 minutes | how long the cached record serves without a store call |
| `reload_min_interval` | `DEFAULT_RELOAD_MIN_INTERVAL`, 5 seconds | the least time between two store reads that an unknown key id or a change signal causes |
| `watch` | `DEFAULT_WATCH`, `true` | whether to follow the store's change signals, where it has them |
| `dek_cache` | `None`, a new cache | the cache of decrypted DEKs; a new one has kms-aead's `DekCacheOptions::DEFAULT_TTL` and `DekCacheOptions::DEFAULT_MAX_ENTRIES` |
| `keyring.cas_retries` | `KeyringOptions::DEFAULT_CAS_RETRIES`, 5 | the conflicts a write of a `KeyringAdmin` retries before `RecordConflict` |
| `keyring.compromised_reads` | `KeyringOptions::DEFAULT_COMPROMISED_READS`, `Block` | what `decrypt` does with a value under a compromised version, see [Lifecycle](./lifecycle.md#reading-a-compromised-version) |

```rust
use std::time::Duration;

use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead_keyring::{KeyringOptions, KeyringRegistryOptions};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let options: KeyringRegistryOptions = KeyringRegistryOptions::new()
    .with_record_ttl(Duration::from_secs(60))
    .with_dek_cache(DekCache::new(
        DekCacheOptions::new().with_ttl(Duration::from_secs(5 * 60)),
    )?);
assert_eq!(options.keyring.cas_retries, KeyringOptions::DEFAULT_CAS_RETRIES);
# Ok(())
# }
```

A `DekCache` may be shared with other keyrings and envelopes.

## How the record is refreshed

- **Age**: the first call that finds the record older than `record_ttl` revalidates it with a
  conditional read, while the other calls keep using it;
- **Change signals**: on a store with push, a signal causes a revalidation, at most once per
  `reload_min_interval`. Signals inside the interval collapse into the next one;
- **Unknown key ids**: a value with a key id the record does not have causes one reload, which
  concurrent misses share, at most once per `reload_min_interval`. Values with random key ids then
  cost at most one store read per interval;
- **Own writes**: a `KeyringAdmin` call takes the record it wrote. Every `Keyring` of the same
  keyring in the registry shares that cached record, so the process that promotes a version seals
  under it at once.

`Keyring::reload` reads the record now, past the TTL and the rate limit, for operators and tests.

## How late a change is seen

A change written by another process, such as a staged version, a promotion or a compromised flag,
reaches a running process:

- with push: within `reload_min_interval` of the signal, about 5 seconds by default;
- without push, on Cloud Storage and S3, with `watch` off, or while the listener is disconnected:
  once the cached record is older than `record_ttl`, at most 5 minutes by default;
- not until the store answers again, while its revalidations fail: it keeps its cached record,
  see below.

So `record_ttl` is the bound to set for how long a compromised version may keep being read
somewhere in the fleet, and the least wait between staging a version and promoting it, see
[Staged rotation](./lifecycle.md#staged-rotation). Writers on the old record keep sealing under the
previous version until their record refreshes, and those values decrypt, since the previous version
is `DecryptOnly`.

## When the store fails or misbehaves

- A failed revalidation keeps the cached record in use, logs a `WARN`, "The keyring record could
  not be revalidated; the cached record stays in use", and is retried after `reload_min_interval`.
  A process that logs it is one that misses every change until the store answers again, so alert
  on it;
- a record that went missing from the store keeps the cached one in use, with a `WARN`. New
  processes fail at `open` with `RecordMissing`;
- a refreshed record is taken only if it moves every version forward from the cached one: no
  version missing, no changed algorithm or creation time, no compromised flag cleared, and no state
  moved back against the lifecycle, such as a version back to `Pending`. Otherwise the process
  keeps its record and logs an `ERROR` naming the first rule broken. `reload` and a write of a
  `KeyringAdmin` return `RecordRegressed` in that case.

The last rule is the detection of a rewritten or restored record in a running process. A process
that starts after such a write has no record to compare with and takes it.

## DEK eviction

Taking a refreshed record evicts from the DEK cache every key it takes out of use: versions
retired, destroyed or newly compromised, and the old bytes of a re-encrypted one.
`mark_compromised` evicts the key from its own process before it returns.

The DEK cache drops expired keys only when it is called. A process that can sit idle while it holds
keys calls `keyring.dek_cache().purge_expired()` on a timer of its own, so the cache's TTL bounds
how long a key stays in memory, see [Key lifetime](../dek-caching.md#key-lifetime).
