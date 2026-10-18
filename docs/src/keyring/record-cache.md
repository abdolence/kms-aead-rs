# Record cache

Each `Keyring` keeps its record in the process, and the unwrapped DEKs of its versions in
kms-aead's [DEK cache](../dek-caching.md). `encrypt` and `decrypt` read both, so the hot path
calls neither the store nor the KMS.

## Options

`KeyringOptions`:

| Option | Default | What it does |
|---|---|---|
| `record_ttl` | 5 minutes | how long the cached record serves without a store call |
| `reload_min_interval` | 5 seconds | the least time between two store reads that an unknown key id or a change signal causes |
| `watch` | `true` | whether to follow the store's change signals, where it has them |
| `cas_retries` | 5 | the conflicts an administrative write retries before `RecordConflict` |
| `compromised_reads` | `Block` | what `decrypt` does with a value under a compromised version, see [Lifecycle](./lifecycle.md#reading-a-compromised-version) |
| `bind_keys` | `true` | whether wrapped DEKs are bound to their key id at the KMS, see [Wrap-time key binding](./key-binding.md) |
| `dek_cache` | a new cache | the cache of unwrapped DEKs; the default has a TTL of 15 minutes and 1024 keys |

```rust
use std::time::Duration;

use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead_keyring::KeyringOptions;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let options = KeyringOptions::new()
    .with_record_ttl(Duration::from_secs(60))
    .with_dek_cache(DekCache::new(
        DekCacheOptions::new().with_ttl(Duration::from_secs(5 * 60)),
    )?);
# let _ = options;
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
- **Own writes**: an administrative call takes the record it wrote, so the process that rotates
  seals under the new version at once.

`Keyring::reload` reads the record now, past the TTL and the rate limit, for operators and tests.

## How late a change is seen

A change written by another process, such as a rotation or a compromised flag, reaches a running
process:

- with push: within `reload_min_interval` of the signal, about 5 seconds by default;
- without push, on Cloud Storage, with `watch` off, or while the listener is disconnected: once the
  cached record is older than `record_ttl`, at most 5 minutes by default.

So `record_ttl` is the bound to set for how long a compromised version may keep being read
somewhere in the fleet. Writers on the old record keep sealing under the previous version
until their record refreshes, and those values decrypt, since the previous version is
`DecryptOnly`.

## When the store fails or misbehaves

- A failed revalidation keeps the cached record in use, logs a `WARN`, and is retried after
  `reload_min_interval`;
- a record that went missing from the store keeps the cached one in use, with a `WARN`. New
  processes fail at `open` with `RecordMissing`;
- a refreshed record is taken only if it moves every version forward from the cached one: no
  version missing, no changed algorithm or creation time, no compromised flag cleared, and no state
  moved back against the lifecycle. Otherwise the process keeps its record and logs an `ERROR`
  naming the first rule broken. `reload` and an administrative write return
  `RecordRegressed` in that case.

The last rule is the detection of a rewritten or restored record in a running process. A process
that starts after such a write has no record to compare with and takes it.

## DEK eviction

Taking a refreshed record evicts from the DEK cache every key it takes out of use: versions
retired, destroyed or newly compromised, and the old bytes of a rewrapped one.
`mark_compromised` evicts the key from its own process before it returns.

The DEK cache drops expired keys only when it is called. A process that can sit idle while it holds
keys calls `keyring.dek_cache().purge_expired()` on a timer of its own, so the cache's TTL bounds
how long a key stays in memory, see [Key lifetime](../dek-caching.md#key-lifetime).
