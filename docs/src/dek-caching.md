# DEK caching and reuse

Without a cache, every read of a value decrypts its DEK with one KMS call, and every
`encrypt` encrypts a new DEK with another. The library has two ways to make fewer KMS calls:

- `DekCache`, a cache of decrypted DEKs, which serves repeated reads of values under the same
  DEK without the KMS;
- store-less DEK reuse, with a `DekReusePolicy`, where one DEK seals many values, so a write
  calls the KMS only when the DEK is renewed.

## DEK cache

`kms_aead::cache::DekCache` holds plaintext DEKs a provider decrypted, keyed by the provider's
KEK and the encrypted DEK's bytes. A per-call envelope has no cache unless the options give it one:

```rust
use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadEnvelope, KmsAeadEnvelopeOptions, Ring};
use std::num::NonZeroUsize;
use std::time::Duration;

# fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let cache = DekCache::new(
    DekCacheOptions::new()
        .with_ttl(Duration::from_secs(5 * 60))
        .with_max_entries(NonZeroUsize::new(10_000).expect("not zero")),
)?;

let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_dek_cache(cache.clone()),
)?;
# let _ = envelope;
# Ok(())
# }
```

`decrypt`, the `*_with_encrypted_dek` calls and a store-less `encrypt` decrypt through the
envelope's cache. `Clone` shares the same cache, so one cache may serve several envelopes and
several KEKs: an entry serves only a lookup that names the same KEK, and a key decrypted under
one KEK never reaches a caller with the provider of another.

The cache:

- serves an entry for its TTL after it was inserted, however often it is used, 15 minutes by
  default;
- holds at most `max_entries` entries, 1024 by default, and evicts the oldest entry past it;
- makes one provider call for concurrent misses of the same key, and every caller receives its
  result, the key or the error;
- keeps no entry for a failed decryption, so during a KMS outage every call fails as fast as the KMS
  does;
- zeroises a key when its entry leaves the cache: once it is evicted, invalidated, cleared, or
  purged after it expired.

`DekCache::disabled()` holds nothing, and every lookup calls the provider. It is what a per-call
envelope has by default.

### Sizing

Size `max_entries` above the number of distinct DEKs read per TTL. With per-call envelopes every
value has its own DEK, so a cache helps only values read more than once within the TTL. With
store-less writers the number of DEKs is the number of writers times the renewals per TTL, which
is small.

A longer TTL saves more KMS calls, and keeps DEKs in memory for longer, see
[Key lifetime](#key-lifetime).

### Invalidation

A disabled KMS key or a revoked IAM grant reaches the cached keys only when their entries expire.
To drop one at once, invalidate it with the envelope's own KEK:

```rust
# use kms_aead::cache::{DekCache, DekCacheOptions};
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{KmsAeadEnvelope, KmsAeadEnvelopeOptions, Ring};
use kms_aead::KmsAeadEncryptionProvider;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(provider,
#     KmsAeadEnvelopeOptions::new().with_dek_cache(DekCache::new(DekCacheOptions::new())?))?;
let (_dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;

// One encrypted DEK
envelope
    .dek_cache()
    .invalidate(envelope.provider().kek(), &encrypted_dek);

// Every DEK
envelope.dek_cache().clear();
# Ok(())
# }
```

Pass `envelope.provider().kek()` to `invalidate`, with the `KmsAeadEncryptionProvider` trait in
scope: a `KekRef` built by hand that differs from it matches no entry.

### Key lifetime

The cache runs no thread and no task of its own. Expired entries are dropped at the next call on
the cache, at `purge_expired`, or when the last clone of the cache is dropped. With no calls, the
bytes of an expired key stay in memory. An application whose process can sit idle while the cache
holds keys, and that needs the TTL to bound their lifetime in memory, calls `purge_expired` on a
timer of its own:

```rust,no_run
# use kms_aead::cache::{DekCache, DekCacheOptions};
# fn example() -> kms_aead::KmsAeadResult<()> {
let cache = DekCache::new(DekCacheOptions::new())?;

let purged = cache.clone();
tokio::spawn(async move {
    let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        interval.tick().await;
        purged.purge_expired();
    }
});
# Ok(())
# }
```

A key reaches the caller only inside the closure of `DekCache::with_dek`, and stays intact until
the closure returns, whatever leaves the cache meanwhile. The closure must not keep a copy of the
key: a copy taken out of it outlives the cache's control of its lifetime.

## Store-less DEK reuse

A `KmsAeadEnvelope` with a `DekReusePolicy` encrypts many values under one DEK and renews it at
the first encryption past `max_age` or past `max_uses`, whichever comes first. A renewal makes one
KMS encrypt call. Each value still carries its encrypted DEK in Tink's KMS envelope, so nothing is
stored apart from the values, and values under earlier DEKs stay readable.

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{DekReusePolicy, KmsAeadEnvelope, KmsAeadEnvelopeOptions, Ring};
use secret_vault_value::SecretValue;
use std::num::NonZeroU64;
use std::time::Duration;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_dek_reuse(
        DekReusePolicy::new()
            .with_max_age(Duration::from_secs(60 * 60))
            .with_max_uses(NonZeroU64::new(1_000_000).expect("not zero")),
    ),
)?;

// One KMS encryption for both values
let first = envelope.encrypt(b"events/1", &SecretValue::from("first")).await?;
let second = envelope.encrypt(b"events/2", &SecretValue::from("second")).await?;

// Read with any envelope over the same KEK and algorithm
let decrypted: SecretValue = envelope.decrypt(b"events/2", &second).await?;
assert_eq!(decrypted, SecretValue::from("second"));
# let _ = first;
# Ok(())
# }
```

The defaults are a `max_age` of 24 hours and a `max_uses` of 2^24. `max_age` must be longer than
zero and `max_uses` at most 2^32, the bound for random 96-bit nonces under one key, otherwise the
envelope fails to build with `INVALID_DEK_REUSE_POLICY`.

### The DEK lives in the cache

The envelope keeps only the encrypted DEK. Its plaintext lives in the envelope's `DekCache`, which a
store-less envelope always has: `DekCache::new(DekCacheOptions::new())` unless the options give it
another, and `INVALID_DEK_REUSE_POLICY` beside `DekCache::disabled()`.

The first encryption after the DEK has left the cache renews it. So the DEK is renewed:

- at the cache's TTL, whatever `max_age`;
- when the cache evicts it for capacity;
- after `invalidate` with `envelope.provider().kek()`, or after `clear`.

In a cache shared with readers, size `max_entries` above the number of distinct DEKs read per
TTL, or give the writer a cache of its own, otherwise reads evict the writer's DEK and it renews
more often than the policy says.

A writer that falls quiet leaves its DEK in memory until the cache's next call or
`purge_expired`, see [Key lifetime](#key-lifetime). The values sealed while the cache holds the
DEK are readable by whoever reads the process's memory in that window.
