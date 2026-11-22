# Cut KMS calls with a DEK cache and DEK reuse

A service decrypts the same stored values on every request: a profile page that shows an email, a
payment screen that shows a card's last digits. With a per-call envelope each decryption is one KMS
call, so latency, quota and the KMS bill grow with the traffic. An event or audit stream has the
opposite problem: it writes thousands of values a second, and one KMS call to encrypt a DEK for each
value is far too many. A `DekCache` makes reads call the KMS once per DEK and TTL, and a
`DekReusePolicy` makes writes call it once per renewed DEK. Both keep the stored format of a
per-call envelope: every value still carries its encrypted DEK.

## Reads: a DEK cache

A per-call envelope has no cache unless its options give it one. Pass a `DekCache` to
`KmsAeadEnvelopeOptions`, and every `decrypt` of a value whose DEK the cache holds skips the KMS:

```rust
use kms_aead::backends::Ring;
use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
use secret_vault_value::SecretValue;
use std::num::NonZeroUsize;
use std::time::Duration;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let cache = DekCache::new(
    DekCacheOptions::new()
        .with_ttl(Duration::from_secs(5 * 60))
        .with_max_entries(NonZeroUsize::new(10_000).expect("not zero")),
)?;

let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_dek_cache(cache),
)?;

let stored: Encrypted<SecretValue, Envelope> = envelope
    .encrypt(b"users/1/email", &SecretValue::from("ada@example.com"))
    .await?;

// The first read decrypts the DEK with the KMS, the next ones within the TTL do not
let first: SecretValue = envelope.decrypt(b"users/1/email", &stored).await?;
let second: SecretValue = envelope.decrypt(b"users/1/email", &stored).await?;
assert_eq!(first, second);
# Ok(())
# }
```

`Clone` shares the cache, so one cache may serve every envelope of the process, over several KEKs
as well.

### Choosing the TTL and the size

- A cache serves an entry for its TTL after it was inserted. A longer TTL saves more KMS calls,
  keeps DEKs in memory for longer and delays the effect of a revoked KMS permission;
- past `max_entries` the cache evicts the oldest entry. Set it above the number of distinct DEKs
  read per TTL, otherwise reads evict each other's keys and the KMS is called again;
- with per-call envelopes every value has its own DEK, so the cache helps only values read more
  than once within the TTL. A value read once is one KMS call with or without it.

The defaults of the TTL and of `max_entries` are in [DEK cache](../dek-caching.md#dek-cache).

As an example, a service reads 100 values a second, drawn from 2,000 distinct values, each with its
own DEK. Without a cache that is 100 × 3,600 = 360,000 KMS decryptions an hour. With a cache of
`max_entries` 4,096 and the default TTL of 15 minutes, each DEK is decrypted at most once per TTL,
so at most 2,000 × 4 = 8,000 an hour, and concurrent misses of one DEK share a single call. The
figures follow from the number of distinct DEKs and the TTL, and fewer distinct values need fewer
calls.

## Writes: DEK reuse

A `DekReusePolicy` makes the envelope encrypt many values under one DEK and renew it by age, by
count of values or by bytes, whichever comes first. A write calls the KMS only to renew the DEK:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{DekReusePolicy, Encrypted, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
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
            // The envelope's DEK cache drops the DEK after its TTL, 15 minutes by default, and the
            // next write renews it, so `max_age` decides only when the cache's TTL is longer
            .with_max_age(Duration::from_secs(60 * 60))
            .with_max_uses(NonZeroU64::new(1_000_000).expect("not zero")),
    ),
)?;

// One KMS encryption for both values
let first: Encrypted<SecretValue, Envelope> =
    envelope.encrypt(b"events/1", &SecretValue::from("first")).await?;
let second: Encrypted<SecretValue, Envelope> =
    envelope.encrypt(b"events/2", &SecretValue::from("second")).await?;

// Read with any envelope over the same KEK and algorithm
let decrypted_first: SecretValue = envelope.decrypt(b"events/1", &first).await?;
let decrypted_second: SecretValue = envelope.decrypt(b"events/2", &second).await?;
assert_eq!(decrypted_first, SecretValue::from("first"));
assert_eq!(decrypted_second, SecretValue::from("second"));
# Ok(())
# }
```

Each value carries its encrypted DEK, so nothing is stored apart from the values, and values under
earlier DEKs stay readable. Readers need no policy: any envelope over the same KEK decrypts them,
and a reader with a `DekCache` calls the KMS once per DEK and TTL, as in the previous section.

As an example, a writer encrypts 1,000 values a second. With one DEK per value that is 3,600,000 KMS
encryptions an hour. A store-less envelope keeps its DEK in a cache and renews the DEK when the
cache drops it. With the default TTL of 15 minutes this writer renews it every 15 minutes, before
`max_uses` of 1,000,000 values or `max_age` of an hour is reached: 4 KMS encryptions an hour for
the process. To renew by `max_age` instead, give the envelope a `DekCache` whose TTL is longer than
it.

## With a keyring

A keyring needs no policy: its values carry a 4-byte key id instead of an encrypted DEK, so a write
calls no KMS, and a read decrypts each key version's DEK once per DEK cache TTL.
`KeyringRegistryOptions::with_dek_cache` sets the cache and its TTL, see
[Record cache](../keyring/record-cache.md).

## What to watch for

- A disabled KMS key or a revoked IAM grant reaches cached keys only when their entries expire,
  see [Invalidation](../dek-caching.md#invalidation) for dropping them at once;
- the cache runs no thread of its own, so a process that can sit idle while it holds keys purges
  expired ones on a timer, see [Key lifetime](../dek-caching.md#key-lifetime);
- a store-less writer that shares a cache with readers needs `max_entries` above the distinct DEKs
  read per TTL, or a cache of its own, see
  [The DEK lives in the cache](../dek-caching.md#the-dek-lives-in-the-cache);
- the bytes a DEK encrypts are bounded, see [Volume limit](../dek-caching.md#volume-limit).

The full behaviour of the cache and the policy is in [DEK caching and reuse](../dek-caching.md).
