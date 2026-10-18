# Security considerations

## Threat model

Envelope encryption protects stored values from whoever can read the store but cannot use the
KEK: a database dump, a backup, a replica, a data export or an operator with read access to the
tables. Opening a value needs a KMS unwrap, and the KMS checks the caller's permission and, for the
cloud KMSs, writes an audit log entry.

It does not protect values from:

- a process, or whoever controls it, that may unwrap with the KEK: it can read every value it can
  fetch;
- whoever can read the memory of a process while it holds plaintext DEKs, in the
  [DEK cache](./dek-caching.md#key-lifetime) or as a store-less writer's DEK;
- a reader of the store learning which values are equal, for values sealed with
  [deterministic encryption](./deterministic.md#what-it-leaks).

The AAD protects a value from being moved: a value copied into another row or column, with an AAD
that names its place, fails to open there. The AAD itself is not encrypted, and neither is the
header of envelope layout v1, which holds the key version and the wrapped DEK's length. The header
is not authenticated, so a field in it is only ever an address or an audit value, never a choice of
algorithm or mode.

A wrapped DEK carries no context that the KMS authenticates. Whoever can write where wrapped
DEKs are stored, such as a database table or a keyring store, can copy a wrapped DEK to another
record or relabel it, and the KMS unwraps it for any principal allowed to decrypt with that KEK.
The controls for this are in the deployment:

- write access to the stored keys is kept apart from the right to decrypt with the KEK;
- each isolation boundary, such as a tenant or an environment, has a KEK of its own, so a DEK
  copied across it fails to unwrap;
- the KMS audit log of decrypt calls, turned on where the KMS leaves it off by default, shows
  which principal unwrapped which key.

The local KMS has no IAM, no audit log and no HSM, see its [limits](./providers/local.md#limits).

## Nonces

Every AEAD algorithm takes a random 96-bit nonce from the backend's CSPRNG for each value, and
writes it in front of the cipher text. NIST SP 800-38D allows 2^32 encryptions under one key with
random 96-bit nonces, and the library applies the same bound to every algorithm:

- the per-call envelope seals one value per DEK, so the bound does not apply to it;
- a store-less envelope renews its DEK at `max_uses`, 2^24 by default and at most 2^32;
- with `encrypt_value_with_dek` and `AeadCipher`, the application counts the values it seals
  under one key, and moves to a new key before 2^32;
- the local KMS seals each DEK it wraps with AES-256-GCM, so a KEK version is good for about 2^32
  wraps. Add a new version before that.

AES-256-GCM-SIV (RFC 8452) resists nonce misuse: a repeated nonce reveals only whether the two
values sealed with it are equal, and does not break integrity.

Deterministic encryption with AES-SIV takes no random nonce.

## Key lifetime and zeroization

`DataEncryptionKey`, `LocalKek` and the Vault token are zeroized on drop and shown as `***` by
`Debug`. The DEK cache zeroizes a key when its entry leaves the cache and no `with_key` closure
holds it.

Some copies are out of the library's reach:

- the KMS SDKs and HTTP clients the providers use keep copies of each plaintext DEK in request and
  response buffers, which kms-aead cannot zeroize. The same holds for the Vault token in the HTTP
  stack;
- ring does not zeroize its expanded key schedules, so they stay in freed memory after each call;
- aws-lc-rs clears its key context through AWS-LC's allocator, as long as the application leaves
  that allocator in place. The record keys AES-256-GCM-SIV derives for each call stay on the stack;
- the RustCrypto backend zeroizes its key objects and the per-call Poly1305 and POLYVAL keys;
- an expired DEK stays in the cache's memory until the next call on the cache or
  `purge_expired`;
- a plaintext value returned to the application is a `SecretValue`, zeroized on drop, and what the
  application does with it afterwards is its own.

## What rotation does not protect

Rotating the KEK in the KMS makes new DEKs wrap under the new key version. It does not:

- re-wrap the DEKs already stored: they still unwrap with the old key version, which the KMS must
  keep enabled for as long as those values are read;
- re-encrypt any value: a DEK that leaked keeps opening every value sealed under it, whatever the
  KEK version that wraps it. To retire a leaked DEK, decrypt and encrypt the values again under new
  DEKs;
- reach DEKs already in a DEK cache: they keep serving until their entries expire, or until
  `invalidate` or `clear`. The same holds for disabling a KMS key or revoking an IAM grant;
- renew a store-less writer's DEK: it is renewed by its policy, or once it leaves the cache.

With the local KMS, rotation is a new KEK version. The old version has to stay in the provider for
as long as DEKs wrapped under it are read, and crypto-shredding means destroying every copy of it,
backups included.

## OSS

Open source code is created through voluntary collaboration of software developers. The original
authors license the code so that anyone can see it, modify it, and distribute new versions of it.
You should manage all OSS using the same procedures and tools that you use for commercial
products. As always, train your employees on cyber security best practices that can help them
securely use and manage software products. You should not solely rely on individuals, especially
on the projects like this reading sensitive information.

## Versioning

Please don't use broad version dependency management not to include a new version of dependency
automatically without auditing the changes.

## Reporting a vulnerability

See [SECURITY.md](https://github.com/abdolence/kms-aead-rs/blob/master/SECURITY.md).
