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
length of the wrapped DEK at the start of Tink's KMS envelope, which is not authenticated either.

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

## Keyring deployment

A [keyring](./keyring.md) record decides which versions are read and which one seals new values,
and nothing signs it: its integrity rests on the keyring store's access control. So a deployment
splits two principals:

- **Serving principal**: KMS decrypt on the KEK and read access to the keyring store. `encrypt`,
  `decrypt` and `beacon` make no KMS wrap call, so it needs nothing more;
- **Administrative principal**: KMS encrypt and decrypt on the KEK, and the only principal with
  write access to the keyring store. `create`, `rotate`, `promote`, `change_algorithm`,
  `mark_compromised`, `retire`, `reinstate`, `destroy`, `rewrap` and `export_bigquery_keyset` run
  under it, in a job, never in a request handler.

| KMS | Serving | Administration |
|---|---|---|
| GCP | `roles/cloudkms.cryptoKeyDecrypter` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| AWS | `kms:Decrypt` on the key | `kms:Encrypt` and `kms:Decrypt` on the key, plus `kms:GenerateRandom` with the KMS random generator |
| Azure Key Vault | a role with `keys/unwrap/action` on the key | a role with `keys/wrap/action` and `keys/unwrap/action` on the key |
| Vault Transit | `update` on `transit/decrypt/<key>` | `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` |

The permissions of each store are in [Keyring stores](./keyring/stores.md).

A writer of the keyring store can copy or relabel a wrapped DEK, between versions of one keyring
or between keyrings under the same KEK: the KMS unwraps a wrapped DEK for any principal allowed to
decrypt with the KEK, whatever version or keyring it is filed under. Such a writer can bring a
compromised or destroyed version's DEK back into use under a new key id, or point one tenant's
version at another tenant's DEK. A writer without KMS rights cannot add a DEK of its own, since
every unwrap names the configured KEK and the KMS refuses a DEK wrapped under another key. The
controls for this are the deployment's, as in the [threat model](#threat-model):

- write access to the keyring store for the administrative principal only, and read-only access
  for the serving principals;
- one KEK per isolation boundary, such as a tenant or an environment, so a DEK copied across it
  fails to unwrap;
- backups of the record, or versioning in the store, to compare with and restore from;
- the KMS audit log of encrypt calls, which shows whether the administrative job wrapped a
  version's DEK.

A running process also refuses every record that moves a version backwards, with an `ERROR`, see
[Record cache](./keyring/record-cache.md#when-the-store-fails-or-misbehaves). That catches a
rewritten state, such as a cleared compromised flag, and not a copied DEK filed under a new
version.

## Keyring limits

- **The administrative principal is trusted.** KMS encrypt plus store write re-activates any
  version. The KMS audit log is the detection;
- **a new process has no baseline.** A store writer can clear a compromised flag, re-activate a
  version or restore a destroyed one for the processes that start after the write. Running
  processes refuse such a record and log an `ERROR`; new ones take it. The record is not signed in
  this release;
- **an RSA key on Azure Key Vault wraps for anyone.** With an RSA key the wrap is a public-key
  operation, so whoever holds the public key wraps a DEK of their own into the record. Use an AES
  key, from Managed HSM;
- **`decrypt_envelope_value` knows no key version.** It unwraps the wrapped DEK an envelope value
  carries, so a wrapped DEK kept from a version, compromised or destroyed since, still opens values
  through it. Keep it in the read path for the migration only;
- **a destroyed version's DEK lives as long as the KEK version that wrapped it.** A backup of the
  record holds wrapped DEKs the KMS still opens, see
  [Crypto-shredding](./operations.md#crypto-shredding);
- **an exported BigQuery keyset holds the versions' keys**, wrapped with no associated data, since
  BigQuery unwraps it with none. Treat it as a copy of the record's readable versions, and export
  again after every rotation and every `mark_compromised`;
- **a sweep re-seals forgeries as trusted values.** Values read through a compromised version are
  decided per record before a sweep re-seals them, see
  [The trust of re-sealed values](./operations.md#the-trust-of-re-sealed-values);
- **deterministic fields leak equality and frequency**, and an equality query across a rotation
  links a value's history for whoever reads the query, see
  [Deterministic fields](./keyring/deterministic.md#what-they-leak);
- **beacons leak likely equality and frequency**, as far as their bits tell values apart, see
  [Beacons](./keyring/beacons.md#what-a-beacon-leaks);
- **a promotion has no guard.** A process that has not seen a promoted version reloads its record
  when it meets a value under it, and fails the read when it cannot reach the store, so the wait
  before `promote` is the operator's, see [Staged rotation](./keyring/lifecycle.md#staged-rotation).

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
