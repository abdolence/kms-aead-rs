# Security considerations

## Threat model

Envelope encryption protects stored values from whoever can read the store but cannot use the
KEK: a database dump, a backup, a replica, a data export or an operator with read access to the
tables. Opening a value needs a KMS decryption, and the KMS checks the caller's permission and, for
the cloud KMSs, writes an audit log entry.

It does not protect values from:

- a process, or whoever controls it, that may decrypt with the KEK: it can read every value it can
  fetch;
- whoever can read the memory of a process while it holds plaintext DEKs, in the
  [DEK cache](./dek-caching.md#key-lifetime) or as a store-less writer's DEK;
- a reader of the store learning which values are equal, for values sealed with
  [deterministic encryption](./deterministic.md#what-it-leaks).

The AAD protects a value from being moved: a value copied into another row or column, with an AAD
that names its place, fails to open there. The AAD itself is not encrypted, and neither is the
length of the encrypted DEK at the start of Tink's KMS envelope, which is not authenticated either.

An encrypted DEK carries no context that the KMS authenticates. Whoever can write where encrypted
DEKs are stored, such as a database table or a keyring store, can copy an encrypted DEK to another
record or relabel it, and the KMS decrypts it for any principal allowed to decrypt with that KEK.
The controls for this are in the deployment:

- write access to the stored keys is kept apart from the right to decrypt with the KEK;
- each isolation boundary, such as a tenant or an environment, has a KEK of its own, so a DEK
  copied across it fails to decrypt;
- the KMS audit log of decrypt calls, turned on where the KMS leaves it off by default, shows
  which principal decrypted which key.

The local KMS has no IAM, no audit log and no HSM, see its [limits](./providers/local.md#limits).

## Nonces

Every AEAD algorithm takes a random 96-bit nonce from the backend's CSPRNG for each value, and
writes it in front of the cipher text. NIST SP 800-38D allows 2^32 encryptions under one key with
random 96-bit nonces, and the library applies the same bound to every algorithm:

- the per-call envelope seals one value per DEK, so the bound does not apply to it;
- a store-less envelope renews its DEK at `max_uses`, 2^24 by default and at most 2^32;
- with `encrypt_with_dek` and `AeadCipher`, the application counts the values it seals
  under one key, and moves to a new key before 2^32;
- the local KMS seals each DEK it encrypts with AES-256-GCM, so a KEK version is good for about 2^32
  encryptions. Add a new version before that.

AES-256-GCM-SIV (RFC 8452) resists nonce misuse: a repeated nonce reveals only whether the two
values sealed with it are equal, and does not break integrity.

Deterministic encryption with AES-SIV takes no random nonce.

## Data volume

AES-GCM also has a bound on the data under one key, whatever the nonces: RFC 8446, section 5.5,
allows 2^24.5 records of 2^14 bytes, 2^38.5 bytes, for an AE advantage of about 2^-57. The bound
applies to AES-GCM keys this way:

- a store-less envelope renews its DEK at `max_bytes`, 2^38 bytes by default under AES-GCM and at
  most 2^52, see [Volume limit](./dek-caching.md#volume-limit). AES-256-GCM-SIV and
  ChaCha20-Poly1305 have no default volume limit;
- with `encrypt_with_dek` and `AeadCipher`, the application counts the bytes it seals under one
  AES-GCM key too, and moves to a new key before 2^38 bytes.

## Key lifetime and zeroisation

`DataEncryptionKey`, `LocalKek` and the Vault token are zeroised on drop and shown as `***` by
`Debug`. The DEK cache zeroises a key when its entry leaves the cache and no `with_dek` closure
holds it.

Some copies are out of the library's reach:

- the KMS SDKs and HTTP clients the providers use keep copies of each plaintext DEK in request and
  response buffers, which kms-aead cannot zeroise. The same holds for the Vault token in the HTTP
  stack;
- ring does not zeroise its expanded key schedules, so they stay in freed memory after each call;
- aws-lc-rs clears its key context through AWS-LC's allocator, as long as the application leaves
  that allocator in place. The record keys AES-256-GCM-SIV derives for each call stay on the stack;
- the RustCrypto backend zeroises its key objects and the per-call Poly1305 and POLYVAL keys;
- an expired DEK stays in the cache's memory until the next call on the cache or
  `purge_expired`;
- `decrypt` returns the application's own `T: Plaintext`. Only `SecretValue` as `T` is zeroised on
  drop; `String` and `Vec<u8>` take over the decrypted buffer and leave it in freed memory, and
  what the application does with the value afterwards is its own.

## What rotation does not protect

Rotating the KEK in the KMS makes the KMS encrypt new DEKs under the new key version. It does not:

- re-encrypt the DEKs already stored: they still decrypt with the old key version, which the KMS
  must keep enabled for as long as those values are read;
- re-encrypt any value: a DEK that leaked keeps opening every value sealed under it, whatever the
  KEK version that encrypts it. To retire a leaked DEK, decrypt and encrypt the values again under
  new DEKs;
- reach DEKs already in a DEK cache: they keep serving until their entries expire, or until
  `invalidate` or `clear`. The same holds for disabling a KMS key or revoking an IAM grant;
- renew a store-less writer's DEK: it is renewed by its policy, or once it leaves the cache.

With the local KMS, rotation is a new KEK version. The old version has to stay in the provider for
as long as DEKs encrypted under it are read, and crypto-shredding means destroying every copy of it,
backups included.

## Keyring deployment

A [keyring](./keyring.md) record decides which versions are read and which one seals new values,
and nothing signs it: its integrity rests on the keyring store's access control. So a deployment
splits the two sides of
[Applications and administration](./keyring.md#applications-and-administration) into two
principals:

- **Application**: builds without the `admin` feature, and calls `Keyring` only: encryption,
  decryption, beacons and sweeps. It needs KMS decrypt on the KEK and read access to the keyring
  store. None of its calls asks the KMS to encrypt, so it needs nothing more;
- **Administration**: builds with the `admin` feature, and calls the registry's `create`,
  `open_or_create` and `admin`, and the `KeyringAdmin` they return: `rotate`, `promote`,
  `change_algorithm`, `mark_compromised`, `retire`, `reinstate`, `destroy`,
  `dangerously_destroy_all_versions`, `reencrypt_deks`, `export_bigquery_keyset` and
  `export_tink_keyset`. It needs KMS encrypt and decrypt on the KEK, and is the only principal
  with write access to the keyring store. It runs in a job or in infrastructure automation, never
  in a request handler.

| KMS | Application | Administration |
|---|---|---|
| GCP | `roles/cloudkms.cryptoKeyDecrypter` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| AWS | `kms:Decrypt` on the key | `kms:Encrypt` and `kms:Decrypt` on the key, plus `kms:GenerateRandom` with the KMS random generator |
| Azure Key Vault | a role with `keys/unwrap/action` on the key | a role with `keys/wrap/action` and `keys/unwrap/action` on the key |
| Vault Transit | `update` on `transit/decrypt/<key>` | `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` |

The permissions of each store are in [Keyring stores](./keyring/stores.md).

A writer of the keyring store can copy or relabel an encrypted DEK, between versions of one keyring
or between keyrings under the same KEK: the KMS decrypts an encrypted DEK for any principal allowed
to decrypt with the KEK, whatever version or keyring it is filed under. Such a writer can bring a
compromised or destroyed version's DEK back into use under a new key id, or point one tenant's
version at another tenant's DEK. A writer without KMS rights cannot add a DEK of its own, since
every decryption names the configured KEK and the KMS refuses a DEK encrypted under another key. The
controls for this are the deployment's, as in the [threat model](#threat-model):

- write access to the keyring store for the administration only, and read-only access for the
  applications;
- one KEK per isolation boundary, such as a tenant or an environment, so a DEK copied across it
  fails to decrypt;
- backups of the record, or versioning in the store, to compare with and restore from;
- the KMS audit log of encrypt calls, which shows whether the administrative job encrypted a
  version's DEK.

A running process also refuses every record that moves a version backwards, with an `ERROR`, see
[Record cache](./keyring/record-cache.md#when-the-store-fails-or-misbehaves). That catches a
rewritten state, such as a cleared compromised flag, and not a copied DEK filed under a new
version.

## Keyring limits

- **The administration is trusted.** KMS encrypt plus store write re-activates any version, and
  so does an application that provisions keyrings lazily with the `admin` feature and those
  rights. The KMS audit log is the detection;
- **a new process has no baseline.** A store writer can clear a compromised flag, re-activate a
  version or restore a destroyed one for the processes that start after the write. Running
  processes refuse such a record and log an `ERROR`; new ones take it. The record is not signed in
  this release;
- **an RSA key on Azure Key Vault encrypts for anyone.** With an RSA key the encryption is a
  public-key operation, so whoever holds the public key encrypts a DEK of their own into the record.
  Use an AES key, from Managed HSM;
- **`decrypt_envelope_for_migration` knows no key version.** It decrypts the encrypted DEK an envelope value
  carries, so an encrypted DEK kept from a version, compromised or destroyed since, still opens
  values through it. Keep it in the read path for the migration only;
- **a destroyed version's DEK lives as long as the KEK version that encrypted it.** A backup of the
  record holds encrypted DEKs the KMS still opens, see
  [Crypto-shredding](./operations.md#crypto-shredding);
- **an exported BigQuery keyset holds the versions' keys**, encrypted with no associated data, since
  BigQuery decrypts it with none. Treat it as a copy of the record's readable versions, and export
  again after every rotation and every `mark_compromised`;
- **a sweep re-seals forgeries as trusted values.** Values read through a compromised version are
  decided per record before a sweep re-seals them, see
  [The trust of re-sealed values](./operations.md#the-trust-of-re-sealed-values);
- **deterministic fields leak equality and frequency**, and an equality query across a rotation
  links a value's history for whoever reads the query, see
  [Deterministic fields](./keyring/deterministic.md#what-they-leak);
- **beacons leak likely equality and frequency**, as far as their bits tell values apart, see
  [Beacons](./keyring/beacons.md#what-a-beacon-leaks);
- **a promotion's guard covers healthy processes only.** `promote` refuses until `record_ttl` has
  passed since the rotation, and `promote_now` skips that. A process whose revalidations fail
  keeps an older record for longer: when it meets a value under a version it has not seen, it
  reloads its record, and fails the read when it cannot reach the store. So the wait beyond the
  record TTL is the operator's, see [Staged rotation](./keyring/lifecycle.md#staged-rotation).

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
