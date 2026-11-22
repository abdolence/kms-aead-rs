# KMS envelope encryption for Rust

The library provides envelope encryption with a key encryption key held by a KMS, and AEAD
encryption without a KMS. It covers:

- envelope encryption with Google Cloud KMS, AWS KMS, Azure Key Vault, HashiCorp Vault Transit or a
  local KMS, see [Envelope encryption](./envelope-encryption.md) and
  [KMS providers](./providers.md);
- AEAD encryption on ring, aws-lc-rs or RustCrypto, see [Crypto backends](./crypto-backends.md);
- typed encrypted fields for serde, tokio-postgres and sqlx, see [Stored values](./stored-values.md);
- fewer KMS calls with a DEK cache and DEK reuse, see [DEK caching and reuse](./dek-caching.md);
- deterministic encryption and beacons for lookups by equality, see
  [Deterministic encryption](./deterministic.md) and [Beacons](./beacons.md);
- keys versioned and rotated centrally, in the `kms-aead-keyring` crate, see
  [Keyring and field encryption](./keyring.md);
- streaming encryption of files of any length, see [Streaming encryption](./streaming.md);
- signatures and MACs, see [Signatures and MACs](./signing.md);
- asymmetric KEKs for producers that can encrypt and never decrypt, see
  [Asymmetric KEKs](./asymmetric-kek.md);
- values that BigQuery and Tink, Google's open-source cryptography library, read, see
  [Formats](./formats.md);
- tracing spans for every operation and every KMS call, see [Observability](./observability.md);
- no unsafe code.

To start using the library, see [Getting started](./getting-started.md).

## Envelope encryption

A value is encrypted with an AEAD algorithm under a data encryption key (DEK). The DEK is then
encrypted by a key encryption key (KEK) that never leaves the KMS, and the encrypted DEK is stored
next to the cipher text. KMS documentation, and Azure Key Vault's `wrapKey` and `unwrapKey`
operations, call this wrapping the DEK. To read the value, the KMS decrypts the DEK, and the DEK
decrypts the value locally.

So the KMS sees only DEKs, never the data, and a KMS call is needed only to encrypt or decrypt a
DEK. Access to the data is controlled by access to the KEK: revoke the KMS permission, or
destroy the key, and the stored values cannot be decrypted.

The additional authenticated data (AAD) is authenticated but not encrypted: a value decrypts only
with the AAD it was encrypted with. Use it to tie a value to where it is stored, such as a table
and a row id, so that a value copied to another row fails to decrypt.

## Choosing a mode

The ways to use a KMS differ in how many DEKs exist, how often the KMS is called and what a
stored value holds. The table below sets the four modes side by side. Pick one by what the data
needs:

- **Per-call envelope**, the default of `KmsAeadEnvelope`. Use it when values are written rarely,
  such as secrets and configuration, or when one DEK per value is a requirement. See
  [Envelope encryption](./envelope-encryption.md);
- **Store-less DEK reuse**, a `KmsAeadEnvelope` with a `DekReusePolicy`. Use it for high write
  rates where a KMS call per value costs too much. See [DEK caching and reuse](./dek-caching.md)
  and [Cut KMS calls with a DEK cache and DEK reuse](./use-cases/fewer-kms-calls.md);
- **One fixed key**, `encrypt` of `AeadCipher` or `DeterministicCipher`. Use it for a column that
  BigQuery reads, with no key rotation. See [One fixed key](./one-fixed-key.md);
- **Keyring**, the `kms-aead-keyring` crate. Use it when keys need central rotation and
  retirement, or when BigQuery and Tink read values across rotations. See
  [Keyring and field encryption](./keyring.md).

| | Per-call envelope | Store-less DEK reuse | One fixed key | Keyring |
|---|---|---|---|---|
| Crate | `kms-aead` | `kms-aead` | `kms-aead` | `kms-aead-keyring` |
| DEKs | one per value | one per process at a time, renewed by age or count | one, encrypted once by an administrative job | one per key version of a scope |
| KMS calls on write | one encryption per value | one encryption per renewed DEK | no encryption, and one decryption per DEK cache TTL | no encryption, and one decryption per key version per DEK cache TTL |
| KMS calls on read | one decryption per value, or per DEK cache miss | one decryption per DEK per cache TTL | one decryption per cache TTL | one decryption per key version per cache TTL |
| A value carries | its encrypted DEK | its encrypted DEK | a 4-byte key id | a 4-byte key id |
| Infrastructure | a KMS | a KMS | a KMS, and the encrypted DEK in the application's settings | a KMS and a keyring store |
| Rotation | the KEK in the KMS | the KEK in the KMS, and DEK renewal per process | the KEK in the KMS; the DEK is not rotated | central: staged rotate and promote, retire, destroy, and a compromised flag every process sees |
| Deterministic fields | with keys the application stores, see [Deterministic encryption](./deterministic.md) | no | yes, with `DeterministicCipher` | yes, with queries across rotations |
| BigQuery readers | no | no | yes, with a keyset of the key encrypted by a Cloud KMS KEK | yes, with a Cloud KMS KEK |
| Tink readers | yes, with `KmsEnvelopeAead` for GCP and AWS keys | yes, with `KmsEnvelopeAead` for GCP and AWS keys | yes, with a keyset of the key | yes, with a KEK in Cloud KMS, AWS KMS by key ARN or Vault Transit |
| Crypto-shredding | KEK destruction | KEK destruction | KEK destruction | KEK destruction, or `dangerously_shred()` and the deletion of the record's backups |

No mode needs another. Values of the envelope modes move to a keyring with a sweep, see
[Move envelope values to a keyring](./production/envelope-to-keyring.md).

Streamed values come in the same modes: under a keyring, under an envelope, or with a DEK the
application holds, see [Streaming encryption](./streaming.md).

Both envelope modes encrypt a value of a Rust type, such as an application newtype, into an
`Encrypted<T, Envelope>` that carries its encrypted DEK, and serde, tokio-postgres and sqlx store
it as bytes, so a column of secrets needs no store of its own. See
[Stored values](./stored-values.md).

`AeadCipher` and `DeterministicCipher` work without a KMS at all, with keys the application
holds.

## Where to start

The setup is under [Getting started](./getting-started.md): [Choose a provider and a
backend](./getting-started/choosing.md), FIPS included, and [Develop and test without a
cloud](./getting-started/local-development.md).

Use cases are in five groups, each a situation and the way through it:

| To | Read |
|---|---|
| Encrypt columns, make fewer KMS calls, give each customer its own keys, look a row up by an encrypted value or erase a customer | [Protect data in your database](./use-cases/database.md) |
| Let BigQuery or Tink read encrypted columns, or let partners and devices encrypt without being able to decrypt | [Share encrypted data with other systems](./use-cases/sharing.md) |
| Encrypt uploads and exports of any size, and read byte ranges of them | [Files and streams](./use-cases/files-and-streams.md) |
| Publish a file anyone can verify, or detect tampering between your own services | [Prove where data came from](./use-cases/provenance.md) |
| Log a payload that fails to parse, with no encryption | [Keep sensitive data out of logs](./use-cases/logs.md) |

Running in production, one page per task:

| To | Read |
|---|---|
| Give the applications and the administration their own rights | [Permissions: applications and administration](./production/permissions.md) |
| Alert on both | [Monitoring and alerts](./production/monitoring.md) |
| Rotate the DEKs and the KEK without downtime | [Rotate keys and re-encrypt values](./production/rotation.md) |
| Respond to a leaked key or a damaged keyring record | [Incident runbook](./production/runbook.md) |
| Stop a writer of the keyring store from changing which keys are used | [Protect the keyring record](./production/signed-records.md) |
| Move envelope values to a keyring | [Move envelope values to a keyring](./production/envelope-to-keyring.md) |

Moving to a newer version is covered by the guides in the Upgrading section at the end of the
book: [Migrating from 0.30](./migrating-from-0.30.md) and [Migrating from 0.29](./migrating-from-0.29.md).
Apply them in order, newest first.

## Licence

Apache Software License (ASL)
