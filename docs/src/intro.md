# KMS envelope encryption for Rust

Library provides envelope encryption with a key encryption key held by a KMS, and AEAD
encryption without a KMS:

- KMS providers for:
    - Google Cloud KMS;
    - AWS KMS;
    - Azure Key Vault and Managed HSM;
    - HashiCorp Vault Transit;
    - A local KMS with a key the application holds, for development, tests and single-host
      installs;
- AEAD algorithms ChaCha20-Poly1305, AES-128-GCM, AES-256-GCM and AES-256-GCM-SIV;
- Tink's KMS envelope format for every provider, so Tink reads the values of GCP and AWS keys
  and the library reads Tink's, see [Formats](./formats.md);
- Crypto backends ring, aws-lc-rs (including its FIPS module) and the pure Rust RustCrypto
  crates. A value encrypted by one backend decrypts with any other;
- Per-call envelopes, store-less DEK reuse, and an in-process cache of decrypted data encryption
  keys;
- Deterministic encryption with AES-SIV, for values that are looked up by equality;
- Typed fields, `Encrypted<T, F>`, stored with serde, tokio-postgres or sqlx;
- Optional KMS-side random generators for GCP and AWS;
- Field encryption with a keyring, in the `kms-aead-keyring` crate: key versions kept in
  Firestore, PostgreSQL, Cloud Storage or S3, central staged rotation, beacons, and values in
  Tink's wire format;
- Streaming encryption for files of any length, with reads of any byte range that fetch only the
  chunks that cover it;
- Signatures with Ed25519 and ECDSA P-256 keys held by a KMS, verified without a KMS in Rust and in
  a browser, and MACs under keyring key versions;
- Signed keyring records, so that whoever can write the keyring store cannot change which keys are
  used;
- Asymmetric KEKs, for producers that encrypt with a public key and can never decrypt;
- Tracing spans for every operation and every KMS call, with no plaintext, key material or AAD
  in them;
- No unsafe code.

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
stored value holds:

- **Per-call envelope**, the default of `KmsAeadEnvelope`: a new DEK for every value, encrypted
  with one KMS call, and stored in the value itself. Every decryption decrypts its DEK with one
  more KMS call, unless the envelope has a DEK cache, which serves repeated reads without the KMS,
  see [Cut KMS calls with a DEK cache and DEK reuse](./use-cases/fewer-kms-calls.md). Use it when
  values are written rarely, such as secrets and configuration, or when one DEK per value is a
  requirement. See [Envelope encryption](./envelope-encryption.md);
- **Store-less DEK reuse**, a `KmsAeadEnvelope` with a `DekReusePolicy`: one DEK encrypts many
  values and is renewed by age or by count, so a write calls the KMS only to renew it. Values
  still carry their encrypted DEK, so nothing is stored apart from them, and reads decrypt through
  the DEK cache. Use it for high write rates where a KMS call per value costs too much. See
  [DEK caching and reuse](./dek-caching.md);
- **One fixed key**, `encrypt` of `AeadCipher` or `DeterministicCipher` with one key that
  the KMS encrypts once and the DEK cache decrypts: values carry a 4-byte key id in Tink's wire
  format instead of an encrypted DEK, and BigQuery and Tink read them with a keyset of that key. Use
  it for a column that BigQuery reads, with no key rotation. See
  [One fixed key](./one-fixed-key.md);
- **Keyring**, the `kms-aead-keyring` crate: a keyring record per scope holds the encrypted DEK
  versions, and values carry a 4-byte key id in Tink's wire format instead of an encrypted DEK. The
  record is the place for central rotation and retirement of keys, and for values that BigQuery
  and Tink read across rotations. See [Keyring and field encryption](./keyring.md).

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

Moving to a newer version is in the Upgrading section at the end of the book, starting with
[Migrating from 0.30](./migrating-from-0.30.md).

## Licence

Apache Software License (ASL)
