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
  crates. A value sealed by one backend opens with any other;
- Per-call envelopes, store-less DEK reuse, and an in-process cache of decrypted data encryption
  keys;
- Deterministic encryption with AES-SIV, for values that are looked up by equality;
- Typed fields, `Encrypted<T, F>`, stored with serde, tokio-postgres or sqlx;
- Optional KMS-side random generators for GCP and AWS;
- Field encryption with a keyring, in the `kms-aead-keyring` crate: key versions kept in
  Firestore, PostgreSQL, Cloud Storage or S3, central staged rotation, beacons, and values in
  Tink's wire format;
- Tracing spans for every operation and every KMS call, with no plaintext, key material or AAD
  in them;
- No unsafe code.

To start using the library, see [Getting started](./getting-started.md).

## Envelope encryption

A value is sealed with an AEAD algorithm under a data encryption key (DEK). The DEK is then
encrypted by a key encryption key (KEK) that never leaves the KMS, and the encrypted DEK is stored
next to the cipher text. KMS documentation, and Azure Key Vault's `wrapKey` and `unwrapKey`
operations, call this wrapping the DEK. To read the value, the KMS decrypts the DEK, and the DEK
opens the value locally.

So the KMS sees only DEKs, never the data, and a KMS call is needed only to encrypt or decrypt a
DEK. Access to the data is controlled by access to the KEK: revoke the KMS permission, or
destroy the key, and the stored values cannot be opened.

The additional authenticated data (AAD) is authenticated but not encrypted: a value opens only
with the AAD it was sealed with. Use it to tie a value to where it is stored, such as a table
and a row id, so that a value copied to another row fails to open.

## Choosing a mode

The ways to use a KMS differ in how many DEKs exist, how often the KMS is called and what a
stored value holds:

- **Per-call envelope**, the default of `KmsAeadEnvelope`: a new DEK for every value, encrypted
  with one KMS call, and stored in the value itself. Every decryption decrypts its DEK with one
  more KMS call, unless the envelope has a DEK cache. Use it when values are written rarely,
  such as secrets and configuration, or when one DEK per value is a requirement. See
  [Envelope encryption](./envelope-encryption.md);
- **Store-less DEK reuse**, a `KmsAeadEnvelope` with a `DekReusePolicy`: one DEK seals many
  values and is renewed by age or by count, so a write calls the KMS only to renew it. Values
  still carry their encrypted DEK, so nothing is stored apart from them, and reads decrypt through
  the DEK cache. Use it for high write rates where a KMS call per value costs too much. See
  [DEK caching and reuse](./dek-caching.md);
- **One fixed key**, `encrypt` of `AeadCipher` or `DeterministicCipher` with one key that
  the KMS encrypts once and the DEK cache decrypts: values carry a 4-byte key id in Tink's wire
  format instead of an encrypted DEK, and BigQuery and Tink read them with a keyset of that key. Use
  it for a column that BigQuery reads, with no key rotation. See
  [One fixed key](./envelope-encryption.md#one-fixed-key);
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
| Crypto-shredding | KEK destruction | KEK destruction | KEK destruction | KEK destruction, or `dangerously_destroy_all_versions` and the deletion of the record's backups |

No mode needs another. Values of the envelope modes move to a keyring with a sweep, see
[Move envelope values to a keyring](./use-cases/envelope-to-keyring.md).

Both envelope modes seal a value of a Rust type, such as an application newtype, into an
`Encrypted<T, Envelope>` that carries its encrypted DEK, and serde, tokio-postgres and sqlx store
it as bytes, so a column of secrets needs no store of its own. See
[Stored values](./stored-values.md).

`AeadCipher` and `DeterministicCipher` work without a KMS at all, with keys the application
holds.

## Where to start

| To | Read |
|---|---|
| Encrypt a few fields or secrets with a cloud KMS and no store | [Encrypt fields with a KMS](./use-cases/encrypt-fields.md) |
| Give each tenant its own keys | [A keyring per tenant](./use-cases/keyring-per-tenant.md) |
| Find rows by an encrypted value | [Find rows by an encrypted value](./use-cases/equality-lookups.md) |
| Read the values in BigQuery or with Tink | [Read values in BigQuery or Tink](./use-cases/bigquery-and-tink.md) |
| Rotate the DEKs and the KEK without downtime | [Rotate keys and re-encrypt values](./use-cases/rotation.md) |
| Respond to a leaked key, or shred a tenant | [A leaked key or a shredded tenant](./use-cases/incidents.md) |
| Run the applications and the administration with their own rights, and alert on both | [Applications and administration apart](./use-cases/deployment.md) |
| Pick a KMS and a crypto backend, FIPS included | [Choose a provider and a backend](./use-cases/choosing.md) |
| Develop and test without a cloud account | [Develop and test without a cloud](./use-cases/local-development.md) |
| Move envelope values to a keyring | [Move envelope values to a keyring](./use-cases/envelope-to-keyring.md) |
| Upgrade from 0.29 | [Migrating from 0.29](./migrating-from-0.29.md) |

## Licence

Apache Software License (ASL)
