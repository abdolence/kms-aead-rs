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
- Crypto backends chosen at runtime: ring, aws-lc-rs (including its FIPS module) and the pure
  Rust RustCrypto crates. A value sealed by one backend opens with any other;
- Per-call envelopes, store-less DEK reuse, and an in-process cache of unwrapped data encryption
  keys;
- Deterministic encryption with AES-SIV, for values that are looked up by equality;
- Binding a wrapped key to non-secret text the KMS authenticates;
- Optional KMS-side random generators for GCP and AWS;
- Field encryption with a keyring, in the `kms-aead-keyring` crate: key versions kept in
  Firestore, PostgreSQL or Cloud Storage, central rotation, and values in Tink's wire format;
- Tracing spans for every operation and every KMS call, with no plaintext, key material or AAD
  in them;
- No unsafe code.

To start using the library, see [Getting started](./getting-started.md).

## Envelope encryption

A value is sealed with an AEAD algorithm under a data encryption key (DEK). The DEK is then
wrapped (encrypted) by a key encryption key (KEK) that never leaves the KMS, and the wrapped DEK
is stored next to the cipher text. To read the value, the KMS unwraps the DEK, and the DEK opens
the value locally.

So the KMS sees only DEKs, never the data, and a KMS call is needed only to wrap or unwrap a
DEK. Access to the data is controlled by access to the KEK: revoke the KMS permission, or
destroy the key, and the stored values cannot be opened.

The additional authenticated data (AAD) is authenticated but not encrypted: a value opens only
with the AAD it was sealed with. Use it to tie a value to where it is stored, such as a table
and a row id, so that a value copied to another row fails to open.

## Choosing a mode

The library has three ways to use a KMS, and they differ in how many DEKs exist and how often
the KMS is called:

- **Per-call envelope**, the default of `KmsAeadEnvelope`: a new DEK for every value, wrapped
  with one KMS call, and stored in the value itself. Every decryption unwraps its DEK with one
  more KMS call, unless the envelope has a DEK cache. Use it when values are written rarely,
  such as secrets and configuration, or when one DEK per value is a requirement. See
  [Envelope encryption](./envelope-encryption.md);
- **Store-less DEK reuse**, a `KmsAeadEnvelope` with a `DekReusePolicy`: one DEK seals many
  values and is renewed by age or by count, so a write calls the KMS only to renew it. Values
  still carry their wrapped DEK, so nothing is stored apart from them, and reads unwrap through
  the DEK cache. Use it for high write rates where a KMS call per value costs too much. See
  [DEK caching and reuse](./dek-caching.md);
- **Keyring**, the `kms-aead-keyring` crate: a keyring record per scope holds the wrapped key
  versions, and values carry a 4-byte key id in Tink's wire format instead of a wrapped DEK. The
  record is the place for central rotation and retirement of keys, and for values that BigQuery
  and Tink read too. See [Keyring and field encryption](./keyring.md).

| | Per-call envelope | Store-less DEK reuse | Keyring |
|---|---|---|---|
| Crate | `kms-aead` | `kms-aead` | `kms-aead-keyring` |
| DEKs | one per value | one per process at a time, renewed by age or count | one per key version of a scope |
| KMS calls on write | one wrap per value | one wrap per renewed DEK | none |
| KMS calls on read | one unwrap per value, or per DEK cache miss | one unwrap per DEK per cache TTL | one unwrap per key version per cache TTL |
| A value carries | its wrapped DEK | its wrapped DEK | a 4-byte key id |
| Infrastructure | a KMS | a KMS | a KMS and a keyring store |
| Rotation | the KEK in the KMS | the KEK in the KMS, and DEK renewal per process | central: rotate, retire, destroy, and a compromised flag every process sees |
| Deterministic fields | with keys the application stores, see [Deterministic encryption](./deterministic.md) | no | yes, with queries across rotations |
| BigQuery and Tink readers | no | no | yes, with a Cloud KMS KEK |
| Crypto-shredding | KEK destruction | KEK destruction | KEK destruction, or destroying a keyring's versions |

Neither mode needs the other. Values of the envelope modes move to a keyring with a sweep, see
[Migrating from envelope values](./operations.md#migrating-from-envelope-values).

`AeadCipher` and `DeterministicCipher` work without a KMS at all, with keys the application
holds.

## Licence

Apache Software License (ASL)
