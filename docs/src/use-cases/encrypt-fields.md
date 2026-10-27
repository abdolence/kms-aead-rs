# Encrypt fields with a KMS

A field or a secret in the application's own table, encrypted under a DEK that a cloud KMS encrypts,
with no keyring store. Every value carries its encrypted DEK, so nothing is stored apart from the
values. For central rotation, deterministic fields across rotations or BigQuery reads across
rotations, see [Choosing a mode](../intro.md#choosing-a-mode) and the keyring.

## Which mode

| Values are | Mode | See |
|---|---|---|
| written rarely, such as secrets and configuration | per-call envelope: a new DEK for every value, one KMS call to encrypt it | [Envelope encryption](../envelope-encryption.md) |
| written at a high rate | store-less DEK reuse: one DEK for many values, renewed by age, count and bytes | [Store-less DEK reuse](../dek-caching.md#store-less-dek-reuse) |
| grouped, such as a file in chunks or a tenant's rows, with one DEK the application keeps | the `*_with_dek` and `*_with_encrypted_dek` calls, with the encrypted DEK stored apart | [Working with DEKs yourself](../envelope-encryption.md#working-with-deks-yourself) |
| encrypted with a key the application holds, with no KMS | `AeadCipher` | [AEAD without a KMS](../crypto-backends.md#aead-without-a-kms) |

## The path

1. A provider for the KMS, such as `GcpKmsProvider::new(&key_ref)`, with the rights of
   [KMS rights](../keyring/deployment.md#kms-rights): decrypt for a reader, encrypt too for a
   writer, see [KMS providers](../providers.md);
2. `KmsAeadEnvelope::new(provider)`, or `with_options` with a `DekReusePolicy` for store-less DEK
   reuse and a `DekCache` for repeated reads, see [DEK caching and reuse](../dek-caching.md);
3. a newtype per field, such as `Email`, that implements `Plaintext`, and normalises the value if
   it is ever looked up, see [`Plaintext`](../stored-values.md#plaintext);
4. the AAD that ties the value to its place, `<table>/<row id>/<column>`, so a value copied into
   another row fails to decrypt, see [AAD](../envelope-encryption.md#aad);
5. `envelope.encrypt(aad, &value)` into an `Encrypted<Email, Envelope>`, stored as a serde field, a
   `BYTEA` column through tokio-postgres or sqlx, or hex in a `TEXT` column, see
   [Storing](../stored-values.md#storing);
6. `envelope.decrypt(aad, &encrypted)` with the same AAD, rebuilt from the row.

A first example, with the local KMS, is in [With an envelope](../getting-started.md#with-an-envelope).

## Lookups, readers and rotation

- Finding rows by an encrypted field needs a deterministic field or a beacon, see
  [Find rows by an encrypted value](./equality-lookups.md);
- Tink reads envelope values on Cloud KMS and AWS KMS keys, and BigQuery does not, see
  [Read values in BigQuery or Tink](./bigquery-and-tink.md);
- the KEK rotates in the KMS, and the stored DEKs are encrypted again before the old version is
  disabled, see [Rotate keys and re-encrypt values](./rotation.md#with-kms-aead-alone);
- values move to a keyring later with a sweep, see
  [Move envelope values to a keyring](./envelope-to-keyring.md).
