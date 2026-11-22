# Envelope encryption

`KmsAeadEnvelope` encrypts values under data encryption keys (DEKs) on the crypto backend it is
built with, and encrypts the DEKs with the KEK of its provider. A call that makes no KMS call is not
`async`, and every call opens one `DEBUG` span, see [Spans and events](./observability/spans-and-events.md).

This page specifies the calls of `KmsAeadEnvelope`. To encrypt the columns of a table, read
[Encrypt personal data and secrets in your database](./use-cases/encrypt-fields.md). To make fewer
KMS calls, read [Cut KMS calls with a DEK cache and DEK reuse](./use-cases/fewer-kms-calls.md). To
rotate the KEK, read [Rotate keys and re-encrypt values](./production/rotation.md).

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
// AES-256-GCM by default
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

// Or another algorithm
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
)?;
# let _ = envelope;
# Ok(())
# }
```

The value does not record the algorithm, so the writer and the reader of a value must be
configured with the same one. The backend can differ, see
[Crypto backends](./crypto-backends.md). The default, AES-256-GCM, is read by every
implementation of Tink, Google's cryptography library, too, see [Tink's KMS envelope](./formats/values.md#tinks-kms-envelope). Values that
an older release encrypted under another default are covered by [Default
algorithm](./migrating-from-0.29.md#default-algorithm).

Over a provider that only encrypts, such as the `PublicKeyKekProvider` of a producer, the envelope
has the calls that encrypt: `encrypt`, `encrypt_with_dek` and the `generate_encrypted_*` calls.
The calls that decrypt a DEK or a value, from `decrypt` to the re-encryptions, need a provider
that implements `KmsAeadDecryptionProvider` too, as every KMS provider does, and do not compile
over one that does not, see [KMS providers](./providers.md#your-own-provider).

## Encrypting values

`encrypt` encrypts a value under a new DEK, encrypts the DEK with one KMS call, and returns both in
one `Encrypted<T, Envelope>`, where `T` is the type of the value. `decrypt` decrypts the DEK with
one KMS call, decrypts the value and returns a `T`. A value with no type of its own is a
`SecretValue`:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let aad = b"orders/1042";
let encrypted: Encrypted<SecretValue, Envelope> = envelope
    .encrypt(aad, &SecretValue::from("4111 1111 1111 1111"))
    .await?;

// The bytes to store, and the value read back from them
let stored: Vec<u8> = encrypted.into_value();
let read_back = Encrypted::<SecretValue, Envelope>::try_from(stored)?;

let decrypted: SecretValue = envelope.decrypt(aad, &read_back).await?;
assert_eq!(decrypted, SecretValue::from("4111 1111 1111 1111"));
# Ok(())
# }
```

The bytes in and out of an `Encrypted` are in [Stored values](./stored-values.md#bytes-in-and-out).

The value is in Tink's KMS envelope format for every provider, so Tink's `KmsEnvelopeAead` reads
it with the same KMS key and algorithm, see [Tink's KMS envelope](./formats/values.md#tinks-kms-envelope).

A new DEK comes from the backend's CSPRNG (cryptographically secure random number generator), or from the KMS generator when the provider is
configured to use one, see [KMS random generators](./providers.md#kms-random-generators).

## Typed fields

`encrypt` and `decrypt` take a value of any type that implements `Plaintext`, such as an
application's `Email` newtype, and the result is an `Encrypted<T, Envelope>` that names the type.
The calls run in the envelope's mode, a DEK per value or store-less DEK reuse, and decrypt through
the envelope's DEK cache, whatever the type. `Plaintext`, the bytes of an `Encrypted` and how
serde, tokio-postgres and sqlx store it are in [Stored values](./stored-values.md).

## AAD

The AAD is authenticated but not encrypted: a value decrypts only with the AAD it was encrypted
with, and a wrong AAD fails with `DECRYPT`. Use it to bind a value to its place, such as
`<table>/<row id>/<column>`, so that a value copied into another row or column fails to decrypt.

The AAD is not stored in the value, so the reader rebuilds it from the same data. It is never
logged or put in an error, but it is not secret either: keep secrets in the value itself.

The keyring takes a structured AAD instead of free bytes, built from the field and the row, see
[Why the AAD is structured](./keyring/fields.md#why-the-aad-is-structured).

## Working with DEKs yourself

The `*_with_dek` and `*_with_encrypted_dek` calls let the application keep one DEK for many
values and store the encrypted DEK apart from them, such as one DEK per tenant or per file. The
values are `Encrypted<T, Bare>`, with no encrypted DEK in them.

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Bare;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

// One KMS call: a new DEK and the same DEK encrypted
let (dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;

// No KMS call: encrypt and decrypt with the plaintext DEK
let first: Encrypted<SecretValue, Bare> =
    envelope.encrypt_with_dek(b"files/1/chunk/0", &SecretValue::from("first"), &dek)?;
let second: Encrypted<SecretValue, Bare> =
    envelope.encrypt_with_dek(b"files/1/chunk/1", &SecretValue::from("second"), &dek)?;
let decrypted: SecretValue = envelope.decrypt_with_dek(b"files/1/chunk/0", &first, &dek)?;
assert_eq!(decrypted, SecretValue::from("first"));

// Later, with only the encrypted DEK: the envelope decrypts it with the KMS
let decrypted: SecretValue = envelope
    .decrypt_with_encrypted_dek(b"files/1/chunk/1", &second, &encrypted_dek)
    .await?;
assert_eq!(decrypted, SecretValue::from("second"));
# Ok(())
# }
```

The calls are:

- `generate_encrypted_dek`: a new DEK and the same DEK encrypted, one KMS call;
- `encrypt_with_dek` and `decrypt_with_dek`: with a plaintext DEK, no KMS call;
- `encrypt_with_encrypted_dek` and `decrypt_with_encrypted_dek`: with an encrypted DEK, decrypted
  through the envelope's DEK cache, so one KMS call per call without a cache.

Be aware of the number of values one DEK encrypts: every value takes a random 96-bit nonce, which
bounds the count, see [Nonces](./security.md#nonces).

## Storing encrypted DEKs

`EncryptedDataEncryptionKey` holds the bytes the provider returned, which also name the KMS key
version where the KMS needs one to decrypt after a rotation. Store `value()` or `to_hex_string()`,
and read them back with `EncryptedDataEncryptionKey::from` or `try_from_hex_string()`:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{KmsKeyVersion, LocalKekId, LocalKmsProvider};
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEnvelope};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let (_dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;

let stored: Vec<u8> = encrypted_dek.value().to_vec();
let read_back_encrypted_dek = EncryptedDataEncryptionKey::from(stored);

let stored_hex: String = encrypted_dek.to_hex_string();
let read_back_hex_encrypted_dek = EncryptedDataEncryptionKey::try_from_hex_string(&stored_hex)?;

assert_eq!(read_back_encrypted_dek, read_back_hex_encrypted_dek);

// The KEK version beside it, for the check before an old KEK version is disabled
let stored_kek_version: Option<String> = encrypted_dek.kek_version().map(KmsKeyVersion::to_string);
let read_back_kek_version: Option<KmsKeyVersion> =
    stored_kek_version.map(KmsKeyVersion::try_from).transpose()?;
let read_back_encrypted_dek = match read_back_kek_version {
    Some(kek_version) => read_back_encrypted_dek.with_kek_version(kek_version),
    None => read_back_encrypted_dek,
};
# assert_eq!(read_back_encrypted_dek.kek_version(), encrypted_dek.kek_version());
# Ok(())
# }
```

An encrypted DEK that the provider has just returned carries in `kek_version()` the version of the
KEK that encrypted it, as the KMS reported it. It is `None` under AWS KMS, whose Encrypt response
names no key material, and wherever the KMS reported no version. Decryption never needs it, and neither
`value()` nor `to_hex_string()` holds it, so an encrypted DEK read back from them has none. Stored
beside the encrypted DEK, it shows without a KMS call which DEKs are still under an old KEK
version, see [The check](./production/reencrypt-deks.md#the-check). `with_kek_version` puts it back
on the encrypted DEK read from the bytes.

Equality and hashing take the bytes alone, so an encrypted DEK read back without its KEK version is
the same key, to the DEK cache and in a map, as the one the provider returned with it.

The encrypted DEK is the one Tink stores in its KMS envelope, so `Encrypted::join` of a bare value
and its encrypted DEK is an `Encrypted<T, Envelope>` that Tink reads. See
[Encrypted DEKs](./formats/values.md#encrypted-deks) for each provider's bytes.

## Re-encrypting DEKs

After a KEK rotation, a DEK stored before it keeps decrypting with the old KEK version only. Two
calls move a stored DEK to the version the provider encrypts with, without decrypting any value:

- `reencrypt_dek` takes an `Encrypted<T, Envelope>` and returns it with its DEK under the current
  version;
- `reencrypt_encrypted_dek` takes an `EncryptedDataEncryptionKey`, for the DEKs stored apart from
  their values, such as those of the `*_with_encrypted_dek` calls, of beacons and of deterministic
  fields, and for a DEK that many values share.

Each call makes two KMS calls, a decryption and an encryption, and never goes through the DEK
cache. A value or a DEK in a legacy layout fails with `LEGACY_FORMAT`: `upgrade_legacy_value` and
`upgrade_legacy_encrypted_dek` rewrite it in Tink's format, see
[Upgrading stored values](./migrating-from-0.29.md#upgrading-stored-values).

The order of a rotation, the sweep, the checks around the disable of the old version and the
rollback are in [Re-encrypt DEKs after a KEK rotation](./production/reencrypt-deks.md).
