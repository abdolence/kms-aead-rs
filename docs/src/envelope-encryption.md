# Envelope encryption

`KmsAeadEnvelope` seals values under data encryption keys (DEKs) on the crypto backend it is built
with, and wraps the DEKs with the KEK of its provider. A call that makes no KMS call is not
`async`, and every call opens one `DEBUG` span, see [Observability](./observability.md).

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadEnvelope, KmsAeadEnvelopeOptions, Ring};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
// AES-256-GCM by default
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

// Or another algorithm
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
)?;
# let _ = envelope;
# Ok(())
# }
```

The value does not record the algorithm, so the writer and the reader of a value must be
configured with the same one. The backend can differ, see
[Crypto backends](./crypto-backends.md). The default, AES-256-GCM, is read by every Tink
implementation too, see [Formats](./formats.md#tinks-kms-envelope). Values that 0.29 and earlier
sealed under their default open only with ChaCha20-Poly1305 configured, see
[Migrating from 0.29](./migrating-from-0.29.md#default-algorithm).

## Encrypting values

`encrypt_value` seals a value under a new DEK, wraps the DEK with one KMS call, and returns both
in one `CipherTextWithEncryptedKey`. `decrypt_value` unwraps the DEK with one KMS call and opens
the value:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{CipherTextWithEncryptedKey, KmsAeadEnvelope, Ring, ValueStruct};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

let aad = b"orders/1042";
let encrypted = envelope
    .encrypt_value(aad, &SecretValue::from("4111 1111 1111 1111"))
    .await?;

// The bytes to store, and the value read back from them
let stored: Vec<u8> = encrypted.value().clone();
let read_back = CipherTextWithEncryptedKey(stored);

let decrypted = envelope.decrypt_value(aad, &read_back).await?;
assert_eq!(decrypted, SecretValue::from("4111 1111 1111 1111"));
# Ok(())
# }
```

`ValueStruct` is re-exported by the crate: its `value()` and `into_value()` read the bytes of
`CipherText`, `CipherTextWithEncryptedKey`, `EncryptedDataEncryptionKey` and
`DeterministicCipherText`. `to_hex_string()` returns them as lowercase hex.

The value is in Tink's KMS envelope format for every provider, so Tink's `KmsEnvelopeAead` reads
it with the same KMS key and algorithm, see [Formats](./formats.md#tinks-kms-envelope).

A new DEK comes from the backend's CSPRNG, or from the KMS generator when the provider is
configured to use one, see [KMS random generators](./providers.md#kms-random-generators).

## AAD

The AAD is authenticated but not encrypted: a value opens only with the AAD it was sealed with,
and a wrong AAD fails with `DECRYPT`. Use it to bind a value to its place, such as
`<table>/<row id>/<column>`, so that a value copied into another row or column fails to open.

The AAD is not stored in the value, so the reader rebuilds it from the same data. It is never
logged or put in an error, but it is not secret either: keep secrets in the value itself.

## Working with DEKs yourself

The `*_with_dek` and `*_with_encrypted_dek` calls let the application keep one DEK for many
values and store the wrapped DEK apart from them, such as one DEK per tenant or per file. The
cipher texts are `CipherText` values without a wrapped key.

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

// One KMS call: a new DEK and the same DEK wrapped
let (dek, encrypted_dek) = envelope.generate_new_dek().await?;

// No KMS call: seal and open with the plaintext DEK
let first = envelope.encrypt_value_with_dek(b"files/1/chunk/0", &SecretValue::from("first"), &dek)?;
let second = envelope.encrypt_value_with_dek(b"files/1/chunk/1", &SecretValue::from("second"), &dek)?;
assert_eq!(
    envelope.decrypt_value_with_dek(b"files/1/chunk/0", &first, &dek)?,
    SecretValue::from("first")
);

// Later, with only the wrapped DEK: the envelope unwraps it with the KMS
let decrypted = envelope
    .decrypt_value_with_encrypted_dek(b"files/1/chunk/1", &second, &encrypted_dek)
    .await?;
assert_eq!(decrypted, SecretValue::from("second"));
# Ok(())
# }
```

The calls are:

- `generate_new_dek`: a new DEK and the same DEK wrapped, one KMS call;
- `encrypt_value_with_dek` and `decrypt_value_with_dek`: with a plaintext DEK, no KMS call;
- `encrypt_value_with_encrypted_dek` and `decrypt_value_with_encrypted_dek`: with a wrapped DEK,
  unwrapped through the envelope's DEK cache, so one KMS call per call without a cache.

Be aware not to seal more than about 2^32 values under one DEK: every value takes a random 96-bit
nonce, see [Security considerations](./security.md#nonces).

## Storing wrapped DEKs

`EncryptedDataEncryptionKey` holds the bytes the provider returned, which also name the KMS key
version where the KMS needs one to unwrap after a rotation. Store `value()` or `to_hex_string()`,
and read them back with `EncryptedDataEncryptionKey::from` or `try_from_hex_string()`:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEnvelope, Ring, ValueStruct};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
let (_dek, encrypted_dek) = envelope.generate_new_dek().await?;

let stored: Vec<u8> = encrypted_dek.value().clone();
let read_back = EncryptedDataEncryptionKey::from(stored);

let stored_hex: String = encrypted_dek.to_hex_string();
let read_back_hex = EncryptedDataEncryptionKey::try_from_hex_string(&stored_hex)?;

assert_eq!(read_back, read_back_hex);
# Ok(())
# }
```

The wrapped DEK is the one Tink stores in its KMS envelope, so `CipherTextWithEncryptedKey::join`
of a value and its wrapped DEK is a value Tink reads. See [Formats](./formats.md#wrapped-deks) for
each provider's bytes.
