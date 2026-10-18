# Deterministic encryption

Feature `deterministic`.

Randomized encryption gives a different cipher text every time, even for the same value. A
deterministic algorithm gives equal cipher texts for equal values under one key and one AAD, so a
sealed column can be compared, joined or looked up by equality without opening it.

The library provides AES-SIV (RFC 5297) with a 64-byte key, `DeterministicAlgorithm::Aes256Siv`,
on the RustCrypto `aes-siv` crate, whatever AEAD backend the build enables. Its name for
`FromStr` and `Display` is `aes-256-siv`.

## What it leaks

Be aware what equal cipher texts tell a reader of the stored data:

- **Equality**: which rows hold the same value;
- **Frequency**: how often each value occurs. On a column with few distinct values, such as a
  country, a status or a yes/no answer, the most frequent cipher text is the most frequent value,
  and the values can be read back from public statistics.

So do not use deterministic encryption:

- for a column with few distinct values or a skewed distribution;
- when equality itself is sensitive;
- when the value is never looked up by equality: randomized encryption leaks nothing of the
  kind.

The AAD narrows what leaks: values are equal only under the same AAD, so a per-tenant AAD keeps
equal values of two tenants apart.

## Usage

`DeterministicCipher` seals and opens with a `DeterministicDataEncryptionKey`. It is a type of its
own, with no conversion to or from `DataEncryptionKey`, so a key is not handed to the cipher of the
other purpose by mistake.

```rust
use kms_aead::{DeterministicAlgorithm, DeterministicCipher};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = DeterministicCipher::new(DeterministicAlgorithm::Aes256Siv)?;
let key = cipher.generate_key()?;

let aad = b"customers/email";
let first = cipher.encrypt_value(aad, &SecretValue::from("user@example.com"), &key)?;
let second = cipher.encrypt_value(aad, &SecretValue::from("user@example.com"), &key)?;

// Equal values give equal cipher texts, to look up by
assert_eq!(first, second);
assert_eq!(cipher.decrypt_value(aad, &first, &key)?, SecretValue::from("user@example.com"));
# Ok(())
# }
```

`DeterministicCipherText` is `[synthetic IV: 16][ciphertext]`, the output order of RFC 5297. Its
equality compares in constant time, and its `Debug` prints only the length, since the bytes tell
which values are equal. Its value is equal to a Tink AES-SIV value after Tink's 5-byte prefix.

## Keys wrapped by a KMS

The envelope generates and unwraps deterministic keys with its provider:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadBackend, DeterministicAlgorithm, DeterministicCipher, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("example".to_string())?, AeadBackend::Ring)?;
let envelope = KmsAeadEnvelope::new(provider, AeadBackend::Ring)?;
let algorithm = DeterministicAlgorithm::Aes256Siv;

// A new key, and the same key wrapped, to store
let (key, encrypted_key) = envelope.generate_new_deterministic_dek(algorithm).await?;

// Later: unwrap the stored key
let unwrapped = envelope.decrypt_deterministic_dek(algorithm, &encrypted_key).await?;

let cipher = DeterministicCipher::new(algorithm)?;
let sealed = cipher.encrypt_value(b"aad", &SecretValue::from("value"), &key)?;
assert_eq!(cipher.decrypt_value(b"aad", &sealed, &unwrapped)?, SecretValue::from("value"));
# Ok(())
# }
```

`decrypt_deterministic_dek` calls the provider every time and does not go through the envelope's
DEK cache. To cache deterministic keys, use `DekCache::with_deterministic_key`, which keeps them
apart from randomized keys.

`DeterministicCipher::generate_wrapped_key` does the same with any provider.
