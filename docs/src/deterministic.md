# Deterministic encryption

Feature `deterministic`.

Randomised encryption gives a different cipher text every time, even for the same value. A
deterministic algorithm gives equal cipher texts for equal values under one key and one AAD, so a
sealed column can be compared, joined or looked up by equality without opening it.

The library provides AES-SIV (RFC 5297) with a 64-byte key, `DeterministicAlgorithm::Aes256Siv`.
Its name for `FromStr` and `Display` is `aes-256-siv`. `DeterministicCipher` takes a backend, as
`AeadCipher` does, and draws its keys from the backend's CSPRNG. Every backend seals and opens with
the RustCrypto `aes-siv` crate, so a value sealed under one backend opens under any other.

AES-SIV is not a FIPS-approved mode. A FIPS deployment keeps deterministic fields outside its
validated boundary, also on `aws-lc-fips`, where the keys come from the FIPS module's DRBG.

## What it leaks

Be aware what equal cipher texts tell a reader of the stored data:

- **Equality**: which rows hold the same value;
- **Frequency**: how often each value occurs. On a column with few distinct values, such as a
  country, a status or a yes/no answer, the most frequent cipher text is the most frequent value,
  and the values can be read back from public statistics.

So do not use deterministic encryption:

- for a column with few distinct values or a skewed distribution;
- when equality itself is sensitive;
- when the value is never looked up by equality: randomised encryption leaks nothing of the
  kind.

The AAD narrows what leaks: values are equal only under the same AAD, so a per-tenant AAD keeps
equal values of two tenants apart.

A beacon finds rows by equality as well and keeps the value randomised, see
[Beacon or deterministic field](./envelope-encryption.md#beacon-or-deterministic-field).

## Usage

`DeterministicCipher` seals and opens with a `DataEncryptionKey` of
`DeterministicAlgorithm::key_len()` bytes, 64 for AES-SIV, and refuses a key of another length
with `INVALID_KEY_LENGTH`, such as the 16 or 32 bytes of a randomised algorithm's key. The
application keeps track of which key serves which algorithm, as kms-aead-keyring does with its
key ids.

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Deterministic;
use kms_aead::{DeterministicAlgorithm, DeterministicCipher, Encrypted, KeyId};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = DeterministicCipher::<Ring>::new(DeterministicAlgorithm::Aes256Siv)?;
let dek = cipher.generate_dek()?;

let aad = b"customers/email";
let first: Encrypted<SecretValue, Deterministic> =
    cipher.encrypt(KeyId::new(1), aad, &SecretValue::from("user@example.com"), &dek)?;
let second: Encrypted<SecretValue, Deterministic> =
    cipher.encrypt(KeyId::new(1), aad, &SecretValue::from("user@example.com"), &dek)?;

// Equal values give equal cipher texts, to look up by
assert_eq!(first, second);
let decrypted: SecretValue = cipher.decrypt(aad, &first, &dek)?;
assert_eq!(decrypted, SecretValue::from("user@example.com"));
# Ok(())
# }
```

An `Encrypted<T, Deterministic>` is `[0x01][key id: u32 BE][synthetic IV: 16][ciphertext]`: Tink's
5-byte TINK prefix that names the key by its `KeyId`, then the output of RFC 5297, so Tink and
BigQuery read it with a keyset of that key, see
[One fixed key](./envelope-encryption.md#one-fixed-key). Its equality compares in constant time,
and its `Debug` prints only the length, since the bytes tell which values are equal.

## Keys encrypted by a KMS

The envelope generates and decrypts deterministic keys with its provider:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Deterministic;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{DeterministicAlgorithm, DeterministicCipher, Encrypted, KeyId, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let algorithm = DeterministicAlgorithm::Aes256Siv;

// A new key, and the same key encrypted, to store
let (dek, encrypted_dek) = envelope.generate_encrypted_deterministic_dek(algorithm).await?;

// Later: decrypt the stored key
let decrypted_dek = envelope.decrypt_deterministic_dek(algorithm, &encrypted_dek).await?;

let cipher = DeterministicCipher::<Ring>::new(algorithm)?;
let sealed: Encrypted<SecretValue, Deterministic> =
    cipher.encrypt(KeyId::new(1), b"aad", &SecretValue::from("value"), &dek)?;
let decrypted: SecretValue = cipher.decrypt(b"aad", &sealed, &decrypted_dek)?;
assert_eq!(decrypted, SecretValue::from("value"));
# Ok(())
# }
```

`decrypt_deterministic_dek` calls the provider every time and does not go through the envelope's
DEK cache. To cache deterministic keys, use `DekCache::with_dek`, which holds the keys of both
kinds of algorithm.

`DeterministicCipher::generate_encrypted_dek` does the same with any provider.
