# Migrating from 0.29

0.30 replaces the ring-only API with a choice of crypto backends, adds store-less DEK reuse,
the DEK cache, deterministic encryption and the local KMS, and makes ring optional. It writes
Tink's KMS envelope format for every provider, so values written by 0.29 and earlier read only
with the deprecated `legacy-formats` feature, which also rewrites them in the new format, see
[Old values](#old-values). The default algorithm of the envelope is AES-256-GCM, see
[Default algorithm](#default-algorithm).

## Features

| 0.29 | 0.30 |
|---|---|
| `ring-aead-encryption` | `ring` |
| a provider feature alone, which turned on ring | the provider feature plus `ring`, `aws-lc`, `aws-lc-fips` or `rustcrypto` |
| `vault-transit-kms-encryption` | `hashicorp-vault-transit-kms-encryption` |
| `vault-transit-kms-encryption-base` | `hashicorp-vault-transit-kms-encryption-base` |
| `vault-transit-kms-encryption-tls-roots`, `-tls-webpki` | `hashicorp-vault-transit-kms-encryption-tls-roots`, `-tls-webpki` |
| `vault-transit-kms-encryption-tls-aws-lc-rs`, `-tls-ring` | `hashicorp-vault-transit-kms-encryption-tls-aws-lc-rs`, `-tls-ring` |

ring is no longer turned on by the provider features. A 0.29 build that relied on it fails with
"kms-aead needs a crypto backend for its KMS providers", so add a backend feature. `aws-lc` adds
no second crypto library to a cloud provider build, see [Choosing a
backend](./getting-started.md#choosing-a-backend).

The crate declares `rust-version = "1.99"`.

## Names

| 0.29 | 0.30 |
|---|---|
| `KmsAeadRingEnvelopeEncryption<P>` | `KmsAeadEnvelope<P, Ring>`, with the backend as a type parameter |
| `KmsAeadRingEnvelopeEncryption::new(provider).await?` | `KmsAeadEnvelope::<P, Ring>::new(provider)?`, not `async`, on AES-256-GCM rather than ChaCha20-Poly1305, see [Default algorithm](#default-algorithm) |
| `KmsAeadRingEnvelopeEncryption::with_algorithm(provider, &ring::aead::AES_256_GCM)` | `KmsAeadEnvelope::<P, Ring>::with_options(provider, KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm))` |
| `with_options`, `with_algorithm_options` | `KmsAeadEnvelope::<P, Ring>::with_options(provider, options)` |
| `KmsAeadRingEnvelopeEncryptionOptions` | `KmsAeadEnvelopeOptions` |
| `KmsAeadRingEncryptionProvider` | `KmsAeadEncryptionProvider`, see [Your own provider](#your-own-provider) |
| module `kms_aead::ring_encryption` | removed; `AeadCipher<Ring>`, with `AeadCipher` at the crate root and `Ring` in `kms_aead::backends` |
| `RingAeadEncryption::new()` | `AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)` |
| `RingAeadEncryption::with_algorithm(&ring::aead::AES_256_GCM, rand)` | `AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)` |
| `RingAeadEncryption::with_rand`, `with_options`, `with_algorithm_options` | removed; the backend owns its CSPRNG, and the random nonce was the only option |
| `RingAeadEncryptionOptions`, `RingAeadEncryptionNonceKind` | removed |
| `RingAeadEncryption.algo` | `AeadCipher::algorithm()` |
| `RingAeadEncryption::generate_data_encryption_key()` | `AeadCipher::generate_dek()` |
| `kms_aead::kms_envelope_encryption::…` | the same names at the crate root |
| `CipherText(bytes)` | `Encrypted::<SecretValue, Bare>::try_from(bytes)?`, which checks the layout |
| `CipherTextWithEncryptedKey(bytes)` | `Encrypted::<SecretValue, Envelope>::try_from(bytes)?`, which checks the layout |
| `CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)` | `Encrypted::<SecretValue, Envelope>::join(&bare, &encrypted_dek)?`, in Tink's KMS envelope format |
| `cipher_text.to_hex_string()` | `value.to_hex_string()`, read back with `Encrypted::try_from_hex_string` |
| `cipher_text == other` | `value.value() == other.value()` |
| `EncryptedDataEncryptionKey::new(encrypted, key_version)` | `EncryptedDataEncryptionKey::new(bytes)`: the provider's bytes, which carry the key version where the KMS needs one |
| `encrypted_dek.wrapped()`, `to_bytes()?`, `TryFrom<&[u8]>` | `encrypted_dek.value()` and `EncryptedDataEncryptionKey::from(bytes)` |
| `encrypted_dek.to_hex_string()?` | `encrypted_dek.to_hex_string()`, infallible |
| `encrypted_dek.key_version()` | removed; the `key_version` field of the KMS spans |
| `kms_aead::KmsKeyVersion` | `kms_aead::providers::KmsKeyVersion`, the type of `AzureKmsKeyRef::key_version` |
| `DataEncryptionKey(secret)`, `dek.0` | `DataEncryptionKey::from(secret)`, `dek.value()` |
| `errors::BoxedError` | removed |

HashiCorp Vault Transit types have the `Hc` prefix:

| 0.29 | 0.30 |
|---|---|
| `VaultTransitProvider` | `HcVaultTransitProvider` |
| `VaultTransitProviderOptions` | `HcVaultTransitProviderOptions` |
| `VaultTransitKeyRef` | `HcVaultTransitKeyRef` |
| `VaultTransitToken` | `HcVaultTransitToken` |
| `examples/vault_transit_kms.rs` | `examples/hc_vault_transit_kms.rs` |

## Traits replaced by inherent methods

`AeadEncryption` and `KmsAeadEnvelopeEncryption` are gone. Their methods are inherent methods of
`AeadCipher` and `KmsAeadEnvelope`, so delete the trait imports. The AAD is any
`&(impl AsRef<[u8]> + ?Sized)`, like 0.29's `Aad: AsRef<[u8]>`, so `&aad` still compiles, and the
calls that make no KMS call are not `async`:

| 0.29 | 0.30 |
|---|---|
| `use kms_aead::KmsAeadEnvelopeEncryption;` `envelope.encrypt_value(&aad, &value).await?` | `envelope.encrypt(&aad, &value).await?` |
| `envelope.encrypt_value_with_dek(&aad, &value, &dek).await?` | `envelope.encrypt_with_dek(&aad, &value, &dek)?` |
| `envelope.decrypt_value(&aad, &cipher_text).await?` | `envelope.decrypt(&aad, &value).await?` |
| `envelope.decrypt_value_with_dek(&aad, &cipher_text, &dek).await?` | `envelope.decrypt_with_dek(&aad, &bare, &dek)?` |
| `encrypt_value_with_encrypted_dek`, `decrypt_value_with_encrypted_dek` | `encrypt_with_encrypted_dek`, `decrypt_with_encrypted_dek` |
| `KmsAeadEnvelopeEncryption::<Aad>::generate_new_dek(&envelope)` | `envelope.generate_encrypted_dek()` |
| `use kms_aead::AeadEncryption;` `cipher.encrypt_value(&aad, &value, &key).await?` | `cipher.encrypt_bare(&aad, &value, &key)?` |
| `cipher.decrypt_value(&aad, &cipher_text, &key).await?` | `cipher.decrypt_bare(&aad, &bare, &key)?` |

Every cipher text is an `Encrypted<T, F>`, see [Formats](./formats.md#formats-of-encrypted). It
has its own `value()` and `into_value()`. Those of `EncryptedDataEncryptionKey` come from
`ValueStruct`, which the crate re-exports: `use kms_aead::ValueStruct`. `DataEncryptionKey` no
longer implements `ValueStruct`, and has its own `value()`.

## Your own provider

An application's own implementation of the provider trait:

- implements `KmsAeadEncryptionProvider` instead of `KmsAeadRingEncryptionProvider`;
- adds `fn kek(&self) -> &KekRef`, with `KekProvider::Other` and a key name that identifies the
  key;
- deletes `generate_encryption_key` when it returned the backend's key. The replacement,
  `generate_key_material(&self, len)`, has a default implementation that lets the backend generate
  the key, and is implemented only for a KMS generator;
- returns `EncryptedDataEncryptionKey::new(bytes)`. A KMS that needs the key version to decrypt
  gets it from those bytes, as the Azure provider's do.

The plaintext the provider encrypts is the DEK serialised as a Tink key, see
[Formats](./formats.md#serialised-deks). The library never inspects the provider's own bytes.

## Errors

`KmsAeadError` is `#[non_exhaustive]`, so an exhaustive `match` on it needs a `_` arm. It has two
new variants, `UnsupportedAlgorithm` and `LegacyFormat`. `code()` returns the code of any variant,
and `source()` returns the root cause.

The `From` conversions of SDK errors into `KmsAeadError` are gone: `gcloud_sdk::error::Error`,
`gcloud_sdk::tonic::Status`, the AWS `SdkError`, the hyper client error, `azure_core::Error` and
`SystemTimeError`. Map an SDK error in the application.

`ConstantTimeEq` is no longer implemented on the public types. `==` still compares in constant
time. The `Debug` of `Encrypted` prints only the length, and `==` is gone from randomised values:
only an `Encrypted<T, Deterministic>` has it.

Error codes that changed:

| 0.29 | 0.30 | Where |
|---|---|---|
| `INVALID_CIPHERTEXT` | `INVALID_CIPHER_TEXT_FORMAT` | `Encrypted::try_from` of a `Bare` value shorter than a nonce and a tag |
| `ENCRYPTION` | `RANDOM_GENERATOR` | a CSPRNG failure, for a nonce or a key |
| `DECRYPT_KEY` | `ENCRYPT_KEY` | the GCP encryption, when its request cannot be built |
| `DECRYPT_KEY` | `RANDOM_GENERATOR` | the GCP KMS generator, when its request cannot be built |
| `SYSTEM_TIME_ERROR` | removed | |
| `UNKNOWN_ENCRYPTED_KEY_LAYOUT` | removed | stored encrypted DEKs are the provider's bytes |
| `AZURE_KEY_VERSION_MISSING` | `AZURE_ENCRYPTED_DEK_FORMAT` | the Azure decryption of bytes outside its layout; the old code stays for a 0.29 value without a key version, with `legacy-formats` |

The other 0.29 codes keep their spelling. The new codes are listed in
[Error handling](./errors.md#codes).

## AWS KMS decryption names the key

The AWS provider sends the configured key as `KeyId` on every decryption. In 0.29 a decryption left
it out, so AWS KMS decrypted under whichever key the encrypted DEK named, for any key the principal
may decrypt with. A 0.30 process refuses a DEK encrypted under another key with
`IncorrectKeyException`. A deployment that relied on decrypting under a second key configures a
provider per key.

An alias name such as `alias/orders` becomes an alias ARN, where 0.29 built a key ARN of it.
Configure the key ARN rather than an alias, see [AWS KMS](./providers/aws.md#key-arn-and-aliases).

## Default algorithm

The default algorithm of `KmsAeadEnvelope` is AES-256-GCM, which every Tink implementation reads
in a KMS envelope. The default of 0.29 was ChaCha20-Poly1305.

A value does not record its algorithm. Values sealed under the default of 0.29 open only with
ChaCha20-Poly1305 configured, and an envelope on the new default fails them with `DECRYPT`. A 0.29
envelope that named no algorithm becomes:

```rust,no_run
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadEnvelope, KmsAeadEnvelopeOptions};

# async fn example(key_ref: GcpKmsKeyRef) -> kms_aead::KmsAeadResult<()> {
// 0.29: KmsAeadRingEnvelopeEncryption::new(provider).await?
let envelope = KmsAeadEnvelope::<GcpKmsProvider, Ring>::with_options(
    GcpKmsProvider::new(&key_ref).await?,
    KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
)?;
# let _ = envelope;
# Ok(())
# }
```

Configure it on every envelope that reads those values, on the one that upgrades them, see
[Old values](#old-values), and on every envelope that writes new values beside them: a reader
cannot tell the two algorithms apart. AES-256-GCM suits a column that holds no 0.29 values.

## Old values

0.30 writes Tink's KMS envelope, and encrypts every DEK but Azure's as a serialised Tink key. 0.29
wrote envelope layout v1 and the encrypted DEK layout v1 `[0xFF][0x01]…`, and 0.28.1 and earlier a
length-prefixed envelope, all with the raw DEK encrypted. 0.30 reads them only with the deprecated
`legacy-formats` feature, and fails with `LEGACY_FORMAT` without it, see
[Formats](./formats.md#values-written-by-029-and-earlier).

The envelopes that read and upgrade those values keep the algorithm they were sealed with, see
[Default algorithm](#default-algorithm).

To move stored values to the new format:

1. upgrade every process that reads the values to 0.30 with `legacy-formats`. 0.29 and earlier
   cannot read Tink's format, so no process writes it before every reader has the upgrade;
2. rewrite the stored values with `upgrade_legacy_value` and `upgrade_legacy_encrypted_dek` of
   `KmsAeadEnvelope`, one or two KMS calls per value, see
   [Upgrading stored values](./formats.md#upgrading-stored-values). `upgrade_legacy_value` takes
   the value's AAD, and fails with `DECRYPT` on a value that does not open under the envelope's
   algorithm and that AAD;
3. turn the feature off.

`Encrypted::<T, Envelope>::separate` reads Tink's format only, with or without the feature, so
code that separated stored 0.29 values runs after the sweep.
