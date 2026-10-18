# Migrating from 0.29

0.30 replaces the ring-only API with a choice of crypto backends, adds store-less DEK reuse,
the DEK cache, deterministic encryption and the local KMS, and makes ring optional. It writes
Tink's KMS envelope format for every provider, so values written by 0.29 and earlier read only
with the deprecated `legacy-formats` feature, which also rewrites them in the new format, see
[Old values](#old-values).

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
no second crypto library to a cloud provider build, see [Choosing a backend](./getting-started.md#choosing-a-backend).

The crate declares `rust-version = "1.99"`.

## Names

| 0.29 | 0.30 |
|---|---|
| `KmsAeadRingEnvelopeEncryption<P>` | `KmsAeadEnvelope<P, Ring>`, with the backend as a type parameter |
| `KmsAeadRingEnvelopeEncryption::new(provider).await?` | `KmsAeadEnvelope::<_, Ring>::new(provider)?`, not `async` |
| `KmsAeadRingEnvelopeEncryption::with_algorithm(provider, &ring::aead::AES_256_GCM)` | `KmsAeadEnvelope::<_, Ring>::with_options(provider, KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::Aes256Gcm))` |
| `with_options`, `with_algorithm_options` | `KmsAeadEnvelope::<_, Ring>::with_options(provider, options)` |
| `KmsAeadRingEnvelopeEncryptionOptions` | `KmsAeadEnvelopeOptions` |
| `KmsAeadRingEncryptionProvider` | `KmsAeadEncryptionProvider`, see [Your own provider](#your-own-provider) |
| module `kms_aead::ring_encryption` | removed; `AeadCipher<Ring>` at the crate root |
| `RingAeadEncryption::new()` | `AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)` |
| `RingAeadEncryption::with_algorithm(&ring::aead::AES_256_GCM, rand)` | `AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)` |
| `RingAeadEncryption::with_rand`, `with_options`, `with_algorithm_options` | removed; the backend owns its CSPRNG, and the random nonce was the only option |
| `RingAeadEncryptionOptions`, `RingAeadEncryptionNonceKind` | removed |
| `RingAeadEncryption.algo` | `AeadCipher::algorithm()` |
| `RingAeadEncryption::generate_data_encryption_key()` | `AeadCipher::generate_key()` |
| `kms_aead::kms_envelope_encryption::…` | the same names at the crate root |
| `CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)` | `CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?`, in Tink's KMS envelope format |
| `EncryptedDataEncryptionKey::new(wrapped, key_version)` | `EncryptedDataEncryptionKey::new(bytes)`: the provider's bytes, which carry the key version where the KMS needs one |
| `encrypted_dek.wrapped()`, `to_bytes()?`, `TryFrom<&[u8]>` | `encrypted_dek.value()` and `EncryptedDataEncryptionKey::from(bytes)` |
| `encrypted_dek.to_hex_string()?` | `encrypted_dek.to_hex_string()`, infallible |
| `encrypted_dek.key_version()` | removed; the `key_version` field of the KMS spans |
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
`AeadCipher` and `KmsAeadEnvelope`, so delete the trait imports. The AAD is `&[u8]` instead of a
generic `&Aad`, and the calls that make no KMS call are not `async`:

| 0.29 | 0.30 |
|---|---|
| `use kms_aead::KmsAeadEnvelopeEncryption;` `envelope.encrypt_value(&aad, &value).await?` | `envelope.encrypt_value(aad.as_bytes(), &value).await?` |
| `envelope.encrypt_value_with_dek(&aad, &value, &dek).await?` | `envelope.encrypt_value_with_dek(aad, &value, &dek)?` |
| `envelope.decrypt_value_with_dek(&aad, &cipher_text, &dek).await?` | `envelope.decrypt_value_with_dek(aad, &cipher_text, &dek)?` |
| `KmsAeadEnvelopeEncryption::<Aad>::generate_new_dek(&envelope)` | `envelope.generate_new_dek()` |
| `use kms_aead::AeadEncryption;` `cipher.encrypt_value(&aad, &value, &key).await?` | `cipher.encrypt_value(aad, &value, &key)?` |

`value()` and `into_value()` of `CipherText`, `CipherTextWithEncryptedKey`,
`EncryptedDataEncryptionKey` and `DeterministicCipherText` come from `ValueStruct`, which the crate re-exports: `use
kms_aead::ValueStruct`. `DataEncryptionKey` no longer implements `ValueStruct`, and has its own
`value()`.

## Your own provider

An application's own implementation of the provider trait:

- implements `KmsAeadEncryptionProvider` instead of `KmsAeadRingEncryptionProvider`;
- adds `fn kek(&self) -> &KekRef`, with `KekProvider::Other` and a key name that identifies the
  key;
- deletes `generate_encryption_key` when it returned the backend's key. The replacement,
  `generate_key_material(&self, len)`, has a default implementation that lets the backend generate
  the key, and is implemented only for a KMS generator;
- returns `EncryptedDataEncryptionKey::new(bytes)`. A KMS that needs the key version to unwrap
  gets it from those bytes, as the Azure provider's do.

The plaintext the provider wraps is the DEK serialized as a Tink key, see
[Formats](./formats.md#serialized-deks). The library never inspects the provider's own bytes.

## Errors

`KmsAeadError` is `#[non_exhaustive]`, so an exhaustive `match` on it needs a `_` arm. It has two
new variants, `UnsupportedAlgorithm` and `LegacyFormat`. `code()` returns the code of any variant,
and `source()` returns the root cause.

The `From` conversions of SDK errors into `KmsAeadError` are gone: `gcloud_sdk::error::Error`,
`gcloud_sdk::tonic::Status`, the AWS `SdkError`, the hyper client error, `azure_core::Error` and
`SystemTimeError`. Map an SDK error in the application.

`ConstantTimeEq` is no longer implemented on the public types. `==` still compares in constant
time. The `Debug` of `CipherText` and `CipherTextWithEncryptedKey` prints only the length.

Error codes that changed:

| 0.29 | 0.30 | Where |
|---|---|---|
| `INVALID_CIPHERTEXT` | `INVALID_CIPHER_TEXT_FORMAT` | `AeadCipher::decrypt_value` on a value too short for its nonce and tag |
| `ENCRYPTION` | `RANDOM_GENERATOR` | a CSPRNG failure, for a nonce or a key |
| `DECRYPT_KEY` | `ENCRYPT_KEY` | the GCP wrap, when its request cannot be built |
| `DECRYPT_KEY` | `RANDOM_GENERATOR` | the GCP KMS generator, when its request cannot be built |
| `SYSTEM_TIME_ERROR` | removed | |
| `UNKNOWN_ENCRYPTED_KEY_LAYOUT` | removed | stored wrapped DEKs are the provider's bytes |
| `AZURE_KEY_VERSION_MISSING` | `AZURE_WRAPPED_KEY_FORMAT` | the Azure unwrap of bytes outside its layout; the old code stays for a 0.29 value without a key version, with `legacy-formats` |

The other 0.29 codes keep their spelling. The new codes are listed in
[Error handling](./errors.md#codes).

## AWS KMS unwraps name the key

The AWS provider sends the configured key as `KeyId` on every unwrap. In 0.29 an unwrap left it
out, so AWS KMS unwrapped under whichever key the wrapped DEK named, for any key the principal may
decrypt with. A 0.30 process refuses a DEK wrapped under another key with `IncorrectKeyException`.
A deployment that relied on unwrapping under a second key configures a provider per key.

An alias name such as `alias/orders` becomes an alias ARN, where 0.29 built a key ARN of it.
Configure the key ARN rather than an alias, see [AWS KMS](./providers/aws.md#key-arn-and-aliases).

## Old values

0.30 writes Tink's KMS envelope, and wraps every DEK as a serialized Tink key. 0.29 wrote envelope
layout v1 and the encrypted key layout `[0xFF][0x01]…`, and 0.28.1 and earlier a length-prefixed
envelope, all with the raw DEK wrapped. 0.30 reads them only with the deprecated `legacy-formats`
feature, and fails with `LEGACY_FORMAT` without it, see [Formats](./formats.md#values-written-by-029-and-earlier).

The algorithm needs no change: the default stays ChaCha20-Poly1305, so a configuration that never
named one keeps reading its values. Tink for C++ and Python has no ChaCha20-Poly1305: for values
they read, configure AES-256-GCM for new values only, since a value opens only with the algorithm
it was sealed with.

To move stored values to the new format:

1. upgrade every process that reads the values to 0.30 with `legacy-formats`. 0.29 and earlier
   cannot read Tink's format, so no process writes it before every reader has the upgrade;
2. rewrite the stored values with `upgrade_legacy_value` and `upgrade_legacy_encrypted_key` of
   `KmsAeadEnvelope`, one or two KMS calls per value, see
   [Upgrading stored values](./formats.md#upgrading-stored-values);
3. turn the feature off.

`CipherTextWithEncryptedKey::separate` reads Tink's format only, with or without the feature, so
code that separated stored 0.29 values runs after the sweep.
