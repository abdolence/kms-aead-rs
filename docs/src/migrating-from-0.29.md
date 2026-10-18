# Migrating from 0.29

0.30 replaces the ring-only API with a choice of crypto backends, adds store-less DEK reuse,
the DEK cache, deterministic encryption and the local KMS, and makes ring optional. Stored values
need no migration: every algorithm writes the same bytes on every backend, and envelope layout v1
is unchanged. Values written by 0.28.1 and earlier need the `legacy-formats` feature, see
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
| `CipherTextWithEncryptedKey::new(&cipher_text, &encrypted_dek)` | `CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?` |
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

`value()` and `into_value()` of `CipherText`, `CipherTextWithEncryptedKey` and
`DeterministicCipherText` come from `ValueStruct`, which the crate re-exports: `use
kms_aead::ValueStruct`. `DataEncryptionKey` no longer implements `ValueStruct`, and has its own
`value()`.

## Your own provider

An application's own implementation of the provider trait:

- implements `KmsAeadEncryptionProvider` instead of `KmsAeadRingEncryptionProvider`;
- adds `fn kek(&self) -> &KekRef`, with `KekProvider::Other` and a key name that identifies the
  key;
- deletes `generate_encryption_key` when it returned the backend's key. The replacement,
  `generate_key_material(&self, len)`, has a default implementation that lets the backend generate
  the key, and is implemented only for a KMS generator.

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

0.29 read every layout written since 0.8.0. 0.30 reads the length-prefixed envelope and the bare
encrypted key, the layouts of 0.28.1 and earlier, only with the deprecated `legacy-formats`
feature, and fails with `LEGACY_FORMAT` without it. To keep reading such values:

1. enable `legacy-formats`;
2. rewrite the stored values with the upgrade functions, see
   [Upgrading stored values](./formats.md#upgrading-stored-values);
3. turn the feature off.

Values written by 0.29 read without the feature.
