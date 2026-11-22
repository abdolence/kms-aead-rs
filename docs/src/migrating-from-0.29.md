# Migrating from 0.29

0.30 replaces the ring-only API with a choice of crypto backends, adds store-less DEK reuse,
the DEK cache, deterministic encryption and the local KMS, and makes ring optional. It writes
Tink's KMS envelope format for every provider, so values written by 0.29 and earlier read only
with the deprecated `legacy-formats` feature, which also rewrites them in the new format, see
[Old values](#old-values). The default algorithm of the envelope is AES-256-GCM, see
[Default algorithm](#default-algorithm).

0.30 also adds what 0.29 had no counterpart for, so nothing below maps to it:

- typed fields: `Encrypted<T, F>` takes any type that implements `Plaintext`, such as an
  application newtype, where the tables below name `SecretValue`, see
  [Stored values](./stored-values.md);
- beacons, for lookups of randomised fields, see [Beacons](./beacons.md);
- the `kms-aead-keyring` crate, with key versions kept in a store, staged rotation and sweeps, see
  [Keyring and field encryption](./keyring.md). Envelope values move to it with a sweep, see
  [Move envelope values to a keyring](./production/envelope-to-keyring.md).

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
no second crypto library to a cloud provider build, see [Choose a provider and a
backend](./getting-started/choosing.md#crypto-backends).

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
| `RingAeadEncryption::new()` | `AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?` |
| `RingAeadEncryption::with_algorithm(&ring::aead::AES_256_GCM, rand)` | `AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?` |
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
| `EncryptedDataEncryptionKey::new(encrypted, key_version)` | `EncryptedDataEncryptionKey::new(bytes)`: the provider's bytes, which carry the key version where the KMS needs one; a provider adds the KEK version the KMS reported with `with_kek_version` |
| `encrypted_dek.wrapped()`, `to_bytes()?`, `TryFrom<&[u8]>` | `encrypted_dek.value()`, a `&[u8]`, and `EncryptedDataEncryptionKey::from(bytes)` |
| `encrypted_dek.to_hex_string()?` | `encrypted_dek.to_hex_string()`, infallible |
| `encrypted_dek.key_version()` | `encrypted_dek.kek_version()`, the KEK version the KMS reported, on an encrypted DEK the provider has just returned or a keyring record holds, and `None` on one read back from the bytes; the `kek_version` field of the KMS spans |
| `kms_aead::KmsKeyVersion` | `kms_aead::providers::KekVersion`, `KmsKeyVersion` from 0.31, the type of `AzureKmsKeyRef::kek_version` |
| `AzureKmsKeyRef::with_key_version`, `opt_key_version`, `without_key_version`, `key_version`, `mopt_key_version`, `reset_key_version` | `AzureKmsKeyRef::with_kek_version`, `opt_kek_version`, `without_kek_version`, `kek_version`, `mopt_kek_version`, `reset_kek_version` |
| `AzureKmsKeyRef.key_version` | `AzureKmsKeyRef.kek_version` |
| `DataEncryptionKey(secret)`, `DataEncryptionKey::new(secret)`, `dek.0` | `DataEncryptionKey::from(secret)`, `dek.value()` |
| `errors::BoxedError` | removed |
| `AzureKmsProviderOptions::with_algorithm(EncryptionAlgorithm::RsaOaep256)`, with the Azure SDK's enum | `with_algorithm(AzureKmsAlgorithm::RsaOaepSha256)`; `RsaOaep` is `RsaOaepSha1`, `A128Kw`, `A192Kw` and `A256Kw` are `Aes128KeyWrap`, `Aes192KeyWrap` and `Aes256KeyWrap`, and `CkmAesKeyWrap` and `CkmAesKeyWrapPad` are `Pkcs11AesKeyWrap` and `Pkcs11AesKeyWrapWithPadding`. `Rsa1_5`, refused by 0.29 too, and the algorithms Key Vault does not wrap keys with have no variant |

HashiCorp Vault Transit types have the `Hc` prefix:

| 0.29 | 0.30 |
|---|---|
| `VaultTransitProvider` | `HcVaultTransitProvider` |
| `VaultTransitProviderOptions` | `HcVaultTransitProviderOptions` |
| `VaultTransitKeyRef` | `HcVaultTransitKeyRef` |
| `VaultTransitToken` | `HcVaultTransitToken` |
| `examples/vault_transit_kms.rs` | `examples/hc_vault_transit_kms.rs` |

`GcpKmsProviderOptions`, `AwsKmsProviderOptions` and `AzureKmsProviderOptions` are
`#[non_exhaustive]`, so a struct literal of one fails to compile. Build them with `new()` and the
`with_*` setters.

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

Every cipher text is an `Encrypted<T, F>`, see [Formats](./formats/values.md#formats-of-encrypted). It
has its own `value()` and `into_value()`, and so has `EncryptedDataEncryptionKey`.
`DataEncryptionKey` no longer implements `ValueStruct`, and has its own `value()`.

## Your own provider

An application's own implementation of the provider trait:

- implements `KmsAeadEncryptionProvider` instead of `KmsAeadRingEncryptionProvider`, without
  `#[async_trait]`. Its methods stay `async fn`, and their futures must be `Send`;
- adds `fn kek(&self) -> &KekRef`, with `KekProvider::Other`, `KmsProvider::Other` from 0.31, and
  a key name that identifies the key;
- deletes `generate_encryption_key` when it returned the backend's key. The replacement,
  `generate_key_material(&self, len)`, has a default implementation that lets the backend generate
  the key, and is implemented only for a KMS generator;
- returns `EncryptedDataEncryptionKey::new(bytes)` from `encrypt_data_encryption_key`, with the
  KEK version the KMS reported added by `with_kek_version`. A KMS that needs the key version to
  decrypt gets it from those bytes, as the Azure provider's do.

The plaintext the provider encrypts is the DEK serialised as a Tink key, see
[Formats](./formats/values.md#serialised-deks). The library never inspects the provider's own bytes.

The trait has no `dyn` form, so a `Box<dyn KmsAeadRingEncryptionProvider>` becomes a type
parameter `P: KmsAeadEncryptionProvider`, or an enum of the providers the application uses. The
trait requires `Send` and `Sync`, so `P: KmsAeadEncryptionProvider` needs no `+ Send + Sync`.

0.31 moves `decrypt_data_encryption_key` to a trait of its own, `KmsAeadDecryptionProvider`, see
[Migrating from 0.30](./migrating-from-0.30.md#your-own-provider).

## Errors

`KmsAeadError` is `#[non_exhaustive]`, so an exhaustive `match` on it needs a `_` arm. It has two
new variants, `UnsupportedAlgorithm` and `LegacyFormat`. `code()` returns the code of any variant,
and `source()` returns the root cause.

`KmsAeadSystemError`, `KmsAeadNetworkError`, `KmsAeadEncryptionError` and the type of their
`public` field, `KmsAeadErrorPublicGenericDetails`, are `#[non_exhaustive]` too, so a struct
literal of one fails to compile, and a pattern on one needs `..`. Build the errors with
`create(code, message)`, or with `new(public, message)` and, where it has one, `with_root_cause`,
and the details with `KmsAeadErrorPublicGenericDetails::new(code)`.

The `From` conversions of SDK errors into `KmsAeadError` are gone: `gcloud_sdk::error::Error`,
`gcloud_sdk::tonic::Status`, the AWS `SdkError`, the hyper client error, `azure_core::Error` and
`SystemTimeError`. Map an SDK error in the application.

The variant of a Google Cloud KMS or AWS KMS error follows its code. In 0.29 every gRPC status was
a `NetworkError` and every AWS error an `EncryptionError`. A `PermissionDenied` or `NotFound` from
Google Cloud KMS is an `EncryptionError` now, and a timeout, a connection failure or a
`ThrottlingException` from AWS KMS a `NetworkError`. The codes stay the same. See
[Retries](./errors.md#retries).

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
| `AZURE_WRAP_ALGORITHM` | removed | `AzureKmsAlgorithm` has no variant for `Rsa1_5` or an unknown algorithm |

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

A value does not record its algorithm. Values encrypted under the default of 0.29 decrypt only with
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
[Values written by 0.29 and earlier](#values-written-by-029-and-earlier).

The envelopes that read and upgrade those values keep the algorithm they were encrypted with, see
[Default algorithm](#default-algorithm).

To move stored values to the new format:

1. upgrade every process that reads the values to 0.30 with `legacy-formats`. 0.29 and earlier
   cannot read Tink's format, so no process writes it before every reader has the upgrade;
2. rewrite the stored values with `upgrade_legacy_value` and `upgrade_legacy_encrypted_dek` of
   `KmsAeadEnvelope`, one or two KMS calls per value, see
   [Upgrading stored values](#upgrading-stored-values). `upgrade_legacy_value` takes
   the value's AAD, and fails with `DECRYPT` on a value that does not decrypt under the envelope's
   algorithm and that AAD;
3. turn the feature off.

`Encrypted::<T, Envelope>::separate` reads Tink's format only, with or without the feature, so
code that separated stored 0.29 values runs after the sweep.

## Values written by 0.29 and earlier

The layouts of 0.29 and earlier are read only with the deprecated `legacy-formats` feature:

- `KmsAeadEnvelope::decrypt` reads the three envelope layouts, which `Encrypted<T, Envelope>`
  holds with the feature;
- the `*_with_encrypted_dek` calls and the DEK cache read the encrypted DEK layout v1 of 0.29 and
  raw encrypted DEKs.

`Encrypted::separate` never reads the older envelope layouts: for Azure, the encrypted DEK they
hold needs the provider to become its bytes.

Without the feature, reading them fails with `KmsAeadError::LegacyFormat`, the code
`LEGACY_FORMAT`, and one of:

- `KmsAeadLegacyFormat::EnvelopeV1`;
- `KmsAeadLegacyFormat::LengthPrefixedEnvelope`;
- `KmsAeadLegacyFormat::EncryptedDekV1`;
- `KmsAeadLegacyFormat::RawEncryptedDek`, for an encrypted DEK that decrypts to the raw key. The
  values of 32-bit targets before 0.24.0 fail with it, since their framing is Tink's.

The error never echoes the bytes read. With the feature, the first read of each layout in a
process logs one `WARN` event that names the upgrade methods. Without it, the `KMS AEAD decrypt`
spans of such values record `error_code=LEGACY_FORMAT`, see [Observability](./observability.md).

## Upgrading stored values

With `legacy-formats`, two methods of `KmsAeadEnvelope` rewrite a stored value in Tink's format,
and return `None` when it already is in it, so a sweep writes only the rows that change:

- `upgrade_legacy_value`, for envelope values;
- `upgrade_legacy_encrypted_dek`, for encrypted DEKs stored apart, such as the bytes of 0.29's
  `to_bytes`.

Each decrypts the DEK with the provider, without the DEK cache, and encrypts it again as a
serialised Tink key when it was in an older layout: one KMS call for a current value, two for an old
one. A value in Tink's framing needs the decryption to be told from the 32-bit layout before 0.24.0.
The AEAD bytes stay as they are.

An upgraded DEK is encrypted under the KEK's current version, so the upgrade also does what
`reencrypt_dek` and `reencrypt_encrypted_dek` do for a value or a DEK already in Tink's format, see
[Re-encrypt DEKs after a KEK rotation](./production/reencrypt-deks.md).
Those two refuse a layout of 0.29 or earlier with `LEGACY_FORMAT`, so a sweep after a KEK rotation
upgrades a value in an old layout and re-encrypts the DEK of a value in Tink's format.

The envelope's algorithm is the one the values were encrypted with: ChaCha20-Poly1305 for values
that 0.29 and earlier encrypted under their default. A raw DEK does not record its algorithm, and
the encrypted DEK of the upgrade records it as a Tink key type, so `upgrade_legacy_value` takes the
value's AAD and decrypts the value before it writes anything. Under another algorithm or another AAD
it fails with `DECRYPT`. `upgrade_legacy_encrypted_dek` has no value to decrypt, so it records the
envelope's algorithm for any key of its length. Be aware not to upgrade a DEK stored apart under
another algorithm than its values were encrypted with: use `upgrade_legacy_value` wherever the
values are at hand.

A sweep over stored rows:

```rust
use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{Encrypted, KmsAeadDecryptionProvider, KmsAeadEnvelope, KmsAeadResult};
use secret_vault_value::SecretValue;

/// A stored envelope value and the AAD it was encrypted under.
struct Row {
    aad: Vec<u8>,
    value: Vec<u8>,
}

/// Rewrites the envelope values of `rows` in Tink's format, and returns how many changed.
#[allow(deprecated)]
async fn upgrade_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &mut [Row],
) -> KmsAeadResult<usize>
where
    P: KmsAeadDecryptionProvider,
    B: AeadBackend,
{
    let mut upgraded = 0;
    for row in rows.iter_mut() {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.value.clone())?;
        if let Some(value) = envelope.upgrade_legacy_value(&row.aad, &stored).await? {
            row.value = value.into_value();
            upgraded += 1;
        }
    }
    Ok(upgraded)
}
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{AeadAlgorithm, AeadCipher, KmsAeadEncryptionProvider, KmsAeadEnvelopeOptions};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# // A value as 0.28.1 wrote it: [w: u64 BE][encrypted raw key][cipher text]
# let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
# let dek = cipher.generate_dek()?;
# let bare = cipher.encrypt_bare(b"aad", &SecretValue::from("secret"), &dek)?;
# let encrypted_dek = provider.encrypt_data_encryption_key(&dek).await?;
# let mut legacy = u64::try_from(encrypted_dek.value().len()).unwrap().to_be_bytes().to_vec();
# legacy.extend_from_slice(encrypted_dek.value());
# legacy.extend_from_slice(bare.value());
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     provider,
#     KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
# )?;
# let mut rows = vec![Row { aad: b"aad".to_vec(), value: legacy }];
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 1);
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 0);
# let upgraded = Encrypted::<SecretValue, Envelope>::try_from(rows[0].value.clone())?;
# let decrypted: SecretValue = envelope.decrypt(b"aad", &upgraded).await?;
# assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

Upgrade every reader to 0.30 before the sweep writes: 0.29 and earlier cannot read Tink's format.

## Deprecation

Reading the layouts of 0.29 and earlier is deprecated since 0.30.0 and will be removed in a later
breaking release, together with the `legacy-formats` feature and the upgrade methods, which carry
`#[deprecated]` from their first release, so every call site warns. Without the feature, the
older layouts keep failing with `LEGACY_FORMAT`.
