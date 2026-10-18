# KMS providers

A provider wraps and unwraps data encryption keys with one key encryption key (KEK). Each one is
a type in `kms_aead::providers`, enabled by its feature:

| KMS | Type | Feature |
|---|---|---|
| Google Cloud KMS | `GcpKmsProvider` | `gcp-kms-encryption` |
| AWS KMS | `AwsKmsProvider` | `aws-kms-encryption` |
| Azure Key Vault and Managed HSM | `AzureKmsProvider` | `azure-kms-encryption` |
| HashiCorp Vault Transit | `HcVaultTransitProvider` | `hashicorp-vault-transit-kms-encryption` |
| A KEK the process holds | `LocalKmsProvider` | none, in every build |

Every provider implements `KmsAeadEncryptionProvider`, and `KmsAeadEnvelope` takes any of them:

```rust,no_run
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{AeadBackend, KmsAeadEnvelope};

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let envelope = KmsAeadEnvelope::new(GcpKmsProvider::new(&kms_ref).await?, AeadBackend::AwsLc)?;
# let _ = envelope;
# Ok(())
# }
```

Each provider names its configured KEK on every unwrap, so a DEK wrapped under another KEK fails
at the KMS and never opens a value. `provider.kek()` returns that KEK as a `KekRef`: the KMS
and the key name. It is also the `provider` and `key` field of the [KMS spans](./observability.md)
and the key of the [DEK cache](./dek-caching.md).

## Binding a wrapped key

A wrap and an unwrap take an optional `DekBinding`: non-secret text that the KMS authenticates
with the wrapped key. Only an unwrap that names the same binding opens it, so a wrapped DEK
copied to another tenant or another record fails to unwrap. A binding is 1 to 1024 bytes of
UTF-8 without control characters.

| Provider | How the binding is sent | Unwrap with another binding |
|---|---|---|
| GCP | additional authenticated data of Encrypt and Decrypt, not written to audit logs | `InvalidArgument` |
| AWS | encryption context `{"kms-aead": <binding>}`, logged by CloudTrail in plain text | `InvalidCiphertextException` |
| Azure | not supported: Key Vault's wrapKey has no associated data | `AZURE_BINDING_UNSUPPORTED` before any request |
| Vault Transit | `associated_data`, Vault 1.13 or later and an AEAD key type | `VAULT_BINDING_IGNORED` when Vault ignored it |
| Local | part of the AES-256-GCM associated data of the wrap | `DECRYPT` |

`KmsAeadEnvelope` wraps and unwraps unbound. A bound DEK is wrapped and unwrapped through the
provider directly, or through `DekCache::with_key`:

```rust
use kms_aead::cache::DekCache;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, AeadBackend, AeadCipher, DekBinding};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("example".to_string())?, AeadBackend::Ring)?;
let cipher = AeadCipher::new(AeadBackend::Ring, AeadAlgorithm::Aes256Gcm)?;
let binding = DekBinding::try_from("tenant/42".to_string())?;

// A new DEK, wrapped with the binding, to store next to the tenant's values
let (dek, encrypted_dek) = cipher.generate_wrapped_key(&provider, Some(&binding)).await?;
let cipher_text = cipher.encrypt_value(b"orders/1042", &SecretValue::from("secret"), &dek)?;

// Unwrapping needs the same binding
let cache = DekCache::disabled();
let (decrypted, _) = cache
    .with_key(&provider, &encrypted_dek, Some(&binding), |dek| {
        cipher.decrypt_value(b"orders/1042", &cipher_text, dek)
    })
    .await?;
assert_eq!(decrypted?, SecretValue::from("secret"));
# Ok(())
# }
```

## KMS random generators

By default a DEK comes from the CSPRNG of the crypto backend. The GCP and AWS providers can take
it from the KMS instead, at the cost of one more KMS request per new DEK:

- GCP: `GcpKmsProviderOptions::new().with_use_kms_random_gen(true)`, Cloud KMS
  `GenerateRandomBytes` at the HSM protection level;
- AWS: `AwsKmsProviderOptions::new().with_use_kms_random_gen(true)`, AWS KMS `GenerateRandom`.

Azure, Vault Transit and the local KMS always use the backend's CSPRNG. Nonces always come from
the backend's CSPRNG.

## Your own provider

An application can implement `KmsAeadEncryptionProvider` for a KMS of its own, or as a wrapper
around another provider. The implementation:

- returns from `kek()` a `KekRef` with `KekProvider::Other` and a key name that identifies the
  key across every KMS instance it may address. A wrapper returns the inner provider's `kek()`;
- names that KEK to the KMS on every unwrap;
- fails a wrap or an unwrap with `Some(binding)` when its KMS cannot bind, and never wraps
  unbound in its place;
- keeps key material, plaintext or wrapped, out of its errors' `Display` and `Debug`.

`generate_key_material` has a default implementation that returns `Ok(None)`, so the backend
generates the key.
