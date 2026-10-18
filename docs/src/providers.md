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
use kms_aead::{AwsLc, KmsAeadEnvelope};

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let envelope = KmsAeadEnvelope::<_, AwsLc>::new(GcpKmsProvider::new(&kms_ref).await?)?;
# let _ = envelope;
# Ok(())
# }
```

Each provider names its configured KEK on every unwrap, so a DEK wrapped under another KEK fails
at the KMS and never opens a value. `provider.kek()` returns that KEK as a `KekRef`: the KMS
and the key name. It is also the `provider` and `key` field of the [KMS spans](./observability.md)
and the key of the [DEK cache](./dek-caching.md). Nothing else is checked: a wrapped DEK carries
no context that the KMS authenticates, see [Security considerations](./security.md#threat-model).

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
- keeps key material, plaintext or wrapped, out of its errors' `Display` and `Debug`.

`generate_key_material` has a default implementation that returns `Ok(None)`, so the backend
generates the key.
