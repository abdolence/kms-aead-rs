# KMS providers

A provider encrypts and decrypts data encryption keys with one key encryption key (KEK). Each one is
a type in `kms_aead::providers`, enabled by its feature:

| KMS | Type | Feature |
|---|---|---|
| Google Cloud KMS | `GcpKmsProvider` | `gcp-kms-encryption` |
| AWS KMS | `AwsKmsProvider` | `aws-kms-encryption` |
| Azure Key Vault and Managed HSM | `AzureKmsProvider` | `azure-kms-encryption` |
| HashiCorp Vault Transit | `HcVaultTransitProvider` | `hashicorp-vault-transit-kms-encryption` |
| A KEK the process holds | `LocalKmsProvider` | none, in every build |
| An RSA KEK the process holds | `LocalAsymmetricKmsProvider` | none, in every build |

Every KMS provider above implements the two provider traits, `KmsAeadEncryptionProvider`, which
encrypts DEKs, and `KmsAeadDecryptionProvider`, which decrypts them, and `KmsAeadEnvelope` takes
any of them:

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::KmsAeadEnvelope;

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let provider = GcpKmsProvider::new(&kms_ref).await?;
let envelope = KmsAeadEnvelope::<GcpKmsProvider, AwsLc>::new(provider)?;
# let _ = envelope;
# Ok(())
# }
```

Each provider names its configured KEK on every decryption, so a DEK encrypted under another KEK
fails at the KMS and never decrypts a value. `provider.kek()` returns that KEK as a `KekRef`: the
KMS and the key name. It is also the `provider` and `key` field of the [KMS
spans](./observability.md) and the key of the [DEK cache](./dek-caching.md). Nothing else is
checked: an encrypted DEK carries no context that the KMS authenticates, see [Security
considerations](./security.md#threat-model).

## Asymmetric KEKs

A KEK can be an RSA key pair: its public half encrypts a DEK with RSA-OAEP (RSA encryption with OAEP
padding), in the process of whoever holds the public key, and its private half decrypts it. Each
provider above reads the `0x02` encrypted DEK of such an encryption beside its own bytes, and
fetches the public key for the administration with a `public_key` call. No side needs the KMS
encrypt right: the encryption is a local operation, and the KMS only decrypts. The layout, the
choices and the limits are in [Asymmetric KEKs](./asymmetric-kek.md).

Two further providers are in every build and hold the public key:

- `PublicKeyKekProvider` encrypts, for a producer that must never decrypt. It implements
  `KmsAeadEncryptionProvider` alone, so an envelope over it has no call that decrypts a DEK or
  a value, and no keyring opens over it;
- `AsymmetricKekProvider` encrypts with the public key and decrypts through the KMS provider of the
  same KEK, for the keyring administration.

The call that fetches the public key, and the rights of a reader and of the administration:

| KMS | Public key | Reader | Administration, in addition |
|---|---|---|---|
| Google Cloud KMS | `GcpKmsProvider::public_key(&version)` | `cloudkms.cryptoKeyVersions.useToDecrypt`, as in `roles/cloudkms.cryptoKeyDecrypter` | `cloudkms.cryptoKeyVersions.viewPublicKey`, as in `roles/cloudkms.publicKeyViewer`. `roles/cloudkms.cryptoKeyDecrypter` does not carry it |
| AWS KMS | `AwsKmsProvider::public_key()` | `kms:Decrypt` on the key | `kms:GetPublicKey` on the key |
| Azure Key Vault | `AzureKmsProvider::public_key(None)` for the latest version, or `Some(&version)` | `keys/unwrap/action` | `keys/get`. "Key Vault Crypto Service Encryption User" carries read, `wrap` and `unwrap` and no decrypt |
| Vault Transit | `HcVaultTransitProvider::public_key(None)` or `Some(&version)` | `update` on `transit/decrypt/<key>` | `read` on `transit/keys/<key>` or `transit/export/public-key/<key>` |
| Local KMS | `LocalAsymmetricKmsProvider::public_key(None)` for its encrypting version | none | none |

`encrypts_with_public_key()` is `true` for `PublicKeyKekProvider`, `AsymmetricKekProvider` and
`LocalAsymmetricKmsProvider`, so that a keyring refuses the BigQuery and Tink exports its KEK
cannot serve.

## KMS random generators

By default a DEK comes from the CSPRNG of the crypto backend. The GCP and AWS providers can take
it from the KMS instead, at the cost of one more KMS request per new DEK:

- GCP: `GcpKmsProviderOptions::new().with_use_kms_random_gen(true)`, Cloud KMS
  `GenerateRandomBytes` at the HSM protection level;
- AWS: `AwsKmsProviderOptions::new().with_use_kms_random_gen(true)`, AWS KMS `GenerateRandom`.

Azure, Vault Transit and the local KMS always use the backend's CSPRNG. Nonces always come from
the backend's CSPRNG.

## Your own provider

An application can implement the provider traits for a KMS of its own, or as a wrapper around
another provider: `KmsAeadEncryptionProvider`, with `kek`, `encrypt_data_encryption_key` and the
defaulted `generate_key_material` and `encrypts_with_public_key`, and `KmsAeadDecryptionProvider`,
with `decrypt_data_encryption_key`. A provider that only encrypts implements the first alone, and
the calls that decrypt do not compile over it. A wrapper implements each trait where the provider it
wraps does, as the example in [Migrating from 0.30](./migrating-from-0.30.md#your-own-provider)
shows. The implementation:

- is `Send` and `Sync`, and writes `encrypt_data_encryption_key`, `decrypt_data_encryption_key`
  and `generate_key_material` as `async fn`, whose futures must be `Send`. The traits have no
  `dyn` form, so code that holds a provider is generic over it;
- returns from `kek()` a `KekRef` with `KmsProvider::Other` and a key name that identifies the
  key across every KMS instance it may address. A wrapper returns the inner provider's `kek()`;
- names that KEK to the KMS on every decryption;
- adds to the encrypted DEK that `encrypt_data_encryption_key` returns, with `with_kek_version`,
  the KEK version the KMS's response names, never the one it expects, and none when the response
  names none;
- returns `true` from `encrypts_with_public_key()` when it encrypts DEKs with the public half of a
  key pair, so that a keyring refuses the BigQuery and Tink exports its KEK cannot serve. The method
  has a default of `false`;
- keeps key material, plaintext or encrypted, out of its errors' `Display` and `Debug`.

`generate_key_material` has a default implementation that returns `Ok(None)`, so the backend
generates the key.
