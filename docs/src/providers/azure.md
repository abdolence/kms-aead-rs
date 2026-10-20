# Azure Key Vault

Feature `azure-kms-encryption`, or one of the TLS variants in
[Cargo features](../features.md).

`AzureKmsKeyRef` names the key by the vault URL and the key name. Without a key version, the
latest version encrypts new DEKs. Each encrypted DEK records the version that encrypted it, and the
decryption uses that version, so DEKs encrypted before a rotation still decrypt afterwards.

The provider takes any Azure credential, for example one from `azure_identity`:

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let kms_ref = AzureKmsKeyRef::new(
    "https://my-vault.vault.azure.net".to_string(),
    "my-key".to_string(),
);

// Azure CLI or Azure Developer CLI credentials for local runs;
// use `azure_identity::ManagedIdentityCredential` in Azure deployments
let credential = azure_identity::DeveloperToolsCredential::new(None)?;

let provider = AzureKmsProvider::new(&kms_ref, credential)?;
let envelope = KmsAeadEnvelope::<AzureKmsProvider, AwsLc>::new(provider)?;

let cipher_text = envelope
    .encrypt(b"orders/1042", &SecretValue::from("secret"))
    .await?;
# let _ = cipher_text;
# Ok(())
# }
```

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/azure_kms.rs).

The provider sends no request until the first encryption or decryption. The principal needs the
wrapKey and unwrapKey key operations, as in the "Key Vault Crypto User" role.

## Options

`AzureKmsProviderOptions` has:

- `algorithm`: the wrap algorithm, which must suit the key type: `RsaOaep256` for RSA keys,
  `A256Kw` for Managed HSM AES keys. The default, `DEFAULT_ALGORITHM`, is `RsaOaep256` for every
  key, so a Managed HSM AES key needs `algorithm` set to `A256Kw` and the provider built with
  `AzureKmsProvider::with_options`. `RsaOaep` (SHA-1) is accepted for existing keys; `Rsa1_5`
  and unknown algorithms are refused. Encrypted DEKs do not record the algorithm, so it stays fixed for the
  life of the key;
- `client_options`: settings passed to the Azure SDK, such as a custom HTTP transport or retry
  policy.

A Managed HSM AES key, with `A256Kw`:

```rust,no_run
use azure_security_keyvault_keys::models::EncryptionAlgorithm;
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions};

# fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let kms_ref = AzureKmsKeyRef::new(
    "https://my-hsm.managedhsm.azure.net".to_string(),
    "my-aes-key".to_string(),
);
let credential = azure_identity::DeveloperToolsCredential::new(None)?;

let provider = AzureKmsProvider::with_options(
    &kms_ref,
    AzureKmsProviderOptions::new().with_algorithm(EncryptionAlgorithm::A256Kw),
    credential,
)?;
# let _ = provider;
# Ok(())
# }
```

## Encrypted DEKs

Key Vault decrypts only with the key version that encrypted, so the provider's encrypted DEK carries
it before Key Vault's encrypted DEK, in the library's own layout, see
[Formats](../formats.md#encrypted-deks). No Tink client exists for Azure, so Tink does not read the
values of this provider, and the plaintext Key Vault encrypts is the raw DEK of 16, 32 or 64 bytes,
as in 0.29, rather than the DEK as Tink serialises it. Every wrap algorithm takes it, `A256Kw` too,
which takes only multiples of 8 bytes. Store the encrypted DEK as it is, see
[Envelope encryption](../envelope-encryption.md#storing-encrypted-deks).

## Key versions and rotation

A rotation adds a version to the key, by hand or by the key's rotation policy. Without a key version
in `AzureKmsKeyRef`, the latest version encrypts new DEKs; with one, that version does, so move it
to the new version before a sweep. A sweep with a provider pinned to the old version re-encrypts
under the old version. The `kek_version()` of the encrypted DEK an encryption returns is the
version Key Vault encrypted with, read from the `kid` of its response.

Once the sweep has reached every value, see
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
disable the old version: Key Vault refuses to decrypt under it, and enabling it again restores it.
Key Vault deletes a key with all its versions and never one version alone, so the old version stays
disabled rather than destroyed.

## Errors

A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
`AZURE_STATUS_<status>` when the response has none. Which statuses are a `NetworkError` and which an
`EncryptionError` is in [Retries](../errors.md#retries). A decryption of an encrypted DEK in another
layout fails with `AZURE_ENCRYPTED_DEK_FORMAT`, before any request.
