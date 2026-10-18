# Azure Key Vault

Feature `azure-kms-encryption`, or one of the TLS variants in
[Getting started](../getting-started.md#features).

`AzureKmsKeyRef` names the key by the vault URL and the key name. Without a key version, the
latest version encrypts new DEKs. Each encrypted DEK records the version that encrypted it, and the
decryption uses that version, so DEKs encrypted before a rotation still decrypt afterwards.

The provider takes any Azure credential, for example one from `azure_identity`:

```rust,no_run
use kms_aead::providers::{AzureKmsKeyRef, AzureKmsProvider};
use kms_aead::{AwsLc, KmsAeadEnvelope};
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
    .encrypt_value(b"orders/1042", &SecretValue::from("secret"))
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

- `algorithm`: the wrap algorithm, `RsaOaep256` by default for RSA keys, `A256Kw` for Managed
  HSM AES keys. `RsaOaep` (SHA-1) is accepted for existing keys; `Rsa1_5` and unknown
  algorithms are refused. Encrypted DEKs do not record the algorithm, so it stays fixed for the
  life of the key;
- `client_options`: settings passed to the Azure SDK, such as a custom HTTP transport or retry
  policy.

## Encrypted DEKs

Key Vault decrypts only with the key version that encrypted, so the provider's encrypted DEK carries
it before Key Vault's encrypted DEK, in the library's own layout, see
[Formats](../formats.md#encrypted-deks). No Tink client exists for Azure, so Tink does not read the
values of this provider, and the plaintext Key Vault encrypts is the raw DEK of 16, 32 or 64 bytes,
as in 0.29, rather than the DEK as Tink serialises it. Every wrap algorithm takes it, `A256Kw` too,
which takes only multiples of 8 bytes. Store the encrypted DEK as it is, see
[Envelope encryption](../envelope-encryption.md#storing-encrypted-deks).

## Errors

A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
`AZURE_STATUS_<status>` when the response has none. A server error or a rate limit is a
`NetworkError`, any other status an `EncryptionError`. A decryption of an encrypted DEK in another
layout fails with `AZURE_ENCRYPTED_DEK_FORMAT`, before any request.
