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
`wrapKey` and `unwrapKey` key operations, Key Vault's names for encrypting and decrypting a DEK, as
in the "Key Vault Crypto User" role.

## Options

`AzureKmsProviderOptions` has:

- `algorithm`: an `AzureKmsAlgorithm`, Key Vault's `alg` of the `wrapKey` and `unwrapKey`
  operations, which must suit the key type: `RsaOaepSha256` (`RSA-OAEP-256`) for RSA keys,
  `Aes256KeyWrap` (`A256KW`) for Managed HSM AES keys. The default, `DEFAULT_ALGORITHM`, is
  `RsaOaepSha256` for every key, so a Managed HSM AES key needs `algorithm` set to
  `Aes256KeyWrap` and the provider built with `AzureKmsProvider::with_options`. `RsaOaepSha1`
  (`RSA-OAEP`) is for an RSA key whose encrypted DEKs were written with it. The other AES key
  wraps, `Aes128KeyWrap` (`A128KW`), `Aes192KeyWrap` (`A192KW`), `Pkcs11AesKeyWrap`
  (`CKM_AES_KEY_WRAP`) and `Pkcs11AesKeyWrapWithPadding` (`CKM_AES_KEY_WRAP_PAD`), are for
  Managed HSM AES keys too. `RSA1_5` is not offered. Encrypted DEKs do not record the algorithm, so it
  stays fixed for the life of the key;
- `client_options`: settings passed to the Azure SDK, such as a custom HTTP transport or retry
  policy.

A Managed HSM AES key, with `Aes256KeyWrap`:

```rust,no_run
use kms_aead::providers::{
    AzureKmsAlgorithm, AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions,
};

# fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let kms_ref = AzureKmsKeyRef::new(
    "https://my-hsm.managedhsm.azure.net".to_string(),
    "my-aes-key".to_string(),
);
let credential = azure_identity::DeveloperToolsCredential::new(None)?;

let provider = AzureKmsProvider::with_options(
    &kms_ref,
    AzureKmsProviderOptions::new().with_algorithm(AzureKmsAlgorithm::Aes256KeyWrap),
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
as in 0.29, rather than the DEK as Tink serialises it. Every algorithm takes it, `Aes256KeyWrap`
too, which takes only multiples of 8 bytes. Store the encrypted DEK as it is, see
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

## Asymmetric keys

An RSA key of 2048, 3072 or 4096 bits, `RSA` or `RSA-HSM`, is an asymmetric KEK, see [Asymmetric
KEKs](../asymmetric-kek.md). The provider has always encrypted with it through `wrapKey`; a `0x02`
encrypted DEK moves the encryption into the producer, and the provider still decrypts through
`unwrapKey`:

- `AzureKmsProvider::public_key(None)` sends `GetKey` for the latest version, or
  `public_key(Some(&version))` for one, and returns the JSON Web Key's `n` and `e` as the public key
  of the version the `kid` of the response names. It fails with `ASYMMETRIC_KEK_PUBLIC_KEY` for a
  key whose `kty` is not `RSA` or `RSA-HSM`, whose `key_ops` lack `unwrapKey`, or whose `kid` names
  no version or another key;
- a decryption of a `0x02` encrypted DEK sends `unwrapKey` on the key and the version the encrypted
  DEK names, with `alg` `RSA-OAEP-256`. This path ignores `AzureKmsProviderOptions::algorithm`,
  which stays the algorithm of the `0x01` layout;
- the principal of a reader needs `keys/unwrap/action`, and the administration also `keys/get`. "Key
  Vault Crypto Service Encryption User" carries read, `wrap` and `unwrap` and no decrypt. Nobody
  needs `keys/wrap/action`.

An existing deployment on an RSA key is under an asymmetric KEK already and needs no re-encryption
to move its encryptions to the producers, see
[Migrating an Azure or Transit RSA deployment](../asymmetric-kek.md#migrating-an-azure-or-transit-rsa-deployment).
A Managed HSM AES key stays on `wrapKey` and `unwrapKey` with `Aes256KeyWrap`: it is a symmetric KEK
and has no public half.

## Signing

`AzureKmsSigningProvider` signs with one version of an EC `P-256` key, `EC` or `EC-HSM`, with
`ES256`, see [Signatures and MACs](../signing.md). Key Vault signs no Ed25519, so the provider's
algorithm is `EcdsaP256Sha256`. `AzureKmsSigningKeyRef` names the vault, the key and the version,
which a signer requires: it never follows the latest version.

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::formats::PublicKeyFormat;
use kms_aead::providers::{AzureKmsSigningKeyRef, AzureKmsSigningProvider, KmsKeyVersion};
use kms_aead::signing::Signer;

# async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let key_ref = AzureKmsSigningKeyRef::new(
    "https://my-vault.vault.azure.net".to_string(),
    "my-signing-key".to_string(),
    KmsKeyVersion::try_from("4387e9f3d6e14c459867679a90fd0f79".to_string())?,
);
let credential = azure_identity::DeveloperToolsCredential::new(None)?;

let provider = AzureKmsSigningProvider::new(&key_ref, credential)?;
let signer = Signer::<_, AwsLc>::new(provider).await?;

// The public key to publish for the verifiers
let jwk = signer.verifying_key().encode(PublicKeyFormat::Jwk)?;
# let _ = jwk;
# Ok(())
# }
```

`AzureKmsSigningProvider::with_client_options` takes the settings of the Azure SDK, such as a
custom HTTP transport or retry policy. Creating the provider sends no request and fails with
`AZURE_KEY_NAME` or `AZURE_VAULT_URL` as `AzureKmsProvider` does; `Signer::new` sends the first
request.

- `sign` calls the sign operation with `ES256`, the SHA-256 of the pre-image as `value` and the
  version in the request path. The `result` is `r || s` as RFC 7518 defines it, 64 bytes; another
  length fails with `SIGNATURE_ENCODING`;
- a response whose `kid` is not the configured vault, key and version, or has none, fails with
  `SIGNING_KEY_MISMATCH`;
- `verifying_key` calls `get_key` with the version and reads the `crv`, `x` and `y` of the JSON Web
  Key. A key that is not `EC` or `EC-HSM` on `P-256` fails with `SIGNING_ALGORITHM_MISMATCH`;
- the principal needs the `sign` and `get` key operations: the data actions
  `Microsoft.KeyVault/vaults/keys/sign/action` and `Microsoft.KeyVault/vaults/keys/read`, which
  "Key Vault Crypto User" grants.

A rotation is a new key version that a new signer names, see [Key ids and rotation](../signing.md#key-ids-and-rotation).

## Errors

A failed request carries Key Vault's error code, such as `Forbidden` or `KeyNotFound`, or
`AZURE_STATUS_<status>` when the response has none. Which statuses are a `NetworkError` and which an
`EncryptionError` is in [Retries](../errors.md#retries). `AzureKmsSigningProvider` returns the same
codes, with a `SignatureError` where the encryption provider returns an `EncryptionError`. A decryption of an encrypted DEK in another
layout fails with `AZURE_ENCRYPTED_DEK_FORMAT`, before any request.
