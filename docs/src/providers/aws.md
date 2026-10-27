# AWS KMS

Feature `aws-kms-encryption`.

`AwsKmsKeyRef` names the key by the AWS account and the key id, which is anything AWS KMS
accepts: a key id, a key ARN, an alias name such as `alias/orders`, or an alias ARN.

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{AwsKmsKeyRef, AwsKmsProvider, AwsKmsProviderOptions};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = AwsKmsKeyRef::new(
    "123456789012".to_string(),
    "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab".to_string(),
);

let provider = AwsKmsProvider::new(&kms_ref).await?;
let envelope = KmsAeadEnvelope::<AwsKmsProvider, AwsLc>::new(provider)?;

// Or with DEKs from AWS KMS GenerateRandom
let envelope = KmsAeadEnvelope::<AwsKmsProvider, AwsLc>::new(
    AwsKmsProvider::with_options(
        &kms_ref,
        AwsKmsProviderOptions::new().with_use_kms_random_gen(true),
    )
    .await?,
)?;

let cipher_text = envelope
    .encrypt(b"orders/1042", &SecretValue::from("secret"))
    .await?;
# let _ = cipher_text;
# Ok(())
# }
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/aws_kms.rs).

## Authentication and region

`AwsKmsProvider::new` loads the AWS configuration from the environment, as the AWS SDK does:
environment variables, the shared config and credentials files, the instance or container
role, and the session of `aws login`. It sends no request, so missing credentials or an unreachable endpoint fail the first
encryption or decryption.

Without `aws_region` in the key reference, the provider takes the region of the AWS
configuration it loads. Set one with `AwsKmsKeyRef::new(..).with_aws_region(region)`.

The principal needs `kms:Encrypt` and `kms:Decrypt` on the key, and `kms:GenerateRandom` when
the KMS generator is on.

## Key ARN and aliases

A decryption names the configured key to AWS KMS, so a DEK encrypted under another key fails with
`IncorrectKeyException`, even when the principal may decrypt with that key.

Configure the key ARN rather than an alias: a DEK encrypted under an alias that later moves to
another key fails to decrypt with `IncorrectKeyException`.

The provider turns the key id into an ARN with the region and the account: an alias name into
an alias ARN, a key id into a key ARN, and an ARN stays as it is. That ARN always starts with
`arn:aws:`, so outside the `aws` partition, such as in GovCloud or China, give the full ARN.

## Key versions and rotation

AWS KMS rotates the key material of a key, on its rotation schedule or on demand, and keeps every
earlier key material for as long as the key exists. A DEK encrypted before a rotation decrypts
afterwards. An encryption's response names no key material, so the `kek_version()` of the
encrypted DEK it returns is `None`.

Key material that AWS KMS generated cannot be disabled or deleted on its own. The sweep of
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation)
is optional for it: it moves each DEK to the current key material, and with nothing to disable,
the check and the destruction do not apply.

Imported key material is deleted in two ways: by `DeleteImportedKeyMaterial`, for the material a
`KeyMaterialId` names or the current one without it, and at its expiry. `ExpirationModel` defaults
to `KEY_MATERIAL_EXPIRES`, and at its `ValidTo`, at most 365 days after the import, AWS KMS deletes
the material without any call. Either way the key moves to `PendingImport`, and AWS KMS refuses
every operation with it, whichever material a DEK is under, until the same material is imported
again. Import with `KEY_MATERIAL_DOES_NOT_EXPIRE`, or import again before `ValidTo`, and
keep a copy of every material to import again.

A sweep therefore retires no imported key material from a key in use, and with every
`kek_version` `None`, neither a keyring record nor a stored `kek_version` shows which DEKs are under
which material. After a deletion or an expiry, import the material again and decrypt every stored
DEK: each keyring's with `reencrypt_deks`, the application's own as in
[The check](../envelope-encryption.md#the-check). An error means the key is still in
`PendingImport`: `ListKeyRotations` lists each material with its import state, and the one still
missing is imported again.

## Asymmetric keys

A KMS key of the spec `RSA_2048`, `RSA_3072` or `RSA_4096` with the usage `ENCRYPT_DECRYPT` is an
asymmetric KEK, see [Asymmetric KEKs](../asymmetric-kek.md):

- `AwsKmsProvider::public_key()` sends `GetPublicKey` for the configured key and returns the
  DER SubjectPublicKeyInfo, for the producers. The key must be of usage `ENCRYPT_DECRYPT` and list
  `RSAES_OAEP_SHA_256` among its `EncryptionAlgorithms`, and the call fails with
  `ASYMMETRIC_KEK_PUBLIC_KEY` otherwise, and when the response holds no public key;
- a decryption of a `0x02` encrypted DEK sends `Decrypt` with the configured key as `KeyId`,
  `EncryptionAlgorithm` `RSAES_OAEP_SHA_256` and the RSA block as `CiphertextBlob`. AWS KMS takes no
  encryption context with the RSA algorithms. The encrypted DEK records no key version, as under a
  symmetric key;
- AWS KMS does not rotate an asymmetric key: a rotation is a new key, by hand, and so a new
  keyring;
- the principal of a reader needs `kms:Decrypt` on the key, and the administration also
  `kms:GetPublicKey`. Nobody needs `kms:Encrypt`.

An asymmetric key is configured by its ARN, as a symmetric key is. AWS prices and limits the RSA
requests apart from the symmetric ones, see
[Keyrings under an asymmetric KEK](../asymmetric-kek.md#keyrings-under-an-asymmetric-kek).

## Signing

`AwsKmsSigningProvider` signs with an asymmetric KMS key of the usage `SIGN_VERIFY`, see
[Signatures and MACs](../signing.md). `AwsKmsSigningKeyRef` names the key as `AwsKmsKeyRef` does,
and adds the algorithm: `Ed25519` for an `ECC_NIST_EDWARDS25519` key and `EcdsaP256Sha256` for
`ECC_NIST_P256`.

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::formats::PublicKeyFormat;
use kms_aead::providers::{AwsKmsSigningKeyRef, AwsKmsSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm};

# async fn example() -> kms_aead::KmsAeadResult<()> {
let key_ref = AwsKmsSigningKeyRef::new(
    "123456789012".to_string(),
    "arn:aws:kms:eu-west-1:123456789012:key/1234abcd-12ab-34cd-56ef-1234567890ab".to_string(),
    SigningAlgorithm::EcdsaP256Sha256,
);

let provider = AwsKmsSigningProvider::new(&key_ref).await?;
let signer = Signer::<_, AwsLc>::new(provider).await?;

// The public key to publish for the verifiers
let jwk = signer.verifying_key().encode(PublicKeyFormat::Jwk)?;
# let _ = jwk;
# Ok(())
# }
```

The provider loads the AWS configuration and takes the region as `AwsKmsProvider` does, and
`AwsKmsSigningProvider::with_client` takes a client the application built itself. Creating the
provider sends no request; `Signer::new` sends the first one.

An asymmetric key has no versions, and a rotation is a new key. Configure the key id or the key
ARN, never an alias: an alias that moves to another key would sign with a key that the key id of
the signature does not name. An alias name, `alias/…`, or an alias ARN fails at creation with
`AWS_SIGNING_KEY_ALIAS`, a `SystemError`.

- `sign` sends `Sign` with `MessageType` `RAW` and `ED25519_SHA_512` for Ed25519, and with `DIGEST`
  and `ECDSA_SHA_256` for P-256, where the message is the SHA-256 of the pre-image. The pre-image
  is at most 302 bytes, within the 4,096-byte limit of `Message`;
- a response whose `KeyId` is not the configured key fails with `SIGNING_KEY_MISMATCH`, and one
  whose `SigningAlgorithm` is not the requested one with `SIGNING_ALGORITHM_MISMATCH`. A P-256
  signature is DER, converted to `r || s`; one that is not strict DER, or an Ed25519 signature
  that is not 64 bytes, fails with `SIGNATURE_ENCODING`;
- `verifying_key` sends `GetPublicKey` and parses the DER `PublicKey`. A `KeySpec` other than the
  configured one fails with `SIGNING_ALGORITHM_MISMATCH`;
- the principal needs `kms:Sign` and `kms:GetPublicKey` on the key.

## Errors

An error AWS KMS returned keeps its AWS error code, such as `IncorrectKeyException` or
`NotFoundException`, and the message AWS KMS returned. An `EncryptionError` keeps the SDK error as
its root cause. A response without the encrypted DEK, the plaintext DEK or the random bytes it was
asked for fails with `AWS_ERROR`, an `EncryptionError`. Which
errors are a `NetworkError` and which an `EncryptionError` is in [Retries](../errors.md#retries).
`AwsKmsSigningProvider` returns the same codes, with a `SignatureError` where the encryption
provider returns an `EncryptionError`.
