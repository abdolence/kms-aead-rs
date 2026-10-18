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
role, etc. It sends no request, so missing credentials or an unreachable endpoint fail the first
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
afterwards, and AWS KMS exposes no versions of a key, so `key_version` returns `None` and no earlier
key material can be disabled or deleted on its own.

The steps of [Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation)
are optional under AWS KMS: `reencrypt_dek` moves a DEK to the current key material, and nothing
needs the earlier material retired.

## Errors

An error AWS KMS returned keeps its AWS error code, such as `IncorrectKeyException` or
`NotFoundException`, and the message AWS KMS returned. A `NetworkError`:

- `ThrottlingException`, `KMSInternalException`, `DependencyTimeoutException` and
  `KeyUnavailableException`;
- any 5xx or 429 status;
- a timeout, a connection failure, or a response the SDK could not read.

Any other error, such as `AccessDeniedException`, `DisabledException` or a request that could not
be built or signed, is an `EncryptionError` whose root cause is the SDK error. See
[Error handling](../errors.md#retries).
