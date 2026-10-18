# Google Cloud KMS

Feature `gcp-kms-encryption`, or `gcp-kms-encryption-webpki` for the bundled WebPKI roots.

`GcpKmsKeyRef` names a CryptoKey by its project, location, key ring and key. The provider encrypts
under the primary version of the key, and each encrypted DEK records the version that encrypted it,
so DEKs encrypted before a rotation still decrypt afterwards.

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider, GcpKmsProviderOptions};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);

let provider = GcpKmsProvider::new(&kms_ref).await?;
let envelope = KmsAeadEnvelope::<GcpKmsProvider, AwsLc>::new(provider)?;

// Or with DEKs from the Cloud KMS generator at the HSM protection level
let envelope = KmsAeadEnvelope::<GcpKmsProvider, AwsLc>::new(
    GcpKmsProvider::with_options(
        &kms_ref,
        GcpKmsProviderOptions::new().with_use_kms_random_gen(true),
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

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/gcp_kms.rs).

## Authentication

`GcpKmsProvider::new` and `with_options` build a Cloud KMS client with the application default
credentials. They look for credentials in the following places, preferring the first location
found:

- A JSON file whose path is specified by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable;
- A JSON file in a location known to the gcloud command-line tool using
  `gcloud auth application-default login`;
- On Google Compute Engine, Cloud Run, GKE, etc., the metadata server.

For local development don't confuse `gcloud auth login` with `gcloud auth application-default login`,
since the first one authorises only the `gcloud` tool to access the Cloud Platform.

`GcpKmsProvider::with_client` takes a client the application built itself, for other
credentials.

The principal needs `cloudkms.cryptoKeyVersions.useToEncrypt` and `useToDecrypt` on the key, as
in the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role, and `cloudkms.locations.generateRandomBytes`
on the location when the KMS generator is on.

## Errors

A failed KMS call is a `NetworkError` whose code is the gRPC status code, such as
`PermissionDenied` or `NotFound`.
