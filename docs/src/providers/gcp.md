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

## Key versions and rotation

A rotation adds a version to the CryptoKey and makes it the primary version, by hand or on the
key's rotation schedule. New DEKs are encrypted under the primary version from then on, and Cloud
KMS decrypts every DEK with the version that encrypted it, for as long as that version is enabled.

The encrypted DEK is the Cloud KMS ciphertext as it is, which Tink and BigQuery read, and Cloud KMS
keeps the version inside it in a form it does not document. So `key_version` returns `None`, and
the version is recorded only in the `KMS encrypt DEK` span. A sweep with `reencrypt_dek` after a
rotation has to re-encrypt every value written before it, see
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).

To retire the old version, disable it once the sweep is done: decryptions under it fail, and
enabling it again restores them. Destroying it schedules its destruction, 30 days later by default,
and until then the version can be restored.

## Errors

The code of a failed KMS call is the gRPC status code. `Unavailable`, `DeadlineExceeded`,
`ResourceExhausted`, `Aborted`, `Internal`, `Unknown` and `Cancelled` are a `NetworkError`, any
other code, such as `PermissionDenied` or `NotFound`, an `EncryptionError`. See
[Error handling](../errors.md#retries).
