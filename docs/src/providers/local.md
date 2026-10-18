# Local KMS

`LocalKmsProvider` wraps DEKs with a key encryption key the process holds, with AES-256-GCM on
the backend it is built with. It is in every build, with no feature, for:

- development and tests without a cloud KMS;
- single-host installs where the operator protects the KEK.

kms-aead builds one only when the application calls one of its constructors; no provider falls
back to it. Each constructor logs one `INFO` event naming the KEK id, its versions and where
each version came from (`ephemeral`, `file`, `env` or `secret`), never the key.

## KEK ids and versions

A `LocalKekId` names the KEK: 1 to 255 bytes of ASCII alphanumerics, `-`, `_` and `.`. Every
wrapped DEK records it, and an unwrap refuses a DEK wrapped under another id. The id is also the
key of the [DEK cache](../dek-caching.md), so one id must name one set of KEK material: two
providers with the same id and different keys share cache entries.

A provider holds one or more `LocalKek` versions of 32 bytes each. The highest version wraps new
DEKs, and every version it holds unwraps. Each wrapped DEK records its version, so adding a new
version keeps the DEKs wrapped under older ones readable.

A KEK comes from one of:

- `LocalKek::from_secret`: bytes the application already holds, such as a key an operator
  unseals with their own tool (systemd-creds, a TPM, sops, age);
- `LocalKek::from_file`: the standard base64 of the 32 bytes in a file, trailing whitespace
  allowed. The file must be a regular file of at most 256 bytes. No permission or ownership
  check runs: restricting who can read or replace the file is the operator's job;
- `LocalKek::from_env`: the standard base64 of the 32 bytes in an environment variable. Be aware
  the variable stays in the process environment for the life of the process: the same user can
  read it through `/proc/<pid>/environ`, and every child process inherits it.

Errors name the file or the variable, never its content.

## Tests and development

An ephemeral provider has one random version-1 KEK that lives as long as the provider, so the
DEKs it wraps cannot be unwrapped once the process exits. It suits tests:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tests".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

let encrypted = envelope
    .encrypt_value(b"orders/1042", &SecretValue::from("secret"))
    .await?;
assert_eq!(
    envelope.decrypt_value(b"orders/1042", &encrypted).await?,
    SecretValue::from("secret")
);
# Ok(())
# }
```

For a development environment whose data outlives a run, keep a KEK in a variable or a file.
Generate one with:

```bash
openssl rand -base64 32
```

```rust,no_run
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use kms_aead::Ring;
use std::num::NonZeroU32;

# fn example() -> kms_aead::KmsAeadResult<()> {
let version = LocalKekVersion::from(NonZeroU32::MIN);
let provider = LocalKmsProvider::<Ring>::new(
    LocalKekId::try_from("dev".to_string())?,
    vec![LocalKek::from_env(version, "APP_DEV_KEK")?],
)?;
# let _ = provider;
# Ok(())
# }
```

## A VM or a single host

On a host, keep the KEK out of the environment. With systemd, encrypt it with `systemd-creds`,
bound to the host's TPM where it has one, and let systemd pass it to the service as a credential:

```bash
openssl rand -base64 32 | systemd-creds encrypt --name=kek-v1 - /etc/credstore.encrypted/kek-v1
```

```ini
[Service]
LoadCredentialEncrypted=kek-v1:/etc/credstore.encrypted/kek-v1
```

systemd decrypts it into `$CREDENTIALS_DIRECTORY`, readable only by the service:

```rust,no_run
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use kms_aead::AwsLc;
use std::num::NonZeroU32;
use std::path::PathBuf;

# fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let credentials = PathBuf::from(std::env::var("CREDENTIALS_DIRECTORY")?);
let version = LocalKekVersion::from(NonZeroU32::MIN);

let provider = LocalKmsProvider::<AwsLc>::new(
    LocalKekId::try_from("orders-host-1".to_string())?,
    vec![LocalKek::from_file(version, &credentials.join("kek-v1"))?],
)?;
# let _ = provider;
# Ok(())
# }
```

To rotate, add `kek-v2` the same way and list both versions. Version 2 wraps new DEKs, and the
DEKs wrapped under version 1 still unwrap. Version 1 can be dropped once nothing wrapped under it
is left.

## Limits

- No IAM, no audit log and no HSM. Protecting the KEK, at rest and in backups, is the
  operator's job;
- Every wrap is one AES-256-GCM encryption with a random 96-bit nonce, so a KEK version is safe
  for about 2^32 wraps. With the per-call envelope every value costs one wrap: a host sealing
  1,000 values per second spends 2^32 wraps in 50 days. Use [DEK reuse](../dek-caching.md) so a
  wrap happens once per DEK, and add a new KEK version before the budget is spent;
- Crypto-shredding means destroying every copy of the KEK, backups included;
- DEKs wrapped by a local KEK cannot be exported to BigQuery, which unwraps with Cloud KMS.

## Errors

A wrap fails with `RANDOM_GENERATOR` when the backend's CSPRNG fails. An unwrap fails with
`LOCAL_WRAPPED_KEY_FORMAT` when the wrapped DEK is not in the local layout,
`LOCAL_KEK_ID_MISMATCH` when it was wrapped under another KEK id, `LOCAL_KEK_UNKNOWN_VERSION`
when the provider does not hold its version, and `DECRYPT` when it is not authentic under that
version.

Creating a provider fails with `INVALID_LOCAL_KEK_ID` for an invalid id, `LOCAL_KEK_VERSIONS`
when the versions are empty or list one version twice, and `LOCAL_KEK_SOURCE` or
`LOCAL_KEK_LENGTH` when a KEK cannot be read or is not 32 bytes.
