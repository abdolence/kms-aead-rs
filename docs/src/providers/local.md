# Local KMS

`LocalKmsProvider` encrypts DEKs with a key encryption key the process holds, with AES-256-GCM on
the backend it is built with. It is in every build, with no feature, for:

- development and tests without a cloud KMS;
- single-host installs where the operator protects the KEK.

kms-aead builds one only when the application calls one of its constructors; no provider falls
back to it. Each constructor logs one `INFO` event naming the KEK id, its versions and where
each version came from (`ephemeral`, `file`, `env` or `secret`), never the key.

## KEK ids and versions

A `LocalKekId` names the KEK: 1 to 255 bytes of ASCII alphanumerics, `-`, `_` and `.`. Every
encrypted DEK records it, and a decryption refuses a DEK encrypted under another id. The id is also
the key of the [DEK cache](../dek-caching.md), so one id must name one set of KEK material: two
providers with the same id and different keys share cache entries.

A provider holds one or more `LocalKek` versions of 32 bytes each. The highest version encrypts new
DEKs unless `with_encrypting_version` names another, and every version it holds decrypts. Each
encrypted DEK records its version, so adding a new version keeps the DEKs encrypted under older
ones readable.

A KEK comes from one of three loaders, each taking the `SymmetricKeyFormat` the material is in:
`Raw`, the 32 bytes themselves, `Base64`, their standard base64 with trailing whitespace allowed,
or `Jwk`, an `oct` JSON Web Key. The format is always named and never guessed from the bytes:

- `LocalKek::from_secret(version, material, format)`: bytes the application already holds, such as
  a key an operator unseals with their own tool (systemd-creds, a TPM, sops, age);
- `LocalKek::from_file(version, path, format)`: the material in a file. The file must be a regular
  file of at most 32 KiB. No permission or ownership check runs: restricting who can read or
  replace the file is the operator's job;
- `LocalKek::from_env(version, variable, format)`: the material in an environment variable. `Raw`
  takes the variable's bytes as the key, which an environment holds only when none of them is
  `0x00`. Be aware the variable stays in the process environment for the life of the process: the
  same user can read it through `/proc/<pid>/environ`, and every child process inherits it.

`Jwk` reads the JSON object of [RFC 7518 section 6.4](https://www.rfc-editor.org/rfc/rfc7518#section-6.4),
where `k` is the 32 key bytes in base64url without padding:

```json
{"kty": "oct", "k": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}
```

`kty` must be `oct`. `alg` is optional and must be `A256GCM` or `A256KW` when present; `kid`,
`use`, `key_ops` and any other member are ignored. A `k` in padded or standard base64, or one that
does not decode to 32 bytes, is refused. There is no PEM form of a symmetric key, since no standard
gives it a label.

```rust
use std::num::NonZeroU32;

use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{LocalKek, LocalKekVersion};
use secret_vault_value::SecretValue;

# fn example() -> kms_aead::KmsAeadResult<()> {
let jwk = r#"{"kty": "oct", "k": "QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI"}"#;
let kek = LocalKek::from_secret(
    LocalKekVersion::from(NonZeroU32::MIN),
    SecretValue::from(jwk),
    SymmetricKeyFormat::Jwk,
)?;
# let _ = kek;
# Ok(())
# }
```

0.30 took the raw bytes in `from_secret` and base64 in `from_file` and `from_env`, see
[Migrating from 0.30](../migrating-from-0.30.md#loading-a-local-kek). Errors name the file or the
variable, never its content.

## Tests and development

An ephemeral provider has one random version-1 KEK that lives as long as the provider, so the
DEKs it encrypts cannot be decrypted once the process exits. It suits tests:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tests".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let encrypted = envelope
    .encrypt(b"orders/1042", &SecretValue::from("secret"))
    .await?;
let decrypted: SecretValue = envelope.decrypt(b"orders/1042", &encrypted).await?;
assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

For a development environment whose data outlives a run, keep a KEK in a variable or a file.
Generate one with:

```bash
openssl rand -base64 32
```

```rust,no_run
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};

# fn example() -> kms_aead::KmsAeadResult<()> {
let version = LocalKekVersion::from(NonZeroU32::MIN);
let provider = LocalKmsProvider::<Ring>::new(
    LocalKekId::try_from("dev".to_string())?,
    vec![LocalKek::from_env(version, "APP_DEV_KEK", SymmetricKeyFormat::Base64)?],
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
use std::num::NonZeroU32;
use std::path::PathBuf;

use kms_aead::backends::AwsLc;
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};

# fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let credentials = PathBuf::from(std::env::var("CREDENTIALS_DIRECTORY")?);
let version = LocalKekVersion::from(NonZeroU32::MIN);

let provider = LocalKmsProvider::<AwsLc>::new(
    LocalKekId::try_from("orders-host-1".to_string())?,
    vec![LocalKek::from_file(version, &credentials.join("kek-v1"), SymmetricKeyFormat::Base64)?],
)?;
# let _ = provider;
# Ok(())
# }
```

To rotate, add `kek-v2` the same way and list both versions, as the next section describes.

## Key versions and rotation

Every version in the provider's list decrypts, and the highest one encrypts unless
`with_encrypting_version` names another. The `kek_version()` of the encrypted DEK an encryption
returns is the version that encrypted, in decimal. A process that does not list a version fails on
a DEK under it with `LOCAL_KEK_UNKNOWN_VERSION`, so a rotation without downtime takes two deploys:

1. list the new version in every process, with `with_encrypting_version` keeping the current one
   encrypting;
2. once every process lists the new version, drop `with_encrypting_version`, or point it at the new
   version, so the new version encrypts.

```rust
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::formats::SymmetricKeyFormat;
use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use secret_vault_value::SecretValue;

# fn example(
#     kek_v1: SecretValue,
#     kek_v2: SecretValue,
# ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
let v1 = LocalKekVersion::from(NonZeroU32::try_from(1)?);
let v2 = LocalKekVersion::from(NonZeroU32::try_from(2)?);

// The first deploy: version 2 decrypts, version 1 still encrypts
let provider = LocalKmsProvider::<Ring>::new(
    LocalKekId::try_from("orders".to_string())?,
    vec![
        LocalKek::from_secret(v1, kek_v1, SymmetricKeyFormat::Raw)?,
        LocalKek::from_secret(v2, kek_v2, SymmetricKeyFormat::Raw)?,
    ],
)?
.with_encrypting_version(v1)?;
# let _ = provider;
# Ok(())
# }
```

A version that is not in the list fails `with_encrypting_version` with `LOCAL_KEK_VERSIONS`.

Then sweep, see
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation),
and check with a provider that lists the new version alone, before the deploy that drops the old
version, so that a DEK the sweep missed fails the check and no read in the application. Dropping
the old version from the list disables it, and listing it again restores it. Destroying it means
destroying every copy of its material, backups included.

## An asymmetric KEK

`LocalAsymmetricKmsProvider` is the local KMS with an RSA key pair per version, for the same uses as
`LocalKmsProvider`, see [Asymmetric KEKs](../asymmetric-kek.md). A `LocalAsymmetricKek` is one
version: an RSA private key of 2048, 3072 or 4096 bits in PKCS#8, zeroised on drop. 2048 bits is
deprecated and stays for the keys that exist. The loaders have the names of `LocalKek`'s and take a
`PrivateKeyFormat` from `kms_aead::formats`: `Pkcs8Der`, the DER bytes, or `Pkcs8Pem`, a
`PRIVATE KEY` PEM block, as `openssl genpkey` writes it. The format is never guessed from the
bytes, and a file is at most 32 KiB. `from_env` reads the PEM text for `Pkcs8Pem`, and for `Pkcs8Der`
the standard base64 of the DER, since a variable holds text.

```rust,ignore
let version = LocalKekVersion::from(NonZeroU32::MIN);
let provider = LocalAsymmetricKmsProvider::<AwsLc>::new(
    LocalKekId::try_from("dev".to_string())?,
    AsymmetricKekAlgorithm::RsaOaepSha256,
    vec![LocalAsymmetricKek::from_file(version, &path, PrivateKeyFormat::Pkcs8Pem)?],
)?;

// The public half of the encrypting version, for the producers
let public_key = provider.public_key(None)?;
```

- the KEK id names one KEK, symmetric or asymmetric, never both, and the version list, the
  encrypting version and the rotation work as for the symmetric KEK;
- an encrypted DEK is the `0x02` layout with the KEK id and the decimal version. A decryption fails
  with `ASYMMETRIC_ENCRYPTED_DEK_FORMAT`, `LOCAL_KEK_ID_MISMATCH`, `LOCAL_KEK_UNKNOWN_VERSION` or
  `DECRYPT`;
- `LocalAsymmetricKmsProvider::ephemeral` has one generated version-1 key of 2048 bits, for tests;
- it needs a backend with RSA: aws-lc-rs or RustCrypto. On ring it fails at construction with
  `UNSUPPORTED_ALGORITHM`. On RustCrypto the private half decrypts DEKs from trusted sources only, see
  [Asymmetric KEKs](../asymmetric-kek.md#what-each-backend-does).

## Limits

- No IAM, no audit log and no HSM. Protecting the KEK, at rest and in backups, is the
  operator's job;
- Every DEK encryption is one AES-256-GCM encryption with a random 96-bit nonce, so a KEK version is
  safe for about 2^32 encryptions. With the per-call envelope every value costs one encryption: a
  host encrypting 1,000 values per second spends 2^32 encryptions in 50 days. Use [DEK
  reuse](../dek-caching.md) so that one encryption serves many values, and add a new KEK version
  before the budget is spent;
- Crypto-shredding means destroying every copy of the KEK, backups included;
- DEKs encrypted by a local KEK cannot be exported to BigQuery, which decrypts with Cloud KMS.

## Errors

An encryption fails with `RANDOM_GENERATOR` when the backend's CSPRNG fails. A decryption fails with
`LOCAL_ENCRYPTED_DEK_FORMAT` when the encrypted DEK is not in the local layout,
`LOCAL_KEK_ID_MISMATCH` when it was encrypted under another KEK id, `LOCAL_KEK_UNKNOWN_VERSION`
when the provider does not hold its version, and `DECRYPT` when it is not authentic under that
version.

Creating a provider fails with `INVALID_LOCAL_KEK_ID` for an invalid id, `LOCAL_KEK_VERSIONS` when
the versions are empty or list one version twice, and `LOCAL_KEK_SOURCE` or `LOCAL_KEK_LENGTH` when
a KEK cannot be read or is not 32 bytes. An asymmetric provider fails with
`ASYMMETRIC_KEK_PRIVATE_KEY` for private key bytes that are not in the named format or not an RSA
key of 2048, 3072 or 4096 bits.
