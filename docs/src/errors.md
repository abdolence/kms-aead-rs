# Error handling

Every fallible call returns `KmsAeadResult<T>`, whose error is `kms_aead::errors::KmsAeadError`:

- `SystemError`: the configuration or the environment, such as invalid provider options or a KMS
  client that cannot be built;
- `NetworkError`: a KMS that could not be reached or did not answer in time, a server error or a
  rate limit from Azure Key Vault or Vault, and every gRPC status from Google Cloud KMS;
- `EncryptionError`: encrypting, decrypting, wrapping or unwrapping failed, or a stored value
  could not be read. Includes every AWS KMS error, and the requests Azure Key Vault and Vault
  refused;
- `UnsupportedAlgorithm`: the backend does not implement the algorithm, from constructors only;
- `LegacyFormat`: a stored value in a layout that only the `legacy-formats` feature reads, see
  [Formats](./formats.md).

The enum is `#[non_exhaustive]`, so a `match` on it needs a `_` arm.

## Codes

`code()` returns a code to match on: one of the library's own codes, or the code the KMS returned,
such as AWS's `IncorrectKeyException`. It is also the `error_code` field of the spans.

```rust
use kms_aead::errors::KmsAeadError;
use kms_aead::{AeadAlgorithm, AeadBackend, AeadCipher, CipherText};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = AeadCipher::new(AeadBackend::Ring, AeadAlgorithm::Aes256Gcm)?;
let key = cipher.generate_key()?;
let cipher_text = cipher.encrypt_value(b"orders/1042", &SecretValue::from("secret"), &key)?;

match cipher.decrypt_value(b"orders/1043", &cipher_text, &key) {
    Err(KmsAeadError::EncryptionError(error)) if error.public.code == "DECRYPT" => {
        // Not authentic under this key and AAD
    }
    other => panic!("{other:?}"),
}

let too_short = cipher.decrypt_value(b"orders/1042", &CipherText(vec![0; 8]), &key);
assert!(matches!(&too_short, Err(e) if e.code() == "INVALID_CIPHER_TEXT_FORMAT"));
# Ok(())
# }
```

The library's codes:

| Code | Variant | Meaning |
|---|---|---|
| `ENCRYPT`, `DECRYPT` | encryption | sealing failed, or a value is not authentic under the key and the AAD |
| `ENCRYPT_KEY`, `DECRYPT_KEY` | encryption | the backend refused a key, or a KMS request could not be built |
| `RANDOM_GENERATOR` | encryption | the CSPRNG failed, for a nonce or a key |
| `INVALID_KEY_LENGTH` | encryption | a key that does not fit the algorithm, or a KMS generator that returned another length |
| `UNSUPPORTED_ALGORITHM` | unsupported algorithm | the backend does not implement the algorithm |
| `UNKNOWN_ALGORITHM` | encryption | `FromStr` of an algorithm name it does not know |
| `INVALID_CIPHER_TEXT_FORMAT` | encryption | a value too short, or a length past its end |
| `UNKNOWN_CIPHER_TEXT_LAYOUT` | encryption | an empty envelope value or an unknown layout tag |
| `INVALID_ENCRYPTED_KEY_FORMAT`, `UNKNOWN_ENCRYPTED_KEY_LAYOUT` | encryption | stored wrapped DEK bytes that cannot be read |
| `INVALID_KEY_VERSION` | encryption | a key version that is not ASCII alphanumeric |
| `INVALID_HEX` | encryption | `try_from_hex_string` of text that is not hex |
| `LEGACY_FORMAT` | legacy format | a pre-0.29 layout without `legacy-formats` |
| `INVALID_DEK_BINDING` | system | a `DekBinding` that is empty, too long or holds a control character |
| `INVALID_DEK_CACHE_TTL` | system | a DEK cache TTL of zero |
| `INVALID_DEK_REUSE_POLICY` | system | a reuse policy out of range, or beside a disabled cache |
| `INVALID_LOCAL_KEK_ID`, `LOCAL_*` | system, encryption | the [local KMS](./providers/local.md#errors) |
| `AZURE_*` | system, encryption | the [Azure provider](./providers/azure.md#errors) |
| `VAULT_*` | system, network, encryption | the [Vault Transit provider](./providers/hc-vault-transit.md#errors) |

The KMS codes are the gRPC status codes of Google Cloud KMS, such as `PermissionDenied`, the AWS
error codes, such as `NotFoundException`, and Key Vault's error codes, such as `KeyNotFound`.

## Retries

The library retries nothing itself. The AWS and Azure SDKs apply their own retry policies, which
the Azure provider takes in `client_options`.

A `NetworkError` is the class to consider for a retry: a KMS that was not reached, a timeout, a
server error or a rate limit. For Google Cloud KMS every failed call is a `NetworkError`, so check
its code as well: `Unavailable`, `DeadlineExceeded` or `ResourceExhausted` are worth a retry,
`PermissionDenied` or `InvalidArgument` are not. An `EncryptionError` from a decrypt does not
change on a retry.

## What errors never carry

No error carries plaintext, key material in any form, plaintext or wrapped, AAD content or cipher
text bytes, in `Display` or in `Debug`. An application can log errors with `{}` and `{:?}`.

`message` is meant for a person reading logs. `public` holds the code, the part safe to return to
the application's own callers, and with the `serde` feature it is `Serialize` and `Deserialize`.
`std::error::Error::source()` returns the root cause, the error of the SDK or library that
failed, when there is one.
