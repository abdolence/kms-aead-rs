# Error handling

Every fallible call returns `KmsAeadResult<T>`, whose error is `kms_aead::errors::KmsAeadError`:

- `SystemError`: the configuration or the environment, such as invalid provider options or a KMS
  client that cannot be built, and the caller's own source or sink of a stream failing
  (`STREAM_IO`);
- `NetworkError`: a KMS that could not be reached, did not answer in time, failed on its side or
  limited the rate of requests. The same call may succeed later;
- `EncryptionError`: encrypting or decrypting a value or a DEK failed, a stored value could not
  be read, or a KMS refused the request, such as a denied permission or a disabled key. The same
  call fails the same way again;
- `UnsupportedAlgorithm`: the backend does not implement the algorithm, from constructors only;
- `SignatureError`: a signature could not be made, read or verified, or a KMS refused a sign or
  public-key request; never retried;
- `LegacyFormat`: a stored value in a layout of 0.29 or earlier, which only the
  `legacy-formats` feature reads, see [Formats](./formats.md#values-written-by-029-and-earlier).

The enum is `#[non_exhaustive]`, so a `match` on it needs a `_` arm.

## Codes

`code()` returns a code to match on: one of the library's own codes, or the code the KMS returned,
such as AWS's `IncorrectKeyException`. It is also the `error_code` field of the spans.

```rust
use kms_aead::backends::Ring;
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::Bare;
use kms_aead::{AeadAlgorithm, AeadCipher, Encrypted};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
let dek = cipher.generate_dek()?;
let cipher_text: Encrypted<SecretValue, Bare> =
    cipher.encrypt_bare(b"orders/1042", &SecretValue::from("secret"), &dek)?;

match cipher.decrypt_bare(b"orders/1043", &cipher_text, &dek) {
    Err(KmsAeadError::EncryptionError(error)) if error.public.code == "DECRYPT" => {
        // Not authentic under this key and AAD
    }
    other => panic!("{other:?}"),
}

let too_short = Encrypted::<SecretValue, Bare>::try_from(vec![0; 8]);
assert!(matches!(&too_short, Err(e) if e.code() == "INVALID_CIPHER_TEXT_FORMAT"));
# Ok(())
# }
```

The library's codes:

| Code | Variant | Meaning |
|---|---|---|
| `ENCRYPT`, `DECRYPT` | encryption | encrypting failed, or a value, or a chunk of a streamed value, is not authentic under the key and the AAD, among them a final chunk that a sequential read finds cut or followed by more bytes |
| `ENCRYPT_KEY`, `DECRYPT_KEY` | encryption | the backend refused a key, or a KMS request could not be built |
| `SIGN_KEY`, `GET_PUBLIC_KEY` | signature | a Cloud KMS signing request, or its public key request, whose routing header could not be built |
| `RANDOM_GENERATOR` | encryption | the CSPRNG failed, for a nonce or a key |
| `INVALID_KEY_LENGTH` | encryption | a key that does not fit the algorithm, such as a MAC key of another length than 32 or 64 bytes, a KMS generator that returned another length, or a DEK longer than the OAEP limit of the public key it is encrypted with |
| `UNSUPPORTED_ALGORITHM` | unsupported algorithm | the backend does not implement the algorithm, an AEAD algorithm or an asymmetric KEK algorithm such as RSA-OAEP on ring. `algorithm` is a `BackendAlgorithm` |
| `UNKNOWN_ALGORITHM` | encryption | `FromStr` of an algorithm name it does not know, a signing or MAC algorithm included |
| `INVALID_CIPHER_TEXT_FORMAT` | encryption | a value too short, a length past its end, a `Randomized` or `Deterministic` value without Tink's output prefix, a stream header that is not 61 bytes (56 bare) or does not start with `0x01`, or an envelope stream header whose encrypted DEK length is not 1 to 4,096 or that is not `60 + w` bytes |
| `UNKNOWN_CIPHER_TEXT_LAYOUT` | encryption | an empty envelope value, or a first byte that starts no layout |
| `INVALID_PLAINTEXT` | encryption | a decrypted value that is not an encoding of its type, or a `JsonEncoded` value that does not serialise |
| `INVALID_KEY_FORMAT` | encryption | a decrypted DEK that is not a serialised Tink key, such as an encrypted keyset |
| `INVALID_ENCRYPTED_KEY_FORMAT` | encryption | the encrypted DEK layout v1 of 0.29 that cannot be read, with `legacy-formats` |
| `INVALID_KEY_VERSION` | encryption | a key version that is not ASCII alphanumeric, in an Azure encrypted DEK or a layout of 0.29 |
| `INVALID_HEX` | encryption | `try_from_hex_string` of text that is not hex |
| `INVALID_BEACON_FORMAT` | encryption | stored bytes that are not `[0x01][key id: u32 BE]` and 1 to 32 bytes of HMAC, at `Beacon::try_from` |
| `INVALID_BEACON_CONTEXT` | encryption | a beacon context longer than 2^32 - 1 bytes |
| `BEACON` | encryption | the backend failed to calculate a beacon's HMAC |
| `STREAM_ALGORITHM` | encryption | a cipher or key version whose algorithm is not AES-256-GCM asked to encrypt or decrypt a streamed value |
| `STREAM_LENGTH` | encryption | a stored length that the length rules refuse, given to `StreamFormat::plan_chunk_read` or `plan_final_chunk_read`; bytes given to `decrypt_chunk_read` of another length than the plan's `ciphertext()`; a source of a sequential read that ends at a chunk boundary or less than a tag into a chunk, where no value ends, or holds more chunks than a value can; a source that ends inside the header that `decrypting_stream` or `decrypting_reader` read |
| `STREAM_KEY_COMMITMENT` | encryption | the header's commitment is not the one the DEK, the salt and the AAD derive: a wrong key, a wrong AAD, or a modified salt or commitment |
| `STREAM_RANGE` | encryption | a plaintext range past the value's length or with `start > end`, or a chunk read plan of a value in another form |
| `STREAM_IO` | system | the source or the sink of `encrypt_stream` or `decrypt_stream`, or the source of an `EncryptingStream` or a `DecryptingStream`, or the source of `decrypting_stream` or `decrypting_reader` while they read the header, failed; the source's or sink's error is the root cause. The retry is the whole stream again |
| `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` | encryption | a `0x02` encrypted DEK with an unknown algorithm byte, a header past the end, an `i` or `k` of another shape than the reading provider's, or a block of another length than its key's, before any KMS call |
| `ASYMMETRIC_KEK_PUBLIC_KEY` | system | public key bytes that are not in the named `PublicKeyFormat`, or not an RSA key of 2048, 3072 or 4096 bits, a key the backend refuses, a KEK version missing where the KMS decrypts with one, present under AWS, or not a decimal version for a local KEK, or a KMS key the fetch describes as another kind |
| `ASYMMETRIC_KEK_PRIVATE_KEY` | system | local private key bytes that are not in the named `PrivateKeyFormat`, or not an RSA key of 2048, 3072 or 4096 bits |
| `ASYMMETRIC_KEK_MISMATCH` | system | an `AsymmetricKekProvider` whose public key names another KEK than its KMS provider, or a `pinned` producer whose key has another fingerprint |
| `SIGNATURE_INVALID` | signature | no key with the signature's key id verifies it |
| `SIGNING_KEY_UNKNOWN` | signature | no key in the set has the signature's key id: the set is stale, or the signer is not trusted; also `with_record_signer`, `create_signed` and `open_or_create_signed` with a signer the registry's record verification does not hold |
| `INVALID_SIGNATURE_FORMAT` | signature | bytes that are not a `Signature` or `Signed` layout, at `TryFrom` |
| `SIGNATURE_ENCODING` | signature | the KMS returned a signature that is not strict DER, or not 64 bytes, or a Cloud KMS checksum failed |
| `SIGNING_KEY_MISMATCH` | signature | the KMS response names another key or version than the configured one |
| `SIGNING_ALGORITHM_MISMATCH` | signature | the KMS key is not of the configured algorithm |
| `INVALID_PUBLIC_KEY` | signature | a public key, JWK or JWK Set that does not parse, is of another algorithm, is not on the curve, or is an Ed25519 point of order 8 or less |
| `EMPTY_KEY_SET` | signature | `Verifier::new` with no key, and `KeyringRegistry::new` with `RecordSignaturePolicy::Required` and no key |
| `DUPLICATE_KEY_ID` | signature | two different keys under one key id, at `VerifyingKeySet::new`, `insert` or `from_jwks`, or two local versions sharing one |
| `INVALID_PAYLOAD` | encryption | `to_payload` or `from_payload` failed, from a signing or a MAC call, such as a payload that is not the JSON of a `JsonEncoded` type |
| `MAC_INVALID` | encryption | the tag does not match, or is not the length of the key's algorithm |
| `INVALID_MAC_FORMAT` | encryption | bytes that are not a `Mac` or `WithMac` layout |
| `MAC` | encryption | the backend failed to compute an HMAC |
| `DIGEST` | encryption | the backend failed to compute a SHA-256, of a payload or a pre-image |
| `SIGN` | signature | the backend failed to sign with a local signing key |
| `LEGACY_FORMAT` | legacy format | a layout of 0.29 or earlier without `legacy-formats`, at `Encrypted::try_from` or at decryption, and the envelope layouts of 0.29 and earlier in `separate` |
| `INVALID_DEK_CACHE_TTL` | system | a DEK cache TTL of zero |
| `INVALID_DEK_REUSE_POLICY` | system | a reuse policy out of range, or beside a disabled cache |
| `AWS_ERROR` | encryption | an AWS KMS response without the encrypted DEK, the plaintext DEK or the random bytes it was asked for, see [AWS KMS](./providers/aws.md#errors) |
| `INVALID_LOCAL_KEK_ID`, `LOCAL_*` | system, encryption | the [local KMS](./providers/local.md#errors) |
| `AZURE_*` | system, encryption | the [Azure provider](./providers/azure.md#errors) |
| `INVALID_LOCAL_SIGNING_KEY_NAME`, `LOCAL_SIGNING_KEY_SOURCE`, `LOCAL_SIGNING_KEY_FORMAT`, `LOCAL_SIGNING_KEY_VERSIONS` | system | the local signing provider's configuration |
| `AWS_SIGNING_KEY_ALIAS` | system | an AWS signing key named by an alias, which a rotation could point at another key |
| `VAULT_*` | system, network, encryption | the [Vault Transit provider](./providers/hc-vault-transit.md#errors) |

The KMS codes are the gRPC status codes of Google Cloud KMS, such as `PermissionDenied`, the AWS
error codes, such as `NotFoundException`, and Key Vault's error codes, such as `KeyNotFound`. A
sign or public-key request that fails with a network code is a `NetworkError`, and with any other
KMS code a `SignatureError` that keeps the KMS's code.

## Retries

The library retries nothing itself. The AWS and Azure SDKs apply their own retry policies, which
the Azure provider takes in `client_options`.

A `NetworkError` may be retried, with a backoff. An `EncryptionError` or a `SignatureError` should
not be: a revoked permission, a missing key or an encrypted DEK of another key fails the same way on
every retry.
The variant per provider:

| Provider | `NetworkError` | `EncryptionError` |
|---|---|---|
| Google Cloud KMS | gRPC `Unavailable`, `DeadlineExceeded`, `ResourceExhausted`, `Aborted`, `Internal`, `Unknown`, `Cancelled` | any other gRPC code, such as `PermissionDenied`, `Unauthenticated`, `NotFound`, `InvalidArgument`, `FailedPrecondition` |
| AWS KMS | `ThrottlingException`, `KMSInternalException`, `DependencyTimeoutException`, `KeyUnavailableException`, a 5xx or 429 status, a timeout, a connection failure, a response the SDK could not read | any other AWS error code, such as `AccessDeniedException`, `NotFoundException`, `IncorrectKeyException`, `InvalidCiphertextException`, `DisabledException`, `KMSInvalidStateException`, a request that could not be built or signed, and `AWS_ERROR` |
| Azure Key Vault | a 5xx or 429 status, a connection or I/O failure | any other status, such as `Forbidden` or `KeyNotFound`, and a response that does not parse |
| Vault Transit | `VAULT_STATUS_5xx`, `VAULT_STATUS_429`, `VAULT_HTTP`, `VAULT_TIMEOUT` | any other `VAULT_STATUS_<status>`, `VAULT_RESPONSE`, `VAULT_RESPONSE_TOO_LARGE`, `VAULT_CIPHERTEXT` |

Google's client libraries retry the Cloud KMS `Encrypt` and `Decrypt` calls on `Unavailable` and
`DeadlineExceeded` only. Keep a retry on the other Google Cloud KMS network codes to a few
attempts.

`STREAM_IO` is the caller's own source or sink failing, such as a reset download or a full disk,
and the library cannot tell whether it may be retried. The root cause is the source's or the sink's
error, and it says whether a retry can help. The retry is the whole stream again, from the start.

## Keyring errors

Every fallible call of kms-aead-keyring returns `KeyringResult<T>`, whose error is
`KeyringError`, also `#[non_exhaustive]`. `code()` returns kms-aead's code for `KmsAead`, such as
`DECRYPT` or a KMS's code, and the variant's name in upper snake case otherwise, such as
`KEY_VERSION_COMPROMISED`. It is the `error_code` field of the keyring's spans and the
`error.type` of its metrics. Match on the variant and its fields, or on the code: the `Display`
text may change in any release.

| Variant | Code | Meaning |
|---|---|---|
| `KmsAead` | kms-aead's | a KMS call, a decryption or an encoding failed, see [Codes](#codes) |
| `Store` | `STORE` | the keyring store failed: `store`, `operation`, and the client's error as `root_cause` and `source()` |
| `InvalidIdentifier` | `INVALID_IDENTIFIER` | a keyring id, an AAD part or a store name that breaks the rule of its type |
| `RecordMissing` | `RECORD_MISSING` | no record for the keyring: at `open` and `admin`, before an administrative write, and from `reload` once the process took the record as deleted, see [A record gone from the store](./keyring/record-cache.md#a-record-gone-from-the-store). A `dangerously_shred()` of a keyring already gone returns `Ok` |
| `RecordExists` | `RECORD_EXISTS` | `create` found a record |
| `RecordInvalid` | `RECORD_INVALID` | a record that breaks a size cap or an invariant, such as two versions holding the same encrypted DEK (`DuplicateEncryptedDek`) or a `signature` member that is not a detached signature (`MalformedSignature`), see [Keyring records](./formats.md#keyring-records) |
| `RecordUnsigned` | `RECORD_UNSIGNED` | an unsigned record where record verification is `Required`, or where a signing admin writes over it, see [Signing the keyring record](./signing.md#signing-the-keyring-record) |
| `RecordSignatureInvalid` | `RECORD_SIGNATURE_INVALID` | a record whose signature fails under the verifying keys, or that is signed where the registry has no key; the cause carries the signature error's code |
| `RecordSignerMissing` | `RECORD_SIGNER_MISSING` | a write by an administration without a record signer over a signed record, before any store write |
| `RecordSignatureRemoved` | `RECORD_SIGNATURE_REMOVED` | an unsigned record where the process holds a signed one, under `VerifyIfSigned` |
| `RecordRegressed` | `RECORD_REGRESSED` | a record that moves a version backwards from the one this process holds, from `reload` and before an administrative write |
| `RecordConflict` | `RECORD_CONFLICT` | an administrative write lost every compare-and-swap, `attempts` of them |
| `KekMismatch` | `KEK_MISMATCH` | the provider's KEK is not the one the record names |
| `NoActiveVersion` | `NO_ACTIVE_VERSION` | no active version of the purpose, so nothing new is encrypted under it |
| `NoAlgorithm` | `NO_ALGORITHM` | the record names no algorithm for the purpose, so no version of it is created: `change_algorithm` sets one |
| `KeyVersionUnknown` | `KEY_VERSION_UNKNOWN` | no version with the value's key id, also after a reload |
| `KeyVersionRetired` | `KEY_VERSION_RETIRED` | the value's version is retired; `reinstate` brings it back |
| `KeyVersionDestroyed` | `KEY_VERSION_DESTROYED` | the value's version is destroyed |
| `KeyVersionPending` | `KEY_VERSION_PENDING` | a pending version selected as the primary of a keyset export |
| `KeyVersionCompromised` | `KEY_VERSION_COMPROMISED` | the value's version is compromised under the `Block` policy |
| `EncryptorOutdated` | `ENCRYPTOR_OUTDATED` | a value under a version newer than the encryptor's record |
| `KeyPurposeMismatch` | `KEY_PURPOSE_MISMATCH` | a key id of another purpose than the call's |
| `InvalidTransition` | `INVALID_TRANSITION` | a lifecycle call that does not apply to the version's state, see [States](./keyring/lifecycle.md#states) |
| `PromotionTooEarly` | `PROMOTION_TOO_EARLY` | a promotion before `record_ttl` has passed since the version was staged |
| `ReservedKeyId` | `RESERVED_KEY_ID` | a key id no version has: ordinal zero |
| `DeterministicDisabled` | `DETERMINISTIC_DISABLED` | a deterministic version created without the `deterministic` feature |
| `Interop` | `INTEROP` | an encryption or a keyset export that a field's `Interop` reader would not read |
| `CustomAadUnsupported` | `CUSTOM_AAD_UNSUPPORTED` | `custom_aad` on a field BigQuery decrypts |
| `ExportAlgorithmUnsupported` | `EXPORT_ALGORITHM_UNSUPPORTED` | a version in an export whose algorithm the keyset's reader does not read |
| `UnknownKeyVersionState` | `UNKNOWN_KEY_VERSION_STATE` | `FromStr` of a name that is no `KeyVersionState` |
| `InvalidEncryptionMarker` | `INVALID_ENCRYPTION_MARKER` | stored bytes that are not an `EncryptionMarker` |

Besides the retry policies of the store clients, such as aws-sdk-s3's, the keyring retries only an
administrative write's compare-and-swap, up to `cas_retries` times. What a caller may run again:

- `KmsAead`: as in [Retries](#retries), a `NetworkError` with a backoff;
- `Store`: the library does not classify a store's errors, so the decision follows the client's
  error in `root_cause`;
- `RecordConflict`: the administrative call, which reads the record again;
- `EncryptorOutdated`: the write, with a new encryptor from `Keyring::encryptor`, see
  [Re-encrypting a value](./operations/sweeps.md#re-encrypting-a-value);
- `PromotionTooEarly`: the promotion, once its `remaining` has passed.

The other variants fail the same way until the record, the configuration or the call changes.

## What errors never carry

No error carries plaintext, key material in any form, plaintext or encrypted, AAD content or cipher
text bytes, in `Display` or in `Debug`. An application can log errors with `{}` and `{:?}`. A
`JsonEncoded` value that does not decode also logs a redacted outline of its JSON, see
[Observability](./observability.md#json-that-does-not-decode).

`message` is meant for a person reading logs. `public` holds the code, the part safe to return to
the application's own callers, and it is `Serialize` and `Deserialize`.
`std::error::Error::source()` returns the root cause, the error of the SDK or library that
failed, when there is one.
