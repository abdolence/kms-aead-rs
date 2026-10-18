# Formats

Every byte layout the library reads or writes:

| Layout | Type | Bytes | Written by |
|---|---|---|---|
| AEAD value | `CipherText` | `[nonce: 12][ciphertext][tag: 16]` | every release |
| Envelope layout v1 | `CipherTextWithEncryptedKey` | `[0x01][k: u8][key version: k][w: u16 BE][wrapped key: w][cipher text]` | 0.29.0 and later |
| Encrypted key layout v1 | `EncryptedDataEncryptionKey` | `[0xFF][0x01][k: u8][key version: k][wrapped key]` | 0.29.0 and later |
| Local KMS wrapped key | `EncryptedDataEncryptionKey::wrapped()` | `[0x01][i: u8][KEK id: i][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]` | 0.30.0 and later |
| Deterministic value | `DeterministicCipherText` | `[synthetic IV: 16][ciphertext]` | 0.30.0 and later |
| Length-prefixed envelope | `CipherTextWithEncryptedKey` | `[w: u64 BE][wrapped key: w][cipher text]`, and a 4-byte `w` from 32-bit targets before 0.24.0 | 0.8.0 to 0.28.1, read with `legacy-formats` only |
| Bare encrypted key | `EncryptedDataEncryptionKey` | the wrapped key as the KMS returned it | up to 0.28.1, read with `legacy-formats` only |

`k = 0` records no key version. A key version is 1 to 255 ASCII alphanumeric characters, such as
the `N` of a GCP `cryptoKeyVersions/N`.

## Envelope layout v1

`encrypt_value` writes envelope layout v1, and `CipherTextWithEncryptedKey::join` writes it from a
cipher text and a wrapped DEK. `separate` reads it back:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{CipherTextWithEncryptedKey, KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
let encrypted = envelope.encrypt_value(b"aad", &SecretValue::from("secret")).await?;

let (cipher_text, encrypted_dek) = encrypted.separate()?;
assert_eq!(CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?, encrypted);
# Ok(())
# }
```

The header is not authenticated, so a header field is only ever an address or an audit value,
such as the key version. The layout does not record the AEAD algorithm.

The key version comes from the provider: GCP, Azure, Vault Transit and the local KMS record one,
AWS records none and needs none to unwrap.

## Encrypted key layout v1

`EncryptedDataEncryptionKey::to_bytes` and `to_hex_string` write the wrapped DEK with its key
version, for the `*_with_encrypted_dek` calls. `TryFrom<&[u8]>` and `try_from_hex_string` read it,
see [Storing wrapped DEKs](./envelope-encryption.md#storing-wrapped-deks). `0xFF` marks the layout,
and `0x01` is its version.

## Values written by 0.28.1 and earlier

Two layouts written up to 0.28.1 are read only with the `legacy-formats` feature:

- the length-prefixed envelope, whose first byte is `0x00`;
- the bare encrypted key, stored with `value()` or `to_hex_string()` up to 0.28.1. Those keys come
  only from GCP, starting with `0x0a`, and from AWS, starting with `0x01`.

Without the feature, reading them fails with `KmsAeadError::LegacyFormat` and the code
`LEGACY_FORMAT`, with `KmsAeadLegacyFormat::LengthPrefixedEnvelope` or
`KmsAeadLegacyFormat::BareEncryptedKey`. The error never echoes the bytes read. An envelope or a
kms-aead-keyring value handed to the encrypted key reader by mistake also starts with `0x01`, so
`BareEncryptedKey` may mean that too.

With the feature, both read as they did in 0.29, and the first read of each legacy layout in a
process logs one `WARN` event that names the upgrade function to use.

In a build without `legacy-formats`, the `KMS AEAD decrypt` spans of such rows record
`error_code=LEGACY_FORMAT`, see [Observability](./observability.md).

## Upgrading stored values

With `legacy-formats`, two functions rewrite a stored value in the current layout, and return
`None` when it already is in it, so a sweep can skip the rows that need no write:

- `CipherTextWithEncryptedKey::upgrade_legacy_layout`, for envelope values;
- `EncryptedDataEncryptionKey::upgrade_legacy_layout`, which takes the stored bytes, since a parsed
  key does not record the layout it was read from. A caller that stores hex decodes before and
  encodes after.

Both are local re-framing: the wrapped DEK and the AEAD bytes stay as they are, and no KMS is
called. The upgraded value records no key version, and the GCP and AWS providers, the only ones
before 0.29, unwrap without one.

A sweep over stored rows:

```rust
use kms_aead::{CipherTextWithEncryptedKey, EncryptedDataEncryptionKey, KmsAeadResult, ValueStruct};

/// Rewrites the envelope values of `rows` in layout v1, and returns how many changed.
#[allow(deprecated)]
fn upgrade_values(rows: &mut [Vec<u8>]) -> KmsAeadResult<usize> {
    let mut upgraded = 0;
    for row in rows.iter_mut() {
        if let Some(value) = CipherTextWithEncryptedKey(row.clone()).upgrade_legacy_layout()? {
            *row = value.into_value();
            upgraded += 1;
        }
    }
    Ok(upgraded)
}

/// Rewrites stored wrapped DEKs in encrypted key layout v1.
#[allow(deprecated)]
fn upgrade_keys(rows: &mut [Vec<u8>]) -> KmsAeadResult<()> {
    for row in rows.iter_mut() {
        if let Some(bytes) = EncryptedDataEncryptionKey::upgrade_legacy_layout(row)? {
            *row = bytes;
        }
    }
    Ok(())
}
# fn main() -> KmsAeadResult<()> {
# // A length-prefixed value as 0.28.1 wrote it: [w: u64 BE][wrapped key][cipher text]
# let mut legacy = 3u64.to_be_bytes().to_vec();
# legacy.extend_from_slice(&[0x0a, 0x01, 0x02]);
# legacy.extend_from_slice(&[0u8; 28]);
# let mut values = vec![legacy];
# assert_eq!(upgrade_values(&mut values)?, 1);
# assert_eq!(upgrade_values(&mut values)?, 0);
# let mut keys = vec![vec![0x0a, 0x01, 0x02]];
# upgrade_keys(&mut keys)?;
# assert_eq!(keys[0][0], 0xFF);
# Ok(())
# }
```

Upgrade every reader to 0.29 or later before the sweep writes: 0.28.1 and earlier cannot read the
current layouts.

## Deprecation

Reading the pre-0.29 layouts is deprecated since 0.30.0 and will be removed in a later breaking
release, together with the `legacy-formats` feature and the upgrade functions, which carry
`#[deprecated]` from their first release, so every call site warns.

Envelope layout v1 and encrypted key layout v1 are current and not deprecated.
