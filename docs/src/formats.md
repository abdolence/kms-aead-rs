# Formats

Every byte layout the library reads or writes is on this page.

The library writes one envelope format for every provider, Tink's KMS envelope. A value encrypted
by `encrypt_value` opens with Tink's `KmsEnvelopeAead` on the same KMS key and algorithm, and a
value Tink encrypts opens with `decrypt_value`.

| Layout | Type | Bytes | Read by | Written by |
|---|---|---|---|---|
| Tink KMS envelope | `CipherTextWithEncryptedKey`, `Encrypted<T, Envelope>` | `[w: u32 BE][encrypted DEK: w][nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | 0.30.0 and later |
| AEAD value | `CipherText` | `[nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink (RAW output) | every release |
| Encrypted DEK | `EncryptedDataEncryptionKey` | the provider's bytes, see [Encrypted DEKs](#encrypted-deks) | kms-aead, Tink for GCP and AWS keys | 0.30.0 and later |
| Serialised DEK | the plaintext of an encrypted DEK, but Azure's | Tink's key message, see [Serialised DEKs](#serialised-deks) | kms-aead, Tink | 0.30.0 and later |
| Deterministic value | `DeterministicCipherText` | `[synthetic IV: 16][ciphertext]` | kms-aead; Tink and BigQuery after a TINK prefix | 0.30.0 and later |
| TINK-prefixed value | `Encrypted<T, Randomized>`, `Encrypted<T, Deterministic>`, named by a `KeyId` | `[0x01][key id: u32 BE][value]` | kms-aead, Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| Tink keyset | `TinkKeyset` | `google.crypto.tink.Keyset` | Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| Tink encrypted keyset | `TinkKeyset::into_encrypted_bytes` | `google.crypto.tink.EncryptedKeyset`, `[0x12][w: varint][encrypted keyset: w]` | Tink with a GCP, AWS or Vault Transit key | 0.30.0 and later |
| Envelope layout v1 | `CipherTextWithEncryptedKey` | `[0x01][k: u8][key version: k][w: u16 BE][encrypted DEK: w][cipher text]` | kms-aead with `legacy-formats` | 0.29 |
| Encrypted key layout v1 | stored `EncryptedDataEncryptionKey` | `[0xFF][0x01][k: u8][key version: k][encrypted DEK]` | kms-aead with `legacy-formats` | 0.29 |
| Length-prefixed envelope | `CipherTextWithEncryptedKey` | `[w: u64 BE][encrypted DEK: w][cipher text]`, and `[w: u32 BE]` from 32-bit targets before 0.24.0 | kms-aead with `legacy-formats` | 0.8.0 to 0.28.1 |
| Raw encrypted DEK | `EncryptedDataEncryptionKey` | the KMS ciphertext of the DEK's 16 or 32 raw bytes | kms-aead with `legacy-formats` | up to 0.29 |

`k = 0` records no key version. A key version is 1 to 255 ASCII alphanumeric characters. The Azure
provider encrypts the raw DEK in every release, see [Encrypted DEKs](#encrypted-deks).

## Tink's KMS envelope

`encrypt_value` writes Tink's KMS envelope, and `CipherTextWithEncryptedKey::join` writes it from
a cipher text and an encrypted DEK. `separate` reads it back:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{CipherTextWithEncryptedKey, KmsAeadEnvelope, Ring};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let encrypted = envelope.encrypt_value(b"aad", &SecretValue::from("secret")).await?;

let (cipher_text, encrypted_dek) = encrypted.separate()?;
assert_eq!(CipherTextWithEncryptedKey::join(&cipher_text, &encrypted_dek)?, encrypted);
# Ok(())
# }
```

- `w` is 1 to 4,096 bytes, the limit of every Tink implementation, on write and on read;
- the encrypted DEK is the provider's [`EncryptedDataEncryptionKey`](#encrypted-deks), the KMS
  ciphertext of the [serialised DEK](#serialised-deks), or of the raw DEK for Azure;
- the AAD goes to the DEK's AEAD only. The KMS encryption of the DEK has no AAD, as in Tink, so
  Tink's AWS client sends no encryption context and its GCP client no additional authenticated data;
- the rest is the `CipherText`, Tink's RAW output.

The envelope records neither the algorithm nor the KMS key version, so the writer and the reader,
kms-aead or Tink, are configured with the same algorithm. Tink calls it the DEK template:

| Algorithm | Tink key type | Tink for Java and Go | Tink for C++ and Python |
|---|---|---|---|
| ChaCha20-Poly1305 | `ChaCha20Poly1305Key` | reads and writes | no |
| AES-128-GCM, AES-256-GCM | `AesGcmKey` | reads and writes | reads and writes |
| AES-256-GCM-SIV | `AesGcmSivKey` | reads and writes | reads and writes |

AES-256-GCM is the default of `KmsAeadEnvelope::new`, so every Tink implementation reads the
values of an envelope that names no algorithm. The default of 0.29 and earlier was
ChaCha20-Poly1305, see [Migrating from 0.29](./migrating-from-0.29.md#default-algorithm).

Tink for Python reads a kms-aead value with the key URI of the provider's key:

```python
from tink import aead
from tink.integration import gcpkms

aead.register()
key_uri = 'gcp-kms://projects/p/locations/l/keyRings/r/cryptoKeys/k'
remote = gcpkms.GcpKmsClient(key_uri).get_aead(key_uri)
envelope = aead.KmsEnvelopeAead(aead.aead_key_templates.AES256_GCM, remote)
plain_text = envelope.decrypt(value, aad)
```

Checked on a Cloud KMS key and an AWS KMS key, both ways: AES-128-GCM, AES-256-GCM and
AES-256-GCM-SIV with Tink 1.16.1 for Python, and ChaCha20-Poly1305 with Tink 1.24.0 for Java on
the Cloud KMS key. `tests/tink_interop.py` and `examples/tink_interop.rs` repeat the Python check.

## Encrypted DEKs

`EncryptedDataEncryptionKey` is the bytes the provider returned from an encryption, which are also
the bytes to store and the bytes it decrypts. Each provider's bytes name the KMS key version that
encrypted the DEK where the KMS needs one to decrypt:

| Provider | Bytes | Key version |
|---|---|---|
| GCP | the Cloud KMS ciphertext, starting with `0x0a` | inside the ciphertext |
| AWS | the AWS KMS ciphertext blob, starting with `0x01` | not exposed |
| Azure | `[0x01][k: u8][key version: k][Key Vault encrypted DEK]` | in the layout |
| Vault Transit | the Transit ciphertext, `vault:vN:…` | the `N` |
| local | `[0x01][i: u8][KEK id: i][KEK version: u32 BE][nonce: 12][sealed DEK][tag: 16]` | in the layout |
| an application's own | whatever it returns | |

The Azure layout is the library's own: Key Vault decrypts only with the key version that encrypted,
and no Tink client exists for Azure. For the same reason, the Key Vault encrypted DEK is the KMS
ciphertext of the raw DEK of 16, 32 or 64 bytes, as in 0.29, not of the serialised DEK: AES key
wrap, `A128KW` to `A256KW`, takes only multiples of 8 bytes, which no serialised DEK is. The local
KMS seals the DEK with AES-256-GCM under the KEK version, with its header up to the version as the
AAD, so neither the id nor the version can be changed without the decryption failing.

Store `value()` or `to_hex_string()`, and read them back with `EncryptedDataEncryptionKey::from`
or `try_from_hex_string`, see
[Storing encrypted DEKs](./envelope-encryption.md#storing-encrypted-deks).

## Serialised DEKs

The plaintext a provider encrypts is the DEK serialised as Tink serialises a key, the message of its
Tink key type with `version` 0, which protobuf leaves out. The Azure provider encrypts the raw DEK
instead, see [Encrypted DEKs](#encrypted-deks):

| Algorithm | Message | Bytes |
|---|---|---|
| ChaCha20-Poly1305 | `ChaCha20Poly1305Key` | `[0x12][0x20][key: 32]` |
| AES-128-GCM | `AesGcmKey` | `[0x1a][0x10][key: 16]` |
| AES-256-GCM | `AesGcmKey` | `[0x1a][0x20][key: 32]` |
| AES-256-GCM-SIV | `AesGcmSivKey` | `[0x1a][0x20][key: 32]` |
| AES-256-SIV, deterministic | `AesSivKey` | `[0x12][0x40][key: 64]` |

A beacon key of HMAC-SHA256 is serialised as `[0x1a][0x20][key: 32]`, its 32 bytes in
`key_value`, field 3, as in Tink's `HmacPrfKey` without its parameters: the bytes of a 32-byte
`AesGcmKey`. It is encrypted as a DEK is, raw under an Azure key.

`generate_dek`, `generate_new_deterministic_dek` and the `generate_dek` of both
ciphers and of `BeaconMac` encrypt their keys the same way. The message does not name its type, and
AES-256-GCM and AES-256-GCM-SIV keys are written alike, so the algorithm of the reader decides
how the key is used, as in Tink.

A decrypted DEK that is no serialised Tink key, or under an Azure key no raw DEK, fails with
`INVALID_KEY_FORMAT`. An encrypted Tink
keyset decrypts under the same KEK too, and this is what keeps it out of the DEK cache.

## Tink keysets and the TINK prefix

Two items describe the TINK-prefixed values:

- `kms_aead::KeyId`: the key id of Tink's output prefix of type TINK, `[0x01][key id: u32 BE]`,
  the start of every `Randomized` and `Deterministic` value and of every beacon. It picks the key
  that opens the value, and Tink and BigQuery pick the key of a keyset by it. It is not
  authenticated;
- `kms_aead::formats::TinkKeyset`: a serialised `google.crypto.tink.Keyset` of enabled, symmetric,
  TINK-prefixed keys, the bytes `tinkey` writes for the same keys. Encrypted by a Cloud KMS key, it
  is the keyset of BigQuery's `KEYS.KEYSET_CHAIN`: an application writes it for its one key, see
  [One fixed key](./envelope-encryption.md#one-fixed-key), and a keyring exports it for its
  versions.

`TinkKeyset::into_encrypted_bytes` writes the keyset encrypted by a KMS key, as Tink writes an
encrypted keyset: a `google.crypto.tink.EncryptedKeyset` whose `encrypted_keyset`, field 2, is the
KMS ciphertext of the serialised keyset, encrypted with no associated data. Tink's binary keyset
writers leave out `keyset_info`, field 3, and so does the library. Tink's `KeysetHandle.read`
reads it with the KMS client of `KekRef::tink_key_uri`, which Tink has for GCP and AWS keys, and
Tink for Go for Vault Transit keys too.

## Typed fields

`Encrypted<T, F>` holds the bytes of one layout, named by its format `F`, and
`Encrypted::try_from` checks stored bytes against it:

| Format | Layout | Shortest value | Written by |
|---|---|---|---|
| `Envelope` | [Tink's KMS envelope](#tinks-kms-envelope) | an encrypted DEK of 1 to 4,096 bytes, then 28 bytes | `encrypt_field` |
| `Randomized` | `[0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]` | 33 bytes | `AeadCipher::encrypt_field`, and kms-aead-keyring through it |
| `Deterministic` | `[0x01][key id: u32 BE][synthetic IV: 16][ciphertext]` | 21 bytes | `DeterministicCipher::encrypt_field`, and kms-aead-keyring through it |

The check reads the framing only. As an `Envelope` value, the envelope layout v1 of 0.29 and the
length-prefixed envelope fail with `LEGACY_FORMAT`, with or without `legacy-formats`: read them
with `decrypt_value`, or rewrite them first, see [Upgrading stored
values](#upgrading-stored-values). The layout of 32-bit targets before 0.24.0 has Tink's framing, so
`decrypt_field` reads it as `decrypt_value` does.

The plaintext inside is the encoding of the field's `Plaintext` type: UTF-8 for `String`, the
bytes themselves for `Vec<u8>` and `SecretValue`, `true` or `false` for `bool`, decimal ASCII for
the integers, and compact JSON for `Json<T>`. See
[Typed fields](./envelope-encryption.md#typed-fields).

## Beacons

A `Beacon<T>` is a prefix and a truncated HMAC-SHA256:

```text
[0x01][key id: u32 BE][HMAC-SHA256: the first ceil(bits / 8) bytes]
```

- `0x01` is the version of the beacon layout. A later layout takes another first byte, so that
  beacons of both layouts can share a column during a re-index;
- the key id names the beacon key that computed the beacon;
- the HMAC keeps its first `bits` bits, and the unused low bits of the last byte are zero. A
  beacon is 6 to 37 bytes.

The HMAC covers the bits, the context and the plaintext, as the `Plaintext` type encodes it:

```text
HMAC-SHA256(key, [bits: u16 BE][context length: u32 BE][context][plaintext])
```

so that beacons of two fields, or of two bit counts, never match. `Beacon::try_from` checks the
prefix and that 1 to 32 bytes of HMAC follow, and fails with `INVALID_BEACON_FORMAT` otherwise.

## Telling layouts apart

The first bytes of a stored value:

| First bytes | Layout |
|---|---|
| `00 00 00 00` | the length-prefixed envelope of 0.28.1 and earlier |
| `00`, then a length of 1 to 4,096 | Tink's KMS envelope, or the 4-byte length prefix of 32-bit targets before 0.24.0 |
| `01` | envelope layout v1 of 0.29, or a TINK-prefixed value |
| `FF 01` | encrypted key layout v1 of 0.29 |

Only the decrypted DEK tells a Tink envelope from the 32-bit layout before 0.24.0: a raw key of
16 or 32 bytes against a serialised Tink key, whose lengths differ. An encrypted DEK of AWS, Azure
or the local KMS also starts with `0x01`, and Tink's LEGACY and CRUNCHY output prefixes with `0x00`.

A column that holds two layouts:

- Tink envelopes and TINK-prefixed values: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.29 envelopes: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.28.1 envelopes: the first four bytes;
- 0.29 envelopes and TINK-prefixed values: no byte tells them apart, so the layout is recorded
  outside the value, such as in another column;
- encrypted DEKs of 0.29 and of 0.30: `0xFF 0x01` starts no encrypted DEK of a built-in provider, so
  the library tells them apart for those. It never inspects the bytes of an application's own
  provider: strip the header `[0xFF][0x01][k][key version]` of its 0.29 keys before reading them.

## Values written by 0.29 and earlier

The layouts of 0.29 and earlier are read only with the deprecated `legacy-formats` feature:

- `decrypt_value` reads the three envelope layouts;
- the `*_with_encrypted_dek` calls and the DEK cache read the encrypted key layout of 0.29 and
  raw encrypted DEKs.

`CipherTextWithEncryptedKey::separate` never reads the older envelope layouts: for Azure, the
encrypted DEK they hold needs the provider to become its bytes.

Without the feature, reading them fails with `KmsAeadError::LegacyFormat`, the code
`LEGACY_FORMAT`, and one of:

- `KmsAeadLegacyFormat::EnvelopeV1`;
- `KmsAeadLegacyFormat::LengthPrefixedEnvelope`;
- `KmsAeadLegacyFormat::EncryptedKeyV1`;
- `KmsAeadLegacyFormat::RawEncryptedDek`, for an encrypted DEK that decrypts to the raw key. The
  values of 32-bit targets before 0.24.0 fail with it, since their framing is Tink's.

The error never echoes the bytes read. With the feature, the first read of each layout in a
process logs one `WARN` event that names the upgrade methods. Without it, the `KMS AEAD decrypt`
spans of such values record `error_code=LEGACY_FORMAT`, see [Observability](./observability.md).

## Upgrading stored values

With `legacy-formats`, two methods of `KmsAeadEnvelope` rewrite a stored value in Tink's format,
and return `None` when it already is in it, so a sweep writes only the rows that change:

- `upgrade_legacy_value`, for envelope values;
- `upgrade_legacy_encrypted_key`, for encrypted DEKs stored apart, such as the bytes of 0.29's
  `to_bytes`.

Each decrypts the DEK with the provider, without the DEK cache, and encrypts it again as a
serialised Tink key when it was in an older layout: one KMS call for a current value, two for an old
one. A value in Tink's framing needs the decryption to be told from the 32-bit layout before 0.24.0.
The AEAD bytes stay as they are.

The envelope's algorithm is the one the values were sealed with: ChaCha20-Poly1305 for values that
0.29 and earlier sealed under their default. A raw DEK does not record its algorithm, and the
encrypted DEK of the upgrade records it as a Tink key type, so `upgrade_legacy_value` takes the
value's AAD and opens the value before it writes anything. Under another algorithm or another AAD
it fails with `DECRYPT`. `upgrade_legacy_encrypted_key` has no value to open, so it records the
envelope's algorithm for any key of its length. Be aware not to upgrade a DEK stored apart under
another algorithm than its values were sealed with: use `upgrade_legacy_value` wherever the values
are at hand.

A sweep over stored rows:

```rust
use kms_aead::{
    AeadBackend, CipherTextWithEncryptedKey, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadResult, ValueStruct,
};

/// A stored envelope value and the AAD it was sealed under.
struct Row {
    aad: Vec<u8>,
    value: Vec<u8>,
}

/// Rewrites the envelope values of `rows` in Tink's format, and returns how many changed.
#[allow(deprecated)]
async fn upgrade_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &mut [Row],
) -> KmsAeadResult<usize>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut upgraded = 0;
    for row in rows.iter_mut() {
        let stored = CipherTextWithEncryptedKey(row.value.clone());
        if let Some(value) = envelope.upgrade_legacy_value(&row.aad, &stored).await? {
            row.value = value.into_value();
            upgraded += 1;
        }
    }
    Ok(upgraded)
}
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{AeadAlgorithm, AeadCipher, KmsAeadEnvelopeOptions, Ring};
# use secret_vault_value::SecretValue;
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# // A value as 0.28.1 wrote it: [w: u64 BE][encrypted raw key][cipher text]
# let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
# let key = cipher.generate_key()?;
# let cipher_text = cipher.encrypt_value(b"aad", &SecretValue::from("secret"), &key)?;
# let encrypted = provider.encrypt_data_encryption_key(&key).await?;
# let mut legacy = u64::try_from(encrypted.value().len()).unwrap().to_be_bytes().to_vec();
# legacy.extend_from_slice(encrypted.value());
# legacy.extend_from_slice(cipher_text.value());
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     provider,
#     KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
# )?;
# let mut rows = vec![Row { aad: b"aad".to_vec(), value: legacy }];
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 1);
# assert_eq!(upgrade_values(&envelope, &mut rows).await?, 0);
# let upgraded = CipherTextWithEncryptedKey(rows[0].value.clone());
# assert_eq!(envelope.decrypt_value(b"aad", &upgraded).await?, SecretValue::from("secret"));
# Ok(())
# }
```

Upgrade every reader to 0.30 before the sweep writes: 0.29 and earlier cannot read Tink's format.

## Deprecation

Reading the layouts of 0.29 and earlier is deprecated since 0.30.0 and will be removed in a later
breaking release, together with the `legacy-formats` feature and the upgrade methods, which carry
`#[deprecated]` from their first release, so every call site warns. Without the feature, the
older layouts keep failing with `LEGACY_FORMAT`.
