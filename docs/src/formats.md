# Formats

Every byte layout the library reads or writes is listed on this page and described on the pages
below it:

- [Values and DEKs](./formats/values.md): `Encrypted<T, F>` and its formats, Tink's KMS envelope,
  encrypted DEKs and the serialised DEKs inside them, DEKs encrypted with a public key, and
  beacons;
- [Streamed values](./formats/streamed-values.md): the header and chunks of streamed values, in the
  prefixed, bare and envelope forms, and how a range read maps to chunks;
- [Signature and MAC formats](./formats/signatures-and-macs.md): detached and attached signatures
  and MACs, what they are computed over, the key ids of signing keys and the test vectors;
- [Keyring records and keysets](./formats/keyring-records.md): the key ids of a keyring, the JSON
  record every store keeps, encryption markers, and Tink keysets.

The library writes one envelope format for every provider, Tink's KMS envelope. A value encrypted
by `KmsAeadEnvelope::encrypt` decrypts with Tink's `KmsEnvelopeAead` on the same KMS key and
algorithm, and a value Tink encrypts decrypts with `KmsAeadEnvelope::decrypt`.

| Layout | Type | Bytes | Read by | Written by |
|---|---|---|---|---|
| [Tink KMS envelope](./formats/values.md#tinks-kms-envelope) | `Encrypted<T, Envelope>` | `[w: u32 BE][encrypted DEK: w][nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | 0.30.0 and later |
| [Bare value](./formats/values.md#formats-of-encrypted) | `Encrypted<T, Bare>` | `[nonce: 12][ciphertext][tag: 16]` | kms-aead, Tink | every release |
| [Encrypted DEK](./formats/values.md#encrypted-deks) | `EncryptedDataEncryptionKey` | the provider's bytes | kms-aead, Tink for GCP and AWS keys | 0.30.0 and later |
| [Serialised DEK](./formats/values.md#serialised-deks) | the plaintext of an encrypted DEK, but Azure's | Tink's key message | kms-aead, Tink | 0.30.0 and later |
| [TINK-prefixed value](./formats/values.md#formats-of-encrypted) | `Encrypted<T, Randomized>`, `Encrypted<T, Deterministic>`, named by a `KeyId` | `[0x01][key id: u32 BE][value]` | kms-aead, Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| [Streamed value](./formats/streamed-values.md) | `StreamEncryptor` and `StreamDecryptor` of `AeadCipher::stream_encryptor` and `stream_decryptor`, and of the keyring's `Encryptor::stream_encryptor` and `Keyring::stream_decryptor` | see its page | kms-aead with `stream`; a C2SP chunked-encryption reader from byte 5 | 0.31.0 and later, and kms-aead-keyring through it |
| [Envelope streamed value](./formats/streamed-values.md) | `StreamEncryptor` and `StreamDecryptor` of `KmsAeadEnvelope::stream_encryptor` and `stream_decryptor` | see its page | kms-aead with `stream`; a C2SP chunked-encryption reader from byte `4 + w` | 0.31.0 and later |
| [Bare streamed value](./formats/streamed-values.md) | `StreamEncryptor` and `StreamDecryptor` of the `stream_encryptor_bare` and `stream_decryptor_bare` calls of `AeadCipher` and `KmsAeadEnvelope` | see its page | kms-aead with `stream`, any C2SP chunked-encryption reader | 0.31.0 and later |
| [Detached signature](./formats/signatures-and-macs.md) | `Signature<T>` | `[0x01][key id: u32 BE][signature]` | kms-aead | 0.31.0 and later |
| [Attached signature](./formats/signatures-and-macs.md) | `Signed<T>` | `[0x01][key id: u32 BE][w: u16 BE][signature: w][payload]` | kms-aead | 0.31.0 and later |
| [Detached MAC](./formats/signatures-and-macs.md) | `Mac<T>` | `[0x01][key id: u32 BE][tag]` | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |
| [Attached MAC](./formats/signatures-and-macs.md) | `WithMac<T>` | `[0x01][key id: u32 BE][w: u16 BE][tag: w][payload]` | kms-aead, and kms-aead-keyring for its MAC versions | 0.31.0 and later |
| [Tink keyset](./formats/keyring-records.md#tink-keysets-and-the-tink-prefix) | `TinkKeyset` | `google.crypto.tink.Keyset` | Tink, BigQuery | 0.30.0 and later, and kms-aead-keyring through it |
| [Tink encrypted keyset](./formats/keyring-records.md#tink-keysets-and-the-tink-prefix) | `TinkKeyset::into_encrypted_bytes` | `google.crypto.tink.EncryptedKeyset`, `[0x12][w: varint][encrypted keyset: w]` | Tink with a GCP, AWS or Vault Transit key | 0.30.0 and later, and kms-aead-keyring through it |
| Envelope layout v1 | `Encrypted<T, Envelope>` with `legacy-formats` | `[0x01][k: u8][key version: k][w: u16 BE][encrypted DEK: w][cipher text]` | kms-aead with `legacy-formats` | 0.29 |
| Encrypted DEK layout v1 | stored `EncryptedDataEncryptionKey` | `[0xFF][0x01][k: u8][key version: k][encrypted DEK]` | kms-aead with `legacy-formats` | 0.29 |
| Length-prefixed envelope | `Encrypted<T, Envelope>` with `legacy-formats` | `[w: u64 BE][encrypted DEK: w][cipher text]`, and `[w: u32 BE]` from 32-bit targets before 0.24.0 | kms-aead with `legacy-formats` | 0.8.0 to 0.28.1 |
| Raw encrypted DEK | `EncryptedDataEncryptionKey` | the KMS ciphertext of the DEK's 16 or 32 raw bytes | kms-aead with `legacy-formats` | up to 0.29 |

`k = 0` records no key version. A key version is 1 to 255 ASCII alphanumeric characters. The Azure
provider encrypts the raw DEK in every release, see
[Encrypted DEKs](./formats/values.md#encrypted-deks).

The layouts of 0.29 and earlier are read only with the deprecated `legacy-formats` feature. The
reading rules and the upgrade of stored values are in
[Migrating from 0.29](./migrating-from-0.29.md#values-written-by-029-and-earlier).

## Telling layouts apart

The first bytes of a stored value:

| First bytes | Layout |
|---|---|
| `00 00 00 00` | the length-prefixed envelope of 0.28.1 and earlier |
| `00`, then a length of 1 to 4,096 | Tink's KMS envelope, an envelope streamed value, or the 4-byte length prefix of 32-bit targets before 0.24.0 |
| `01` | envelope layout v1 of 0.29, or a TINK-prefixed value |
| `02` | a DEK encrypted with the public half of an asymmetric KEK |
| `FF 01` | encrypted DEK layout v1 of 0.29 |

Only the decrypted DEK tells a Tink envelope from the 32-bit layout before 0.24.0: a raw key of
16 or 32 bytes against a serialised Tink key, whose lengths differ. An encrypted DEK of AWS, Azure
or the local KMS also starts with `0x01`, and Tink's LEGACY and CRUNCHY output prefixes with `0x00`.

A column that holds two layouts:

- Tink envelopes and TINK-prefixed values: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.29 envelopes: the first byte, `0x00` or `0x01`;
- Tink envelopes and 0.28.1 envelopes: the first four bytes;
- 0.29 envelopes and TINK-prefixed values: no byte tells them apart, so the layout is recorded
  outside the value, such as in another column;
- bare values and any other layout: a bare value has no framing, and its random nonce can start
  with any byte, so a column of bare values holds no other layout;
- streamed values and bare streamed values: no byte tells them apart, since a bare one starts
  with its random salt, so the call names the form, as `decrypt_bare` does for a bare value, see
  [Streamed values](./formats/streamed-values.md#streamed-values);
- envelope streamed values and Tink envelopes: both start with `[w][encrypted DEK]`, so the
  layout is recorded outside the value, as for bare values;
- encrypted DEKs of 0.29 and of 0.30: `0xFF 0x01` starts no encrypted DEK of a built-in provider, so
  the library tells them apart for those. It never inspects the bytes of an application's own
  provider: strip the header `[0xFF][0x01][k][key version]` of its 0.29 keys before reading them.
