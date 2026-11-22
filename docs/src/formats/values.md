# Values and DEKs

The bytes of the values an application stores and of the DEKs that go with them. The layouts of
every kind of value are listed on [Formats](../formats.md).

## Formats of `Encrypted`

Every value the library encrypts is an `Encrypted<T, F>`: the bytes of one layout, named by its
format `F` from `kms_aead::formats`. `Encrypted::try_from` and `Encrypted::try_from_hex_string`
check stored bytes against it:

| Format | Layout | Shortest value | `key_id()` | Written by |
|---|---|---|---|---|
| `Envelope` | [Tink's KMS envelope](#tinks-kms-envelope) | an encrypted DEK of 1 to 4,096 bytes, then 28 bytes | none | `KmsAeadEnvelope::encrypt`, `Encrypted::join` |
| `Bare` | `[nonce: 12][ciphertext][tag: 16]` | 28 bytes | none | `AeadCipher::encrypt_bare`, `KmsAeadEnvelope::encrypt_with_dek` and `encrypt_with_encrypted_dek`, `Encrypted::separate` |
| `Randomized` | `[0x01][key id: u32 BE][nonce: 12][ciphertext][tag: 16]` | 33 bytes | `KeyId` | `AeadCipher::encrypt`, and kms-aead-keyring through it |
| `Deterministic` | `[0x01][key id: u32 BE][synthetic IV: 16][ciphertext]` | 21 bytes | `KeyId` | `DeterministicCipher::encrypt`, and kms-aead-keyring through it |

A `Bare` value is Tink's AEAD output under a key with the output prefix RAW, and the part of every
`Envelope` value after the encrypted DEK. It names no key: the application keeps track of the key
that decrypts it.

The check reads the framing only, and whether the bytes are authentic is known when they are
decrypted. With `legacy-formats`, an `Envelope` value also holds the envelope layout v1 of 0.29 and
the length-prefixed envelope, checked by their lengths, so a column decodes its old rows into the
same type until they are upgraded, see
[Upgrading stored values](../migrating-from-0.29.md#upgrading-stored-values). Without the feature,
`Encrypted::try_from` refuses them with `LEGACY_FORMAT`. `separate` refuses them in every build. The
layout of 32-bit targets before 0.24.0 has Tink's framing, so it reads as an
`Envelope` value in every build, and `KmsAeadEnvelope::decrypt` decrypts it with `legacy-formats`.

The plaintext inside is the encoding of the value's `Plaintext` type: UTF-8 for `String`, the
bytes themselves for `Vec<u8>` and `SecretValue`, `true` or `false` for `bool`, decimal ASCII for
the integers, and compact JSON for `JsonEncoded<T>`. See
[Stored values](../stored-values.md#plaintext).

## Tink's KMS envelope

`KmsAeadEnvelope::encrypt` writes Tink's KMS envelope, and `Encrypted::join` writes it from a
bare value and an encrypted DEK. `separate` reads it back:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let encrypted: Encrypted<SecretValue, Envelope> =
    envelope.encrypt(b"aad", &SecretValue::from("secret")).await?;

let (bare, encrypted_dek) = encrypted.separate()?;
let joined = Encrypted::<SecretValue, Envelope>::join(&bare, &encrypted_dek)?;
assert_eq!(joined.value(), encrypted.value());
# Ok(())
# }
```

- `w` is 1 to 4,096 bytes, the limit of every Tink implementation, on write and on read;
- the encrypted DEK is the provider's [`EncryptedDataEncryptionKey`](#encrypted-deks), the KMS
  ciphertext of the [serialised DEK](#serialised-deks), or of the raw DEK for Azure;
- the AAD goes to the DEK's AEAD only. The KMS encryption of the DEK has no AAD, as in Tink, so
  Tink's AWS client sends no encryption context and its GCP client no additional authenticated data;
- the rest is a [`Bare` value](#formats-of-encrypted).

The envelope records neither the algorithm nor the KEK version, so the writer and the reader,
kms-aead or Tink, are configured with the same algorithm. Tink calls it the DEK template:

| Algorithm | Tink key type | Tink for Java and Go | Tink for C++ and Python |
|---|---|---|---|
| ChaCha20-Poly1305 | `ChaCha20Poly1305Key` | reads and writes | no |
| AES-128-GCM, AES-256-GCM | `AesGcmKey` | reads and writes | reads and writes |
| AES-256-GCM-SIV | `AesGcmSivKey` | reads and writes | reads and writes |

AES-256-GCM is the default of `KmsAeadEnvelope::new`, so every Tink implementation reads the
values of an envelope that names no algorithm. The default of 0.29 and earlier was
ChaCha20-Poly1305, see [Migrating from 0.29](../migrating-from-0.29.md#default-algorithm).

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
the bytes to store and the bytes it decrypts. Each provider's bytes name the KEK version that
encrypted the DEK where the KMS needs one to decrypt:

| Provider | Bytes | Key version |
|---|---|---|
| GCP | the Cloud KMS ciphertext, starting with `0x0a` | inside the ciphertext |
| AWS | the AWS KMS ciphertext blob, starting with `0x01` | not exposed |
| Azure | `[0x01][k: u8][key version: k][Key Vault encrypted DEK]` | in the layout |
| Vault Transit | the Transit ciphertext, `vault:vN:…` | the `N` |
| local | `[0x01][i: u8][KEK id: i][KEK version: u32 BE][nonce: 12][encrypted DEK][tag: 16]` | in the layout |
| any, encrypted with a public key | `[0x02][a: u8][i: u8][KEK id: i][k: u8][KEK version: k][RSA block]`, see [DEKs encrypted with a public key](#deks-encrypted-with-a-public-key) | in the layout |
| an application's own | whatever it returns | |

The Azure layout is the library's own: Key Vault decrypts only with the key version that encrypted,
and no Tink client exists for Azure. For the same reason, the Key Vault encrypted DEK is the KMS
ciphertext of the raw DEK of 16, 32 or 64 bytes, as in 0.29, not of the serialised DEK: AES key
wrap, `A128KW` to `A256KW`, takes only multiples of 8 bytes, which no serialised DEK is. The local
KMS encrypts the DEK with AES-256-GCM under the KEK version, with its header up to the version as
the AAD, so neither the id nor the version can be changed without the decryption failing.

The `0x02` layout is the same for every KMS: a producer holding the public half of an RSA key
encrypts the DEK in its own process, and the provider of the KMS that holds the private half
decrypts it. The providers of 0.31 read it beside their own bytes, and no earlier release reads it,
see [DEKs encrypted with a public key](#deks-encrypted-with-a-public-key) and [Asymmetric
KEKs](../asymmetric-kek.md).

Store `value()` or `to_hex_string()`, and read them back with `EncryptedDataEncryptionKey::from`
or `try_from_hex_string`. Neither holds the KEK version of `kek_version()`, see
[Storing encrypted DEKs](../envelope-encryption.md#storing-encrypted-deks).

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
| HMAC-SHA256, MAC key | `HmacKey` | `[0x1a][0x20][key: 32]` |
| HMAC-SHA512, MAC key | `HmacKey` | `[0x1a][0x40][key: 64]` |

A beacon key of HMAC-SHA256 is serialised as `[0x1a][0x20][key: 32]`, its 32 bytes in
`key_value`, field 3, as in Tink's `HmacPrfKey` without its parameters: the bytes of a 32-byte
`AesGcmKey`. It is encrypted as a DEK is, raw under an Azure key. A MAC key of a keyring is serialised the same
way, in field 3 and never in field 2, since `[0x12][0x40][key: 64]` is byte for byte an AES-SIV key,
see [MACs in a keyring](../signing.md#macs-in-a-keyring).

`KmsAeadEnvelope::generate_encrypted_dek`, `generate_encrypted_deterministic_dek` and the
`generate_encrypted_dek` of both ciphers and of `BeaconMac` encrypt their keys the same way. The
message does not name its type, and AES-256-GCM and AES-256-GCM-SIV keys are written alike, so the
algorithm of the reader decides how the key is used, as in Tink.

A decrypted DEK that is no serialised Tink key, or under an Azure key no raw DEK, fails with
`INVALID_KEY_FORMAT`. An encrypted Tink
keyset decrypts under the same KEK too, and this is what keeps it out of the DEK cache.

## DEKs encrypted with a public key

An encrypted DEK that a public key encrypted has one layout for every KMS:

```text
[0x02][a: u8][i: u8][KEK id: i bytes][k: u8][KEK version: k ASCII alphanumerics][RSA block]
```

- `0x02` is the layout. No encrypted DEK of a built-in provider starts with it before 0.31, see
  [Telling layouts apart](../formats.md#telling-layouts-apart);
- `a` is the algorithm: `0x01` for RSA-OAEP with SHA-256 as the OAEP hash and the MGF1 hash, and an
  empty label. A later algorithm is another value;
- `i` and the KEK id are the local KEK's `LocalKekId`. `i` is 0 for a cloud KEK;
- `k` and the KEK version are the version the public key carried, as the reader names it to its KMS:
  1 to 255 ASCII alphanumerics. `k` is 0 under AWS KMS, which has no versions, and the version is the
  decimal `LocalKekVersion` under the local KMS;
- the RSA block is as long as the modulus: 256, 384 or 512 bytes for a key of 2048, 3072 or 4096
  bits. The encrypted DEK is the header and the block, 260 bytes under AWS KMS with a 2048-bit key.

The block is the OAEP encryption of the DEK in the form its KEK's provider encrypts it: the
[serialised DEK](#serialised-deks), or the raw DEK under Key Vault. The seed of OAEP is random, so
two encryptions of one DEK differ.

A reader checks the header against its own shape before any KMS call, and refuses the encrypted DEK
with `ASYMMETRIC_ENCRYPTED_DEK_FORMAT` otherwise: a known algorithm byte; a header within the bytes;
`i` of 0 for a cloud KEK; `k` of 0 under AWS KMS and 1 or more elsewhere; a block of 256, 384 or 512
bytes. Nothing in the header is authenticated: a changed version or KEK id names a key that fails to
decrypt the block, and no change decrypts a value.

How each KMS decrypts the block:

| KMS | Request |
|---|---|
| Google Cloud KMS | `AsymmetricDecrypt` on `<key>/cryptoKeyVersions/<version>`, `ciphertext` the block |
| AWS KMS | `Decrypt` with `KeyId` the key, `EncryptionAlgorithm` `RSAES_OAEP_SHA_256` and `CiphertextBlob` the block |
| Azure Key Vault | `unwrapKey` on the key and the version with `alg` `RSA-OAEP-256` |
| Vault Transit | `decrypt` on the key with `ciphertext` `vault:v<version>:` and the standard base64 of the block, `padding_scheme` `oaep` and `hash_algorithm` `sha2-256` |
| Local KMS | RSA-OAEP decryption with the version's private key |

None of the four KMS decryptions takes a label or an AAD. What binds a value to its place is its own
AAD.

## Beacons

A `Beacon<T>` is a prefix and a truncated HMAC-SHA256:

```text
[0x01][key id: u32 BE][HMAC-SHA256: the first ceil(bits / 8) bytes]
```

- `0x01` is the version of the beacon layout. A later layout takes another first byte, so that
  beacons of both layouts can share a column during a re-index;
- the key id names the beacon key that calculated the beacon;
- the HMAC keeps its first `bits` bits, and the unused low bits of the last byte are zero. A
  beacon is 6 to 37 bytes.

The HMAC covers the bits, the context and the plaintext, as the `Plaintext` type encodes it:

```text
HMAC-SHA256(key, [bits: u16 BE][context length: u32 BE][context][plaintext])
```

so that beacons of two fields, or of two bit counts, never match. `Beacon::try_from` checks the
prefix and that 1 to 32 bytes of HMAC follow, and fails with `INVALID_BEACON_FORMAT` otherwise.
