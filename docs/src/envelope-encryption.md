# Envelope encryption

`KmsAeadEnvelope` seals values under data encryption keys (DEKs) on the crypto backend it is built
with, and encrypts the DEKs with the KEK of its provider. A call that makes no KMS call is not
`async`, and every call opens one `DEBUG` span, see [Observability](./observability.md).

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadAlgorithm, KmsAeadEnvelope, KmsAeadEnvelopeOptions};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
// AES-256-GCM by default
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

// Or another algorithm
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
    provider,
    KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305),
)?;
# let _ = envelope;
# Ok(())
# }
```

The value does not record the algorithm, so the writer and the reader of a value must be
configured with the same one. The backend can differ, see
[Crypto backends](./crypto-backends.md). The default, AES-256-GCM, is read by every Tink
implementation too, see [Formats](./formats.md#tinks-kms-envelope). Values that 0.29 and earlier
sealed under their default open only with ChaCha20-Poly1305 configured, see
[Migrating from 0.29](./migrating-from-0.29.md#default-algorithm).

## Encrypting values

`encrypt` seals a value under a new DEK, encrypts the DEK with one KMS call, and returns both in
one `Encrypted<T, Envelope>`, where `T` is the type of the value. `decrypt` decrypts the DEK with
one KMS call, opens the value and returns a `T`. A value with no type of its own is a
`SecretValue`:

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

let aad = b"orders/1042";
let encrypted: Encrypted<SecretValue, Envelope> = envelope
    .encrypt(aad, &SecretValue::from("4111 1111 1111 1111"))
    .await?;

// The bytes to store, and the value read back from them
let stored: Vec<u8> = encrypted.into_value();
let read_back = Encrypted::<SecretValue, Envelope>::try_from(stored)?;

let decrypted: SecretValue = envelope.decrypt(aad, &read_back).await?;
assert_eq!(decrypted, SecretValue::from("4111 1111 1111 1111"));
# Ok(())
# }
```

The bytes in and out of an `Encrypted` are in [Stored values](./stored-values.md#bytes-in-and-out).

The value is in Tink's KMS envelope format for every provider, so Tink's `KmsEnvelopeAead` reads
it with the same KMS key and algorithm, see [Formats](./formats.md#tinks-kms-envelope).

A new DEK comes from the backend's CSPRNG, or from the KMS generator when the provider is
configured to use one, see [KMS random generators](./providers.md#kms-random-generators).

## Typed fields

`encrypt` and `decrypt` take a value of any type that implements `Plaintext`, so a field can have
a type of its own. The value is encoded by its `Plaintext` implementation, and the result is an
`Encrypted<T, Envelope>` that names the type:

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope, KmsAeadResult, Plaintext};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

// Sealed as the same UTF-8 bytes as a String
impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

let aad = b"users/1042/email";
let email = Email("alice@example.com".to_string());
let encrypted: Encrypted<Email, Envelope> = envelope.encrypt(aad, &email).await?;

// The bytes to store, and the field read back from them
let stored: Vec<u8> = encrypted.into_value();
let read_back = Encrypted::<Email, Envelope>::try_from(stored)?;

let decrypted: Email = envelope.decrypt(aad, &read_back).await?;
assert_eq!(decrypted, email);
# Ok(())
# }
```

- an application type maps to one of the built-in `Plaintext` types, as `Email` does, see
  [Stored values](./stored-values.md#plaintext);
- the calls run in the envelope's mode, a DEK per value or store-less DEK reuse, and decrypt
  through the envelope's DEK cache, whatever the type;
- `Encrypted::try_from` checks the stored bytes against Tink's KMS envelope layout, so a
  truncated or foreign value fails when it is read, before any KMS call, with
  `UNKNOWN_CIPHER_TEXT_LAYOUT`, `INVALID_CIPHER_TEXT_FORMAT` or, without `legacy-formats`,
  `LEGACY_FORMAT`. It checks the framing only: a changed value fails to decrypt with `DECRYPT`;
- `decrypt` fails with `INVALID_PLAINTEXT` when the plaintext is not an encoding of `T`.

`Encrypted<T, Envelope>` has no `==` and its `Debug` shows the length only, see
[Stored values](./stored-values.md#encryptedt-f).

### Storing typed fields

serde, tokio-postgres and sqlx store `Encrypted` as bytes, see
[Stored values](./stored-values.md#storing).

### One fixed key

`AeadCipher::encrypt` seals a field under a key the application holds, in Tink's layout of a key
whose output prefix is TINK, `[0x01][key id: u32 BE]` before the AEAD value: an
`Encrypted<T, Randomized>`. `DeterministicCipher::encrypt` does the same for an
`Encrypted<T, Deterministic>`. The key id is a `KeyId`, the application's constant, and Tink
and BigQuery read the values with a keyset of the one key under that id:

```rust,no_run
use kms_aead::backends::Ring;
use kms_aead::cache::{DekCache, DekCacheOptions};
use kms_aead::formats::{Randomized, TinkKeyType, TinkKeyset};
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead::{
    AeadAlgorithm, AeadCipher, DataEncryptionKey, Encrypted, EncryptedDataEncryptionKey, KeyId,
    KmsAeadEncryptionProvider, KmsAeadResult, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

// The id of the one key, in every value and in the keyset
const EMAIL_KEY: KeyId = KeyId::new(1);

# async fn example() -> KmsAeadResult<()> {
let key_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let provider = GcpKmsProvider::new(&key_ref).await?;
let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
let cache = DekCache::new(DekCacheOptions::new())?;

// Once, by an administrative job: the key encrypted by Cloud KMS, stored in the settings
let (_, encrypted_dek): (DataEncryptionKey, EncryptedDataEncryptionKey) =
    cipher.generate_encrypted_dek(&provider).await?;

// On every write and read: the key decrypted through the cache, no KMS call while it is cached
let email = Email("alice@example.com".to_string());
let (encrypted, _) = cache
    .with_dek(&provider, &encrypted_dek, |dek| {
        cipher.encrypt(EMAIL_KEY, b"users/1042/email", &email, dek)
    })
    .await?;
let encrypted: Encrypted<Email, Randomized> = encrypted?;

let (decrypted, _) = cache
    .with_dek(&provider, &encrypted_dek, |dek| {
        cipher.decrypt(b"users/1042/email", &encrypted, dek)
    })
    .await?;
let decrypted: Email = decrypted?;
assert_eq!(decrypted, email);

// Once, for BigQuery: the keyset of the one key, encrypted by the same Cloud KMS key
let mut keyset = TinkKeyset::new(EMAIL_KEY);
let (added, _) = cache
    .with_dek(&provider, &encrypted_dek, |dek| {
        keyset.add_key(EMAIL_KEY, TinkKeyType::from(cipher.algorithm()), dek)
    })
    .await?;
added?;
let first_level_keyset: EncryptedDataEncryptionKey = provider
    .encrypt_data_encryption_key(&DataEncryptionKey::from(keyset.to_bytes()))
    .await?;
# let _ = first_level_keyset;
# Ok(())
# }
```

BigQuery reads the column with `KEYS.KEYSET_CHAIN` over the encrypted keyset, passed as a `BYTES`
query parameter:

```sql
SELECT AEAD.DECRYPT_STRING(
  KEYS.KEYSET_CHAIN(
    'gcp-kms://projects/my-project/locations/europe-north1/keyRings/my-key-ring/cryptoKeys/my-key',
    @first_level_keyset),
  u.email,
  CONCAT('users/', CAST(u.id AS STRING), '/email'))
FROM users u;
```

- BigQuery reads AES-256-GCM values with `AEAD.DECRYPT_STRING` and `AEAD.DECRYPT_BYTES`, and
  the AES-SIV values of `DeterministicCipher` with `DETERMINISTIC_DECRYPT_STRING` and
  `DETERMINISTIC_DECRYPT_BYTES`. `KEYS.KEYSET_CHAIN` decrypts with Cloud KMS only;
- `AeadCipher::decrypt` reads the values Tink and BigQuery write under the same key and id. The
  caller picks the key by `key_id()`, which the prefix names without authenticating it;
- a rotation needs a second key id, values of both ids in one column and a keyset of both keys.
  kms-aead-keyring keeps those versions.

## Beacons

A beacon, or blind index, finds rows by a field's value without decrypting the column, see
[Beacons](./beacons.md).

## AAD

The AAD is authenticated but not encrypted: a value opens only with the AAD it was sealed with,
and a wrong AAD fails with `DECRYPT`. Use it to bind a value to its place, such as
`<table>/<row id>/<column>`, so that a value copied into another row or column fails to open.

The AAD is not stored in the value, so the reader rebuilds it from the same data. It is never
logged or put in an error, but it is not secret either: keep secrets in the value itself.

The keyring takes a structured AAD instead of free bytes, built from the field and the row, see
[Why the AAD is structured](./keyring/fields.md#why-the-aad-is-structured).

## Working with DEKs yourself

The `*_with_dek` and `*_with_encrypted_dek` calls let the application keep one DEK for many
values and store the encrypted DEK apart from them, such as one DEK per tenant or per file. The
values are `Encrypted<T, Bare>`, with no encrypted DEK in them.

```rust
use kms_aead::backends::Ring;
use kms_aead::formats::Bare;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;

// One KMS call: a new DEK and the same DEK encrypted
let (dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;

// No KMS call: seal and open with the plaintext DEK
let first: Encrypted<SecretValue, Bare> =
    envelope.encrypt_with_dek(b"files/1/chunk/0", &SecretValue::from("first"), &dek)?;
let second: Encrypted<SecretValue, Bare> =
    envelope.encrypt_with_dek(b"files/1/chunk/1", &SecretValue::from("second"), &dek)?;
let decrypted: SecretValue = envelope.decrypt_with_dek(b"files/1/chunk/0", &first, &dek)?;
assert_eq!(decrypted, SecretValue::from("first"));

// Later, with only the encrypted DEK: the envelope decrypts it with the KMS
let decrypted: SecretValue = envelope
    .decrypt_with_encrypted_dek(b"files/1/chunk/1", &second, &encrypted_dek)
    .await?;
assert_eq!(decrypted, SecretValue::from("second"));
# Ok(())
# }
```

The calls are:

- `generate_encrypted_dek`: a new DEK and the same DEK encrypted, one KMS call;
- `encrypt_with_dek` and `decrypt_with_dek`: with a plaintext DEK, no KMS call;
- `encrypt_with_encrypted_dek` and `decrypt_with_encrypted_dek`: with an encrypted DEK, decrypted
  through the envelope's DEK cache, so one KMS call per call without a cache.

Be aware not to seal more than about 2^32 values under one DEK: every value takes a random 96-bit
nonce, see [Security considerations](./security.md#nonces).

## Storing encrypted DEKs

`EncryptedDataEncryptionKey` holds the bytes the provider returned, which also name the KMS key
version where the KMS needs one to decrypt after a rotation. Store `value()` or `to_hex_string()`,
and read them back with `EncryptedDataEncryptionKey::from` or `try_from_hex_string()`:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEnvelope, ValueStruct};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let (_dek, encrypted_dek) = envelope.generate_encrypted_dek().await?;

let stored: Vec<u8> = encrypted_dek.value().clone();
let read_back_encrypted_dek = EncryptedDataEncryptionKey::from(stored);

let stored_hex: String = encrypted_dek.to_hex_string();
let read_back_hex_encrypted_dek = EncryptedDataEncryptionKey::try_from_hex_string(&stored_hex)?;

assert_eq!(read_back_encrypted_dek, read_back_hex_encrypted_dek);
# Ok(())
# }
```

The encrypted DEK is the one Tink stores in its KMS envelope, so `Encrypted::join` of a bare value
and its encrypted DEK is an `Encrypted<T, Envelope>` that Tink reads. See
[Formats](./formats.md#encrypted-deks) for each provider's bytes.

## Re-encrypting DEKs after a KEK rotation

A KEK rotation makes the KMS encrypt new DEKs under a new key version, and every DEK stored before
it keeps decrypting with the old version only. `reencrypt_dek` moves the DEK of a stored value to
the current version, so the old version can be retired without downtime:

1. Rotate the KEK in the KMS;
2. re-encrypt the DEK of every stored value with `reencrypt_dek`;
3. confirm that no stored value still needs the old version;
4. disable the old version, wait, then destroy it.

What a rotation, a disabled version and a destroyed version are differs per KMS, see the page of
each provider.

`reencrypt_dek` makes two KMS calls: the KMS decrypts the DEK with the version that encrypted it
and encrypts it again with its current one. The AEAD bytes stay as they are, so the call takes no
AAD, opens nothing, and the value decrypts as before:

```rust
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{
    KmsKeyVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider,
};
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_v1 = SecretValue::new(vec![0x01; 32]);
# let kek_v2 = SecretValue::new(vec![0x02; 32]);
let kek_id = LocalKekId::try_from("orders".to_string())?;
let v1 = LocalKekVersion::from(NonZeroU32::try_from(1)?);
let v2 = LocalKekVersion::from(NonZeroU32::try_from(2)?);
let provider = LocalKmsProvider::<Ring>::new(
    kek_id.clone(),
    vec![LocalKek::from_secret(v1, kek_v1.clone())?],
)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let stored: Encrypted<SecretValue, Envelope> = envelope
    .encrypt(b"orders/1042", &SecretValue::from("4111 1111 1111 1111"))
    .await?;

// The KEK rotated: version 2 encrypts, and version 1 still decrypts
let provider = LocalKmsProvider::<Ring>::new(
    kek_id.clone(),
    vec![
        LocalKek::from_secret(v1, kek_v1)?,
        LocalKek::from_secret(v2, kek_v2.clone())?,
    ],
)?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let reencrypted: Encrypted<SecretValue, Envelope> = envelope.reencrypt_dek(&stored).await?;

let (_, encrypted_dek) = reencrypted.separate()?;
assert_eq!(
    envelope.provider().key_version(&encrypted_dek)?,
    Some(KmsKeyVersion::from(v2))
);

// Version 1 retired: the re-encrypted value still decrypts
let provider = LocalKmsProvider::<Ring>::new(kek_id, vec![LocalKek::from_secret(v2, kek_v2)?])?;
let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
let decrypted: SecretValue = envelope.decrypt(b"orders/1042", &reencrypted).await?;
assert_eq!(decrypted, SecretValue::from("4111 1111 1111 1111"));
# Ok(())
# }
```

The DEK cache plays no part: `reencrypt_dek` decrypts through the provider and leaves the cache as
it is, so a sweep evicts no entry that serves reads. Every call encrypts again, also for a value
already under the current version. The sweep needs KMS encrypt and decrypt on the KEK.

### Finding the values under the old version

The provider's `key_version` reads the version that encrypted a DEK from the encrypted DEK's bytes,
with no KMS call:

| Provider | `key_version` | Read from |
|---|---|---|
| local | the KEK version | the `[KEK version: u32 BE]` field of the local layout |
| Azure | the Key Vault key version | the key version field of the library's Azure layout, which records the version Key Vault names when it encrypts |
| Vault Transit | the `N` of `vault:vN:` | the Transit ciphertext |
| GCP | `None` | nothing: Cloud KMS keeps the version inside its ciphertext in a form it does not document |
| AWS | `None` | nothing: AWS KMS exposes no versions of a key |
| an application's own | `None`, unless it implements `key_version` | its own bytes |

A sweep skips the values under another version than the retired one, where the provider names
versions, and re-encrypts all of them where it does not. Run again, it re-encrypts nothing, which is
step 3 for the providers that name versions:

```rust
use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::providers::KmsKeyVersion;
use kms_aead::{Encrypted, KmsAeadEncryptionProvider, KmsAeadEnvelope, KmsAeadResult};
use secret_vault_value::SecretValue;

/// Moves the DEK of every stored value in `rows` off the KEK version `retired`, and returns how
/// many changed.
async fn reencrypt_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &mut [Vec<u8>],
    retired: &KmsKeyVersion,
) -> KmsAeadResult<usize>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut reencrypted = 0;
    for row in rows.iter_mut() {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
        let (_, encrypted_dek) = stored.separate()?;
        // `None` from a provider that names no versions: every value is re-encrypted
        let version: Option<KmsKeyVersion> = envelope.provider().key_version(&encrypted_dek)?;
        if version.is_some_and(|version| version != *retired) {
            continue;
        }
        *row = envelope.reencrypt_dek(&stored).await?.into_value();
        reencrypted += 1;
    }
    Ok(reencrypted)
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
# )?)?;
# let mut rows = Vec::new();
# for card in ["4111 1111 1111 1111", "5500 0000 0000 0004"] {
#     rows.push(envelope.encrypt(b"orders/1042", &SecretValue::from(card)).await?.into_value());
# }
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id,
#     vec![
#         LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
#         LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
#     ],
# )?)?;
# let retired = KmsKeyVersion::from(v1);
# assert_eq!(reencrypt_values(&envelope, &mut rows, &retired).await?, 2);
# assert_eq!(reencrypt_values(&envelope, &mut rows, &retired).await?, 0);
# Ok(())
# }
```

Under GCP and AWS no stored value tells its version, so step 3 rests on the sweep: it has to reach
every value written before the rotation.

### DEKs shared or stored apart

`reencrypt_dek` gives each value an encrypted DEK of its own. Values that share a DEK, as a
store-less envelope writes them, would then cost one KMS encryption each in the sweep and one KMS
decryption each on a cache miss afterwards. `reencrypt_encrypted_dek` re-encrypts an encrypted DEK
on its own, so each distinct one is re-encrypted once and joined with each of its values:

```rust
use std::collections::HashMap;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{
    Encrypted, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// Re-encrypts each distinct encrypted DEK of the values in `rows` once, so that the values that
/// shared a DEK still share its encrypted DEK.
async fn reencrypt_shared_deks<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &mut [Vec<u8>],
) -> KmsAeadResult<()>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut reencrypted: HashMap<EncryptedDataEncryptionKey, EncryptedDataEncryptionKey> =
        HashMap::new();
    for row in rows.iter_mut() {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
        let (bare, encrypted_dek) = stored.separate()?;
        let new_encrypted_dek = match reencrypted.get(&encrypted_dek) {
            Some(new_encrypted_dek) => new_encrypted_dek.clone(),
            None => {
                let new_encrypted_dek = envelope.reencrypt_encrypted_dek(&encrypted_dek).await?;
                reencrypted.insert(encrypted_dek, new_encrypted_dek.clone());
                new_encrypted_dek
            }
        };
        *row = Encrypted::join(&bare, &new_encrypted_dek)?.into_value();
    }
    Ok(())
}
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::{DekReusePolicy, KmsAeadEnvelopeOptions};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("example".to_string())?)?;
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     provider,
#     KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
# )?;
# let mut rows = Vec::new();
# for card in ["4111 1111 1111 1111", "5500 0000 0000 0004"] {
#     rows.push(envelope.encrypt(b"orders/1042", &SecretValue::from(card)).await?.into_value());
# }
# reencrypt_shared_deks(&envelope, &mut rows).await?;
# let encrypted_deks = rows
#     .iter()
#     .map(|row| Ok(Encrypted::<SecretValue, Envelope>::try_from(row.clone())?.separate()?.1))
#     .collect::<KmsAeadResult<Vec<EncryptedDataEncryptionKey>>>()?;
# assert_eq!(encrypted_deks[0], encrypted_deks[1]);
# Ok(())
# }
```

The same call re-encrypts the DEKs stored apart from their values, such as those of the
`*_with_encrypted_dek` calls, of beacons and of deterministic fields. A value or a DEK in a layout of
0.29 or earlier fails with `LEGACY_FORMAT`: `upgrade_legacy_value` and
`upgrade_legacy_encrypted_dek` rewrite it in Tink's format, with its DEK under the current version,
see [Upgrading stored values](./formats.md#upgrading-stored-values).

### Disabling the old version

Two things keep using the old version after a rotation, and each sets how long to wait:

- a store-less writer keeps sealing under its current DEK, encrypted under the old version, until
  its reuse policy renews the DEK or the DEK leaves its cache, at the cache's TTL of 15 minutes by
  default. Start the sweep once every writer has renewed, or run it again afterwards;
- every DEK cache serves the DEKs it holds, without a KMS call, until their entries expire. A value
  the sweep missed fails to decrypt only once its entry has expired, so wait at least the cache TTL
  after disabling the version before destroying it, see [DEK caching](./dek-caching.md).
