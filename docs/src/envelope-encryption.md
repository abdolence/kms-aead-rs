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
it keeps decrypting with the old version only. `reencrypt_encrypted_dek` and `reencrypt_dek` move a
stored DEK to the current version, so the old version can be retired while the application keeps
reading and writing:

1. rotate the KEK in the KMS, as the page of each provider describes;
2. re-encrypt every stored DEK: the DEKs of the stored values, the DEKs stored apart from their
   values, and the record of each keyring under the KEK with `KeyringAdmin::reencrypt_deks`. Then
   export the keyrings' keysets again and re-encrypt the application's own encrypted keysets, see
   [Encrypted keysets](#encrypted-keysets);
3. once no process holds an encrypted DEK from before step 2, disable the old version, then check
   that the KMS decrypts every stored DEK and every encrypted keyset. A DEK or a keyset it refuses
   is one the sweep missed: enable the old version again, sweep again and check again. When to
   disable, and how the local KMS checks before it, are in [The check](#the-check);
4. keep the old version disabled for as long as the backups of the stored values are kept, check
   once more, then destroy it.

A backup taken before the sweep holds the DEKs under the old version, so destroying the old version
makes every such backup unreadable for good. Keyring records are the same, see
[Key lifecycle](./keyring/lifecycle.md#compromised-versions). What a rotation, a disabled version
and a destroyed version are differs per KMS, see the page of each provider.

### The sweep

`reencrypt_encrypted_dek` makes two KMS calls: the KMS decrypts the DEK with the version that
encrypted it and encrypts it again with its current one. The AEAD bytes of a value stay as they
are, so the sweep takes no AAD, opens nothing, and the value decrypts as before. Each distinct
encrypted DEK is re-encrypted once and joined with each of its values, so the values a store-less
envelope wrote under one DEK still share one afterwards:

```rust
use std::collections::HashMap;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{
    Encrypted, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// The bytes to write back for each stored value in `rows`, beside the bytes read, with its DEK
/// under the KEK's current version. Each distinct encrypted DEK is re-encrypted once.
async fn reencrypt_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &[Vec<u8>],
) -> KmsAeadResult<Vec<(Vec<u8>, Vec<u8>)>>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut reencrypted: HashMap<EncryptedDataEncryptionKey, EncryptedDataEncryptionKey> =
        HashMap::new();
    let mut updates = Vec::with_capacity(rows.len());
    for row in rows {
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
        updates.push((row.clone(), Encrypted::join(&bare, &new_encrypted_dek)?.into_value()));
    }
    Ok(updates)
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# use kms_aead::{DekReusePolicy, KmsAeadEnvelopeOptions};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     LocalKmsProvider::new(
#         kek_id.clone(),
#         vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
#     )?,
#     KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
# )?;
# let mut rows = Vec::new();
# for card in ["4111 1111 1111 1111", "5500 0000 0000 0004"] {
#     rows.push(envelope.encrypt(b"orders/1042", &SecretValue::from(card)).await?.into_value());
# }
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id.clone(),
#     vec![
#         LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
#         LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
#     ],
# )?)?;
# for (read, new) in reencrypt_values(&envelope, &rows).await? {
#     if let Some(row) = rows.iter_mut().find(|row| **row == read) {
#         *row = new;
#     }
# }
# let encrypted_deks = rows
#     .iter()
#     .map(|row| Ok(Encrypted::<SecretValue, Envelope>::try_from(row.clone())?.separate()?.1))
#     .collect::<KmsAeadResult<Vec<EncryptedDataEncryptionKey>>>()?;
# assert_eq!(encrypted_deks[0], encrypted_deks[1]);
# let disabled = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
# )?)?;
# for row in &rows {
#     let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
#     disabled.decrypt(b"orders/1042", &stored).await?;
# }
# Ok(())
# }
```

Write each value back only where the stored bytes are still the ones read, with a compare-and-set
such as `UPDATE orders SET card = $new WHERE id = $id AND card = $read`, or the store's own
conditional write. An unconditional write puts back the value the sweep read over one the
application wrote in the meantime, which is then lost. A row the application rewrote keeps its new
value, and the check in step 3 finds it if its DEK is still under the old version.

`reencrypt_dek` does the same for one value. It gives each value an encrypted DEK of its own, so
values that shared a DEK would then cost one KMS encryption each in the sweep and one KMS decryption
each on a cache miss afterwards. The same `reencrypt_encrypted_dek` re-encrypts the DEKs stored
apart from their values, such as those of the `*_with_encrypted_dek` calls, of beacons and of
deterministic fields. A value or a DEK in a layout of 0.29 or earlier fails with `LEGACY_FORMAT`:
`upgrade_legacy_value` and `upgrade_legacy_encrypted_dek` rewrite it in Tink's format, with its DEK
under the current version, see [Upgrading stored values](./formats.md#upgrading-stored-values).

The DEK cache plays no part: the sweep decrypts through the provider and leaves the cache as it is,
so it evicts no entry that serves reads. Every call encrypts again, also for a DEK already under the
current version. The sweep needs KMS encrypt and decrypt on the KEK.

### Encrypted keysets

An encrypted keyset is a KMS ciphertext as well, under the KEK version that encrypted it, and
`reencrypt_encrypted_dek` refuses one with `INVALID_KEY_FORMAT`, since what the KMS decrypts from
it is a serialised keyset. A sweep of the DEKs leaves every keyset under the old version, so a
query or a reader that opens one fails once the old version is disabled:

- a keyring's `export_bigquery_keyset` and `export_tink_keyset`: export each keyset again, with the
  same selection, after `reencrypt_deks` and, under Cloud KMS, after the new primary version has
  propagated. The new export holds the same keys, encrypted under the KEK's current version. Write
  its bytes wherever the old ones are kept: the query parameter or the literal of each
  `KEYS.KEYSET_CHAIN`, a column or a setting that holds the keyset, and the file or the setting a
  Tink reader opens. See [BigQuery](./keyring/bigquery.md#exporting-a-keyset-to-bigquery);
- the application's own encrypted keyset, such as `first_level_keyset` in
  [One fixed key](#one-fixed-key): the provider decrypts it and encrypts it again, and the new bytes
  replace the old ones wherever they are kept:

```rust
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadResult};

/// `first_level_keyset` encrypted again under the KEK version the provider encrypts with now.
async fn reencrypt_keyset<P: KmsAeadEncryptionProvider>(
    provider: &P,
    first_level_keyset: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<EncryptedDataEncryptionKey> {
    let keyset = provider.decrypt_data_encryption_key(first_level_keyset).await?;
    provider.encrypt_data_encryption_key(&keyset).await
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# use kms_aead::DataEncryptionKey;
# use secret_vault_value::SecretValue;
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let keyset = DataEncryptionKey::from(SecretValue::new(vec![0x0a; 16]));
# let first_level_keyset = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
# )?
# .encrypt_data_encryption_key(&keyset)
# .await?;
# let rotated = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![
#         LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
#         LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
#     ],
# )?;
# let reencrypted = reencrypt_keyset(&rotated, &first_level_keyset).await?;
# let disabled = LocalKmsProvider::<Ring>::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
# )?;
# assert_eq!(disabled.decrypt_data_encryption_key(&reencrypted).await?, keyset);
# Ok(())
# }
```

The check decrypts the bytes of a BigQuery keyset and of the application's own keyset through the
provider, as it does an encrypted DEK, with `EncryptedDataEncryptionKey::from` of the bytes. A
Tink keyset is a `google.crypto.tink.EncryptedKeyset` around the KMS ciphertext, and its check is
an open with the Tink reader that uses it.

### Pacing

The sweep makes two KMS calls per distinct encrypted DEK, and the check one, on top of the calls
the application makes. Under a KMS with a request quota, as the cloud KMSs have, pace the sweep
below it: a fixed number of DEKs per second, or a pause after each batch, with room left for the
application. A sweep over the quota fails with the KMS's error, such as `ResourceExhausted` on GCP,
and so do the application's own calls meanwhile.

### The check

Once the old version is disabled, the KMS refuses every DEK still under it, so the check decrypts
each distinct encrypted DEK through the provider, never through the DEK cache, which would serve a
missed DEK from memory. It needs no AAD and opens no value, and it runs online, under every
provider. Any error counts as a missed DEK:

```rust
use std::collections::HashSet;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{
    Encrypted, EncryptedDataEncryptionKey, KmsAeadEncryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// The distinct encrypted DEKs of the values in `rows` that the provider fails to decrypt.
async fn missed_deks<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &[Vec<u8>],
) -> KmsAeadResult<Vec<EncryptedDataEncryptionKey>>
where
    P: KmsAeadEncryptionProvider + Send + Sync,
    B: AeadBackend,
{
    let mut encrypted_deks: HashSet<EncryptedDataEncryptionKey> = HashSet::new();
    for row in rows {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
        let (_, encrypted_dek) = stored.separate()?;
        encrypted_deks.insert(encrypted_dek);
    }
    let mut missed = Vec::new();
    for encrypted_dek in encrypted_deks {
        if envelope
            .provider()
            .decrypt_data_encryption_key(&encrypted_dek)
            .await
            .is_err()
        {
            missed.push(encrypted_dek);
        }
    }
    Ok(missed)
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
# let stored = envelope.encrypt(b"orders/1042", &SecretValue::from("4111 1111 1111 1111")).await?;
# let rows = vec![stored.into_value()];
# let disabled = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
# )?)?;
# assert_eq!(missed_deks(&disabled, &rows).await?.len(), 1);
# Ok(())
# }
```

A keyring's record is checked by running `KeyringAdmin::reencrypt_deks` again with the old version
disabled: it decrypts every DEK in the record through the provider, and fails on one still under
the old version.

Under the local KMS the check needs no disable. A provider that lists the new version alone, as
the sample above builds it, refuses every DEK under the old version, so the check runs before the
deploy that drops the old version from the list, and a missed DEK costs no outage and no redeploy.

Three things keep using the old version after a rotation, and each sets when to sweep or to
disable:

- a store-less writer keeps sealing under its current DEK, encrypted under the old version, until
  its reuse policy renews the DEK or the DEK leaves its cache, at the cache's TTL of 15 minutes by
  default. Start the sweep once every writer has renewed its DEK after the rotation took effect,
  under Cloud KMS once the new primary version had propagated, or the check finds the values
  written meanwhile;
- every DEK cache serves the DEKs it holds, without a KMS call, until their entries expire. A value
  the sweep missed fails to decrypt in the application only once its entry has expired, see
  [DEK caching](./dek-caching.md). The check does not wait for that, since it never reads a cache;
- a process keeps the encrypted DEKs it read before the sweep. A keyring's cached record holds the
  ones it had before `reencrypt_deks` until it is refreshed, at a change signal of the store or
  once it is older than `record_ttl`, 5 minutes by default, and Cloud Storage and S3 send no
  signal, see [Record cache](./keyring/record-cache.md#how-late-a-change-is-seen). An encrypted DEK
  the application read from its settings at startup, as in [One fixed key](#one-fixed-key), stays
  as it was read. The DEK cache keys its entries by those bytes, so once an entry expires, the KMS
  decrypts the old bytes again and fails under a disabled old version, with no reload. Disable the
  old version no sooner than one `record_ttl` after the last `reencrypt_deks`, and only once every
  process has read its DEKs stored apart from their values again.

A KMS whose changes take time to propagate, such as Cloud KMS, can keep encrypting under the old
version for a while after the rotation and keep decrypting under it for a while after it is
disabled. Wait before the sweep and again before trusting the check, see the page of each provider.

### Rolling back a rotation

A swept value's DEK is under the new version only, so a rollback keeps the new version enabled:
disabling it makes every swept value and every value written since the rotation unreadable, until
it is enabled again. Three providers make the old version encrypt again:

- Cloud KMS: make the old version the primary version again;
- Azure Key Vault: pin the old version in `AzureKmsKeyRef`;
- the local KMS: point `with_encrypting_version` at the old version.

Rolling back to the old version needs no new sweep. To retire the new version afterwards, run the
procedure above with the old version as the current one.

The other two always encrypt under the latest key. Vault Transit encrypts under the latest version
of the key, since the provider names no version in its request, and no older version becomes the
latest again: a rotation is undone by rotating once more and sweeping to that third version. AWS KMS
keeps every earlier key material decrypting and none can be disabled, so a rotation needs no
rollback there.
