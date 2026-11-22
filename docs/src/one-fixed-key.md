# One fixed key

This page specifies the calls that encrypt under one key the application holds, in the layout that
Tink, Google's cryptography library, and BigQuery read. For the BigQuery side of a column, read
[Decrypt columns in BigQuery SQL or with Tink](./use-cases/bigquery-and-tink.md). A column that
needs key rotation belongs under a keyring.

`AeadCipher::encrypt` encrypts a field under a key the application holds, in Tink's layout for a
key with the output prefix TINK: `[0x01][key id: u32 BE]` before the AEAD value, an
`Encrypted<T, Randomized>`. `DeterministicCipher::encrypt` does the same for an
`Encrypted<T, Deterministic>`. The key id is a `KeyId`, the application's constant. Tink and
BigQuery read the values with a keyset, Tink's serialised list of keys and their ids, of the one
key under that id:

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
query parameter, beside the key's Tink URI as a `STRING` one,
`gcp-kms://projects/my-project/locations/europe-north1/keyRings/my-key-ring/cryptoKeys/my-key`:

```sql
SELECT AEAD.DECRYPT_STRING(
  KEYS.KEYSET_CHAIN(@kms_key, @first_level_keyset),
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
