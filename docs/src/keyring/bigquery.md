# BigQuery and Tink interop

Keyring values are in Tink's wire format, so Tink and BigQuery's AEAD functions read the values the
keyring writes, and the keyring reads theirs, given the same keys under the same key ids.

## Wire format

Every value starts with Tink's 5-byte TINK prefix, a version byte `0x01` and the key id as a
big-endian `u32`, followed by what the version's algorithm writes:

| Purpose | Layout | Overhead |
|---|---|---|
| Randomized, AES-256-GCM | `[0x01][key id: 4][nonce: 12][ciphertext][tag: 16]` | 33 bytes |
| Deterministic, AES-SIV | `[0x01][key id: 4][synthetic IV: 16][ciphertext]` | 21 bytes |

These are the layouts of Tink's AEAD and deterministic AEAD primitives, and of BigQuery's
`AEAD.ENCRYPT` and `DETERMINISTIC_ENCRYPT`. A randomized version with another algorithm, such as
ChaCha20-Poly1305, writes the same prefix before its own body, which only kms-aead reads.

The prefix is not authenticated. A value relabelled with another key id selects another version,
whose key the body does not open under.

## AAD in SQL

Both default AADs are UTF-8 text, so SQL rebuilds them from the row with no byte escaping:

```sql
-- Randomized: <kind>/<id>/<field>
AEAD.DECRYPT_STRING(keyset, u.email_enc, CONCAT('user/', u.id, '/email'))

-- Deterministic: <kind>/<field>
DETERMINISTIC_DECRYPT_STRING(keyset, u.email_det, 'user/email')
```

`keyset` is a keyset of the keyring's versions, see
[Exporting a keyset to BigQuery](#exporting-a-keyset-to-bigquery). An AAD built with
`FieldAad::custom` has no structure SQL can rebuild.

The [plaintext encodings](./fields.md#encrypted-values) are the ones SQL reads: `String` and
`Json<T>` with `AEAD.DECRYPT_STRING`, the integers with a `CAST` of it, and `Vec<u8>` with
`AEAD.DECRYPT_BYTES`.

## Fields BigQuery reads

BigQuery decrypts through `KEYS.KEYSET_CHAIN`, which implements AES-256-GCM and AES-SIV only and
unwraps with Cloud KMS only. A field BigQuery also decrypts is declared with
`FieldSpec::with_interop(Interop::BigQuery)`, and the keyring then refuses to seal it unless:

- a randomized value is sealed under an AES-256-GCM version, the default of a new keyring;
- a deterministic value is sealed under an AES-SIV version;
- the KEK is in Google Cloud KMS.

The check runs on `encrypt` and `encrypt_deterministic`, before sealing, and fails with
`KeyringError::Interop` naming the first requirement broken. Values already written always
decrypt: only sealing checks. So a `change_algorithm` away from AES-256-GCM, or a keyring on
another KMS, fails the next write of the field instead of silently writing values BigQuery
cannot read.

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::AeadBackend;
use kms_aead_keyring::errors::{InteropError, InteropRequirement};
use kms_aead_keyring::store::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, Interop, Keyring, KeyringError, KeyringId,
    KeyringOptions, KeyringPolicy,
};

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
// A local KEK, which BigQuery cannot unwrap with
let provider = LocalKmsProvider::ephemeral(
    LocalKekId::try_from("tenant-kek".to_string())?,
    AeadBackend::Ring,
)?;
let keyring = Keyring::open_or_create(
    MemoryKeyringStore::new(),
    provider,
    AeadBackend::Ring,
    KeyringId::from_static("tenant-42"),
    KeyringPolicy::new(),
    KeyringOptions::new(),
)
.await?;

let aad = EMAIL.aad(&EntityId::try_from("42")?);
let refused = keyring.encrypt(&aad, &"alice@example.com".to_string()).await;
assert!(matches!(
    refused,
    Err(KeyringError::Interop(InteropError {
        requirement: InteropRequirement::Kek(_),
        ..
    }))
));
# Ok(())
# }
```

## Exporting a keyset to BigQuery
