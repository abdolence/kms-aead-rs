# BigQuery and Tink interop

Keyring values are in Tink's wire format, so Tink and BigQuery's AEAD functions read the values the
keyring writes, and the keyring reads theirs, given the same keys under the same key ids.

## Wire format

Every value starts with Tink's 5-byte TINK prefix, a version byte `0x01` and the key id, followed
by what the version's algorithm writes, see
[Formats of `Encrypted`](../formats.md#formats-of-encrypted). These are the layouts of Tink's AEAD
and deterministic AEAD primitives, and of BigQuery's `AEAD.ENCRYPT` and `DETERMINISTIC_ENCRYPT`. A
randomised version with another algorithm, such as ChaCha20-Poly1305, writes the same prefix
before its own body, which only kms-aead reads.

The prefix is not authenticated. A value relabelled with another key id selects another version,
whose key the body does not decrypt under.

## AAD in SQL

Both default AADs are UTF-8 text, so SQL rebuilds them from the row with no byte escaping:

```sql
-- Randomised: <kind>/<id>/<field>
AEAD.DECRYPT_STRING(keyset, u.email_enc, CONCAT('user/', u.id, '/email'))

-- Deterministic: <kind>/<field>
DETERMINISTIC_DECRYPT_STRING(keyset, u.email_det, 'user/email')
```

`keyset` is `KEYS.KEYSET_CHAIN(@kms_key, @keyset)` over an export of the keyring's versions, see
[Exporting a keyset to BigQuery](#exporting-a-keyset-to-bigquery). SQL cannot rebuild an AAD of
the application's own bytes, so `FieldSpec::custom_aad` fails on a field declared with
`Interop::BigQuery`, see [Why the AAD is structured](./fields.md#why-the-aad-is-structured).

The [plaintext encodings](./fields.md#encrypted-values) are the ones SQL reads: `String` and
`JsonEncoded<T>` with `AEAD.DECRYPT_STRING`, the integers with a `CAST` of it, and `Vec<u8>` with
`AEAD.DECRYPT_BYTES`. An application type reads as the type it encodes as, such as `Email` as a
`String`.

## Fields BigQuery reads

BigQuery decrypts through `KEYS.KEYSET_CHAIN`, which implements AES-256-GCM and AES-SIV only and
decrypts with Cloud KMS only. A field BigQuery also decrypts is declared with
`FieldSpec::with_interop(Interop::BigQuery)`, and the keyring then refuses to encrypt it unless:

- a randomised value is encrypted under an AES-256-GCM version, the default of a new keyring;
- a deterministic value is encrypted under an AES-SIV version;
- the KEK is in Google Cloud KMS.

The check runs on an encryptor's `encrypt` and `encrypt_deterministic`, before encrypting, and fails
with `KeyringError::Interop` naming the first requirement broken. Values already written always
decrypt: only encrypting checks. So a `change_algorithm` away from AES-256-GCM, or a keyring on
another KMS, fails the next write of the field instead of silently writing values BigQuery cannot
read.

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::KmsAeadResult;
use kms_aead_keyring::errors::{InteropError, InteropRequirement};
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Interop, Keyring, KeyringAdmin,
    KeyringAlgorithms, KeyringError, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeyringResult, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Clone)]
struct Email(String);

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_interop(Interop::BigQuery);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
// A local KEK, which BigQuery cannot decrypt with
let provider =
    LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .create(provider, KeyringId::from_static("tenant-42"), KeyringAlgorithms::new())
    .await?;
let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

let aad = EMAIL.aad(&EntityId::try_from("42")?);
let alice = Email("alice@example.com".to_string());
let refused: KeyringResult<Encrypted<Email, Randomized>> =
    keyring.encryptor().await.encrypt(&aad, &alice).await;
assert!(matches!(
    refused,
    Err(KeyringError::Interop(InteropError {
        requirement: InteropRequirement::Kek(_),
        ..
    }))
));
registry.shutdown(None).await;
# Ok(())
# }
```

## Fields Tink reads

A field that Tink also decrypts, with the keyset of
[`export_tink_keyset`](#exporting-a-keyset-to-tink), is declared with
`FieldSpec::with_interop(Interop::Tink)`. The keyring then refuses to encrypt it unless:

- a randomised value is encrypted under an AES-128-GCM, AES-256-GCM or AES-256-GCM-SIV version;
- a deterministic value is encrypted under an AES-SIV version;
- the KEK has a Tink key URI: a Cloud KMS key, an AWS KMS key named by its ARN, or a Vault
  Transit key.

ChaCha20-Poly1305 is left out, since Tink for Python and C++ do not read it in a keyset. The check
and its errors are the ones of `Interop::BigQuery`, with `Interop::Tink` in the error.

## Exporting a keyset to BigQuery

Feature `bigquery-export`. It builds on kms-aead's GCP provider with no TLS root store, so the
application also enables kms-aead's `gcp-kms-encryption`, or another root store feature of
kms-aead's GCP provider.

BigQuery reads keyring values through `KEYS.KEYSET_CHAIN`, which takes a Tink keyset encrypted by a
Cloud KMS key. `KeyringAdmin::export_bigquery_keyset` builds that keyset from the keyring's
versions, on a keyring whose provider is `GcpKmsProvider`, under the `bigquery-export` feature,
which implies `admin`. The bytes it returns are the Cloud KMS ciphertext of Tink's serialised
`Keyset` message, encrypted with no associated data, without the `EncryptedKeyset` message Tink's
own keyset readers take, see [Exporting a keyset to Tink](#exporting-a-keyset-to-tink):

```rust,no_run
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    encodings, EncryptedKeyset, KeyringAdmin, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeysetSelection, Purpose,
};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let key_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, GcpKmsProvider, Ring> = registry
    .admin(GcpKmsProvider::new(&key_ref).await?, KeyringId::try_from("tenant-42".to_string())?)
    .await?;

let keyset: EncryptedKeyset<encodings::BigQuery> = admin
    .export_bigquery_keyset(KeysetSelection::Readable(Purpose::Randomized))
    .await?;
// The query parameters of `KEYS.KEYSET_CHAIN(@kms_key, @keyset)`: a `STRING` and a `BYTES`
let kms_key: &str = keyset.key_uri();
let keyset_bytes: &[u8] = keyset.value();
# let _ = (kms_key, keyset_bytes);
registry.shutdown(None).await;
# Ok(())
# }
```

The selection:

- `KeysetSelection::Readable(purpose)`: every version of the purpose that decrypts and is not
  compromised, the pending one included, with the active version as the primary. BigQuery decrypts a
  value under the key its prefix names, so one keyset reads a column written across rotations. It
  fails with `NoActiveVersion` when the purpose has none;
- `KeysetSelection::Single(key_id)`: the one version as the primary, also when it is compromised.
  It is the keyset of `DETERMINISTIC_ENCRYPT`, which encrypts under the primary, for the probe of
  one version, and of a read through a compromised version. A retired, destroyed or unknown
  version fails as a read under it does, and a pending one with `KeyVersionPending`, since
  BigQuery would encrypt under it.

Beacon versions are never exported: a selection of the beacon purpose fails with
`ExportAlgorithmUnsupported`. BigQuery's SQL cannot compute a beacon either, see
[BigQuery](../beacons.md#bigquery) in kms-aead.

The type parameter of an `EncryptedKeyset` is its encoding, from the `encodings` module, which names
the reader of its bytes. The `EncryptedKeyset<encodings::BigQuery>` this export returns:

- `value()` and `into_value()`: the encrypted keyset, as a `BYTES` column or query parameter holds
  it;
- `key_uri()`: Tink's key URI of the Cloud KMS key, `gcp-kms://projects/…/cryptoKeys/…`, the
  first argument of `KEYS.KEYSET_CHAIN`, as a `STRING` query parameter;
- `key_ids()`: the key ids of the versions inside, in ascending order.

The export selects its versions from the record in the store, read at the time of the call, not
from the record the process has cached. A version another process flagged compromised is
therefore left out of a `Readable` keyset, even before this process's cached record refreshes. The
read is checked as a revalidation is: a stored record that moves a version backwards fails the
export with `RecordRegressed`, and a missing one with `RecordMissing`.

A keyset is a copy of the record at the time of the export. A `Readable` keyset exported while a
version is pending already holds it, so the order of a rotation is: `rotate`, export the
`Readable` keysets again, wait, `promote`. Values encrypted under the new version then read in
BigQuery from the first one. After `mark_compromised`, whose replacement is active at once, the
replacement's values do not read, and the compromised version stays in a keyset exported before
it, until the keyset is exported again.

A KEK rotation changes no key inside a keyset and leaves the keyset under the KEK version that
encrypted it at the export, so `KEYS.KEYSET_CHAIN` fails once that version is disabled. Export
every keyset again after `reencrypt_deks`, once the new primary version has propagated, and replace
the old bytes in every query and column that holds them before the old version is disabled, see
[Encrypted keysets](../envelope-encryption.md#encrypted-keysets).

### Queries

Every value reaches the query as a parameter: `@kms_key` is the export's `key_uri()`, each
keyset parameter its `value()`, and `@email` the address an equality query looks for:

```sql
-- Randomised values, with a Readable(Randomized) keyset
SELECT AEAD.DECRYPT_STRING(
  KEYS.KEYSET_CHAIN(@kms_key, @keyset), u.email_enc, CONCAT('user/', u.id, '/email'))
FROM users u;

-- Deterministic values, with a Readable(Deterministic) or Single keyset
SELECT DETERMINISTIC_DECRYPT_STRING(KEYS.KEYSET_CHAIN(@kms_key, @keyset), u.email_det, 'user/email')
FROM users u;

-- An equality query: one probe per deterministic version, each with its Single keyset
SELECT u.id
FROM users u
WHERE u.email_det IN (
  DETERMINISTIC_ENCRYPT(KEYS.KEYSET_CHAIN(@kms_key, @keyset_d2), @email, 'user/email'),
  DETERMINISTIC_ENCRYPT(KEYS.KEYSET_CHAIN(@kms_key, @keyset_d1), @email, 'user/email')
);
```

The probes in BigQuery are those of the active and decrypt-only versions. A pending version has
no `Single` keyset, and no value is encrypted under it before its promotion.

The requirements:

- the keyring's KEK is a Cloud KMS key, and the query runs in the KMS key's location;
- the exported versions are AES-256-GCM or AES-SIV. Any other algorithm fails with
  `ExportAlgorithmUnsupported`, before any KMS call;
- the field is declared with `Interop::BigQuery`, so that the keyring never encrypts it under a
  version the keyset could not hold, see [Fields BigQuery reads](#fields-bigquery-reads);
- the principal that queries has decrypt on the KMS key, and the one that exports has encrypt and
  decrypt on it. The export is a `KeyringAdmin` call, see
  [KMS rights](./deployment.md#kms-rights).

### How it behaves

The crate's live test runs the export and the queries against Cloud KMS and BigQuery:

- a value whose key id is not in the keyset fails to decrypt, and reads as `NULL` under
  `SAFE.AEAD.DECRYPT_STRING`;
- the keyset is encrypted with no associated data, since `KEYS.KEYSET_CHAIN` decrypts with none.
  What the KMS decrypts from it is a serialised Tink keyset, which is no serialised Tink key, so
  copied into a record as a version's encrypted DEK it decrypts nothing and fails with
  `INVALID_KEY_FORMAT`;
- the export decrypts each selected version through the provider and never through the DEK cache,
  so the keys stay in the process for the call only. Its span records `dek_cache` as `bypassed`.

Cloud KMS encrypts at most 64 KiB of plaintext, which a keyset reaches at several hundred versions.

## Exporting a keyset to Tink

`export_tink_keyset` exports the same versions as Tink's encrypted keyset, which Tink for Java,
Go and Python decrypt with `KeysetHandle.read` and their own KMS client. It is a `KeyringAdmin`
call, needs the `admin` feature only, and runs on a keyring with any provider whose KEK has a Tink
key URI. The bytes are a `google.crypto.tink.EncryptedKeyset` around the KMS ciphertext of the
serialised keyset, see
[Tink keysets and the TINK prefix](../formats.md#tink-keysets-and-the-tink-prefix).

`key_uri()` is the URI of Tink's KMS client:

- `gcp-kms://projects/…/cryptoKeys/…` for a Cloud KMS key;
- `aws-kms://arn:aws:kms:…` for an AWS KMS key named by its ARN;
- `hcvault://<host>/…/keys/<name>` for a Vault Transit key, which Tink for Go reads. Tink for
  Java and Python have no Vault Transit client.

An Azure Key Vault key, a local or an application's own KEK, and an AWS key named without its
ARN have no Tink client. The export fails on them with `KeyringError::Interop`, `Interop::Tink`
and `InteropRequirement::Kek`, before any store or KMS call.

After a KEK rotation, a Tink keyset is exported again and replaces the old one wherever a Tink
reader decrypts it, as a BigQuery keyset does, see
[Encrypted keysets](../envelope-encryption.md#encrypted-keysets).

```rust,no_run
use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    encodings, EncryptedKeyset, KeyringAdmin, KeyringId, KeyringRegistry, KeyringRegistryOptions,
    KeysetSelection, Purpose,
};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let key_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, GcpKmsProvider, Ring> = registry
    .admin(GcpKmsProvider::new(&key_ref).await?, KeyringId::try_from("tenant-42".to_string())?)
    .await?;

let keyset: EncryptedKeyset<encodings::Tink> = admin
    .export_tink_keyset(KeysetSelection::Readable(Purpose::Randomized))
    .await?;
std::fs::write("tenant-42.keyset", keyset.value())?;
println!("{}", keyset.key_uri());
registry.shutdown(None).await;
# Ok(())
# }
```

Tink for Python reads the keyset with the KMS client of that URI, and decrypts a randomised value
with the value's default AAD as UTF-8:

```python
import tink
from tink import aead
from tink.integration import gcpkms

aead.register()
key_uri = 'gcp-kms://projects/my-project/locations/europe-north1/keyRings/my-key-ring/cryptoKeys/my-key'
with open('tenant-42.keyset', 'rb') as keyset_file:
  keyset_handle = tink.read_keyset_handle(
      tink.BinaryKeysetReader(keyset_file.read()),
      gcpkms.GcpKmsClient(key_uri).get_aead(key_uri),
  )
email_aead = keyset_handle.primitive(aead.Aead)


def decrypt_email(value: bytes, user_id: str) -> str:
  return email_aead.decrypt(value, f'user/{user_id}/email'.encode()).decode()
```

The selection, the fresh read of the record and the rights are those of the BigQuery export. The
algorithms are those of [Fields Tink reads](#fields-tink-reads): a selected ChaCha20-Poly1305 or
beacon version fails with `ExportAlgorithmUnsupported`, before any KMS call.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/tink_export.rs):
it exports a keyset for each Cloud KMS or AWS KMS key whose variables are set, and Tink for Python
decrypts a value encrypted before the rotation with it, through
`tests/tink_interop.py read-keysets`.
