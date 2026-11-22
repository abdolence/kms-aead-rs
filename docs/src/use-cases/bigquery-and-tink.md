# Decrypt columns in BigQuery SQL or with Tink

An analyst needs a column that the application encrypted, in a BigQuery query, or a service in Java
or Python needs to read values a Rust service wrote. Values the library writes are in Tink's
formats, so Tink in another language and BigQuery's SQL read them, given the keys. Three routes lead
there, and they differ in what the reader needs and in whether the key rotates:

| | Envelope values | One fixed key | Keyring |
|---|---|---|---|
| Written by | `KmsAeadEnvelope::encrypt`, per call or store-less | `AeadCipher::encrypt` or `DeterministicCipher::encrypt`, with a key the KMS encrypts once | an encryptor's `encrypt` or `encrypt_deterministic` |
| A value carries | its encrypted DEK | a 4-byte key id | a 4-byte key id |
| Tink reads with | `KmsEnvelopeAead`, on a Cloud KMS or AWS KMS key | a keyset of the key, as `TinkKeyset` builds it | `export_tink_keyset`, on a Cloud KMS key, an AWS KMS key named by its ARN, or a Vault Transit key for Tink for Go |
| BigQuery reads with | nothing: SQL has no KMS envelope | `KEYS.KEYSET_CHAIN` over the keyset encrypted by a Cloud KMS key | `KEYS.KEYSET_CHAIN` over `export_bigquery_keyset`, on a Cloud KMS key |
| Algorithms BigQuery reads | none | AES-256-GCM and AES-SIV | AES-256-GCM and AES-SIV |
| Rotation | the KEK in the KMS | none: a second key needs a second key id and a keyset of both | central, with a new export after each rotation |
| See | [Tink's KMS envelope](../formats/values.md#tinks-kms-envelope) | [One fixed key](../one-fixed-key.md) | [BigQuery and Tink interop](../keyring/bigquery.md) |

## The AAD

The reader decrypts a value only with the AAD it was encrypted with, so the AAD is one the reader
can build:

- envelope values and one fixed key: the application's own bytes, which a Tink reader passes as
  they are, and SQL builds from the row when they are text, see
  [AAD](../envelope-encryption.md#aad);
- a keyring: the field's default AAD, `<kind>/<id>/<field>` for a randomised field, which SQL
  rebuilds from the row as UTF-8 text, see [AAD in SQL](../keyring/bigquery.md#aad-in-sql). A
  custom AAD fails on a field declared for BigQuery.

## With a keyring

1. Declare each field the reader decrypts with `FieldSpec::with_interop(Interop::BigQuery)` or
   `Interop::Tink`: the keyring then refuses to encrypt it under an algorithm or a KEK the reader
   does not read, see [Fields BigQuery reads](../keyring/bigquery.md#fields-bigquery-reads) and
   [Fields Tink reads](../keyring/bigquery.md#fields-tink-reads);
2. the administrative job exports the keyset, with `export_bigquery_keyset` under the
   `bigquery-export` feature or `export_tink_keyset` under `admin`, and writes its bytes where the
   query or the reader takes them;
3. the job exports again:
   - the `Readable` keysets after every `rotate`, before the promotion, and after every `retire`,
     every `mark_compromised` and every KEK rotation;
   - the `Single` keyset of a new deterministic version after its promotion, since a pending
     version has none. Until then, an equality lookup in SQL computes no probe under the new
     version and misses the rows encrypted under it, with no error.

   See [Rotation cadence](../production/rotation.md#rotation-cadence),
   [Retiring the old version](../production/sweeps.md#retiring-the-old-version) and
   [Encrypted keysets](../production/reencrypt-deks.md#encrypted-keysets).

Full example of a Tink export available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/tink_export.rs),
and of a BigQuery sweep in SQL
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_bigquery.rs).

## Query keyring values in BigQuery

Every value reaches the query as a parameter: `@kms_key` is the export's `key_uri()`, each
keyset parameter its `value()`, and `@email` the address an equality query looks for. The
requirements of a query are in [Queries](../keyring/bigquery.md#queries):

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

## Read a keyring export with Tink for Python

Tink for Python reads the keyset that `export_tink_keyset` wrote, such as `tenant-42.keyset` of
[Exporting a keyset to Tink](../keyring/bigquery.md#exporting-a-keyset-to-tink), with the KMS
client of the key URI the export returned, and decrypts a randomised value with the value's default
AAD as UTF-8:

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

## What to watch for

- An exported keyset holds the keys of the versions it selects, so treat it as a copy of the
  record's readable versions, see [Keyring limits](../security.md#keyring-limits);
- BigQuery cannot calculate a beacon: a beacon lookup in BigQuery matches beacons the application
  calculated, see [BigQuery](../beacons.md#bigquery).
