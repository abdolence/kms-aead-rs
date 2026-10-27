# Sweeps on BigQuery

A sweep of a BigQuery table, in two paths: one `UPDATE` in SQL for the fields BigQuery reads, and a
Rust path for the rest. The mechanism is in [Sweeps](./sweeps.md). The Rust path has the five
properties of [Sweeps by store](./sweeps.md#sweeps-by-store), and the SQL path states its own below.

The marker is a `BYTES` column that every write of the encrypted fields sets:

```sql
CREATE TABLE users (
  id STRING NOT NULL,
  phone BYTES NOT NULL,
  encryption_marker BYTES NOT NULL
);
```

A field BigQuery reads, declared with `Interop::BigQuery`, is re-encrypted by one `UPDATE` in SQL,
with no Rust loop and no value leaving BigQuery. Its parameters come from a
`Readable(Purpose::Randomized)` export, see [Exporting a keyset to
BigQuery](../keyring/bigquery.md#exporting-a-keyset-to-bigquery): `@kms_key` is the export's
`key_uri()`, `@keyset` its `value()`, and `@encryption_marker` the bytes of its marker,
`keyset.encryption_marker().value()`:

```sql
UPDATE users
SET
  email = AEAD.ENCRYPT(
    KEYS.KEYSET_CHAIN(@kms_key, @keyset),
    AEAD.DECRYPT_BYTES(
      KEYS.KEYSET_CHAIN(@kms_key, @keyset), email, CAST(CONCAT('user/', id, '/email') AS BYTES)),
    CAST(CONCAT('user/', id, '/email') AS BYTES)),
  encryption_marker = @encryption_marker
WHERE encryption_marker < @encryption_marker;
```

`AEAD.DECRYPT_BYTES`, and `AEAD.ENCRYPT` of bytes, take the AAD as `BYTES`, the UTF-8 of the same
text. `AEAD.ENCRYPT` encrypts under the keyset's primary, which a `Readable` export sets to the
active version of the record it reads from the store, and `EncryptedKeyset::encryption_marker()` is
that record's marker. So every row the statement re-encrypts lies in the
[range](./sweeps.md#records-under-a-version) of the primary, as a row written through an `Encryptor`
does. A keyset exported before a promotion has the previous version as its primary and the previous
epoch's marker, and the rows it re-encrypts stay in the next sweep's query, so the sweep exports its
keyset after the promotion. The export is a `KeyringAdmin` call of the administrative job.

The statement re-encrypts every encrypted field of the row, since the marker it writes covers all of
them. Fields of several purposes are encrypted under one `Readable` keyset each, and the statement
stamps the marker only when their `encryption_marker()` is the same; otherwise it exports them again.
A row with a beacon, which SQL does not compute, goes through the Rust path below.

This sweep:

- resumes without a checkpoint: the statement is atomic, a failed one changed nothing, and the
  next run's `WHERE` finds every row it did not write;
- loses no concurrent write: BigQuery runs DML under snapshot isolation, and of two conflicting
  statements on the same rows one fails and runs again, and its `WHERE` then sees the other's
  marker;
- makes no KMS call per record: BigQuery decrypts the keyset through Cloud KMS for the statement;
- runs on a schedule until it re-encrypts no row. The administrative job retires the old version
  once its range query,
  `SELECT COUNT(*) FROM users WHERE encryption_marker >= @start AND (@end IS NULL OR encryption_marker < @end)`,
  returns 0.

A `Readable` keyset leaves a compromised version out, so the values under it fail
`AEAD.DECRYPT_BYTES` and the whole statement with them. After a compromise those rows go through
the Rust path below, where the encryptor's `reencrypt` reports their trust.

Other fields, such as ChaCha20-Poly1305 values or values under a custom AAD, are re-encrypted in
Rust. BigQuery runs only a few DML statements on one table at a time, so the write is one `MERGE`
per batch of rows rather than one `UPDATE` per row, conditional on the bytes each row held:

```sql
MERGE users u
USING UNNEST(@rows) p
ON u.id = p.id AND u.phone = p.old_phone
WHEN MATCHED THEN UPDATE SET phone = p.phone, encryption_marker = @encryption_marker;
```

The rows stream from the application's BigQuery client, one query of
`SELECT id, phone, encryption_marker FROM users WHERE encryption_marker < @current` with the current
marker, and `sweep::reencrypt_records_batched` cuts them into batches. Each batch is re-encrypted through one
encryptor, and the client runs the `MERGE` with `@encryption_marker` bound to the marker of the
encryptor's record. Every row of a batch goes into `@rows`, the current ones with their bytes as
they are, so that each gets the marker:

```rust
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;

use futures_util::Stream;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::KmsAeadResult;
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ReencryptOutcome, EncryptionMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringError, KeyringResult,
    Plaintext, Encryptor,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;
type UsersEncryptor<'k> = Encryptor<'k, FirestoreKeyringStore, GcpKmsProvider, Ring>;

const PHONE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("phone"),
);
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
/// BigQuery runs 2 mutating DML statements on a table at once and queues the rest.
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(2).unwrap();

# #[derive(Clone)]
# struct Phone(String);
#
# impl Plaintext for Phone {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Phone)
#     }
# }
#
/// A row of `SELECT id, phone FROM users WHERE encryption_marker < @current`.
struct UserRow {
    id: String,
    phone: Encrypted<Phone, Randomized>,
}

/// The row id, and nothing of its columns.
impl Display for UserRow {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "users/{}", self.id)
    }
}

/// One element of `@rows`: a row with the bytes it held and the bytes to write.
struct PhoneUpdate {
    id: String,
    old_phone: Vec<u8>,
    phone: Encrypted<Phone, Randomized>,
}

/// `phone` of user `id` under the active version of `encryptor`, and the outcome of its
/// re-encryption. A value under that version comes back as it is, with `ReencryptOutcome::Skipped`.
async fn reencrypt_phone(
    encryptor: &UsersEncryptor<'_>,
    id: &str,
    phone: &Encrypted<Phone, Randomized>,
) -> KeyringResult<(Encrypted<Phone, Randomized>, ReencryptOutcome)> {
    let aad = PHONE.aad(&EntityId::try_from(id)?);
    let reencrypted = encryptor.reencrypt(&aad, phone).await?;
    let outcome = ReencryptOutcome::from(&reencrypted);
    // A current value still gets the encryptor's marker, so that it leaves the query.
    let phone = reencrypted.map_or_else(|| phone.clone(), |reencrypted| reencrypted.value);
    Ok((phone, outcome))
}

/// Re-encrypts the `rows` of the query in batches, one encryptor per batch, and writes each batch
/// through `merge`, which runs the `MERGE` with `@encryption_marker` bound to the marker it is given, the
/// marker of the batch's encryptor, and returns its number of affected rows. `ClientError` is the
/// error of the application's BigQuery client, which a row that did not read returns and a
/// `KeyringError` converts into, and its `Display` is the text the sweep logs for a failure.
async fn sweep_phones<Rows, Merge, Merged, ClientError>(
    keyring: &UsersKeyring,
    rows: Rows,
    merge: Merge,
) -> SweepReport
where
    Rows: Stream<Item = Result<UserRow, ClientError>>,
    Merge: Fn(Vec<PhoneUpdate>, EncryptionMarker) -> Merged,
    Merged: Future<Output = Result<u64, ClientError>>,
    ClientError: From<KeyringError> + Display,
{
    let options: BatchedSweepOptions = BatchedSweepOptions::new()
        .with_batch_size(BATCH_SIZE)
        .with_concurrency(CONCURRENCY);
    sweep::reencrypt_records_batched(keyring.id(), rows, options, |batch: Vec<UserRow>| {
        let merge = &merge;
        async move {
            let encryptor: UsersEncryptor<'_> = keyring.encryptor().await;
            let mut done: Vec<(UserRow, Result<ReencryptOutcome, ClientError>)> =
                Vec::with_capacity(batch.len());
            let mut queued: Vec<(UserRow, ReencryptOutcome)> = Vec::with_capacity(batch.len());
            let mut updates: Vec<PhoneUpdate> = Vec::with_capacity(batch.len());
            for row in batch {
                match reencrypt_phone(&encryptor, &row.id, &row.phone).await {
                    Ok((phone, outcome)) => {
                        updates.push(PhoneUpdate {
                            id: row.id.clone(),
                            old_phone: row.phone.value().to_vec(),
                            phone,
                        });
                        queued.push((row, outcome));
                    }
                    Err(error) => done.push((row, Err(error.into()))),
                }
            }
            let merged: u64 = merge(updates, encryptor.record().encryption_marker()).await?;
            // A `MERGE` returns a count, not the rows: a batch with one row a concurrent writer
            // changed counts every row as skipped
            let all_written = u64::try_from(queued.len()) == Ok(merged);
            done.extend(queued.into_iter().map(|(row, outcome)| {
                (row, Ok(if all_written { outcome } else { ReencryptOutcome::Skipped }))
            }));
            Ok(done)
        }
    })
    .await
}
#
# fn main() {}
```

A batch is re-encrypted sequentially inside its call, and `concurrency` bounds the batches in
flight, which BigQuery's limit on concurrent DML per table sets low. The five properties hold per
batch: a row that a concurrent writer changed fails the `ON` condition and stays in the query for
the next run.

A `MERGE` returns a count, not the rows it changed, so a batch with one such row counts all its rows
as `Skipped`, the ones it wrote included. Its re-encryptions from a compromised version then drop
out of `SweepReport::reencrypted_from_compromised`, although they went through the trust decision
below, so on this path that count is a lower bound.

The marker takes 7 bytes of a row: its 5 bytes and the 2 BigQuery counts for every `BYTES` value.
Measured on BigQuery, 100,000 markers held 700,000 bytes, and the sweep's query processed 700,000
bytes, the `encryption_marker` column alone. BigQuery does not cluster a `BYTES` column, so the query
reads the whole column: about 70 MB at 10 million rows, about $0.0004 per query at $6.25 per TiB on
demand, and its storage about $0.0013 a month at $0.02 per GiB.

The [`sweep_bigquery`
example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_bigquery.rs)
runs the `UPDATE` above end to end, from the writes to the count of re-encrypted rows, against Cloud
KMS and BigQuery. It writes the rows through the Storage Write API, and the `UPDATE` re-encrypts
them straight after: DML can modify rows recently written through its gRPC interface.
