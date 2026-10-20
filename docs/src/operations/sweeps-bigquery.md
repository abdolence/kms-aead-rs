# Sweeps on BigQuery

The marker is a `BYTES` column. BigQuery gives a column added to a table `NULL` in the rows already
there, so the column's default goes with a write of `SealMarker::ENVELOPE` into them:

```sql
ALTER TABLE users ADD COLUMN seal BYTES;
ALTER TABLE users ALTER COLUMN seal SET DEFAULT b'\x01\x00\x00\x00\x00';
UPDATE users SET seal = b'\x01\x00\x00\x00\x00' WHERE seal IS NULL;
```

A field BigQuery reads, declared with `Interop::BigQuery`, is re-sealed by one `UPDATE` in SQL,
with no Rust loop and no value leaving BigQuery. Its parameters come from a
`Readable(Purpose::Randomized)` export, see
[Exporting a keyset to BigQuery](../keyring/bigquery.md#exporting-a-keyset-to-bigquery): `@kms_key`
is the export's `key_uri()`, `@keyset` its `value()`, and `@seal` the bytes of its marker,
`keyset.seal_marker().value()`:

```sql
UPDATE users
SET
  email = AEAD.ENCRYPT(
    KEYS.KEYSET_CHAIN(@kms_key, @keyset),
    AEAD.DECRYPT_BYTES(
      KEYS.KEYSET_CHAIN(@kms_key, @keyset), email, CAST(CONCAT('user/', id, '/email') AS BYTES)),
    CAST(CONCAT('user/', id, '/email') AS BYTES)),
  seal = @seal
WHERE seal < @seal AND seal > b'\x01\x00\x00\x00\x00';
```

`AEAD.DECRYPT_BYTES`, and `AEAD.ENCRYPT` of bytes, take the AAD as `BYTES`, the UTF-8 of the
same text. `AEAD.ENCRYPT` seals under the keyset's primary, which a `Readable` export sets to the
active version of the record it reads from the store, and `EncryptedKeyset::seal_marker()` is that
record's marker. So every row the statement re-seals lies in the
[range](./sweeps.md#records-under-a-version) of the primary, as a row written through a `Sealer` does. A
keyset exported before a promotion has the previous version as its primary and the previous
epoch's marker, and the rows it re-seals stay in the next sweep's query, so the sweep exports its
keyset after the promotion. The export is a `KeyringAdmin` call of the administrative job.

The statement re-seals every encrypted field of the row, since the marker it writes covers all of
them. Fields of several purposes are sealed under one `Readable` keyset each, and the statement
stamps the marker only when their `seal_marker()` is the same; otherwise it exports them again. A
row with a beacon, which SQL does not compute, goes through the Rust path below, and so does a row
under `SealMarker::ENVELOPE`, the lowest marker, which the statement leaves out: an envelope value
does not open under a keyring's keyset.

This sweep:

- resumes without a checkpoint: the statement is atomic, a failed one changed nothing, and the
  next run's `WHERE` finds every row it did not write;
- loses no concurrent write: BigQuery runs DML under snapshot isolation, and of two conflicting
  statements on the same rows one fails and runs again, and its `WHERE` then sees the other's
  marker;
- makes no KMS call per record: BigQuery opens the keyset through Cloud KMS for the statement;
- runs on a schedule until it re-seals no row. The administrative job retires the old version
  once its range query,
  `SELECT COUNT(*) FROM users WHERE seal >= @start AND (@end IS NULL OR seal < @end)`, returns 0.

A `Readable` keyset leaves a compromised version out, so the values under it fail
`AEAD.DECRYPT_BYTES` and the whole statement with them. After a compromise those rows go through
the Rust path below, where the sealer's `reseal` reports their trust.

Other fields, such as ChaCha20-Poly1305 values or values under a custom AAD, are re-sealed in
Rust. BigQuery runs only a few DML statements on one table at a time, so the write is one `MERGE`
per batch of rows rather than one `UPDATE` per row, conditional on the bytes each row held:

```sql
MERGE users u
USING UNNEST(@rows) p
ON u.id = p.id AND u.phone = p.old_phone
WHEN MATCHED THEN UPDATE SET phone = p.phone, seal = @seal;
```

The rows stream from the application's BigQuery client, one query of
`SELECT id, phone, seal FROM users WHERE seal < @current` with the current marker, and
`sweep::run_batched` cuts them into batches. Each batch is re-sealed through one sealer, and the
client runs the `MERGE` with `@seal` bound to the marker of the sealer's record. Every row of a
batch goes into `@rows`, the current ones with their bytes as they are, so that each gets the
marker:

```rust
use std::fmt::{self, Display, Formatter};
use std::future::Future;
use std::num::NonZeroUsize;

use futures_util::Stream;
use kms_aead::backends::Ring;
use kms_aead::providers::GcpKmsProvider;
use kms_aead::{AeadAlgorithm, KmsAeadResult};
use kms_aead_keyring::formats::{Envelope, Randomized};
use kms_aead_keyring::store::FirestoreKeyringStore;
use kms_aead_keyring::sweep::{self, BatchedSweepOptions, ResealOutcome, SealMarker, SweepReport};
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring, KeyringError,
    KeyringResult, Plaintext, Resealed, Sealer,
};
use secret_vault_value::SecretValue;

type UsersKeyring = Keyring<FirestoreKeyringStore, GcpKmsProvider, Ring>;
type UsersSealer<'k> = Sealer<'k, FirestoreKeyringStore, GcpKmsProvider, Ring>;

const PHONE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("phone"),
);
const BATCH_SIZE: NonZeroUsize = NonZeroUsize::new(1000).unwrap();
/// BigQuery runs 2 mutating DML statements on a table at once and queues the rest.
const CONCURRENCY: NonZeroUsize = NonZeroUsize::new(2).unwrap();
/// The algorithm of the store-less envelope that wrote the values before the migration.
const ENVELOPE_ALGORITHM: AeadAlgorithm = AeadAlgorithm::Aes256Gcm;

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
/// A row of `SELECT id, phone, seal FROM users WHERE seal < @current`.
struct UserRow {
    id: String,
    /// An envelope value under `SealMarker::ENVELOPE`, a keyring value under any other marker.
    phone: Vec<u8>,
    seal: SealMarker,
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

/// The AAD the application gave its envelope values.
fn envelope_aad(id: &str) -> Vec<u8> {
    format!("users:{id}:phone").into_bytes()
}

/// `phone`, the stored bytes of user `id` under the marker `seal`, under the active version of
/// `sealer`, and the outcome of its re-seal. A keyring value under that version comes back as it
/// is, with `ResealOutcome::Skipped`.
async fn reseal_phone(
    keyring: &UsersKeyring,
    sealer: &UsersSealer<'_>,
    id: &str,
    seal: SealMarker,
    phone: &[u8],
) -> KeyringResult<(Encrypted<Phone, Randomized>, ResealOutcome)> {
    let aad = PHONE.aad(&EntityId::try_from(id)?);
    if seal == SealMarker::ENVELOPE {
        let value = Encrypted::<Phone, Envelope>::try_from(phone.to_vec())?;
        let opened: Phone = keyring
            .decrypt_envelope_for_migration(&envelope_aad(id), &value, ENVELOPE_ALGORITHM)
            .await?;
        // Envelope values name no key version, so the record carries no trust to decide on
        let resealed = ResealOutcome::Resealed {
            from_compromised: false,
        };
        return Ok((sealer.encrypt(&aad, &opened).await?, resealed));
    }
    let phone = Encrypted::<Phone, Randomized>::try_from(phone.to_vec())?;
    let resealed: Option<Resealed<Phone, Randomized>> = sealer.reseal(&aad, &phone).await?;
    Ok(match resealed {
        Some(resealed) => {
            let from_compromised = matches!(resealed.trust, KeyTrust::Compromised(_));
            (resealed.value, ResealOutcome::Resealed { from_compromised })
        }
        // The value is current: the row gets the marker alone
        None => (phone, ResealOutcome::Skipped),
    })
}

/// Re-seals the `rows` of the query in batches, one sealer per batch, and writes each batch
/// through `merge`, which runs the `MERGE` with `@seal` bound to the marker it is given, the
/// marker of the batch's sealer, and returns its number of affected rows. `ClientError` is the
/// error of the application's BigQuery client, which a row that did not read returns and a
/// `KeyringError` converts into, and its `Display` is the text the sweep logs for a failure.
async fn sweep_phones<Rows, Merge, Merged, ClientError>(
    keyring: &UsersKeyring,
    rows: Rows,
    merge: Merge,
) -> SweepReport
where
    Rows: Stream<Item = Result<UserRow, ClientError>>,
    Merge: Fn(Vec<PhoneUpdate>, SealMarker) -> Merged,
    Merged: Future<Output = Result<u64, ClientError>>,
    ClientError: From<KeyringError> + Display,
{
    let options: BatchedSweepOptions = BatchedSweepOptions::new()
        .with_batch_size(BATCH_SIZE)
        .with_concurrency(CONCURRENCY);
    sweep::run_batched(keyring.id(), rows, options, |batch: Vec<UserRow>| {
        let merge = &merge;
        async move {
            let sealer: UsersSealer<'_> = keyring.sealer().await;
            let mut done: Vec<(UserRow, Result<ResealOutcome, ClientError>)> =
                Vec::with_capacity(batch.len());
            let mut queued: Vec<(UserRow, ResealOutcome)> = Vec::with_capacity(batch.len());
            let mut updates: Vec<PhoneUpdate> = Vec::with_capacity(batch.len());
            for row in batch {
                match reseal_phone(keyring, &sealer, &row.id, row.seal, &row.phone).await {
                    Ok((phone, outcome)) => {
                        updates.push(PhoneUpdate {
                            id: row.id.clone(),
                            old_phone: row.phone.clone(),
                            phone,
                        });
                        queued.push((row, outcome));
                    }
                    Err(error) => done.push((row, Err(error.into()))),
                }
            }
            let merged: u64 = merge(updates, sealer.record().seal_marker()).await?;
            // A `MERGE` returns a count, not the rows: a batch with one row a concurrent writer
            // changed counts every row as skipped
            let all_written = u64::try_from(queued.len()) == Ok(merged);
            done.extend(queued.into_iter().map(|(row, outcome)| {
                (row, Ok(if all_written { outcome } else { ResealOutcome::Skipped }))
            }));
            Ok(done)
        }
    })
    .await
}
#
# fn main() {}
```

A batch is re-sealed sequentially inside its call, and `concurrency` bounds the batches in flight,
which BigQuery's limit on concurrent DML per table sets low. The five properties hold per batch: a
row that a concurrent writer changed fails the `ON` condition and stays in the query for the next
run.

A `MERGE` returns a count, not the rows it changed, so a batch with one such row counts all its rows
as `Skipped`, the ones it wrote included. Its re-seals from a compromised version then drop out of
`SweepReport::resealed_from_compromised`, although they went through the trust decision below, so
on this path that count is a lower bound.

The marker takes 7 bytes of a row: its 5 bytes and the 2 BigQuery counts for every `BYTES` value.
Measured on BigQuery, 100,000 markers held 700,000 bytes, and the sweep's query processed
700,000 bytes, the `seal` column alone. BigQuery does not cluster a `BYTES` column, so the query
reads the whole column: about 70 MB at 10 million rows, about $0.0004 per query at $6.25 per TiB
on demand, and its storage about $0.0013 a month at $0.02 per GiB.

The [`sweep_bigquery` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_bigquery.rs)
runs the `UPDATE` above end to end, from the writes to the count of re-sealed rows, against Cloud
KMS and BigQuery. It writes the rows through the Storage Write API, and the `UPDATE` re-seals them
straight after: DML can modify rows recently written through its gRPC interface.
