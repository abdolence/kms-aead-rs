# Move envelope values to a keyring

Values that kms-aead's `KmsAeadEnvelope` wrote, per call or store-less, move to keyring values in
five steps:

1. the model gains `encryption_marker: EncryptionMarker`, and every record without one reads as
   `EncryptionMarker::ENVELOPE`: through `#[serde(default)]`, or a column default of its bytes,
   `'\x0100000000'`;
2. the field keeps its stored bytes, whose layout the marker names: envelope values under
   `ENVELOPE`, epoch 0, and keyring values under any other marker, since the epochs of a keyring
   start at 1;
3. reads go through the marker: `Keyring::decrypt_envelope_for_migration` decrypts an envelope
   value, with the AAD and the algorithm the application used for it, and `Keyring::decrypt` a
   keyring value;
4. the sweep's query, `encryption_marker < $1` with the current marker, finds every envelope record
   too, and the re-encryption encrypts it as keyring values through an encryptor and writes the
   marker of the encryptor's record;
5. once no record holds `ENVELOPE`, the read path drops its envelope branch.

A range query never matches a record whose marker is missing: Firestore skips a document without the
field, and `<` in SQL is never true on `NULL`. A PostgreSQL column added with a default holds it in
every existing row:

```sql
ALTER TABLE users ADD COLUMN encryption_marker BYTEA NOT NULL DEFAULT '\x0100000000';
CREATE INDEX users_encryption_marker ON users (encryption_marker);
```

A BigQuery column holds `NULL` in the rows already there until an `UPDATE` writes `ENVELOPE` into
them:

```sql
ALTER TABLE users ADD COLUMN encryption_marker BYTES;
ALTER TABLE users ALTER COLUMN encryption_marker SET DEFAULT b'\x01\x00\x00\x00\x00';
UPDATE users SET encryption_marker = b'\x01\x00\x00\x00\x00' WHERE encryption_marker IS NULL;
```

The `UPDATE` in SQL of [Sweeps on BigQuery](../operations/sweeps-bigquery.md) does not decrypt an
envelope value, so its `WHERE` leaves the envelope rows out with
`AND encryption_marker > b'\x01\x00\x00\x00\x00'`, and they go through the Rust sweep.

Firestore documents written before the marker get `ENVELOPE` written into them first, or the
migration's first sweep scans the whole collection and tests `doc.encryption_marker < current` on
each, since `#[serde(default)]` reads a missing marker as `ENVELOPE`.

The sweep's re-encryption branches on the marker. An envelope value is decrypted with the algorithm
the application used for it and encrypted as a keyring value; a keyring value goes through
`Encryptor::reencrypt`, and `ReencryptOutcome::from(&reencrypted)` turns its `Option` into the
outcome. An envelope value names no key version, so its outcome has `from_compromised: false`:

```rust,ignore
let (email, outcome) = match StoredEmail::try_from(row)? {
    StoredEmail::Envelope(value) => {
        let email: Email = keyring
            .decrypt_envelope_for_migration(&envelope_aad(user), &value, ENVELOPE_ALGORITHM)
            .await?;
        let outcome = ReencryptOutcome::Reencrypted { from_compromised: false };
        (encryptor.encrypt(&aad, &email).await?, outcome)
    }
    StoredEmail::Keyring { value, .. } => {
        let reencrypted = encryptor.reencrypt(&aad, &value).await?;
        let outcome = ReencryptOutcome::from(&reencrypted);
        (reencrypted.map_or(value, |reencrypted| reencrypted.value), outcome)
    }
};
```

The keyring's provider decrypts the envelope values, so they must have been encrypted by the
keyring's KEK. `decrypt_envelope_for_migration` reads Tink's KMS envelope, the layout kms-aead 0.30 writes.
Values written by kms-aead 0.29 or earlier are upgraded in place first, with
`KmsAeadEnvelope::upgrade_legacy_value(aad, value)` under kms-aead's `legacy-formats` feature, see
[Upgrading stored values](../formats.md#upgrading-stored-values). The layout of a value is always
the marker's, never inferred from its bytes.

`decrypt_envelope_for_migration` decrypts whatever encrypted DEK an envelope value carries, under the
keyring's KEK. It knows no key version, and so no compromised flag and no destroyed state: keep its
branch in the read path for the migration only.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/migrate.rs),
run it with `cargo run -p kms-aead-keyring --example migrate --features ring,admin`.
