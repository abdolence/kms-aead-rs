# Move envelope values to a keyring

Values that kms-aead's `KmsAeadEnvelope` wrote, per call or store-less, move to keyring values in
five steps:

1. the model gains `seal: SealMarker`, and every record without one reads as
   `SealMarker::ENVELOPE`: through `#[serde(default)]`, or a column default of its bytes,
   `'\x0100000000'`;
2. the field keeps its stored bytes, whose layout the marker names: envelope values under
   `ENVELOPE`, epoch 0, and keyring values under any other marker, since the epochs of a keyring
   start at 1;
3. reads go through the marker: `Keyring::decrypt_envelope_for_migration` opens an envelope value,
   with the AAD and the algorithm the application used for it, and `Keyring::decrypt` a keyring
   value;
4. the sweep's query, `seal < $1` with the current marker, finds every envelope record too, and the
   re-seal seals it as keyring values through a sealer and writes the marker of the sealer's
   record;
5. once no record holds `ENVELOPE`, the read path drops its envelope branch.

A range query never matches a record whose marker is missing: Firestore skips a document without the
field, and `<` in SQL is never true on `NULL`. A PostgreSQL column added with a default holds it in
every existing row. A BigQuery column holds `NULL` there until an `UPDATE` writes `ENVELOPE`, see
[BigQuery](../operations/sweeps-bigquery.md). Firestore documents written before the marker get `ENVELOPE` written into
them first, or the migration's first sweep scans the whole collection and tests `doc.seal < current`
on each, since `#[serde(default)]` reads a missing marker as `ENVELOPE`.

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
run it with `cargo run -p kms-aead-keyring --example migrate --features ring,admin,serde`.
