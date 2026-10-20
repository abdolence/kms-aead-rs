# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

A rotation is staged: `rotate`, export the BigQuery keysets again, wait for every process to see
the pending version, then `promote`. How often to rotate follows from the nonce and volume bounds
of each purpose, and deterministic and beacon versions rotate rarely, since each adds a probe to
every lookup until a sweep. See [Rotation cadence](./operations/rotation.md#rotation-cadence).

## Rotating the KEK

The KEK rotates in the KMS on its own schedule, and `reencrypt_deks` moves the record's DEKs to
its current version without changing any value, before the old KEK version is disabled. See
[Rotating the KEK](./operations/rotation.md#rotating-the-kek).

## Sweeps

A sweep re-seals stored values under the active versions, after a rotation, after a compromise
and to migrate envelope values: a job the application runs on a schedule, which finds the records
behind by their seal marker. [Sweeps](./operations/sweeps.md) has the mechanism, and the sweeps by
store have the queries and writes of [Firestore](./operations/sweeps-firestore.md),
[PostgreSQL](./operations/sweeps-postgres.md) and [BigQuery](./operations/sweeps-bigquery.md).

## Migrating from envelope values

Values that `KmsAeadEnvelope` wrote move to keyring values in five steps, with the seal marker
telling the two layouts apart and a sweep re-sealing the envelope values. See
[Move envelope values to a keyring](./use-cases/envelope-to-keyring.md).

## Emergency runbook

What to do after a leak of a plaintext DEK, an encrypted DEK or the record, a KMS IAM over-grant,
a version the administrative job did not create, a deleted or corrupted record or a KMS outage,
and how to crypto-shred a scope. See [Emergency runbook](./operations/runbook.md).
