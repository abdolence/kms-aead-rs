# Operations

Running a keyring in production: how often to rotate, how sweeps move values to the active
versions, the migration from envelope values, and what to do when a key leaks.

## Rotation cadence

See [Rotation cadence](./operations/rotation.md#rotation-cadence).

## Rotating the KEK

See [Rotating the KEK](./operations/rotation.md#rotating-the-kek).

## Sweeps

See [Sweeps](./operations/sweeps.md), and the sweeps by store:
[Firestore](./operations/sweeps-firestore.md),
[PostgreSQL](./operations/sweeps-postgres.md) and
[BigQuery](./operations/sweeps-bigquery.md).

## Migrating from envelope values

See [Move envelope values to a keyring](./use-cases/envelope-to-keyring.md).

## Emergency runbook

See [Emergency runbook](./operations/runbook.md).
