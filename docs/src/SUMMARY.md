# Summary

[KMS envelope encryption for Rust](./intro.md)
[Getting started](./getting-started.md)

# Use cases

- [Encrypt fields with a KMS](./use-cases/encrypt-fields.md)
- [A keyring per tenant](./use-cases/keyring-per-tenant.md)
- [Find rows by an encrypted value](./use-cases/equality-lookups.md)
- [Read values in BigQuery or Tink](./use-cases/bigquery-and-tink.md)
- [Rotate keys and re-encrypt values](./use-cases/rotation.md)
- [A leaked key or a shredded tenant](./use-cases/incidents.md)
- [Applications and administration apart](./use-cases/deployment.md)
- [Choose a provider and a backend](./use-cases/choosing.md)
- [Develop and test without a cloud](./use-cases/local-development.md)
- [Move envelope values to a keyring](./use-cases/envelope-to-keyring.md)
- [Migrating from 0.29](./migrating-from-0.29.md)

# Values and keys

- [Stored values](./stored-values.md)
- [Envelope encryption](./envelope-encryption.md)
- [DEK caching and reuse](./dek-caching.md)
- [Deterministic encryption](./deterministic.md)
- [Beacons](./beacons.md)
- [Crypto backends](./crypto-backends.md)
- [KMS providers](./providers.md)
  - [Google Cloud KMS](./providers/gcp.md)
  - [AWS KMS](./providers/aws.md)
  - [Azure Key Vault](./providers/azure.md)
  - [HashiCorp Vault Transit](./providers/hc-vault-transit.md)
  - [Local KMS](./providers/local.md)

# Keyring

- [Keyring and field encryption](./keyring.md)
  - [Applications and administration](./keyring/deployment.md)
  - [Key versions and lifecycle](./keyring/lifecycle.md)
  - [Keyring stores](./keyring/stores.md)
  - [Record cache](./keyring/record-cache.md)
  - [Encrypted fields and AAD](./keyring/fields.md)
  - [Deterministic fields](./keyring/deterministic.md)
  - [Beacons](./keyring/beacons.md)
  - [BigQuery and Tink interop](./keyring/bigquery.md)

# Operating a keyring

- [Operations](./operations.md)
  - [Rotation](./operations/rotation.md)
  - [Sweeps](./operations/sweeps.md)
    - [Sweeps on Firestore](./operations/sweeps-firestore.md)
    - [Sweeps on PostgreSQL](./operations/sweeps-postgres.md)
    - [Sweeps on BigQuery](./operations/sweeps-bigquery.md)
  - [Emergency runbook](./operations/runbook.md)

# Reference

- [Cargo features](./features.md)
- [Formats](./formats.md)
- [Error handling](./errors.md)
- [Observability](./observability.md)
- [Security considerations](./security.md)
