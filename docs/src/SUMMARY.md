# Summary

[KMS envelope encryption for Rust](./intro.md)

- [Getting started](./getting-started.md)
  - [Choose a provider and a backend](./getting-started/choosing.md)
  - [Develop and test without a cloud](./getting-started/local-development.md)

# Use cases

- [Protect data in your database](./use-cases/database.md)
  - [Encrypt personal data and secrets in your database](./use-cases/encrypt-fields.md)
  - [Cut KMS calls with a DEK cache and DEK reuse](./use-cases/fewer-kms-calls.md)
  - [Give each customer of a SaaS its own keys](./use-cases/keyring-per-tenant.md)
  - [Find a user by an encrypted email](./use-cases/equality-lookups.md)
  - [Erase one customer's data for good](./use-cases/erase-a-tenant.md)
- [Share encrypted data with other systems](./use-cases/sharing.md)
  - [Decrypt columns in BigQuery SQL or with Tink](./use-cases/bigquery-and-tink.md)
  - [Accept data from partners and devices that cannot read it back](./use-cases/write-only-producers.md)
- [Files and streams](./use-cases/files-and-streams.md)
  - [Store customer uploads and serve byte ranges](./use-cases/large-files.md)
  - [Send a large export over HTTP, encrypted](./use-cases/encrypted-http-streams.md)
- [Prove where data came from](./use-cases/provenance.md)
  - [Publish a rate sheet or a release anyone can verify](./use-cases/publish-verifiable.md)
  - [Detect tampering with jobs and rows between your services](./use-cases/service-integrity.md)
- [Keep sensitive data out of logs](./use-cases/logs.md)
  - [Log a webhook payload that failed to parse](./use-cases/log-json-payloads.md)

# Running in production

- [Permissions: applications and administration](./production/permissions.md)
- [Monitoring and alerts](./production/monitoring.md)
- [Rotate keys and re-encrypt values](./production/rotation.md)
  - [Re-encrypt DEKs after a KEK rotation](./production/reencrypt-deks.md)
  - [Sweeps](./production/sweeps.md)
    - [Sweeps on Firestore](./production/sweeps/firestore.md)
    - [Sweeps on PostgreSQL](./production/sweeps/postgres.md)
    - [Sweeps on BigQuery](./production/sweeps/bigquery.md)
- [Incident runbook](./production/runbook.md)
- [Protect the keyring record](./production/signed-records.md)
- [Move envelope values to a keyring](./production/envelope-to-keyring.md)

# Values and keys

- [Stored values](./stored-values.md)
- [Envelope encryption](./envelope-encryption.md)
- [One fixed key](./one-fixed-key.md)
- [DEK caching and reuse](./dek-caching.md)
- [Deterministic encryption](./deterministic.md)
- [Beacons](./beacons.md)
- [Streaming encryption](./streaming.md)
- [Signatures and MACs](./signing.md)
- [Crypto backends](./crypto-backends.md)
- [KMS providers](./providers.md)
  - [Google Cloud KMS](./providers/gcp.md)
  - [AWS KMS](./providers/aws.md)
  - [Azure Key Vault](./providers/azure.md)
  - [HashiCorp Vault Transit](./providers/hc-vault-transit.md)
  - [Local KMS](./providers/local.md)
- [Asymmetric KEKs](./asymmetric-kek.md)

# Keyring

- [Keyring and field encryption](./keyring.md)
  - [Key versions and lifecycle](./keyring/lifecycle.md)
  - [Keyring stores](./keyring/stores.md)
  - [Record cache](./keyring/record-cache.md)
  - [Encrypted fields and AAD](./keyring/fields.md)
  - [Deterministic fields](./keyring/deterministic.md)
  - [Beacons](./keyring/beacons.md)
  - [BigQuery and Tink interop](./keyring/bigquery.md)

# Reference

- [Cargo features](./features.md)
- [Formats](./formats.md)
  - [Values and DEKs](./formats/values.md)
  - [Streamed values](./formats/streamed-values.md)
  - [Signature and MAC formats](./formats/signatures-and-macs.md)
  - [Keyring records and keysets](./formats/keyring-records.md)
- [Error handling](./errors.md)
- [Observability](./observability.md)
- [Security considerations](./security.md)

# Upgrading

- [Migrating from 0.30](./migrating-from-0.30.md)
- [Migrating from 0.29](./migrating-from-0.29.md)
