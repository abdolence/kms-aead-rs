# Summary

[KMS envelope encryption for Rust](./intro.md)
[Getting started](./getting-started.md)

# Providers

- [KMS providers](./providers.md)
  - [Google Cloud KMS](./providers/gcp.md)
  - [AWS KMS](./providers/aws.md)
  - [Azure Key Vault](./providers/azure.md)
  - [HashiCorp Vault Transit](./providers/hc-vault-transit.md)
  - [Local KMS](./providers/local.md)

# Encryption

- [Envelope encryption](./envelope-encryption.md)
- [DEK caching and reuse](./dek-caching.md)
- [Crypto backends](./crypto-backends.md)
- [Deterministic encryption](./deterministic.md)

# Keyring

- [Keyring and field encryption](./keyring.md)
  - [Key versions and lifecycle](./keyring/lifecycle.md)
  - [Keyring stores](./keyring/stores.md)
  - [Record cache](./keyring/record-cache.md)
  - [Encrypted fields and AAD](./keyring/fields.md)
  - [Deterministic fields](./keyring/deterministic.md)
  - [Beacons](./keyring/beacons.md)
  - [BigQuery and Tink interop](./keyring/bigquery.md)
- [Operations](./operations.md)

# Reference

- [Formats](./formats.md)
- [Error handling](./errors.md)
- [Observability](./observability.md)
- [Security considerations](./security.md)
- [Migrating from 0.29](./migrating-from-0.29.md)
