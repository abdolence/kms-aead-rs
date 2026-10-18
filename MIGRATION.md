# Migration guide

## 0.30

v0.30.0 replaces the ring-only API with crypto backends chosen at runtime and makes ring optional.
Stored values need no migration, except the values written by 0.28.1 and earlier, which need the
deprecated `legacy-formats` feature.

In short:

- add a backend feature next to the provider features: `ring`, `aws-lc`, `aws-lc-fips` or
  `rustcrypto`. The provider features no longer turn on ring, and `ring-aead-encryption` is `ring`;
- `vault-transit-kms-encryption*` features are `hashicorp-vault-transit-kms-encryption*`, and the
  `VaultTransit*` types are `HcVaultTransit*`;
- `KmsAeadRingEnvelopeEncryption::new(provider).await?` is
  `KmsAeadEnvelope::new(provider, AeadBackend::Ring)?`, and `RingAeadEncryption` is `AeadCipher`;
- the `AeadEncryption` and `KmsAeadEnvelopeEncryption` traits are inherent methods taking
  `aad: &[u8]`;
- `KmsAeadError` is `#[non_exhaustive]`, the SDK error conversions are gone, and a few error
  codes changed;
- the AWS provider names the configured key on every unwrap.

The full list of changes, with the old and new names, is in
[Migrating from 0.29](https://kms-aead-rust.abdolence.dev/migrating-from-0.29.html).
