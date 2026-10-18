# Migration guide

## 0.30

v0.30.0 replaces the ring-only API with a choice of crypto backends, makes ring optional, and
writes Tink's KMS envelope format for every provider. Values written by 0.29 and earlier read only
with the deprecated `legacy-formats` feature, which also rewrites them in the new format.

In short:

- add a backend feature next to the provider features: `ring`, `aws-lc`, `aws-lc-fips` or
  `rustcrypto`. The provider features no longer turn on ring, and `ring-aead-encryption` is `ring`;
- `vault-transit-kms-encryption*` features are `hashicorp-vault-transit-kms-encryption*`, and the
  `VaultTransit*` types are `HcVaultTransit*`;
- `KmsAeadRingEnvelopeEncryption::new(provider).await?` is
  `KmsAeadEnvelope::<P, Ring>::new(provider)?`, and `RingAeadEncryption` is `AeadCipher<Ring>`.
  The backend is a type parameter: `Ring`, `AwsLc` or `RustCrypto`;
- the `AeadEncryption` and `KmsAeadEnvelopeEncryption` traits are inherent methods; the AAD is
  any `&(impl AsRef<[u8]> + ?Sized)`, and every cipher text is an `Encrypted<T, F>`;
- `KmsAeadError` is `#[non_exhaustive]`, the SDK error conversions are gone, and a few error
  codes changed;
- the default algorithm of `KmsAeadEnvelope` is AES-256-GCM; the default of 0.29 was
  ChaCha20-Poly1305. A value does not record its algorithm, so values sealed under the default of
  0.29 open only with `KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305)`,
  and fail with `DECRYPT` without it;
- the AWS provider names the configured key on every decryption;
- `EncryptedDataEncryptionKey` is the provider's bytes: store `value()` or `to_hex_string()`, and
  read them back with `EncryptedDataEncryptionKey::from` or `try_from_hex_string`;
- to move stored values to the new format, upgrade every reader to 0.30 with `legacy-formats`,
  rewrite the values with `KmsAeadEnvelope::upgrade_legacy_value`, which takes the value's AAD
  and opens the value before it writes, and `upgrade_legacy_encrypted_dek`, then turn the
  feature off.

The full list of changes, with the old and new names, is in
[Migrating from 0.29](https://kms-aead-rust.abdolence.dev/migrating-from-0.29.html).
