# Migration guide

## 0.31

v0.31.0 adds streaming encryption, signatures and MACs, signed keyring records, asymmetric KEKs
and the deletion of a keyring's record. Eight changes break a build against 0.30, and one changes
behaviour without breaking it.

In short:

- `KmsAeadUnsupportedAlgorithmError::algorithm` is a `BackendAlgorithm` rather than an
  `AeadAlgorithm`, so that the one error names an AEAD algorithm or an asymmetric KEK algorithm.
  `BackendAlgorithm::Aead(algorithm)` holds what the field held, and `BackendAlgorithm` is
  `#[non_exhaustive]`, so a `match` on it needs a `_` arm. The variant and code do not change;
- `Purpose` and `KeyAlgorithm` gain the `Mac` variant and are `#[non_exhaustive]`: an exhaustive
  `match` on either needs a `_` arm;
- `LocalKek::from_secret`, `from_file` and `from_env` take a `SymmetricKeyFormat` as their last
  argument, `Raw` where 0.30 took raw bytes and `Base64` where it read base64. `from_file` reads
  up to 32 KiB;
- the `serde` and `serde-json` features of kms-aead and of kms-aead-keyring are removed: serde
  support, `JsonEncoded<T>` and JWK are in every build of both. Delete the two features from the
  dependency on each crate in your `Cargo.toml`, since Cargo refuses an unknown feature;
- the provider trait is two traits, so that a provider that only encrypts has no decryption.
  `KmsAeadEncryptionProvider` keeps `kek`, `encrypt_data_encryption_key` and
  `generate_key_material`, and `decrypt_data_encryption_key` moves to the new
  `KmsAeadDecryptionProvider`, whose supertrait is `KmsAeadEncryptionProvider`. An application's
  own provider moves the method into an `impl KmsAeadDecryptionProvider`, and code generic over a
  provider that decrypts, or over a keyring's provider, names `P: KmsAeadDecryptionProvider`;
- an application's own `KeyringStore` implements the new `delete(id, expected)`, which has no
  default. It deletes the record when its stored revision is `expected`, with every earlier version
  the store keeps, and returns `Deletion::Deleted` or `Deletion::Conflict`. A store never gives an
  id the same revision twice, across a delete too;
- the `firestore` feature of 0.30 is `firestore-tls-roots`. `firestore` is the store without a TLS
  root store or crypto provider, and `firestore-tls-webpki` is the store on rustls with no native
  TLS;
- a running process takes a keyring record that goes missing from the store as a shredded keyring:
  it destroys every version of its cached record in memory, so the handles it holds fail, and the
  registry's next `open` of the id reads the store again. In 0.30 it kept the record in use. The
  process refuses a copy of the record from before the deletion, as a regression, so it restarts
  after a restore;
- one vocabulary, encrypt and decrypt, names every confidentiality operation, and "open" names
  only the opening of a keyring. The keyring's write handle, its re-encryption and the sweep's
  marker take the new words, and `KekProvider` and `KekVersion` become `KmsProvider` and
  `KmsKeyVersion`, with no aliases for the old names: see the tables below. Nothing stored changes:
  a keyring record keeps its `seal_epoch` and `seal_epochs` keys, and a marker keeps its bytes;
- the `rustcrypto` feature adds the `rsa` crate, whose advisory RUSTSEC-2023-0071 `cargo audit`
  flags; it reaches only a local asymmetric KEK on RustCrypto;
- move readers before producers: every application and administrative job that decrypts moves to
  0.31 before the first producer encrypts a DEK with a public key, before the first record is
  signed, and before a keyring's first MAC version is created. A 0.30 administrative write removes
  the `signature` member of a record.

The renamed names, by area:

| Area | 0.30 | 0.31 |
|---|---|---|
| KMS names | `kms_aead::KekProvider` | `kms_aead::KmsProvider` |
| | `kms_aead::providers::KekVersion` | `kms_aead::providers::KmsKeyVersion` |
| Keyring writes | `Sealer` | `Encryptor` |
| | `Keyring::sealer()` | `Keyring::encryptor()` |
| | `Sealer::reseal` | `Encryptor::reencrypt` |
| | `Sealer::reseal_deterministic` | `Encryptor::reencrypt_deterministic` |
| | `Resealed<T, F>` | `Reencrypted<T, F>` |
| Sweeps | `sweep::SealMarker` | `sweep::EncryptionMarker` |
| | `sweep::run` | `sweep::reencrypt_records` |
| | `sweep::run_batched` | `sweep::reencrypt_records_batched` |
| | `sweep::SealRange` | `sweep::ReencryptRange` |
| | `sweep::ResealOutcome`, `ResealOutcome::Resealed` | `sweep::ReencryptOutcome`, `ReencryptOutcome::Reencrypted` |
| | `SweepReport::resealed`, `SweepReport::resealed_from_compromised` | `SweepReport::reencrypted`, `SweepReport::reencrypted_from_compromised` |
| | `KeyringRecord::seal_marker` | `KeyringRecord::encryption_marker` |
| | `KeyVersion::seal_range` | `KeyVersion::reencrypt_range` |
| | `EncryptedKeyset::seal_marker` | `EncryptedKeyset::encryption_marker` |
| Plaintexts | `kms_aead::Json<T>`, behind the `serde-json` feature | `kms_aead::JsonEncoded<T>`, in every build |
| | `Json(value)` | `JsonEncoded::new(value)` |
| | `let Json(value) = json;` | `let value = json.0;` |
| Errors | `KeyringError::SealerOutdated`, code `SEALER_OUTDATED` | `KeyringError::EncryptorOutdated`, code `ENCRYPTOR_OUTDATED` |
| | `KeyringError::InvalidSealMarker`, code `INVALID_SEAL_MARKER` | `KeyringError::InvalidEncryptionMarker`, code `INVALID_ENCRYPTION_MARKER` |
| | `RecordInvalidReason::SealEpochOutOfRange` | `RecordInvalidReason::ReencryptEpochOutOfRange` |
| | `RecordInvalidReason::SealRangeInvalid` | `RecordInvalidReason::ReencryptRangeInvalid` |
| | `RegressionRule::SealEpochReverted` | `RegressionRule::ReencryptEpochReverted` |
| | `RegressionRule::SealRangeReverted` | `RegressionRule::ReencryptRangeReverted` |

The telemetry renames, which change what a dashboard, a log query or an alert matches:

| Signal | 0.30 | 0.31 |
|---|---|---|
| `Keyring sweep` span field | `/kms_aead_keyring/resealed` | `/kms_aead_keyring/reencrypted` |
| `Keyring sweep` span field | `/kms_aead_keyring/resealed_from_compromised` | `/kms_aead_keyring/reencrypted_from_compromised` |
| `kms_aead.operation` of a keyring call | `reseal` | `reencrypt` |
| `error.type` and the `error_code` span field | `SEALER_OUTDATED`, `INVALID_SEAL_MARKER` | `ENCRYPTOR_OUTDATED`, `INVALID_ENCRYPTION_MARKER` |

The full list of changes, with the old and new names, is in
[Migrating from 0.30](https://kms-aead-rust.abdolence.dev/migrating-from-0.30.html).

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
  The backend is a type parameter: `Ring`, `AwsLc` or `RustCrypto`, from `kms_aead::backends`;
- the `AeadEncryption` and `KmsAeadEnvelopeEncryption` traits are inherent methods; the AAD is
  any `&(impl AsRef<[u8]> + ?Sized)`, and every cipher text is an `Encrypted<T, F>`;
- `KmsAeadError` is `#[non_exhaustive]`, the SDK error conversions are gone, and a few error
  codes changed. A Google Cloud KMS or AWS KMS error is a `NetworkError` or an `EncryptionError`
  by its code, so a `PermissionDenied` from Google Cloud KMS is no longer a `NetworkError`;
- the default algorithm of `KmsAeadEnvelope` is AES-256-GCM; the default of 0.29 was
  ChaCha20-Poly1305. A value does not record its algorithm, so values encrypted under the default
  of 0.29 decrypt only with
  `KmsAeadEnvelopeOptions::new().with_algorithm(AeadAlgorithm::ChaCha20Poly1305)`, and fail with
  `DECRYPT` without it;
- the AWS provider names the configured key on every decryption;
- an application's own provider implements `KmsAeadEncryptionProvider` without `#[async_trait]`,
  and the trait has no `dyn` form: code that holds a provider is generic over it;
- the Azure provider's `algorithm` is an `AzureKmsAlgorithm` rather than the Azure SDK's
  `EncryptionAlgorithm`, with a variant for every algorithm 0.29 accepted: `RsaOaep256` is
  `RsaOaepSha256`, `RsaOaep` is `RsaOaepSha1`, `A128Kw`, `A192Kw` and `A256Kw` are
  `Aes128KeyWrap`, `Aes192KeyWrap` and `Aes256KeyWrap`, and `CkmAesKeyWrap` and
  `CkmAesKeyWrapPad` are `Pkcs11AesKeyWrap` and `Pkcs11AesKeyWrapWithPadding`. `Rsa1_5`, which
  0.29 refused when the provider was built, has no variant;
- `EncryptedDataEncryptionKey` is the provider's bytes: store `value()` or `to_hex_string()`, and
  read them back with `EncryptedDataEncryptionKey::from` or `try_from_hex_string`. Its
  `kek_version()` is the KEK version the KMS reported, on an encrypted DEK the provider has just
  returned, and `None` on one read back from the bytes;
- to move stored values to the new format, upgrade every reader to 0.30 with `legacy-formats`,
  rewrite the values with `KmsAeadEnvelope::upgrade_legacy_value`, which takes the value's AAD
  and decrypts the value before it writes, and `upgrade_legacy_encrypted_dek`, then turn the
  feature off.

The full list of changes, with the old and new names, is in
[Migrating from 0.29](https://kms-aead-rust.abdolence.dev/migrating-from-0.29.html).
