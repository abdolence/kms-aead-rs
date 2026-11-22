# Migration guide

## Unreleased

- `Plaintext` has no impl for `bool`. `true` and `false` differ in length, and a stored value is as
  long as its plaintext plus a fixed overhead, so the length of an encrypted `bool` revealed it. An
  application that stores a flag defines a newtype with a `Plaintext` impl of its own. To read the
  values written before, its `from_plaintext` accepts the bytes `true` and `false`.
- The `legacy-formats` feature is removed, with `KmsAeadEnvelope::upgrade_legacy_value`,
  `upgrade_legacy_encrypted_dek`, `KmsAeadError::LegacyFormat`, `KmsAeadLegacyFormatError` and
  `KmsAeadLegacyFormat`. A value or an encrypted DEK in a layout of 0.29 or earlier fails with
  `KmsAeadError::EncryptionError` and the code `LEGACY_FORMAT`, as it did without the feature.
  0.33 with `legacy-formats` is the last release that reads such values and rewrites them in
  Tink's format: rewrite them on it before moving on, see
  [Old values](https://kms-aead-rust.abdolence.dev/migrating-from-0.29.html#old-values). Delete
  the feature from the dependency in your `Cargo.toml`, since Cargo refuses an unknown feature.
- The hidden items that kms-aead-keyring calls are public API under new names. `__instruments` is
  the `kms_aead::metrics` module of the `opentelemetry` feature, where `Call` is
  `OperationAttributes`, `Outcome` is `OperationOutcome`, `record_store_load` is
  `record_keyring_store_load` and `record_refusal` is `record_keyring_record_refusal`.
  `OperationOutcome` and its `Value` variant are `#[non_exhaustive]`, so a value's outcome comes
  from `OperationOutcome::value`. In `kms_aead::stream`, `__HeaderGatherer` is
  `StreamHeaderGatherer`, `__read_header` is `read_stream_header`, and
  `__check_stream_algorithm(&cipher)` is `cipher.check_stream_algorithm()`.
- `KmsAeadNetworkError` does not implement `PartialEq` and `Eq`, as the other error structs do not,
  so that a later release can give it a root cause. Code that compared two network errors compares
  their `public.code`.
- `LocalSigningProvider::ephemeral` returns a CSPRNG failure, `RANDOM_GENERATOR`, as a
  `KmsAeadError::EncryptionError`, the variant of every other `RANDOM_GENERATOR` error. It was a
  `SystemError`.
- `Signable::from_payload` takes the payload as `&[u8]`, borrowed from the attached value, so that
  `verify_signed` and `verify_with_mac` do not copy it. An application's own `Signable` impl takes
  `payload: &[u8]`, and copies the bytes where it keeps them, as in `Ok(Invoice(payload.to_vec()))`.
- `AsymmetricKekProvider<B, P>` is `AsymmetricKekProvider<P, B>`: the provider first and the
  backend second, as in `KmsAeadEnvelope<P, B>` and `Signer<P, B>`. Code that names the type swaps
  its two parameters; `AsymmetricKekProvider::new` takes the same arguments.
- The eight key references, `GcpKmsKeyRef`, `AwsKmsKeyRef`, `AzureKmsKeyRef`,
  `HcVaultTransitKeyRef`, `GcpKmsSigningKeyRef`, `AwsKmsSigningKeyRef`, `AzureKmsSigningKeyRef`
  and `HcVaultTransitSigningKeyRef`, are `#[non_exhaustive]`, so that a minor release can add a
  field. Build them with `new` and the `with_*` setters instead of a struct literal.
- The variants of `SigningInput` are `#[non_exhaustive]`. Only the library builds an input, so its
  digest is always the SHA-256 of its pre-image, and an application's own `KmsSigningProvider`
  matches a variant with `..`, as in `SigningInput::Ed25519 { pre_image, .. }`. A test of such a
  provider signs through a `Signer`.
- `AzureKmsSigningProvider::with_client_options(key_ref, client_options, credential)` is
  `with_options(key_ref, options, credential)`. `options` is the new
  `AzureKmsSigningProviderOptions`, `#[non_exhaustive]` and built as `AzureKmsProviderOptions` is:
  `AzureKmsSigningProviderOptions::new().with_client_options(client_options)`.

## 0.33

v0.33.0 moves to jiff 1.0, firestore 0.66, gcloud-sdk 0.34 and bigquery 0.10. Nothing stored or
exported changes: a keyring record keeps its timestamp format in every store and in the BigQuery
export.

In short:

- `Timestamp` in the public API of kms-aead-keyring is the `jiff::Timestamp` of jiff 1.0, in
  `KeyVersion::created_at`, `state_changed_at` and `staged_at`, `KeyringRecord::created_at` and
  `updated_at`, and `Compromise::at`. An application that names the type, or passes one of these
  to its own code, moves its `jiff` dependency to `"1"`; a `Timestamp` of jiff 0.2 is a different
  type and does not compile in its place. jiff 1.0 renames `Zoned` to `ZonedDateTime` and
  `to_zoned` to `to_zoned_datetime`, `Timestamp - Timestamp` returns a `SignedDuration`, and the
  conversion from a `Timestamp` to a `SystemTime` is fallible. See the
  [jiff changelog](https://github.com/BurntSushi/jiff/blob/master/CHANGELOG.md);
- `FirestoreKeyringStore::new` takes the `FirestoreDb` of firestore 0.66, so an application moves
  its `firestore` dependency to `"0.66"`. `From<FirestoreTimestamp> for SystemTime` is a
  `TryFrom` there, see the firestore-rs
  [migration guide](https://github.com/abdolence/firestore-rs/blob/master/MIGRATION.md);
- gcloud-sdk 0.34 and bigquery 0.10 appear in no public signature of kms-aead or kms-aead-keyring.
  An application that uses gcloud-sdk next to them moves its own dependency to `"0.34"` to keep
  one copy in the tree.

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
