# Migrating from 0.30

0.31 adds streaming encryption, signatures and MACs, record signing for keyrings, asymmetric
KEKs and the deletion of a keyring's record. Eight changes break a build against 0.30: one public
field changes its type, two enums gain a variant and become `#[non_exhaustive]`, the three
`LocalKek` loaders take a format, the `serde` and `serde-json` features are removed, the provider
trait's decryption moves to a trait of its own, `KeyringStore` gains a required method, the
`firestore` feature is split into three, and the keyring's write-handle and sweep names, with
`KekProvider` and `KekVersion`, are renamed without aliases. One behaviour changes without breaking
a build: a running process takes a keyring record gone from the store as shredded. The readers of a
deployment move to 0.31 before its producers. Everything else is additive.

## The unsupported algorithm error

`KmsAeadUnsupportedAlgorithmError::algorithm` is a `BackendAlgorithm` in 0.31, an `AeadAlgorithm`
in 0.30, so that the one error names whichever algorithm a backend lacks: an AEAD algorithm, as
AES-256-GCM-SIV on ring, or an asymmetric KEK algorithm, as RSA-OAEP (RSA encryption with OAEP
padding) on ring. The variant, `KmsAeadError::UnsupportedAlgorithm`, and its code,
`UNSUPPORTED_ALGORITHM`, do not change.

| 0.30 | 0.31 |
|---|---|
| `error.algorithm == AeadAlgorithm::Aes256GcmSiv` | `error.algorithm == BackendAlgorithm::Aead(AeadAlgorithm::Aes256GcmSiv)` |
| `let algorithm: AeadAlgorithm = error.algorithm;` | `let BackendAlgorithm::Aead(algorithm) = error.algorithm else { … };` |
| `error.algorithm.key_len()` | `match error.algorithm { BackendAlgorithm::Aead(algorithm) => algorithm.key_len(), _ => … }` |

`BackendAlgorithm` is `#[non_exhaustive]`, so a `match` on it needs a `_` arm, and it implements
`From<AeadAlgorithm>` and `From<AsymmetricKekAlgorithm>`. Its `Display` is the inner algorithm's
name, so a log line that printed `error.algorithm` prints the same text.

## Purpose and KeyAlgorithm

`Purpose` and `KeyAlgorithm` of kms-aead-keyring gain the `Mac` variant for the MAC versions of a
keyring, a MAC being a keyed tag that proves the bytes it covers are unchanged, see
[MACs in a keyring](./signing.md#macs-in-a-keyring). Both are `#[non_exhaustive]` from 0.31, so an
exhaustive `match` on either needs a `_` arm: a breaking change for every such `match`, made once so
that a later purpose is additive.

| 0.30 | 0.31 |
|---|---|
| `match purpose { Purpose::Randomized => …, Purpose::Deterministic => …, Purpose::Beacon => … }` | the same arms and `_ => …`, or `Purpose::Mac => …` |
| `match algorithm { KeyAlgorithm::Randomized(_) => …, KeyAlgorithm::Deterministic(_) => …, KeyAlgorithm::Beacon(_) => … }` | the same arms and `_ => …`, or `KeyAlgorithm::Mac(_) => …` |

## Loading a local KEK

`LocalKek::from_secret`, `from_file` and `from_env` take a `SymmetricKeyFormat` as their last
argument: pass `SymmetricKeyFormat::Raw` where 0.30 took raw bytes (`from_secret`) and
`SymmetricKeyFormat::Base64` where it read base64 (`from_file`, `from_env`). The methods keep their
names, so the old signatures cannot stay as deprecated wrappers, and every call site fails to
compile until it names a format.

| 0.30 | 0.31 |
|---|---|
| `LocalKek::from_secret(version, material)` | `LocalKek::from_secret(version, material, SymmetricKeyFormat::Raw)` |
| `LocalKek::from_file(version, &path)` | `LocalKek::from_file(version, &path, SymmetricKeyFormat::Base64)` |
| `LocalKek::from_env(version, "APP_DEV_KEK")` | `LocalKek::from_env(version, "APP_DEV_KEK", SymmetricKeyFormat::Base64)` |

`SymmetricKeyFormat` is in `kms_aead::formats` and is `#[non_exhaustive]`. `Raw` is the key bytes
themselves, `Base64` the standard base64 of the key bytes, trailing whitespace allowed, and `Jwk` an
`oct` JSON Web Key. The key is 32 bytes in every format. The loaders of the signing and asymmetric KEK keys take the same kind
of enum, see [Key formats](./signing.md#key-formats). `from_file` reads a file of up to 32 KiB,
where 0.30 read up to 256 bytes.

## The serde features

The `serde` and `serde-json` features of kms-aead and of kms-aead-keyring are removed: serde
support, `JsonEncoded<T>` and JWK are in every build of both. Delete the two features from the dependency
on each crate in your `Cargo.toml`; Cargo refuses an unknown feature.

## The Firestore features

The `firestore` feature of 0.30 is `firestore-tls-roots` in 0.31. In 0.31 `firestore` is the
Firestore keyring store on firestore-rs without its default features, so it has no TLS root store
and no crypto provider, as `gcs` has none. A build that names `firestore` therefore enables a
firestore-rs or gcloud-sdk root store feature of its own, or one of the two features that do:

- `firestore-tls-roots`: the system's native roots, firestore-rs's `tls-roots`, which brings
  native-tls and so OpenSSL on Linux;
- `firestore-tls-webpki`: rustls, with the bundled WebPKI roots for the gRPC connection to
  Firestore, and no native TLS;

each with firestore-rs's `auth-default-crypto`. The Cloud Storage features are split the same way:
`gcs`, `gcs-tls-roots` and `gcs-tls-webpki`.

| 0.30 | 0.31 |
|---|---|
| `features = ["firestore"]` | `features = ["firestore-tls-roots"]`, the same build as 0.30 |
| no equivalent | `features = ["firestore-tls-webpki"]`, for a build without OpenSSL |

## The `rustcrypto` feature adds `rsa`

The `rustcrypto` feature adds the `rsa` crate for RSA-OAEP, so every application that enables
it carries `rsa` in its lockfile. The feature also adds `p256` and `ed25519-dalek`, for signatures.
kms-aead depends on `serde`, `serde_bytes`, `serde_json`, `sha2`, `base64ct`, `der`, `spki`,
`pkcs8`, `sec1` and `pem-rfc7468` in every build, for serde support, the key framing, JSON Web Keys
and the thumbprints of public keys, and kms-aead-keyring on `sha2`, for the canonical digest of a
record.

## The `aws` features read `aws login` sessions

The features that enable AWS KMS turn on aws-config's `credentials-login`, so that the default
credentials chain takes the session of `aws login`, as the AWS CLI does.

## Readers before producers

The encrypted DEK a public key encrypts is a layout of 0.31, which starts with `0x02`, and no
earlier release reads it, see [DEKs encrypted with a public
key](./formats.md#deks-encrypted-with-a-public-key). A deployment moves every reader, every
application and administrative job that decrypts, to 0.31 before the first producer encrypts with a
public key, as every reader moved to 0.30 before the first value in Tink's envelope format, see
[Upgrading stored values](./formats.md#upgrading-stored-values). Nothing already stored changes: the
encrypted DEKs the KMS encrypted keep their bytes and keep decrypting.

A keyring record gains a `signature` member, which 0.30 reads and ignores, and which a 0.30
administrative write removes, since 0.30 rewrites the record from its own fields: move every
administrative binary to 0.31 before the first record is signed. A keyring's first MAC version is
created only once every process reads the keyring on 0.31, see
[MACs in a keyring](./signing.md#macs-in-a-keyring).

Run a keyring under an asymmetric KEK with `RecordSignaturePolicy::Required` on every application:
anyone holding the public key can file a DEK of their own in its record, and under `VerifyIfSigned`
a store writer who holds it plants a version for every process that starts afterwards, see [Keyrings
under an asymmetric KEK](./asymmetric-kek.md#keyrings-under-an-asymmetric-kek). An existing Azure
Key Vault or Vault Transit RSA deployment moves its encryptions to the producer in the order of
[Migrating an Azure or Transit RSA
deployment](./asymmetric-kek.md#migrating-an-azure-or-transit-rsa-deployment).

A store-less writer whose renewed DEK leaves the DEK cache before it encrypts now encrypts with the
DEK it generated, in place of decrypting its encrypted DEK again, so a store-less `encrypt` makes no
KMS decryption under any provider, see
[The DEK lives in the cache](./dek-caching.md#the-dek-lives-in-the-cache).

## Names

0.31 uses one vocabulary: encrypt and decrypt for every confidentiality operation, and "open" only
for opening a keyring. The keyring's write handle, its re-encryption of a value under the active
version, and the sweep's encryption marker, the 5 bytes a record stores beside its encrypted
fields to name the key versions they are under, take the new words. `KekProvider` and `KekVersion`
take names that say they belong to any key of a KMS. No old name stays as an alias: a build that
uses one fails until it uses the new one.

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

Nothing stored changes. A keyring record keeps its `seal_epoch` and `seal_epochs` keys, and a
encryption marker keeps its 5 bytes, `0x01` and the epoch, so records and markers that 0.30 wrote
read in 0.31, and the reverse. The book's sweep examples name the marker column `encryption_marker`
where 0.30's named it `seal`; an existing column keeps its name, since the library never reads a
column by name. `KmsProvider` and `KmsKeyVersion` keep every value, method and `Display` string:
the `provider` and `kek_version` span fields keep their values, and a keyring record's
`kek.provider` reads as before. `KekRef` and `LocalKekVersion` keep their names, since they name a
key encryption key.

### Telemetry

These renames change what a dashboard, a log query or an alert matches:

| Signal | 0.30 | 0.31 |
|---|---|---|
| `Keyring sweep` span field | `/kms_aead_keyring/resealed` | `/kms_aead_keyring/reencrypted` |
| `Keyring sweep` span field | `/kms_aead_keyring/resealed_from_compromised` | `/kms_aead_keyring/reencrypted_from_compromised` |
| `kms_aead.operation` of a keyring call | `reseal` | `reencrypt` |
| `error.type` and the `error_code` span field | `SEALER_OUTDATED`, `INVALID_SEAL_MARKER` | `ENCRYPTOR_OUTDATED`, `INVALID_ENCRYPTION_MARKER` |

The error and log messages use the new words too, so a query on the text of a message, such as the
`WARN` of a sweep that could not re-encrypt a record, needs the new text.

## Your own provider

The provider trait of 0.30 is two traits in 0.31, so that a provider that only encrypts, such as
the `PublicKeyKekProvider` of a producer, has no decryption, and an envelope over it has no call
that decrypts:

- `KmsAeadEncryptionProvider` keeps `kek`, `encrypt_data_encryption_key` and
  `generate_key_material`, and gains `encrypts_with_public_key`, with a default of `false`;
- `KmsAeadDecryptionProvider`, whose supertrait is `KmsAeadEncryptionProvider`, holds
  `decrypt_data_encryption_key`, with the signature of 0.30.

A provider of 0.30 fails to compile until its `decrypt_data_encryption_key` moves into an impl of
the new trait. A wrapper implements each trait where the provider it wraps does:

```rust
use std::sync::atomic::{AtomicU64, Ordering};

use kms_aead::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekRef, KmsAeadDecryptionProvider,
    KmsAeadEncryptionProvider, KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// The provider `P`, with a count of its decryptions.
struct Counted<P> {
    inner: P,
    decryptions: AtomicU64,
}

impl<P: KmsAeadEncryptionProvider> KmsAeadEncryptionProvider for Counted<P> {
    fn kek(&self) -> &KekRef {
        self.inner.kek()
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        self.inner.encrypt_data_encryption_key(dek).await
    }

    async fn generate_key_material(&self, len: usize) -> KmsAeadResult<Option<SecretValue>> {
        self.inner.generate_key_material(len).await
    }

    fn encrypts_with_public_key(&self) -> bool {
        self.inner.encrypts_with_public_key()
    }
}

// The method of 0.30's impl, in an impl of its own.
impl<P: KmsAeadDecryptionProvider> KmsAeadDecryptionProvider for Counted<P> {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.decryptions.fetch_add(1, Ordering::Relaxed);
        self.inner.decrypt_data_encryption_key(encrypted_dek).await
    }
}
```

Code generic over a provider names the trait its calls need. `KmsAeadDecryptionProvider` covers
both, so code that encrypts and decrypts names it alone:

| 0.30 | 0.31 |
|---|---|
| `P: KmsAeadEncryptionProvider`, for an envelope's `decrypt`, `decrypt_with_dek`, `*_with_encrypted_dek`, `beacon`, `decrypt_deterministic_dek`, `reencrypt_dek`, `reencrypt_encrypted_dek` or legacy upgrades | `P: KmsAeadDecryptionProvider` |
| `P: KmsAeadEncryptionProvider`, for `DekCache::with_dek` | `P: KmsAeadDecryptionProvider` |
| `P: KmsAeadEncryptionProvider`, for a `Keyring`, a `KeyringAdmin`, an `Encryptor` or a `KeyringRegistry` call that returns one | `P: KmsAeadDecryptionProvider` |
| `P: KmsAeadEncryptionProvider`, for `encrypt`, `encrypt_with_dek` and the `generate_encrypted_*` calls only | unchanged |
| `use kms_aead::KmsAeadEncryptionProvider`, to call `decrypt_data_encryption_key` on a provider | `use kms_aead::KmsAeadDecryptionProvider` |

A provider that encrypts DEKs with the public half of a key pair returns `true` from
`encrypts_with_public_key`, so that a keyring refuses the BigQuery and Tink exports its KEK cannot
serve, see
[Producers and readers](./asymmetric-kek.md#producers-and-readers).

## Your own keyring store

`KeyringStore` gains a fifth method, `delete`, which has no default: a build that implements the
trait for an application's own store fails until the store implements it.

```rust,ignore
fn delete(
    &self,
    id: &KeyringId,
    expected: &Self::Revision,
) -> impl Future<Output = KeyringResult<Deletion>> + Send;
```

It deletes the record when its stored revision is `expected`, with every earlier version of it the
store keeps, such as the noncurrent versions of a versioned bucket:

- `Deletion::Deleted` once the store holds no record of the id, also when it held none;
- `Deletion::Conflict` when the stored revision is another. The live record stays, though the
  store may have removed its earlier versions first;
- errors are returned as `load` returns them, as `KeyringError::Store` with
  `StoreOperation::Delete`, whose text in the error is `delete`. A delete that fails may have removed part
  of the earlier versions already, and the caller repeats it with the same `expected`;
- a store with push signals the deletion as a change;
- the store never gives an id the same revision twice, across a delete too. A revision that
  restarts at 1 for a record created again would let a process that missed the deletion keep the
  deleted record.

`StoreOperation` gains the `Delete` variant. It is `#[non_exhaustive]`, so a `match` on it has a
`_` arm already. What each library store deletes, and what it leaves to the operator, is in
[What a delete removes](./keyring/stores.md#what-a-delete-removes).

## A keyring record gone from the store

In 0.30 a running process kept a record that went missing from the store in use, with a `WARN`,
and only new processes failed at `open`. In 0.31 the process takes it as a shredded keyring:

- it destroys every version of its cached record in memory, and writes nothing. That evicts the
  keyring's keys from the DEK cache;
- it logs a `WARN`, "The keyring store no longer holds the keyring record; every version is
  destroyed in this process", or an `INFO` when the record it held had every version destroyed
  already, as a shred leaves it, sets the `changed` field of the `Keyring load` span to `deleted`,
  and stops revalidating and watching the keyring;
- its handles then fail before any KMS call: encrypting with `NoActiveVersion`, reading with
  `KeyVersionDestroyed`, `reload` with `RecordMissing`;
- the registry's next `open` of the id reads the store again: `RecordMissing`, or a record created
  since. A handle opened before stays on the destroyed record.

So an accidental deletion of a record stops a running process at its next revalidation, within
`reload_min_interval` of the signal with push and once the cached record is older than `record_ttl`
without. A record restored from a copy is refused by that process with `RecordRegressed`, because
it revives versions the process holds destroyed, so the process restarts after a restore. The text of the `WARN` ended in "the cached record stays in use" in 0.30, so change a log alert that
matches that ending. The runbook is
[The keyring record was deleted or corrupted](./operations/runbook.md#the-keyring-record-was-deleted-or-corrupted).

Under record signing, the deleted record stays the baseline of the id: the next record must be
signed if the deleted one was, and a keyring created again opens, see
[Signing the keyring record](./signing.md#signing-the-keyring-record).

## New in 0.31

The other changes are additive. `KmsAeadError` is already `#[non_exhaustive]`, so its new
`SignatureError` variant needs no change in a `match` that has a `_` arm.

- streaming encryption of values of any length, behind the `stream` feature, see
  [Streaming encryption](./streaming.md);
- signatures and MACs, see [Signatures and MACs](./signing.md);
- asymmetric KEKs, see [Asymmetric KEKs](./asymmetric-kek.md);
- `SymmetricKeyFormat::Jwk`, which loads a local KEK from an `oct` JWK, see
  [Local KMS](./providers/local.md#kek-ids-and-versions);
- signed keyring records, see [Signing the keyring record](./signing.md#signing-the-keyring-record);
- `KeyringAdmin::dangerously_shred()`, which destroys every version of a keyring in one write and
  deletes its record from the store with the earlier versions the store keeps, see [Shredding a
  keyring](./operations/runbook.md#shredding-a-keyring).
