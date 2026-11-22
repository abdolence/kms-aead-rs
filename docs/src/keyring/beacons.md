# Beacons

This page covers how a keyring computes, probes and rotates beacons. Beacons need no Cargo feature.
The generic [Beacons](../beacons.md) page owns the primitive, `Beacon<T>` and `BeaconBits`, what a
beacon leaks, its bits and its normalisation; [Formats](../formats/values.md#beacons) has its bytes.
To choose between a beacon and a deterministic field, read
[Find a user by an encrypted email](../use-cases/equality-lookups.md).

A beacon, or blind index, finds rows by a field's value without decrypting the column: a
truncated HMAC-SHA256 of the value, stored beside the field's randomised value, which a data store
matches by equality. The keyring computes beacons under its beacon versions, of the purpose
`Purpose::Beacon`, which rotate like any other.

## What a beacon leaks

What a beacon leaks, and what a leaked beacon key allows, is in
[What a beacon leaks](../beacons.md#what-a-beacon-leaks). The keyring computes a beacon in a field's
context, `<kind>/<field>` such as `user/email`, with no entity id: equal values in different rows
give equal beacons, which is what a lookup matches. A beacon of one field never matches a beacon of
another.

## Usage

A keyring with beacon versions names their algorithm in its `KeyringAlgorithms`: HMAC-SHA256, the
one `BeaconAlgorithm` has. An encryptor's `beacon` computes the beacon of a value under the active
beacon version, in the same write as the field's value, and `Keyring::beacon_probes` the beacons of
a value under every beacon version a lookup matches:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{Beacon, BeaconAlgorithm, BeaconBits, KmsAeadResult};
use kms_aead_keyring::formats::Randomized;
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    Encrypted, EntityId, EntityKind, FieldName, FieldSpec, Keyring, KeyringAdmin, KeyringAlgorithms,
    KeyringId, KeyringRegistry, KeyringRegistryOptions, Plaintext,
};
use secret_vault_value::SecretValue;

#[derive(Debug, Clone, PartialEq)]
struct Email(String);

impl Email {
    // Beacons of one address match regardless of case
    fn new(email: &str) -> Self {
        Email(email.to_lowercase())
    }
}

impl Plaintext for Email {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        self.0.to_plaintext()
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_plaintext(plaintext).map(Email)
    }
}

const EMAIL: FieldSpec = FieldSpec::new(
    EntityKind::from_static("user"),
    FieldName::from_static("email"),
)
.with_beacon_bits(BeaconBits::DEFAULT);

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
    .create(
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
    )
    .await?;
let keyring: &Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = admin.keyring();

// On every write: the field and its beacon, through one encryptor
let aad = EMAIL.aad(&EntityId::try_from("42")?);
let email = Email::new("Alice@Example.com");
let encryptor = keyring.encryptor().await;
let encrypted: Encrypted<Email, Randomized> = encryptor.encrypt(&aad, &email).await?;
let beacon: Beacon<Email> = encryptor.beacon(&EMAIL, &email).await?;

// A lookup: the probes of the value looked for, then a decryption of each matching row
let probes: Vec<Beacon<Email>> = keyring
    .beacon_probes(&EMAIL, &Email::new("alice@example.com"))
    .await?;
assert!(probes.contains(&beacon));
assert_eq!(keyring.decrypt(&aad, &encrypted).await?, email);
registry.shutdown(None).await;
# Ok(())
# }
```

The probes go into the query as the probes of a deterministic field do, see the
[table of queries](./deterministic.md#queries-across-rotations), with the beacon column in place of
the deterministic one. It has no BigQuery row: the keyring never exports beacon keys.

`Beacon` is stored as `Encrypted` is, see [Stored values](../stored-values.md#beacont).

## Bits

`FieldSpec::with_beacon_bits` sets how many bits of the HMAC the field's beacons keep,
`BeaconBits::DEFAULT`, 16, unless set; what the bits trade is in [Bits](../beacons.md#bits). The
bits enter the HMAC, so after a change of a field's bits, its stored beacons match no probe until a
re-index computes them again. A beacon is the HMAC of the bytes the `Plaintext` type encodes, so
the field's newtype normalises the value, as `Email::new` lowercases above, see
[Normalisation](../beacons.md#normalisation).

## BigQuery

The keyring never exports beacon keys to BigQuery: `export_bigquery_keyset` of the beacon purpose
fails with `ExportAlgorithmUnsupported`, see
[Exporting a keyset to BigQuery](./bigquery.md#exporting-a-keyset-to-bigquery). A BigQuery query
matches beacons the application computed, see [BigQuery](../beacons.md#bigquery) in kms-aead.

## Rotating beacon versions

A beacon version rotates as the other purposes do, see [Staged
rotation](./lifecycle.md#staged-rotation), and a column holds beacons of several versions while it
is re-indexed. What differs for beacons:

- lookups use `beacon_probes` throughout: one probe per pending, active or decrypt-only beacon
  version, compromised ones included, newest first. A probe under a staged version is returned from
  the next refresh of each process, so lookups find the beacons computed under it before every
  process has seen the promotion;
- a beacon cannot be re-encrypted, since it is a MAC of the plaintext. The promotion moves the
  keyring's re-encryption epoch on, so every row written before it has an `EncryptionMarker` below
  the current one and a re-index sweep visits it, see [Sweeps](../production/sweeps.md). It reads
  the value, computes the beacon again under the active version and writes the encryptor's marker;
  a row without a beacon gets the marker alone;
- once the sweep reports no failure and the version's range query returns nothing, `retire` the
  old version, and its probe drops out of every lookup, see
  [Retiring the old version](../production/sweeps.md#retiring-the-old-version).

`beacon.key_id()` reads the key id of a stored beacon, so that the sweep recomputes only the beacons
under an older version. In the re-encryption of the sweep, see
[Running a sweep](../production/sweeps.md#running-a-sweep), `reindex` handles one row: a beacon under the active
version keeps its bytes and only the value is re-encrypted; any other gives both again from the
plaintext. The caller writes the returned row back, conditional on the row as it was read:

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::LocalKmsProvider;
# use kms_aead::{Beacon, BeaconBits};
# use kms_aead_keyring::formats::Randomized;
# use kms_aead_keyring::sweep::{ReencryptOutcome, EncryptionMarker};
# use kms_aead_keyring::testing::MemoryKeyringStore;
# use kms_aead_keyring::{
#     Decrypted, Encrypted, EntityId, EntityKind, FieldName, FieldSpec, KeyTrust, Keyring,
#     KeyringResult, Purpose,
# };
# use kms_aead::providers::LocalKekId;
# use kms_aead::{BeaconAlgorithm, KmsAeadResult};
# use kms_aead_keyring::{
#     KeyId, KeyringAdmin, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
#     Plaintext,
# };
# use secret_vault_value::SecretValue;
#
# type UsersKeyring = Keyring<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring>;
#
# const EMAIL: FieldSpec = FieldSpec::new(
#     EntityKind::from_static("user"),
#     FieldName::from_static("email"),
# )
# .with_beacon_bits(BeaconBits::DEFAULT);
#
# #[derive(Debug, Clone, PartialEq)]
# struct Email(String);
#
# impl Plaintext for Email {
#     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
#         self.0.to_plaintext()
#     }
#
#     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
#         String::from_plaintext(plaintext).map(Email)
#     }
# }
#
# #[derive(Clone)]
# struct UserRow {
#     email: Encrypted<Email, Randomized>,
#     email_beacon: Beacon<Email>,
#     encryption_marker: EncryptionMarker,
# }
#
/// Computes the beacon of the row of `user` again under the active beacon version, and re-encrypts
/// its value under the active randomised version, with the marker of the encryptor's record.
async fn reindex(
    keyring: &UsersKeyring,
    user: &str,
    row: UserRow,
) -> KeyringResult<(UserRow, ReencryptOutcome)> {
    let encryptor = keyring.encryptor().await;
    let aad = EMAIL.aad(&EntityId::try_from(user)?);
    let (email, email_beacon, outcome) = if encryptor.is_current(row.email_beacon.key_id()).await? {
        let reencrypted = encryptor.reencrypt(&aad, &row.email).await?;
        let outcome = ReencryptOutcome::from(&reencrypted);
        let email = reencrypted.map_or(row.email, |reencrypted| reencrypted.value);
        (email, row.email_beacon, outcome)
    } else {
        let decrypted: Decrypted<Email> = keyring.decrypt_with_trust(&aad, &row.email).await?;
        let from_compromised = decrypted.trust != KeyTrust::Trusted;
        let email = encryptor.encrypt(&aad, &decrypted.value).await?;
        let email_beacon = encryptor.beacon(&EMAIL, &decrypted.value).await?;
        (email, email_beacon, ReencryptOutcome::Reencrypted { from_compromised })
    };
    let encryption_marker: EncryptionMarker = encryptor.record().encryption_marker();
    Ok((UserRow { email, email_beacon, encryption_marker }, outcome))
}
#
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider =
#     LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenant-kek".to_string())?)?;
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let admin: KeyringAdmin<MemoryKeyringStore, LocalKmsProvider<Ring>, Ring> = registry
#     .create(
#         provider,
#         KeyringId::from_static("tenant-42"),
#         KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
#     )
#     .await?;
# let keyring: &UsersKeyring = admin.keyring();
# let encryptor = keyring.encryptor().await;
# let email = Email("alice@example.com".to_string());
# let row = UserRow {
#     email: encryptor.encrypt(&EMAIL.aad(&EntityId::try_from("42")?), &email).await?,
#     email_beacon: encryptor.beacon(&EMAIL, &email).await?,
#     encryption_marker: encryptor.record().encryption_marker(),
# };
# let staged: KeyId = admin.rotate(Purpose::Beacon).await?;
# admin.promote_now(staged).await?;
# let (reindexed, outcome) = reindex(keyring, "42", row).await?;
# assert_eq!(outcome, ReencryptOutcome::Reencrypted { from_compromised: false });
# assert_eq!(reindexed.email_beacon.key_id(), staged);
# registry.shutdown(None).await;
# Ok(())
# }
```

Beacon versions are rotated by policy and on compromise only: each one adds a probe to every lookup
until the re-index is done.
