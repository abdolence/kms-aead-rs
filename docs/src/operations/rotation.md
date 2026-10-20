# Rotation

## Rotation cadence

A rotation is staged: `rotate(purpose)` adds a pending version, which every process decrypts under
once its record refreshes, and `promote(key_id)` makes it active once every process has had time
to see it, see [Staged rotation](../keyring/lifecycle.md#staged-rotation). The previous version keeps
decrypting. Nothing is lost while the change propagates: processes on the old record seal under
the previous version until their record refreshes, and those values decrypt.

The administrative job runs a rotation in steps, on its `KeyringAdmin`, see
[Applications and administration](../keyring/deployment.md):

1. `rotate(purpose)`;
2. export the `Readable` BigQuery keysets again, which then hold the pending version;
3. wait the longest time any process may run without a successful refresh of its record, counted
   from `staged_at()`, and check that no process logged "The keyring record could not be
   revalidated" meanwhile;
4. `promote(key_id)`. Until `record_ttl` has passed since `staged_at()` it fails with
   `PromotionTooEarly`, whose `remaining` is the time left. `promote_now(key_id)` skips that
   guard, for a fleet known to have refreshed since the rotation or a compromise that cannot wait.

The [`rotate` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/rotate.rs)
runs the whole cycle, and a KEK re-encryption after it, on the memory store and the local KMS:
`cargo run -p kms-aead-keyring --example rotate --features ring,admin`.

How often:

- a randomised version is good for about 2^32 values, see [Nonces](../security.md#nonces), and an
  AES-GCM version for about 2^38 bytes, see [Data volume](../security.md#data-volume). The keyring
  stops at neither, since its DEKs are shared across processes: estimate the values and bytes a
  fleet seals, or measure them, see [Alerting on volume](#alerting-on-volume). At 550 values per
  second a version reaches 2^32 in 90 days, so rotate every 30 to 90 days, sooner at higher rates;
- a deterministic version has no nonce, so it is rotated by policy and on compromise only. Every
  deterministic rotation adds a probe to each equality query until a full sweep re-seals every
  row, see [Queries across rotations](../keyring/deterministic.md#queries-across-rotations), so
  rotate deterministic versions rarely;
- a beacon version likewise, since every beacon rotation adds a probe to each lookup until a
  re-index, see [Rotating beacon versions](../keyring/beacons.md#rotating-beacon-versions).

After a promotion, export the `Single` BigQuery keysets of the new deterministic version, since
a pending version has none.

Rotation does not touch values already written. A [sweep](./sweeps.md) re-seals them: a job that runs
on a schedule until its `SweepReport` shows nothing scanned. Retiring the old version is a separate
step of the administrative job, once the sweep is done and the old version's
[range query](./sweeps.md#records-under-a-version) returns nothing: `retire`, and later `destroy`.

### Alerting on volume

With the `opentelemetry` feature, the keyring counts the values and plaintext bytes it seals
under each version, see [Metrics](../observability.md#metrics). Each process counts its own, and
the alert sums them across the fleet. Here at half of 2^32 values and of 2^38 bytes per version,
in PromQL over the Prometheus export, with the range covering the version's life:

```promql
sum by (keyring, key_id) (
  increase(kms_aead_keyring_values_total{operation="encrypt", purpose="randomized"}[90d])
) > 0.5 * 2^32

sum by (keyring, key_id) (
  increase(kms_aead_keyring_plaintext_bytes_total{operation="encrypt", purpose="randomized"}[90d])
) > 0.5 * 2^38
```

A counter starts at zero in every new process, and `increase()` counts across those restarts. The
bytes alert is for AES-GCM versions only. Rotate the version the alert names, as above.

## Rotating the KEK

The KEK rotates in the KMS on its own schedule. After a rotation, `reencrypt_deks()` decrypts every
DEK in the record and encrypts it again under the KEK's current version. No value changes. A keyring
that is not re-encrypted keeps working as long as the old KEK versions stay enabled in the KMS.

`reencrypt_deks` is a `KeyringAdmin` call and runs in the administrative job, like every call that
encrypts a DEK.

The record keeps the KEK version of each encrypted DEK, as the KMS reported it when it encrypted the
DEK: `KeyVersion::kek_version`. `reencrypt_deks` returns one `DekReencryption` per version, with the
KEK version its DEK was under and the one the KMS encrypted it with now, and `kek_versions_in_use`
of the record lists every KEK version the record's DEKs are under. Before the old KEK version is
disabled, the record that `Keyring::reload` returns must list the new version alone, which needs no
KMS call. Once the old version is disabled, `reencrypt_deks` runs again: it decrypts every DEK
through the KMS and fails on one the KMS no longer decrypts. Here with the local KMS, rotated from
version 1 to version 2, where dropping version 1 from the provider stands for disabling it:

```rust
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::providers::{
    KekVersion, LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider,
};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    DekReencryption, KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions,
};
use secret_vault_value::SecretValue;

const TENANT: KeyringId = KeyringId::from_static("tenant-42");

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let kek_id = LocalKekId::try_from("tenant-kek".to_string())?;
let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new(),
)?;
# let before_rotation = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?],
# )?;
# registry
#     .create(before_rotation, TENANT, KeyringAlgorithms::new())
#     .await?;

// The administrative job after the rotation, with the new version encrypting
let rotated = LocalKmsProvider::<Ring>::new(
    kek_id.clone(),
    vec![
        LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]))?,
        LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?,
    ],
)?;
let admin = registry.admin(rotated, TENANT).await?;

// One entry per version: the KEK version its DEK was under, and the one it is under now
let moved: Vec<DekReencryption> = admin.reencrypt_deks().await?;
let new_kek_version = KekVersion::from(v2);
assert!(moved
    .iter()
    .all(|reencryption| reencryption.kek_version.as_ref() == Some(&new_kek_version)));

// The check before the old version is disabled: every DEK is under the new version
let record = admin.keyring().reload().await?;
assert_eq!(record.kek_versions_in_use(), [Some(&new_kek_version)]);

// The check once the old version is disabled: every DEK still decrypts
let disabled = LocalKmsProvider::<Ring>::new(
    kek_id,
    vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]))?],
)?;
registry.admin(disabled, TENANT).await?.reencrypt_deks().await?;
# Ok(())
# }
```

Under Cloud KMS, a `reencrypt_deks` that ran before the new primary version had propagated reports
the old version as the one the DEK is under now, and the record keeps listing it: run
`reencrypt_deks` again once the rotation has propagated. Under Vault Transit,
`min_decryption_version` disables every version below it at once, which is why the check asks for
the new version alone.

The whole procedure, with the application's own DEKs and keysets, is in
[Re-encrypting DEKs after a KEK rotation](../envelope-encryption.md#re-encrypting-deks-after-a-kek-rotation).

### A KEK version the KMS did not report

A `None` among the versions in use stands for the DEKs whose KMS reported no version: every DEK
under AWS KMS, and under a KMS with versions, a version that is unknown, as with an application's
own provider that returns none. `reencrypt_deks` keeps such a DEK at `None`, so the check before the
disable never passes, and the check once the old version is disabled is the only one:

1. run `reencrypt_deks` after the rotation;
2. disable the old version in the KMS;
3. run `reencrypt_deks` again. It decrypts every DEK through the KMS, so an error is a DEK the KMS
   no longer decrypts: enable the old version again, and go back to step 1.

Between steps 2 and 3, a DEK still under the old version fails in the application too, once its
DEK cache entry has expired. Under AWS KMS only imported key material can be removed, see
[AWS KMS](../providers/aws.md#key-versions-and-rotation).
