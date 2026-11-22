# Re-encrypt DEKs after a KEK rotation

A KEK rotation makes the KMS encrypt new DEKs under a new key version, and every DEK stored before
it keeps decrypting with the old version only. `reencrypt_encrypted_dek` and `reencrypt_dek` move a
stored DEK to the current version, so the old version can be retired while the application keeps
reading and writing:

1. rotate the KEK in the KMS, as the page of each provider describes. Under Cloud KMS, wait until
   the new primary version has propagated, see [Google Cloud
   KMS](../providers/gcp.md#key-versions-and-rotation). Then wait until every store-less writer has
   renewed its DEK. Until then a writer keeps encrypting under its current DEK, encrypted under the
   old version, so the sweep of step 2 misses the values it writes, the check of step 3 does not see
   them, and they first fail at the check of step 6, after the disable. A writer renews its DEK when
   its `DekReusePolicy` says so, and at the latest when the DEK leaves its cache, at the cache's
   `DekCacheOptions::ttl`, see [The DEK lives in the cache](../dek-caching.md#the-dek-lives-in-the-cache);
2. re-encrypt every stored DEK: the DEKs of the stored values, the DEKs stored apart from their
   values, and the record of each keyring under the KEK with `KeyringAdmin::reencrypt_deks`. Then
   export the keyrings' keysets again and re-encrypt the application's own encrypted keysets, see
   [Encrypted keysets](#encrypted-keysets), and replace the old keyset bytes wherever they are
   kept, see [Exporting a keyset to BigQuery](../keyring/bigquery.md#exporting-a-keyset-to-bigquery);
3. check that the `kek_versions_in_use` of every keyring record lists the new version alone, and so
   does the KEK version an application stores beside its own DEKs. A `None` never passes this
   check, see [A KEK version the KMS did not report](./rotation.md#a-kek-version-the-kms-did-not-report);
4. wait until no process holds an encrypted DEK from before step 2: the longest `record_ttl` in the
   fleet after the last `reencrypt_deks`, with no process logging "The keyring record could not
   be revalidated" meanwhile, and every process has read its DEKs stored apart from their values
   again, see [The check](#the-check);
5. disable the old version, and wait until the disable has propagated in the KMS, which takes a
   window under Cloud KMS, see [Google Cloud KMS](../providers/gcp.md#key-versions-and-rotation);
6. check that the KMS decrypts every stored DEK, every keyring's DEKs with `reencrypt_deks`, and
   every encrypted keyset, see [The check](#the-check). A DEK or a keyset it refuses is one the
   sweep missed: enable the old version again, sweep again, and go back to step 3;
7. keep the old version disabled for as long as the backups of the stored values and of the
   keyring records are kept. Immediately before destroying it, run the check of step 6 again, and
   destroy it only when it passes.

A backup taken before the sweep holds the DEKs under the old version, so destroying the old version
makes every such backup unreadable for good. Keyring records are the same, see
[Compromised versions](../keyring/lifecycle.md#compromised-versions). What a rotation, a disabled version
and a destroyed version are differs per KMS, see the page of each provider.

## The sweep

`reencrypt_encrypted_dek` makes two KMS calls: the KMS decrypts the DEK with the version that
encrypted it and encrypts it again with its current one. The AEAD bytes of a value stay as they
are, so the sweep takes no AAD, decrypts nothing, and the value decrypts as before. Each distinct
encrypted DEK is re-encrypted once and joined with each of its values, so the values a store-less
envelope wrote under one DEK still share one afterwards:

```rust
use std::collections::HashMap;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{
    Encrypted, EncryptedDataEncryptionKey, KmsAeadDecryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// The bytes to write back for each stored value in `rows`, beside the bytes read, with its DEK
/// under the KEK's current version. Each distinct encrypted DEK is re-encrypted once.
async fn reencrypt_values<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &[Vec<u8>],
) -> KmsAeadResult<Vec<(Vec<u8>, Vec<u8>)>>
where
    P: KmsAeadDecryptionProvider,
    B: AeadBackend,
{
    let mut reencrypted: HashMap<EncryptedDataEncryptionKey, EncryptedDataEncryptionKey> =
        HashMap::new();
    let mut updates = Vec::with_capacity(rows.len());
    for row in rows {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
        let (bare, encrypted_dek) = stored.separate()?;
        let new_encrypted_dek = match reencrypted.get(&encrypted_dek) {
            Some(new_encrypted_dek) => new_encrypted_dek.clone(),
            None => {
                let new_encrypted_dek = envelope.reencrypt_encrypted_dek(&encrypted_dek).await?;
                reencrypted.insert(encrypted_dek, new_encrypted_dek.clone());
                new_encrypted_dek
            }
        };
        updates.push((row.clone(), Encrypted::join(&bare, &new_encrypted_dek)?.into_value()));
    }
    Ok(updates)
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::formats::SymmetricKeyFormat;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# use kms_aead::{DekReusePolicy, KmsAeadEnvelopeOptions};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::with_options(
#     LocalKmsProvider::new(
#         kek_id.clone(),
#         vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?],
#     )?,
#     KmsAeadEnvelopeOptions::new().with_dek_reuse(DekReusePolicy::new()),
# )?;
# let mut rows = Vec::new();
# for card in ["4111 1111 1111 1111", "5500 0000 0000 0004"] {
#     rows.push(envelope.encrypt(b"orders/1042", &SecretValue::from(card)).await?.into_value());
# }
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id.clone(),
#     vec![
#         LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?,
#         LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?,
#     ],
# )?)?;
# for (read, new) in reencrypt_values(&envelope, &rows).await? {
#     if let Some(row) = rows.iter_mut().find(|row| **row == read) {
#         *row = new;
#     }
# }
# let encrypted_deks = rows
#     .iter()
#     .map(|row| Ok(Encrypted::<SecretValue, Envelope>::try_from(row.clone())?.separate()?.1))
#     .collect::<KmsAeadResult<Vec<EncryptedDataEncryptionKey>>>()?;
# assert_eq!(encrypted_deks[0], encrypted_deks[1]);
# let disabled = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?],
# )?)?;
# for row in &rows {
#     let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
#     disabled.decrypt(b"orders/1042", &stored).await?;
# }
# Ok(())
# }
```

Write each value back only where the stored bytes are still the ones read, with a compare-and-set
(a write that applies only if the stored value is unchanged), such as `UPDATE orders SET card = $new WHERE id = $id AND card = $read`, or the store's own
conditional write. An unconditional write puts back the value the sweep read over one the
application wrote in the meantime, which is then lost. A row the application rewrote keeps its new
value, and the checks of steps 3 and 6 find it if its DEK is still under the old version.

`reencrypt_dek` does the same for one value. It gives each value an encrypted DEK of its own, so
values that shared a DEK would then cost one KMS encryption each in the sweep and one KMS decryption
each on a cache miss afterwards. The same `reencrypt_encrypted_dek` re-encrypts the DEKs stored
apart from their values, such as those of the `*_with_encrypted_dek` calls, of beacons and of
deterministic fields. A value or a DEK in a legacy layout fails with `LEGACY_FORMAT`, see
[Values written by 0.29 and earlier](../migrating-from-0.29.md#values-written-by-029-and-earlier).

The DEK cache plays no part: the sweep decrypts through the provider and leaves the cache as it is,
so it evicts no entry that serves reads. Every call encrypts again, also for a DEK already under the
current version. The sweep needs KMS encrypt and decrypt on the KEK.

The `kek_version()` of the encrypted DEK that `reencrypt_encrypted_dek` returns names the KEK
version the KMS encrypted it with. Under Cloud KMS, a sweep that ran before the new primary version
had propagated shows the old version there, and the DEKs it names are re-encrypted again.

## Encrypted keysets

An encrypted keyset is a KMS ciphertext as well, under the KEK version that encrypted it, and
`reencrypt_encrypted_dek` refuses one with `INVALID_KEY_FORMAT`, since what the KMS decrypts from
it is a serialised keyset. A sweep of the DEKs leaves every keyset under the old version, so a
query or a reader that decrypts one fails once the old version is disabled:

- a keyring's `export_bigquery_keyset` and `export_tink_keyset`: export each keyset again, with the
  same selection, after `reencrypt_deks` and, under Cloud KMS, after the new primary version has
  propagated. The new export holds the same keys, encrypted under the KEK's current version. Write
  its bytes wherever the old ones are kept: the query parameter of each `KEYS.KEYSET_CHAIN`, a
  column or a setting that holds the keyset, and the file or the setting a
  Tink reader decrypts. See [BigQuery](../keyring/bigquery.md#exporting-a-keyset-to-bigquery);
- the application's own encrypted keyset, such as `first_level_keyset` in
  [One fixed key](../one-fixed-key.md): the provider decrypts it and encrypts it again, and the new bytes
  replace the old ones wherever they are kept:

```rust
use kms_aead::{EncryptedDataEncryptionKey, KmsAeadDecryptionProvider, KmsAeadResult};

/// `first_level_keyset` encrypted again under the KEK version the provider encrypts with.
async fn reencrypt_keyset<P: KmsAeadDecryptionProvider>(
    provider: &P,
    first_level_keyset: &EncryptedDataEncryptionKey,
) -> KmsAeadResult<EncryptedDataEncryptionKey> {
    let keyset = provider.decrypt_data_encryption_key(first_level_keyset).await?;
    provider.encrypt_data_encryption_key(&keyset).await
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::formats::SymmetricKeyFormat;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# use kms_aead::{DataEncryptionKey, KmsAeadEncryptionProvider};
# use secret_vault_value::SecretValue;
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let keyset = DataEncryptionKey::from(SecretValue::new(vec![0x0a; 16]));
# let first_level_keyset = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?],
# )?
# .encrypt_data_encryption_key(&keyset)
# .await?;
# let rotated = LocalKmsProvider::<Ring>::new(
#     kek_id.clone(),
#     vec![
#         LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?,
#         LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?,
#     ],
# )?;
# let reencrypted = reencrypt_keyset(&rotated, &first_level_keyset).await?;
# let disabled = LocalKmsProvider::<Ring>::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?],
# )?;
# assert_eq!(disabled.decrypt_data_encryption_key(&reencrypted).await?, keyset);
# Ok(())
# }
```

The check decrypts the bytes of a BigQuery keyset and of the application's own keyset through the
provider, as it does an encrypted DEK, with `EncryptedDataEncryptionKey::from` of the bytes. A
Tink keyset is a `google.crypto.tink.EncryptedKeyset` around the KMS ciphertext, and its check is
a decryption with the Tink reader that uses it.

## Pacing

The sweep makes two KMS calls per distinct encrypted DEK, and the check one, on top of the calls
the application makes. Under a KMS with a request quota, as the cloud KMSs have, pace the sweep
below it: a fixed number of DEKs per second, or a pause after each batch, with room left for the
application. A sweep over the quota fails with the KMS's error, such as `ResourceExhausted` on GCP,
and so do the application's own calls meanwhile.

## The check

Once the old version is disabled, the KMS refuses every DEK still under it, so the check decrypts
each distinct encrypted DEK through the provider, never through the DEK cache, which would serve a
missed DEK from memory. It needs no AAD and decrypts no value, and it runs online, under every
provider. Any error counts as a missed DEK:

```rust
use std::collections::HashSet;

use kms_aead::backends::AeadBackend;
use kms_aead::formats::Envelope;
use kms_aead::{
    Encrypted, EncryptedDataEncryptionKey, KmsAeadDecryptionProvider, KmsAeadEnvelope,
    KmsAeadResult,
};
use secret_vault_value::SecretValue;

/// The distinct encrypted DEKs of the values in `rows` that the provider fails to decrypt.
async fn missed_deks<P, B>(
    envelope: &KmsAeadEnvelope<P, B>,
    rows: &[Vec<u8>],
) -> KmsAeadResult<Vec<EncryptedDataEncryptionKey>>
where
    P: KmsAeadDecryptionProvider,
    B: AeadBackend,
{
    let mut encrypted_deks: HashSet<EncryptedDataEncryptionKey> = HashSet::new();
    for row in rows {
        let stored = Encrypted::<SecretValue, Envelope>::try_from(row.clone())?;
        let (_, encrypted_dek) = stored.separate()?;
        encrypted_deks.insert(encrypted_dek);
    }
    let mut missed = Vec::new();
    for encrypted_dek in encrypted_deks {
        if envelope
            .provider()
            .decrypt_data_encryption_key(&encrypted_dek)
            .await
            .is_err()
        {
            missed.push(encrypted_dek);
        }
    }
    Ok(missed)
}
# use std::num::NonZeroU32;
# use kms_aead::backends::Ring;
# use kms_aead::formats::SymmetricKeyFormat;
# use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let kek_id = LocalKekId::try_from("orders".to_string())?;
# let [v1, v2] = [1, 2].map(|version| LocalKekVersion::from(NonZeroU32::new(version).unwrap()));
# let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id.clone(),
#     vec![LocalKek::from_secret(v1, SecretValue::new(vec![0x01; 32]), SymmetricKeyFormat::Raw)?],
# )?)?;
# let stored = envelope.encrypt(b"orders/1042", &SecretValue::from("4111 1111 1111 1111")).await?;
# let rows = vec![stored.into_value()];
# let disabled = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(LocalKmsProvider::new(
#     kek_id,
#     vec![LocalKek::from_secret(v2, SecretValue::new(vec![0x02; 32]), SymmetricKeyFormat::Raw)?],
# )?)?;
# assert_eq!(missed_deks(&disabled, &rows).await?.len(), 1);
# Ok(())
# }
```

A keyring's record names the KEK version of each of its DEKs, as the KMS reported it, so a first
check makes no KMS call and runs before the old version is disabled: `kek_versions_in_use` of the
record that `Keyring::reload` returns must list the new version alone. Under Cloud KMS, a
`reencrypt_deks` that ran before the new primary version had propagated leaves the old version
listed. A `None` there is a version the KMS did not report, so the first check fails on it. Once the
old version is disabled, `KeyringAdmin::reencrypt_deks` runs again: it decrypts every DEK in the
record through the provider, and fails on one still under the old version. See
[Re-encrypting a keyring's DEKs](./rotation.md#re-encrypting-a-keyrings-deks). An application that stores the `kek_version`
of its own DEKs beside them checks those the same way.

Under the local KMS the check needs no disable. A provider that lists the new version alone, as
the sample above builds it, refuses every DEK under the old version, so the check runs before the
deploy that drops the old version from the list, and a missed DEK costs no outage and no redeploy.

Besides the store-less writers that step 1 of
[Re-encrypt DEKs after a KEK rotation](#re-encrypt-deks-after-a-kek-rotation) waits for, two
things keep using the old version after a rotation, and each sets when to disable it:

- every DEK cache serves the DEKs it holds, without a KMS call, until their entries expire. A value
  the sweep missed fails to decrypt in the application only once its entry has expired, see
  [DEK caching and reuse](../dek-caching.md). The check does not wait for that, since it never reads a cache;
- a process keeps the encrypted DEKs it read before the sweep. A keyring's cached record holds the
  ones it had before `reencrypt_deks` until it is refreshed, at a change signal of the store or
  once it is older than `record_ttl`, and Cloud Storage and S3 send no signal, see [Record cache](../keyring/record-cache.md#how-late-a-change-is-seen). A process whose
  revalidations fail keeps its record for as long as they fail, and logs "The keyring record could
  not be revalidated; the cached record stays in use" at `WARN` on each failure. An encrypted DEK
  the application read from its settings at startup, as in [One fixed key](../one-fixed-key.md), stays
  as it was read. The DEK cache keys its entries by those bytes, so once an entry expires, the KMS
  decrypts the old bytes again and fails under a disabled old version, with no reload. This is the
  wait of step 4 in [Re-encrypt DEKs after a KEK rotation](#re-encrypt-deks-after-a-kek-rotation).

A KMS whose changes take time to propagate, such as Cloud KMS, can keep encrypting under the old
version for a while after the rotation and keep decrypting under it for a while after it is
disabled. Wait before the sweep and again before trusting the check, see the page of each provider.

## Rolling back a rotation

A swept value's DEK is under the new version only, so a rollback keeps the new version enabled:
disabling it makes every swept value and every value written since the rotation unreadable, until
it is enabled again. Where the provider makes the old version encrypt again, rolling back to it
needs no new sweep. To retire the new version afterwards, run the procedure above with the old
version as the current one.

The rule per provider:

- [Google Cloud KMS](../providers/gcp.md#rolling-back-a-rotation);
- [AWS KMS](../providers/aws.md#rolling-back-a-rotation);
- [Azure Key Vault](../providers/azure.md#rolling-back-a-rotation);
- [HashiCorp Vault Transit](../providers/hc-vault-transit.md#rolling-back-a-rotation);
- [the local KMS](../providers/local.md#rolling-back-a-rotation).

