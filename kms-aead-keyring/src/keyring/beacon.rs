//! The beacon calls of [`Sealer`] and [`Keyring`]: a field's blind index under the beacon
//! versions.

use std::cmp::Reverse;

use kms_aead::backends::AeadBackend;
use kms_aead::{Beacon, BeaconMac, KmsAeadEncryptionProvider, Plaintext};

use crate::errors::{KeyringError, KeyringResult, RecordInvalidReason};
use crate::spans;
use crate::store::KeyringStore;
use crate::{FieldSpec, KeyAlgorithm, KeyVersion, Keyring, Purpose, Sealer};

/// Beacons, or blind indexes: a truncated HMAC-SHA256 of a field's plaintext under a beacon
/// version's key, stored beside the encrypted field, which a data store matches by equality.
///
/// A beacon column leaks which rows are likely to hold equal values, and how often each value
/// occurs, to anyone who reads it, and a leaked beacon key lets its holder test guesses against
/// the whole column offline. Beacons fit fields that are looked up and have many distinct
/// values, such as emails and external ids. The context of a field's beacons is
/// `<kind>/<field>`, with no entity id, and the bits are the field's
/// [`with_beacon_bits`](FieldSpec::with_beacon_bits). Normalising a value, such as lowercasing an
/// email, is its `Plaintext` type's.
impl<S, P, B> Sealer<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// The beacon of `value` in `field` under the record's active beacon version, to store
    /// beside the field's encrypted value.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`] when the record has no active beacon version;
    /// [`KeyringError::KmsAead`] with code `INVALID_PLAINTEXT` when the value does not encode; and
    /// the provider's error when the version's key is not in the
    /// [`DekCache`](kms_aead::cache::DekCache) and cannot be decrypted.
    pub async fn beacon<T: Plaintext>(
        &self,
        field: &FieldSpec,
        value: &T,
    ) -> KeyringResult<Beacon<T>> {
        let keyring = self.keyring;
        spans::in_span(spans::beacon(keyring.id()), async {
            let (version, encrypted_dek) = self
                .record
                .active_dek(Purpose::Beacon)
                .ok_or_else(|| KeyringError::no_active_version(keyring.id(), Purpose::Beacon))?;
            spans::record_sealing_version(version);
            let mac = keyring.beacon_mac(version)?;
            let context = field.context();
            let (beacon, outcome) = keyring
                .with_cached_dek(&self.record, version.id(), encrypted_dek, |dek| {
                    mac.beacon(version.id(), &context, field.beacon_bits(), value, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(beacon?)
        })
        .await
    }
}

/// The probes of a beacon lookup across a rotation; see [`Sealer::beacon`] for what a beacon
/// column leaks.
impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadEncryptionProvider + Send + Sync + 'static,
    B: AeadBackend,
{
    /// The beacon of `value` in `field` under every beacon version that is pending, active or
    /// decrypt-only, compromised ones included, newest first: the `IN` list of a lookup, which
    /// finds the rows whose beacons were computed before a rotation as well as after it. Retired
    /// and destroyed versions give no probe. A compromised version's key is decrypted for each
    /// call, never through the [`DekCache`](kms_aead::cache::DekCache).
    ///
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] with code `INVALID_PLAINTEXT` when the value does not encode, and
    /// the provider's error when a version's key cannot be decrypted.
    pub async fn beacon_probes<T: Plaintext>(
        &self,
        field: &FieldSpec,
        value: &T,
    ) -> KeyringResult<Vec<Beacon<T>>> {
        // One span for every version's probe, so it records no field of a single version.
        spans::in_span(spans::beacon(self.id()), async {
            let record = self.cache.current().await;
            let context = field.context();
            let mut versions = record
                .versions()
                .iter()
                .filter(|version| version.algorithm().purpose() == Purpose::Beacon)
                .filter_map(|version| {
                    let (encrypted_dek, compromise) = version.readable_dek()?;
                    Some((version, encrypted_dek, compromise))
                })
                .collect::<Vec<_>>();
            versions.sort_by_key(|(version, ..)| Reverse(version.id().as_u32()));
            let mut probes = Vec::with_capacity(versions.len());
            for (version, encrypted_dek, compromise) in versions {
                let mac = self.beacon_mac(version)?;
                let beacon =
                    |dek: &_| mac.beacon(version.id(), &context, field.beacon_bits(), value, dek);
                let probe = match compromise {
                    None => {
                        self.with_cached_dek(&record, version.id(), encrypted_dek, beacon)
                            .await?
                            .0
                    }
                    Some(_) => self.with_uncached_dek(encrypted_dek, beacon).await?,
                };
                probes.push(probe?);
            }
            Ok(probes)
        })
        .await
    }

    fn beacon_mac(&self, version: &KeyVersion) -> KeyringResult<BeaconMac<B>> {
        match version.algorithm() {
            KeyAlgorithm::Beacon(algorithm) => Ok(BeaconMac::new(algorithm)),
            KeyAlgorithm::Randomized(_) | KeyAlgorithm::Deterministic(_) => {
                Err(KeyringError::record_invalid(
                    self.id(),
                    RecordInvalidReason::PurposeMismatch(version.id()),
                ))
            }
        }
    }
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use kms_aead::cache::DekCache;
    use kms_aead::{BeaconAlgorithm, BeaconBits, BeaconMac};

    use super::*;
    use crate::test_support::{
        TestAdmin, TestBackend, TestProvider, TestRegistry, TestResult, TENANT,
    };
    use crate::testing::MemoryKeyringStore;
    use crate::{
        EntityKind, FieldName, KeyId, KeyVersion, KeyringAlgorithms, KeyringRegistryOptions,
    };

    const EMAIL: FieldSpec = FieldSpec::new(
        EntityKind::from_static("user"),
        FieldName::from_static("email"),
    );
    const NAME: FieldSpec = FieldSpec::new(
        EntityKind::from_static("user"),
        FieldName::from_static("name"),
    );
    const ALICE: &str = "alice@example.com";

    /// A keyring with a beacon version beside the randomised one.
    async fn beacon_keyring(
        provider: TestProvider,
    ) -> KeyringResult<TestAdmin<MemoryKeyringStore>> {
        TestRegistry::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new().with_watch(false),
        )?
        .create(
            provider,
            TENANT,
            KeyringAlgorithms::new().with_beacon(BeaconAlgorithm::HmacSha256),
        )
        .await
    }

    #[tokio::test]
    async fn a_beacon_is_the_hmac_of_the_field_under_the_active_version() -> TestResult {
        let provider = TestProvider::new("tenant-42-kek")?;
        let admin = beacon_keyring(provider.clone()).await?;
        let keyring = admin.keyring();
        let first = KeyId::new((1 << 30) | 1);
        let alice = ALICE.to_string();

        let beacon = keyring.sealer().await.beacon(&EMAIL, &alice).await?;

        let record = keyring.record();
        let encrypted_dek = record
            .version(first)
            .and_then(KeyVersion::encrypted_dek)
            .ok_or("the first beacon version holds no key")?;
        let mac = BeaconMac::<TestBackend>::new(BeaconAlgorithm::HmacSha256);
        let (expected, _) = DekCache::disabled()
            .with_dek(&provider, encrypted_dek, |dek| {
                mac.beacon(first, b"user/email", BeaconBits::DEFAULT, &alice, dek)
            })
            .await?;
        assert_eq!(beacon, expected?);
        assert_eq!(beacon.key_id(), first);
        assert_eq!(keyring.sealer().await.beacon(&EMAIL, &alice).await?, beacon);
        assert_ne!(keyring.sealer().await.beacon(&NAME, &alice).await?, beacon);
        let wide = EMAIL.with_beacon_bits(BeaconBits::new(64).ok_or("64 bits are in range")?);
        assert_eq!(
            keyring
                .sealer()
                .await
                .beacon(&wide, &alice)
                .await?
                .value()
                .len(),
            5 + 8
        );
        Ok(())
    }

    #[tokio::test]
    async fn probes_cover_every_live_beacon_version_newest_first() -> TestResult {
        let admin = beacon_keyring(TestProvider::new("tenant-42-kek")?).await?;
        let keyring = admin.keyring();
        let alice = ALICE.to_string();
        let first = keyring.sealer().await.beacon(&EMAIL, &alice).await?;
        let second = admin.rotate(Purpose::Beacon).await?;
        admin.promote(second).await?;
        let pending = admin.rotate(Purpose::Beacon).await?;

        let probes = keyring.beacon_probes(&EMAIL, &alice).await?;
        assert_eq!(
            probes.iter().map(Beacon::key_id).collect::<Vec<_>>(),
            [pending, second, first.key_id()]
        );
        assert_eq!(
            probes[1],
            keyring.sealer().await.beacon(&EMAIL, &alice).await?
        );
        assert_eq!(probes[2], first);

        admin.retire(first.key_id()).await?;
        let probes = keyring.beacon_probes(&EMAIL, &alice).await?;
        assert_eq!(
            probes.iter().map(Beacon::key_id).collect::<Vec<_>>(),
            [pending, second]
        );
        Ok(())
    }
}
