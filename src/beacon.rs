use std::fmt::{Debug, Display, Formatter};
use std::hash::{Hash, Hasher};
use std::marker::PhantomData;
use std::str::FromStr;

use rvstruct::ValueStruct;
use secret_vault_value::SecretValue;
use subtle::ConstantTimeEq;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::formats::{TinkKeyId, TinkKeyType};
use crate::types::checked_key_bytes;
use crate::{
    generate_random_bytes, AeadBackend, DataEncryptionKey, EncryptedDataEncryptionKey,
    KmsAeadEncryptionProvider, KmsAeadResult, Plaintext,
};

#[cfg(feature = "postgres")]
mod postgres;
#[cfg(feature = "serde")]
mod serde;
#[cfg(feature = "sqlx")]
mod sqlx;

/// The keyed hash a [`Beacon`] is computed with. It exists in every build, so that a keyring
/// record names the algorithm of every beacon version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BeaconAlgorithm {
    /// HMAC-SHA256 under a 32-byte key.
    HmacSha256,
}

impl BeaconAlgorithm {
    /// The length of a beacon key for this algorithm, in bytes.
    pub fn key_len(self) -> usize {
        match self {
            BeaconAlgorithm::HmacSha256 => 32,
        }
    }
}

/// `hmac-sha256`: the value of the `/kms_aead/algorithm` span field.
impl Display for BeaconAlgorithm {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            BeaconAlgorithm::HmacSha256 => "hmac-sha256",
        })
    }
}

/// Reads what `Display` writes.
///
/// # Errors
///
/// `UNKNOWN_ALGORITHM` for any other name.
impl FromStr for BeaconAlgorithm {
    type Err = KmsAeadError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        match name {
            "hmac-sha256" => Ok(BeaconAlgorithm::HmacSha256),
            _ => Err(KmsAeadEncryptionError::create(
                "UNKNOWN_ALGORITHM",
                "Not the name of a beacon algorithm: the name is hmac-sha256",
            )),
        }
    }
}

/// How many bits of its HMAC a [`Beacon`] keeps: 1 to 256.
///
/// The bits decide what a beacon column leaks. With `n` distinct values in a column and `b`
/// bits, about `n / 2^b` values share each beacon: a query by beacon returns that many rows,
/// which the application decrypts and filters, and an equal beacon never proves an equal
/// value. More bits leak more, down to which rows hold equal values once `2^b` is far above
/// `n`; fewer bits return more rows to filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BeaconBits(u16);

impl BeaconBits {
    /// The default: 16 bits, 65,536 beacons, so that a column of a million distinct values
    /// returns about 15 rows per query.
    pub const DEFAULT: BeaconBits = BeaconBits(16);

    /// `bits`, or `None` outside 1 to 256.
    pub const fn new(bits: u16) -> Option<Self> {
        if bits >= 1 && bits <= 256 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The number of bits.
    pub const fn get(self) -> u16 {
        self.0
    }
}

/// A beacon, or blind index: a keyed hash of a `T`'s plaintext, truncated, that a data store
/// matches by equality without the plaintext or its encryption:
///
/// ```text
/// [0x01][key id: u32 BE][HMAC-SHA256: the first ceil(bits / 8) bytes, unused low bits zero]
/// ```
///
/// The first byte is the version of the beacon layout, and the key id names the beacon key
/// that computed it, so that a column holds beacons of several keys during a re-index. The HMAC
/// covers the bits, the context and the plaintext; see the formats chapter of the book.
///
/// It holds the bytes to store, which `value()` and `into_value()` of [`ValueStruct`] return.
/// Bytes read back become a beacon through `TryFrom<Vec<u8>>`, which checks the prefix and the
/// length. Equality compares the bytes, which is what a lookup by beacon does: equal beacons
/// under one key and one context come from equal plaintexts, or from a collision of the
/// truncated HMAC.
///
/// `Debug` shows the key id only. The `serde` feature serializes it as bytes, and the `postgres`
/// and `sqlx` features store it as `BYTEA`, as for [`Encrypted`](crate::Encrypted).
pub struct Beacon<T> {
    key_id: TinkKeyId,
    bytes: Vec<u8>,
    plaintext: PhantomData<fn() -> T>,
}

impl<T> Beacon<T> {
    /// The version of the layout, the first byte of every beacon.
    const VERSION: u8 = 0x01;
    /// The length of the HMAC-SHA256 output, the most a beacon keeps.
    const MAX_HMAC_LEN: usize = 32;

    /// The id of the beacon key that computed this beacon.
    pub fn key_id(&self) -> TinkKeyId {
        self.key_id
    }
}

/// Reads stored bytes as a beacon.
///
/// # Errors
///
/// `INVALID_BEACON_FORMAT` when the bytes do not start with `0x01` and a key id, or carry no
/// HMAC byte or more than 32. The message never quotes the bytes.
impl<T> TryFrom<Vec<u8>> for Beacon<T> {
    type Error = KmsAeadError;

    fn try_from(bytes: Vec<u8>) -> KmsAeadResult<Self> {
        match bytes[..] {
            [Self::VERSION, a, b, c, d, ref hmac @ ..]
                if (1..=Self::MAX_HMAC_LEN).contains(&hmac.len()) =>
            {
                Ok(Self {
                    key_id: TinkKeyId::new(u32::from_be_bytes([a, b, c, d])),
                    bytes,
                    plaintext: PhantomData,
                })
            }
            _ => Err(KmsAeadEncryptionError::create(
                "INVALID_BEACON_FORMAT",
                &format!(
                    "A value of {} bytes is not `[0x01][key id: u32 BE]` and 1 to 32 bytes of \
                     HMAC",
                    bytes.len()
                ),
            )),
        }
    }
}

/// The bytes to store.
impl<T> ValueStruct for Beacon<T> {
    type ValueType = Vec<u8>;

    fn value(&self) -> &Vec<u8> {
        &self.bytes
    }

    fn into_value(self) -> Vec<u8> {
        self.bytes
    }
}

impl<T> Clone for Beacon<T> {
    fn clone(&self) -> Self {
        Self {
            key_id: self.key_id,
            bytes: self.bytes.clone(),
            plaintext: PhantomData,
        }
    }
}

/// The key id only: the bytes tell which values are likely equal.
impl<T> Debug for Beacon<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Beacon")
            .field("key_id", &self.key_id)
            .finish_non_exhaustive()
    }
}

/// Compares the bytes in constant time.
impl<T> PartialEq for Beacon<T> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes.ct_eq(&other.bytes).into()
    }
}

impl<T> Eq for Beacon<T> {}

/// Hashes the bytes, in variable time: which beacons are equal is what they are stored for.
impl<T> Hash for Beacon<T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bytes.hash(state);
    }
}

/// Computes [`Beacon`]s with an algorithm on the backend `B`, under a beacon key the caller
/// holds, without a KMS. It opens no span: it runs inside the caller's.
#[derive(Debug, Clone, Copy)]
pub struct BeaconMac<B> {
    algorithm: BeaconAlgorithm,
    backend: PhantomData<B>,
}

impl<B: AeadBackend> BeaconMac<B> {
    /// A beacon MAC for `algorithm` on the backend `B`. Every backend implements every
    /// [`BeaconAlgorithm`].
    pub fn new(algorithm: BeaconAlgorithm) -> Self {
        Self {
            algorithm,
            backend: PhantomData,
        }
    }

    /// The algorithm this MAC computes beacons with.
    pub fn algorithm(&self) -> BeaconAlgorithm {
        self.algorithm
    }

    /// A new beacon key of `algorithm().key_len()` bytes from the backend's CSPRNG.
    ///
    /// # Errors
    ///
    /// `RANDOM_GENERATOR` when the CSPRNG fails.
    pub fn generate_key(&self) -> KmsAeadResult<DataEncryptionKey> {
        generate_random_bytes::<B>(self.algorithm.key_len()).map(DataEncryptionKey::from)
    }

    /// A new beacon key and the same key wrapped by `provider`, to store. The key comes from the
    /// KMS generator when the provider is configured to use one, and from the backend's CSPRNG
    /// otherwise. It is wrapped as a serialized Tink key with the key in `key_value`, so that
    /// [`DekCache::with_key`](crate::cache::DekCache::with_key) unwraps it.
    ///
    /// # Errors
    ///
    /// The provider's errors, `INVALID_KEY_LENGTH` when the KMS generator returns key material
    /// of another length, and `RANDOM_GENERATOR` when the CSPRNG fails.
    pub async fn generate_wrapped_key<P>(
        &self,
        provider: &P,
    ) -> KmsAeadResult<(DataEncryptionKey, EncryptedDataEncryptionKey)>
    where
        P: KmsAeadEncryptionProvider + Sync + ?Sized,
    {
        // Tink's `HmacPrfKey` and `AesGcmKey` both hold their key in field 3, `key_value`, so a
        // 32-byte beacon key serializes to the bytes of a 32-byte `AesGcmKey`.
        crate::formats::generate_wrapped_key::<B, P>(
            TinkKeyType::AesGcm,
            self.algorithm.key_len(),
            provider,
        )
        .await
    }

    /// The beacon of `value` under `key`, the beacon key `key_id`, for the field `context`,
    /// keeping `bits` bits. `context` names the field, such as a table and a column, and never a
    /// row: equal values in one field must give equal beacons.
    ///
    /// # Errors
    ///
    /// `INVALID_KEY_LENGTH` when `key` does not have `algorithm().key_len()` bytes,
    /// `INVALID_BEACON_CONTEXT` for a context longer than 2^32 - 1 bytes, `INVALID_PLAINTEXT`
    /// when the value does not encode, and `BEACON` when the backend fails.
    pub fn compute<T: Plaintext>(
        &self,
        key_id: TinkKeyId,
        context: &[u8],
        bits: BeaconBits,
        value: &T,
        key: &DataEncryptionKey,
    ) -> KmsAeadResult<Beacon<T>> {
        let key = checked_key_bytes(key, self.algorithm, self.algorithm.key_len())?;
        let context_len = u32::try_from(context.len()).map_err(|_| {
            KmsAeadEncryptionError::create(
                "INVALID_BEACON_CONTEXT",
                &format!(
                    "A beacon context of {} bytes is longer than 2^32 - 1 bytes",
                    context.len()
                ),
            )
        })?;
        let plaintext = value.to_plaintext()?;
        let plaintext = plaintext.ref_sensitive_value();
        // Allocated once at its final size, since growing it would leave a copy of the plaintext
        // in freed memory.
        let mut message =
            SecretValue::new(Vec::with_capacity(2 + 4 + context.len() + plaintext.len()));
        let buffer = message.ref_sensitive_value_mut();
        buffer.extend_from_slice(&bits.0.to_be_bytes());
        buffer.extend_from_slice(&context_len.to_be_bytes());
        buffer.extend_from_slice(context);
        buffer.extend_from_slice(plaintext);
        let hmac = match self.algorithm {
            BeaconAlgorithm::HmacSha256 => B::hmac_sha256(key, buffer),
        }
        .map_err(|_| KmsAeadEncryptionError::create("BEACON", "Unable to compute the beacon"))?;
        let kept = usize::from(bits.0.div_ceil(8));
        let mut bytes = Vec::with_capacity(5 + kept);
        bytes.push(Beacon::<T>::VERSION);
        bytes.extend_from_slice(&key_id.as_u32().to_be_bytes());
        bytes.extend(hmac.iter().take(kept));
        let unused_bits = (8 - bits.0 % 8) % 8;
        if let Some(last) = bytes.last_mut() {
            *last &= 0xFF << unused_bits;
        }
        Ok(Beacon {
            key_id,
            bytes,
            plaintext: PhantomData,
        })
    }
}

#[cfg(all(
    test,
    any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto")
))]
mod tests {
    use super::*;
    use crate::test_provider::TestBackend;

    #[test]
    fn stored_bytes_read_as_a_beacon_only_in_its_layout() -> KmsAeadResult<()> {
        let prefix = [0x01, 0x00, 0x00, 0x00, 0x07];
        for hmac_len in [1, 32] {
            let beacon = Beacon::<String>::try_from([&prefix[..], &vec![0xAB; hmac_len]].concat())?;
            assert_eq!(beacon.key_id(), TinkKeyId::new(7));
        }
        for refused in [
            Vec::new(),
            prefix.to_vec(),
            [&prefix[..], &[0xAB; 33]].concat(),
            [&[0x02, 0x00, 0x00, 0x00, 0x07][..], &[0xAB; 2]].concat(),
        ] {
            let result = Beacon::<String>::try_from(refused);
            assert!(
                matches!(&result, Err(KmsAeadError::EncryptionError(error))
                    if error.public.code == "INVALID_BEACON_FORMAT"),
                "{result:?}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_key_of_another_length_is_refused() {
        let key = DataEncryptionKey::from(SecretValue::new(vec![0x42; 64]));

        let result = BeaconMac::<TestBackend>::new(BeaconAlgorithm::HmacSha256).compute(
            TinkKeyId::new(7),
            b"user/email",
            BeaconBits::DEFAULT,
            &"alice@example.com".to_string(),
            &key,
        );

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_KEY_LENGTH"),
            "{result:?}"
        );
    }
}
