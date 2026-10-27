use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

use super::{Mac, Signature, Signed, WithMac};

/// As bytes, through `serialize_bytes`, as [`Encrypted`](crate::Encrypted) is.
impl<T> Serialize for Signature<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de, T> Deserialize<'de> for Signature<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        Signature::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

/// As bytes, through `serialize_bytes`, as [`Encrypted`](crate::Encrypted) is.
impl<T> Serialize for Signed<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de, T> Deserialize<'de> for Signed<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        Signed::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

/// As bytes, through `serialize_bytes`, as [`Encrypted`](crate::Encrypted) is.
impl<T> Serialize for Mac<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de, T> Deserialize<'de> for Mac<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        Mac::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

/// As bytes, through `serialize_bytes`, as [`Encrypted`](crate::Encrypted) is.
impl<T> Serialize for WithMac<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de, T> Deserialize<'de> for WithMac<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        WithMac::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_signature_round_trips_through_serde_json_as_a_byte_array(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let signature = Signature::<String>::try_from(vec![0x01, 0, 0, 0, 7, 0xAB, 0xCD])?;

        let json = serde_json::to_string(&signature)?;

        assert_eq!(json, "[1,0,0,0,7,171,205]");
        assert_eq!(
            serde_json::from_str::<Signature<String>>(&json)?.value(),
            signature.value()
        );
        assert!(serde_json::from_str::<Mac<String>>(&json).is_err());
        Ok(())
    }
}
