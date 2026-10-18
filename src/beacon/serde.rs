use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

use super::Beacon;

/// As bytes, through `serialize_bytes`: a `bytes` value in Firestore, and an array of numbers in
/// serde_json.
impl<T> Serialize for Beacon<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de, T> Deserialize<'de> for Beacon<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        Beacon::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_beacon_round_trips_through_serde_json_as_a_byte_array(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let beacon = Beacon::<String>::try_from(vec![0x01, 0, 0, 0, 7, 0xAB, 0xCD])?;

        let json = serde_json::to_string(&beacon)?;

        assert_eq!(json, "[1,0,0,0,7,171,205]");
        assert_eq!(serde_json::from_str::<Beacon<String>>(&json)?, beacon);
        Ok(())
    }
}
