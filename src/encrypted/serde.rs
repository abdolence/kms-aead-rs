use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

use super::Encrypted;
use crate::formats::Format;

/// As bytes, through `serialize_bytes`: a `bytes` value in Firestore, and an array of numbers in
/// serde_json.
impl<T, F: Format> Serialize for Encrypted<T, F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them: a malformed stored value fails here, before any decrypt.
impl<'de, T, F: Format> Deserialize<'de> for Encrypted<T, F> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        Encrypted::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{Deterministic, Envelope, Randomized};

    /// The shortest randomised value of the key `7`: a prefix, a nonce and a tag around an empty
    /// plaintext.
    fn randomized_bytes() -> Vec<u8> {
        [&[0x01, 0, 0, 0, 7][..], &[0xAB; 12 + 16]].concat()
    }

    #[test]
    fn a_value_round_trips_through_serde_json_as_a_byte_array(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let value = Encrypted::<String, Randomized>::try_from(randomized_bytes())?;

        let json = serde_json::to_string(&value)?;

        assert!(json.starts_with("[1,0,0,0,7,171,"), "{json}");
        let read_back = serde_json::from_str::<Encrypted<String, Randomized>>(&json)?;
        assert_eq!(read_back.value(), value.value());
        Ok(())
    }

    #[test]
    fn bytes_outside_the_format_fail_to_deserialize() -> Result<(), serde_json::Error> {
        let prefix_only = serde_json::to_string(&[0x01, 0, 0, 0, 7])?;
        let encrypted_dek_past_the_end = serde_json::to_string(&[0x00, 0, 0, 5, 0xAB])?;

        let as_envelope =
            serde_json::from_str::<Encrypted<String, Envelope>>(&encrypted_dek_past_the_end);
        let as_deterministic =
            serde_json::from_str::<Encrypted<String, Deterministic>>(&prefix_only);

        assert!(as_envelope.is_err(), "{as_envelope:?}");
        assert!(as_deterministic.is_err(), "{as_deterministic:?}");
        Ok(())
    }
}
