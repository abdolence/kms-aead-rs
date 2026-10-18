use std::fmt::Formatter;
use std::marker::PhantomData;

use serde::de::{Error, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::Encrypted;
use crate::errors::KmsAeadError;
use crate::formats::Format;

/// As bytes, through `serialize_bytes`: a `bytes` value in Firestore, and an array of numbers in
/// serde_json.
impl<T, F> Serialize for Encrypted<T, F> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.bytes)
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them: a malformed stored value fails here, before any decrypt.
impl<'de, T, F: Format> Deserialize<'de> for Encrypted<T, F> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_bytes(StoredBytesVisitor(PhantomData))
    }
}

/// Reads a `V` from bytes, or from a sequence of byte numbers as serde_json writes them, through
/// its `TryFrom<Vec<u8>>`: the stored values of the crate, [`Encrypted`] and
/// [`Beacon`](crate::Beacon).
pub(crate) struct StoredBytesVisitor<V>(pub(crate) PhantomData<fn() -> V>);

impl<'de, V: TryFrom<Vec<u8>, Error = KmsAeadError>> Visitor<'de> for StoredBytesVisitor<V> {
    type Value = V;

    fn expecting(&self, formatter: &mut Formatter) -> std::fmt::Result {
        formatter.write_str("the bytes of a stored value")
    }

    fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
        self.visit_byte_buf(bytes.to_vec())
    }

    fn visit_byte_buf<E: Error>(self, bytes: Vec<u8>) -> Result<Self::Value, E> {
        V::try_from(bytes).map_err(E::custom)
    }

    /// Grows the buffer as the bytes arrive: the sequence's length hint comes from the input, and
    /// a hostile one claims any length.
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
        let mut bytes = Vec::new();
        while let Some(byte) = seq.next_element()? {
            bytes.push(byte);
        }
        self.visit_byte_buf(bytes)
    }
}

#[cfg(test)]
mod tests {
    use serde::de::value::{Error, SeqDeserializer};

    use super::*;
    use crate::formats::{Deterministic, Envelope, Randomized, TinkOutputPrefix};
    use crate::ValueStruct;

    /// The shortest randomized value of the key `7`: a prefix, a nonce and a tag around an empty
    /// plaintext.
    fn randomized_bytes() -> Vec<u8> {
        [&TinkOutputPrefix::new(7).to_bytes()[..], &[0xAB; 12 + 16]].concat()
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
        let randomized = serde_json::to_string(&randomized_bytes())?;
        let prefix_only = serde_json::to_string(&TinkOutputPrefix::new(7).to_bytes())?;

        let as_envelope = serde_json::from_str::<Encrypted<String, Envelope>>(&randomized);
        let as_deterministic =
            serde_json::from_str::<Encrypted<String, Deterministic>>(&prefix_only);

        assert!(as_envelope.is_err(), "{as_envelope:?}");
        assert!(as_deterministic.is_err(), "{as_deterministic:?}");
        Ok(())
    }

    /// Bytes whose length hint claims `usize::MAX` elements, as a hostile input can.
    struct OverstatedLength(std::vec::IntoIter<u8>);

    impl Iterator for OverstatedLength {
        type Item = u8;

        fn next(&mut self) -> Option<u8> {
            self.0.next()
        }

        fn size_hint(&self) -> (usize, Option<usize>) {
            (usize::MAX, Some(usize::MAX))
        }
    }

    #[test]
    fn a_sequence_overstating_its_length_deserializes() -> Result<(), Error> {
        let bytes = OverstatedLength(randomized_bytes().into_iter());

        let value =
            Encrypted::<String, Randomized>::deserialize(SeqDeserializer::<_, Error>::new(bytes))?;

        assert_eq!(*value.value(), randomized_bytes());
        Ok(())
    }
}
