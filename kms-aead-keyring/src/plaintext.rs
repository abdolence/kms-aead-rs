//! How plaintext types become the bytes a keyring value seals, and back.

use secret_vault_value::SecretValue;

use crate::errors::{KeyringError, KeyringResult};

/// A type a keyring value decrypts to. The encodings are fixed, so that other readers, such as
/// BigQuery's `AEAD.DECRYPT_STRING`, decode them: UTF-8 for `String`, the bytes themselves for
/// `Vec<u8>` and [`SecretValue`], `true` and `false` for `bool`, and decimal ASCII for the
/// integers, which SQL reads with `CAST`. With the `serde-json` feature, [`Json`] stores any
/// serde type as compact JSON.
///
/// The decrypted value belongs to the application, which protects it: only [`SecretValue`] as
/// `T` is zeroized on drop. `String` and `Vec<u8>` take over the decrypted buffer without a
/// copy.
pub trait Plaintext: Sized + Send + Sync {
    /// The bytes to seal.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Plaintext`] when the value does not encode, which only [`Json`] can
    /// fail to do.
    fn to_plaintext(&self) -> KeyringResult<SecretValue>;

    /// The value the decrypted `bytes` encode.
    ///
    /// # Errors
    ///
    /// [`KeyringError::Plaintext`] when the bytes are not an encoding of the type. The reason
    /// never quotes the bytes.
    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self>;
}

impl Plaintext for SecretValue {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(self.clone())
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        Ok(bytes)
    }
}

impl Plaintext for Vec<u8> {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.clone()))
    }

    fn from_plaintext(mut bytes: SecretValue) -> KeyringResult<Self> {
        Ok(std::mem::take(bytes.ref_sensitive_value_mut()))
    }
}

impl Plaintext for String {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.as_bytes().to_vec()))
    }

    fn from_plaintext(mut bytes: SecretValue) -> KeyringResult<Self> {
        String::from_utf8(std::mem::take(bytes.ref_sensitive_value_mut())).map_err(|error| {
            let reason = error.utf8_error().to_string();
            // Dropping the bytes inside a SecretValue zeroizes them.
            drop(SecretValue::from(error.into_bytes()));
            KeyringError::plaintext::<Self>(reason)
        })
    }
}

impl Plaintext for bool {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(if *self { "true" } else { "false" }))
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        match bytes.as_sensitive_bytes() {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => Err(KeyringError::plaintext::<Self>("neither true nor false")),
        }
    }
}

/// The decimal text of an integer, as `to_string` writes it and `parse` reads it.
fn decimal<T>(bytes: &SecretValue) -> KeyringResult<T>
where
    T: std::str::FromStr<Err = std::num::ParseIntError>,
{
    bytes
        .sensitive_value_to_str()
        .map_err(|error| KeyringError::plaintext::<T>(error.to_string()))?
        .parse()
        .map_err(|error: std::num::ParseIntError| KeyringError::plaintext::<T>(error.to_string()))
}

impl Plaintext for i32 {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        decimal(&bytes)
    }
}

impl Plaintext for i64 {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        decimal(&bytes)
    }
}

impl Plaintext for u32 {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        decimal(&bytes)
    }
}

impl Plaintext for u64 {
    fn to_plaintext(&self) -> KeyringResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
        decimal(&bytes)
    }
}

#[cfg(feature = "serde-json")]
mod json {
    use secret_vault_value::SecretValue;
    use serde::de::DeserializeOwned;
    use serde::Serialize;

    use super::Plaintext;
    use crate::errors::{KeyringError, KeyringResult};

    /// A plaintext of any serde type, stored as its compact JSON, which BigQuery reads with
    /// `AEAD.DECRYPT_STRING` and `JSON` functions.
    ///
    /// serde_json grows its output buffer while it writes, so freed copies of a part of the
    /// encoding can stay in memory after `to_plaintext`.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Json<T>(pub T);

    impl<T> Plaintext for Json<T>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        /// # Errors
        ///
        /// [`KeyringError::Plaintext`] when `T`'s `Serialize` fails, with serde_json's category
        /// of the error and none of its message.
        fn to_plaintext(&self) -> KeyringResult<SecretValue> {
            serde_json::to_vec(&self.0)
                .map(SecretValue::from)
                .map_err(|error| KeyringError::json::<Self>(&error))
        }

        /// # Errors
        ///
        /// [`KeyringError::Plaintext`] when the bytes are not the JSON of a `T`, with
        /// serde_json's category, line and column of the error and none of its message, which
        /// quotes the input.
        fn from_plaintext(bytes: SecretValue) -> KeyringResult<Self> {
            serde_json::from_slice(bytes.as_sensitive_bytes())
                .map(Json)
                .map_err(|error| KeyringError::json::<Self>(&error))
        }
    }
}

#[cfg(feature = "serde-json")]
pub use json::Json;

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn round_trip<T: Plaintext>(value: &T) -> KeyringResult<T> {
        T::from_plaintext(value.to_plaintext()?)
    }

    proptest! {
        #[test]
        fn strings_round_trip(value in ".*") {
            prop_assert_eq!(round_trip(&value)?, value);
        }

        #[test]
        fn bytes_round_trip(value in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(round_trip(&value)?, value.clone());
            let secret = SecretValue::from(value.clone());
            prop_assert_eq!(round_trip(&secret)?, secret);
        }

        #[test]
        fn integers_round_trip_as_decimal_text(value in any::<i64>(), unsigned in any::<u64>()) {
            prop_assert_eq!(round_trip(&value)?, value);
            prop_assert_eq!(round_trip(&unsigned)?, unsigned);
            prop_assert_eq!(round_trip(&(value as i32))?, value as i32);
            prop_assert_eq!(round_trip(&(unsigned as u32))?, unsigned as u32);
            let text = value.to_plaintext()?;
            prop_assert_eq!(text.as_sensitive_str(), value.to_string());
        }
    }

    #[test]
    fn booleans_are_true_and_false() -> KeyringResult<()> {
        assert_eq!(true.to_plaintext()?.as_sensitive_str(), "true");
        assert!(!round_trip(&false)?);
        assert!(matches!(
            bool::from_plaintext(SecretValue::from("yes")),
            Err(KeyringError::Plaintext(_))
        ));
        Ok(())
    }

    #[test]
    fn bytes_that_are_not_utf_8_are_no_string() {
        assert!(matches!(
            String::from_plaintext(SecretValue::from(vec![b'o', b'k', 0xFF])),
            Err(KeyringError::Plaintext(_))
        ));
    }

    #[test]
    fn a_number_out_of_range_is_refused() {
        assert!(matches!(
            i32::from_plaintext(SecretValue::from(i64::MAX.to_string())),
            Err(KeyringError::Plaintext(_))
        ));
        assert!(matches!(
            u64::from_plaintext(SecretValue::from("-1")),
            Err(KeyringError::Plaintext(_))
        ));
    }

    #[cfg(feature = "serde-json")]
    #[test]
    fn json_round_trips_as_compact_json() -> KeyringResult<()> {
        let value = Json(vec![("plan".to_string(), 3u32)]);
        assert_eq!(value.to_plaintext()?.as_sensitive_str(), r#"[["plan",3]]"#);
        assert_eq!(round_trip(&value)?, value);
        Ok(())
    }

    #[cfg(feature = "serde-json")]
    #[test]
    fn a_json_decode_error_carries_no_value() {
        const MARKER: &str = "card-4111-1111";
        let bytes = SecretValue::from(format!(r#"{{"plan": "{MARKER}"}}"#));
        let error = Json::<Vec<u32>>::from_plaintext(bytes).err();
        assert!(matches!(error, Some(KeyringError::Plaintext(_))));
        assert!(!format!("{error:?}").contains(MARKER));
        assert!(!format!("{error:?}").contains("plan"));
    }
}
