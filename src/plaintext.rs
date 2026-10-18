use secret_vault_value::SecretValue;

use crate::errors::KmsAeadEncryptionError;
use crate::KmsAeadResult;

/// A type an [`Encrypted`](crate::Encrypted) value decrypts to, and the bytes it is sealed as.
///
/// The encodings of the types here are fixed, so that other readers of the same values decode
/// them, such as BigQuery's `AEAD.DECRYPT_STRING` on a keyring value: UTF-8 for `String`, the
/// bytes themselves for `Vec<u8>` and [`SecretValue`], `true` and `false` for `bool`, and decimal
/// ASCII for the integers, which SQL reads with `CAST`. With the `serde-json` feature, `Json`
/// stores any serde type as compact JSON.
///
/// An application type implements it by mapping to and from one of these, such as a newtype
/// over `String` that is sealed as the same UTF-8 bytes:
///
/// ```rust
/// use kms_aead::{KmsAeadResult, Plaintext};
/// use secret_vault_value::SecretValue;
///
/// #[derive(Debug, PartialEq)]
/// struct Email(String);
///
/// impl Plaintext for Email {
///     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
///         self.0.to_plaintext()
///     }
///
///     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
///         String::from_plaintext(plaintext).map(Email)
///     }
/// }
///
/// # fn main() -> KmsAeadResult<()> {
/// let email = Email("alice@example.com".to_string());
/// assert_eq!(Email::from_plaintext(email.to_plaintext()?)?, email);
/// # Ok(())
/// # }
/// ```
///
/// The decrypted value belongs to the application, which protects it: only [`SecretValue`] as
/// `T` is zeroised on drop. `String` and `Vec<u8>` take over the decrypted buffer without a
/// copy.
pub trait Plaintext: Sized + Send + Sync {
    /// The bytes to seal.
    ///
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when the value does not encode, which of the types here only `Json`
    /// can fail to do.
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue>;

    /// The value the decrypted `plaintext` encodes.
    ///
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when the bytes are not an encoding of the type. The message never
    /// quotes them.
    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self>;
}

impl Plaintext for SecretValue {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(self.clone())
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        Ok(plaintext)
    }
}

impl Plaintext for Vec<u8> {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::new(self.clone()))
    }

    fn from_plaintext(mut plaintext: SecretValue) -> KmsAeadResult<Self> {
        Ok(std::mem::take(plaintext.ref_sensitive_value_mut()))
    }
}

impl Plaintext for String {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::new(self.as_bytes().to_vec()))
    }

    fn from_plaintext(mut plaintext: SecretValue) -> KmsAeadResult<Self> {
        String::from_utf8(std::mem::take(plaintext.ref_sensitive_value_mut())).map_err(|error| {
            let reason = error.utf8_error().to_string();
            // Dropping the bytes inside a SecretValue zeroises them.
            drop(SecretValue::new(error.into_bytes()));
            KmsAeadEncryptionError::invalid_plaintext::<Self>(reason)
        })
    }
}

impl Plaintext for bool {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(if *self { "true" } else { "false" }))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        match plaintext.as_sensitive_bytes() {
            b"true" => Ok(true),
            b"false" => Ok(false),
            _ => Err(KmsAeadEncryptionError::invalid_plaintext::<Self>(
                "neither true nor false",
            )),
        }
    }
}

/// The integer whose decimal text `plaintext` holds, as `to_string` writes it and `parse` reads
/// it.
fn from_decimal<T>(plaintext: &SecretValue) -> KmsAeadResult<T>
where
    T: std::str::FromStr<Err = std::num::ParseIntError>,
{
    plaintext
        .sensitive_value_to_str()
        .map_err(KmsAeadEncryptionError::invalid_plaintext::<T>)?
        .parse()
        .map_err(KmsAeadEncryptionError::invalid_plaintext::<T>)
}

impl Plaintext for i32 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        from_decimal(&plaintext)
    }
}

impl Plaintext for i64 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        from_decimal(&plaintext)
    }
}

impl Plaintext for u32 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        from_decimal(&plaintext)
    }
}

impl Plaintext for u64 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        from_decimal(&plaintext)
    }
}

/// A plaintext of any serde type, stored as its compact JSON, which BigQuery reads with
/// `AEAD.DECRYPT_STRING` and its JSON functions. With the `serde-json` feature.
///
/// serde_json grows its output buffer while it writes, so freed copies of a part of the encoding
/// can stay in memory after `to_plaintext`.
#[cfg(feature = "serde-json")]
#[derive(Debug, PartialEq, Eq)]
pub struct Json<T>(pub T);

#[cfg(feature = "serde-json")]
impl<T> Plaintext for Json<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
{
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when `T`'s `Serialize` fails, with serde_json's category of the error
    /// and none of its message.
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        serde_json::to_vec(&self.0)
            .map(SecretValue::new)
            .map_err(|error| KmsAeadEncryptionError::invalid_json::<Self>(&error))
    }

    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when the bytes are not the JSON of a `T`, with serde_json's category,
    /// line and column of the error and none of its message, which quotes the input.
    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        serde_json::from_slice(plaintext.as_sensitive_bytes())
            .map(Json)
            .map_err(|error| KmsAeadEncryptionError::invalid_json::<Self>(&error))
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;
    use crate::errors::KmsAeadError;

    proptest! {
        #[test]
        fn strings_round_trip(value in ".*") {
            prop_assert_eq!(String::from_plaintext(value.to_plaintext()?)?, value);
        }

        #[test]
        fn bytes_round_trip(value in proptest::collection::vec(any::<u8>(), 0..64)) {
            prop_assert_eq!(Vec::<u8>::from_plaintext(value.to_plaintext()?)?, value.clone());
            let secret = SecretValue::new(value);
            prop_assert_eq!(SecretValue::from_plaintext(secret.to_plaintext()?)?, secret);
        }

        #[test]
        fn integers_round_trip_as_decimal_text(
            long in any::<i64>(),
            unsigned_long in any::<u64>(),
            int in any::<i32>(),
            unsigned_int in any::<u32>(),
        ) {
            let decimal = long.to_plaintext()?;
            prop_assert_eq!(decimal.as_sensitive_str(), long.to_string());
            prop_assert_eq!(i64::from_plaintext(decimal)?, long);
            prop_assert_eq!(u64::from_plaintext(unsigned_long.to_plaintext()?)?, unsigned_long);
            prop_assert_eq!(i32::from_plaintext(int.to_plaintext()?)?, int);
            prop_assert_eq!(u32::from_plaintext(unsigned_int.to_plaintext()?)?, unsigned_int);
        }
    }

    #[test]
    fn booleans_are_true_and_false() -> KmsAeadResult<()> {
        assert_eq!(true.to_plaintext()?.as_sensitive_str(), "true");
        assert!(!bool::from_plaintext(false.to_plaintext()?)?);
        let refused = bool::from_plaintext(SecretValue::from("yes"));
        assert!(
            matches!(&refused, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{refused:?}"
        );
        Ok(())
    }

    #[test]
    fn bytes_that_are_not_utf_8_are_no_string() {
        let result = String::from_plaintext(SecretValue::new(vec![b'o', b'k', 0xFF]));

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{result:?}"
        );
    }

    #[test]
    fn a_number_out_of_range_is_refused() {
        let too_large = i32::from_plaintext(SecretValue::from(i64::MAX.to_string()));
        let negative = u64::from_plaintext(SecretValue::from("-1"));

        assert!(
            matches!(&too_large, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{too_large:?}"
        );
        assert!(
            matches!(&negative, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{negative:?}"
        );
    }

    #[cfg(feature = "serde-json")]
    #[test]
    fn json_round_trips_as_compact_json() -> KmsAeadResult<()> {
        let value = Json(vec![("plan".to_string(), 3u32)]);

        let plaintext = value.to_plaintext()?;

        assert_eq!(plaintext.as_sensitive_str(), r#"[["plan",3]]"#);
        assert_eq!(Json::from_plaintext(plaintext)?, value);
        Ok(())
    }

    #[cfg(feature = "serde-json")]
    #[test]
    fn a_json_decode_error_carries_no_value() {
        const CARD: &str = "card-4111-1111";
        let plaintext = SecretValue::from(format!(r#"{{"plan": "{CARD}"}}"#));

        let result = Json::<Vec<u32>>::from_plaintext(plaintext);

        assert!(
            matches!(&result, Err(KmsAeadError::EncryptionError(error))
                if error.public.code == "INVALID_PLAINTEXT"),
            "{result:?}"
        );
        let error = format!("{result:?}");
        assert!(!error.contains(CARD), "{error}");
        assert!(!error.contains("plan"), "{error}");
    }
}
