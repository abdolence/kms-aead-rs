use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;

use secret_vault_value::SecretValue;

use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::redaction::{JsonRedaction, RedactedJson, ShapeOnly};
use crate::{spans, KmsAeadResult, SignedPayloadType};

/// A type an [`Encrypted`](crate::Encrypted) value decrypts to, and the bytes it is encrypted as.
///
/// The encodings of the types here are fixed, so that other readers of the same values decode
/// them, such as BigQuery's `AEAD.DECRYPT_STRING` on a keyring value: UTF-8 for `String`, the
/// bytes themselves for `Vec<u8>` and [`SecretValue`], `true` and `false` for `bool`, and decimal
/// ASCII for the integers, which SQL reads with `CAST`. `JsonEncoded` stores any serde type as
/// compact JSON.
///
/// An application type implements it by mapping to and from one of these, such as a newtype
/// over `String` that is encrypted as the same UTF-8 bytes:
///
/// ```rust
/// use kms_aead::{KmsAeadResult, Plaintext};
/// use secret_vault_value::SecretValue;
///
/// #[derive(Debug, Clone, PartialEq)]
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
/// A newtype over [`SecretValue`] keeps the decrypted value zeroised on drop, and its `Debug`
/// prints `***` instead of the value. Text stored this way is the same bytes as through `String`,
/// so `AEAD.DECRYPT_STRING` still reads it. In exchange there is no UTF-8 check on read, and the
/// text is reached through `SecretValue`'s accessors, such as `as_sensitive_str()`, which panics on
/// bytes that are not UTF-8, or `sensitive_value_to_str()`, which returns an error. `SecretValue`
/// suits values that are secrets or personal data, `String` values that are used as text
/// throughout:
///
/// ```rust
/// use kms_aead::{KmsAeadResult, Plaintext};
/// use secret_vault_value::SecretValue;
///
/// #[derive(Debug, Clone, PartialEq)]
/// struct Email(SecretValue);
///
/// impl Plaintext for Email {
///     fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
///         Ok(self.0.clone())
///     }
///
///     fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
///         Ok(Email(plaintext))
///     }
/// }
///
/// # fn main() -> KmsAeadResult<()> {
/// let email = Email(SecretValue::from("alice@example.com"));
/// let decrypted: Email = Email::from_plaintext(email.to_plaintext()?)?;
/// assert_eq!(decrypted, email);
/// assert_eq!(decrypted.0.as_sensitive_str(), "alice@example.com");
/// assert_eq!(format!("{decrypted:?}"), "Email(***)");
/// # Ok(())
/// # }
/// ```
///
/// The decrypted value belongs to the application, which protects it: only [`SecretValue`] as
/// `T` is zeroised on drop. `String` and `Vec<u8>` take over the decrypted buffer without a
/// copy.
pub trait Plaintext: Sized + Send + Sync {
    /// The bytes to encrypt.
    ///
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when the value does not encode, which of the types here only `JsonEncoded`
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
fn integer_from_decimal_plaintext<T>(plaintext: &SecretValue) -> KmsAeadResult<T>
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
        integer_from_decimal_plaintext(&plaintext)
    }
}

impl Plaintext for i64 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        integer_from_decimal_plaintext(&plaintext)
    }
}

impl Plaintext for u32 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        integer_from_decimal_plaintext(&plaintext)
    }
}

impl Plaintext for u64 {
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        Ok(SecretValue::from(self.to_string()))
    }

    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        integer_from_decimal_plaintext(&plaintext)
    }
}

/// A plaintext of any serde type, stored as its compact JSON, which BigQuery reads with
/// `AEAD.DECRYPT_STRING` and its JSON functions, and the [`Signable`](crate::Signable) payload of
/// a [`SignableType`](crate::SignableType).
///
/// JSON that does not decode to `T` fails with `INVALID_PLAINTEXT` or `INVALID_PAYLOAD`, which
/// never quote it, and logs a `WARN` event on the `kms_aead::json` target with an outline of the
/// JSON under the policy `P`: the shape only under the default, [`ShapeOnly`], and what a
/// [`JsonRedaction`] of the application's own opts into, see [`redaction`](crate::redaction).
///
/// serde_json grows its output buffer while it writes, so freed copies of a part of the encoding
/// can stay in memory after `to_plaintext`.
pub struct JsonEncoded<T, P = ShapeOnly>(pub T, PhantomData<fn() -> P>);

impl<T> JsonEncoded<T> {
    /// `value` under the default policy, [`ShapeOnly`]. A type with a policy of its own is built
    /// with `From`, such as `InvoiceJson::from(invoice)` for
    /// `type InvoiceJson = JsonEncoded<Invoice, InvoiceLog>`.
    pub fn new(value: T) -> Self {
        Self(value, PhantomData)
    }
}

impl<T, P> From<T> for JsonEncoded<T, P> {
    fn from(value: T) -> Self {
        Self(value, PhantomData)
    }
}

impl<T: Debug, P> Debug for JsonEncoded<T, P> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("JsonEncoded").field(&self.0).finish()
    }
}

impl<T: Clone, P> Clone for JsonEncoded<T, P> {
    fn clone(&self) -> Self {
        Self::from(self.0.clone())
    }
}

impl<T: PartialEq, P> PartialEq for JsonEncoded<T, P> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<T: Eq, P> Eq for JsonEncoded<T, P> {}

impl<T, P> JsonEncoded<T, P>
where
    T: serde::de::DeserializeOwned,
    P: JsonRedaction,
{
    /// The value whose JSON `json` holds, or the error `invalid` makes of serde_json's, logged
    /// first as a `WARN` event with the outline of `json` under `P`. `payload_type` is the one of
    /// a signed value.
    pub(crate) fn from_json(
        json: &[u8],
        payload_type: Option<SignedPayloadType>,
        invalid: fn(&serde_json::Error) -> KmsAeadError,
    ) -> KmsAeadResult<Self> {
        serde_json::from_slice::<T>(json)
            .map(Self::from)
            .map_err(|json_error| {
                let error = invalid(&json_error);
                spans::json_not_decoded::<T>(
                    &error,
                    payload_type,
                    &json_error,
                    &RedactedJson::new::<P>(json),
                );
                error
            })
    }
}

impl<T, P> Plaintext for JsonEncoded<T, P>
where
    T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync,
    P: JsonRedaction,
{
    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when `T`'s `Serialize` fails, with serde_json's category of the error
    /// and none of its message or position.
    fn to_plaintext(&self) -> KmsAeadResult<SecretValue> {
        serde_json::to_vec(&self.0)
            .map(SecretValue::new)
            .map_err(|error| KmsAeadEncryptionError::invalid_json::<T>(&error))
    }

    /// # Errors
    ///
    /// `INVALID_PLAINTEXT` when the bytes are not the JSON of a `T`, with serde_json's category of
    /// the error and none of its message, which quotes the input, or its position. The error is
    /// logged first as a `WARN` event on the `kms_aead::json` target with the outline of the bytes
    /// under `P`.
    fn from_plaintext(plaintext: SecretValue) -> KmsAeadResult<Self> {
        Self::from_json(
            plaintext.as_sensitive_bytes(),
            None,
            KmsAeadEncryptionError::invalid_json::<T>,
        )
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;
    use tracing::Level;

    use super::*;
    use crate::redaction::FieldPaths;
    use crate::test_events::EventCapture;
    use crate::{Signable, SignableType};

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

    #[test]
    fn json_round_trips_as_compact_json() -> KmsAeadResult<()> {
        let value = JsonEncoded::new(vec![("plan".to_string(), 3u32)]);

        let plaintext = value.to_plaintext()?;

        assert_eq!(plaintext.as_sensitive_str(), r#"[["plan",3]]"#);
        assert_eq!(JsonEncoded::from_plaintext(plaintext)?, value);
        Ok(())
    }

    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct Order {
        id: u64,
        customer: String,
    }

    impl SignableType for Order {
        const PAYLOAD_TYPE: SignedPayloadType =
            SignedPayloadType::from_static("application/vnd.example.order+json");
    }

    struct OrderLog;

    impl JsonRedaction for OrderLog {
        const SIZES: bool = true;
        const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["id"]);
    }

    #[test]
    fn a_plaintext_that_does_not_decode_logs_one_event_and_fails_without_its_value() {
        const CARD: &str = "card-4111-1111";
        let events = EventCapture::install();

        let result =
            JsonEncoded::<Vec<u32>>::from_plaintext(SecretValue::from(format!(r#"["{CARD}"]"#)));

        let error = result.map(drop).expect_err("a string is no u32");
        assert_eq!(error.code(), "INVALID_PLAINTEXT");
        let message = format!("{error:?}");
        for hidden in [CARD, "line", "column"] {
            assert!(!message.contains(hidden), "{message}");
        }
        let events = events.events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(events[0].level, Level::WARN);
        assert_eq!(events[0].target, "kms_aead::json");
        assert_eq!(
            events[0].fields["/kms_aead/error_code"],
            "INVALID_PLAINTEXT"
        );
        assert_eq!(events[0].fields["/kms_aead/json_error"], "Data error");
        assert!(!format!("{events:?}").contains(CARD), "{events:?}");
    }

    #[test]
    fn a_payload_that_does_not_decode_logs_its_outline_and_position_under_its_policy() {
        let events = EventCapture::install();
        let payload = br#"{"id":"not-a-number","customer":"Northwind Traders"}"#;

        let result = <JsonEncoded<Order, OrderLog> as Signable>::from_payload(payload.to_vec());

        let error = result.map(drop).expect_err("the id is not a number");
        assert_eq!(error.code(), "INVALID_PAYLOAD");
        let message = error.to_string();
        for hidden in ["Northwind", "line", "column"] {
            assert!(!message.contains(hidden), "{message}");
        }
        let events = events.events();
        assert_eq!(events.len(), 1, "{events:?}");
        assert_eq!(
            events[0].fields["/kms_aead/payload_type"],
            "application/vnd.example.order+json"
        );
        assert_eq!(
            events[0].fields["/kms_aead/json_error"],
            "Data error at line 1 column 20"
        );
        assert_eq!(
            events[0].fields["/kms_aead/outline"],
            r#"52 bytes: {"id": "not-a-number", <key, 8 chars>: <string, 17 chars>}"#
        );
    }
}
