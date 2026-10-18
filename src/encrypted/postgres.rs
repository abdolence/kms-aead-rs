use std::error::Error;

use bytes::BytesMut;
use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

use super::Encrypted;
use crate::formats::Format;

/// As `BYTEA`, and as `BYTEA[]` through the slice and `Vec` impls of postgres-types, which an
/// `= ANY($1)` takes.
impl<T, F: Format> ToSql for Encrypted<T, F> {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.bytes.as_slice().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&[u8] as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

/// From `BYTEA`, checked as `TryFrom<Vec<u8>>` checks the bytes: a malformed stored value fails
/// here, before any decrypt.
impl<'a, T, F: Format> FromSql<'a> for Encrypted<T, F> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Encrypted::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::{Envelope, Randomized};
    use crate::ValueStruct;

    #[test]
    fn bytea_is_read_through_the_layout_check() -> Result<(), Box<dyn Error + Sync + Send>> {
        let randomized = [&[0x01, 0, 0, 0, 7][..], &[0xAB; 12 + 16]].concat();

        let value = Encrypted::<String, Randomized>::from_sql(&Type::BYTEA, &randomized)?;
        let malformed = Encrypted::<String, Envelope>::from_sql(&Type::BYTEA, &[0x02]);

        assert_eq!(*value.value(), randomized);
        assert!(malformed.is_err(), "{malformed:?}");
        Ok(())
    }
}
