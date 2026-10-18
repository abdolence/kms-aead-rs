use std::error::Error;

use bytes::BytesMut;
use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

use super::Beacon;

/// As `BYTEA`, and as `BYTEA[]` through the slice and `Vec` impls of postgres-types, which an
/// `= ANY($1)` of probes takes.
impl<T> ToSql for Beacon<T> {
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

/// From `BYTEA`, checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<'a, T> FromSql<'a> for Beacon<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Beacon::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::TinkKeyId;

    #[test]
    fn bytea_is_read_through_the_layout_check() -> Result<(), Box<dyn Error + Sync + Send>> {
        let stored = [0x01, 0, 0, 0, 7, 0xAB, 0xCD];

        let beacon = Beacon::<String>::from_sql(&Type::BYTEA, &stored)?;
        let malformed = Beacon::<String>::from_sql(&Type::BYTEA, &stored[..5]);

        assert_eq!(beacon.key_id(), TinkKeyId::new(7));
        assert!(malformed.is_err(), "{malformed:?}");
        Ok(())
    }
}
