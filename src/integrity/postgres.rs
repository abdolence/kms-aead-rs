use std::error::Error;

use bytes::BytesMut;
use postgres_types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

use super::{Mac, Signature, Signed, WithMac};

/// As `BYTEA`.
impl<T> ToSql for Signature<T> {
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
impl<'a, T> FromSql<'a> for Signature<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Signature::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

/// As `BYTEA`.
impl<T> ToSql for Signed<T> {
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
impl<'a, T> FromSql<'a> for Signed<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Signed::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

/// As `BYTEA`.
impl<T> ToSql for Mac<T> {
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
impl<'a, T> FromSql<'a> for Mac<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(Mac::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

/// As `BYTEA`.
impl<T> ToSql for WithMac<T> {
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
impl<'a, T> FromSql<'a> for WithMac<T> {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(WithMac::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}
