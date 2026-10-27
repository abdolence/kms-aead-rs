use sqlx_core::decode::Decode;
use sqlx_core::encode::{Encode, IsNull};
use sqlx_core::error::BoxDynError;
use sqlx_core::types::Type;
use sqlx_postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres};

use super::{Mac, Signature, Signed, WithMac};

/// `BYTEA`.
impl<T> Type<Postgres> for Signature<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// The value's bytes.
impl<T> Encode<'_, Postgres> for Signature<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<T> Decode<'_, Postgres> for Signature<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Signature::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}

/// `BYTEA`.
impl<T> Type<Postgres> for Signed<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// The value's bytes.
impl<T> Encode<'_, Postgres> for Signed<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<T> Decode<'_, Postgres> for Signed<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Signed::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}

/// `BYTEA`.
impl<T> Type<Postgres> for Mac<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// The value's bytes.
impl<T> Encode<'_, Postgres> for Mac<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<T> Decode<'_, Postgres> for Mac<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Mac::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}

/// `BYTEA`.
impl<T> Type<Postgres> for WithMac<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// The value's bytes.
impl<T> Encode<'_, Postgres> for WithMac<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<T> Decode<'_, Postgres> for WithMac<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(WithMac::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}
