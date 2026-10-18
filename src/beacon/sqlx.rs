use sqlx_core::decode::Decode;
use sqlx_core::encode::{Encode, IsNull};
use sqlx_core::error::BoxDynError;
use sqlx_core::types::Type;
use sqlx_postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef, Postgres};

use super::Beacon;

/// `BYTEA`.
impl<T> Type<Postgres> for Beacon<T> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// `BYTEA[]`, which an `= ANY($1)` of probes takes.
impl<T> PgHasArrayType for Beacon<T> {
    fn array_type_info() -> PgTypeInfo {
        <Vec<u8> as PgHasArrayType>::array_type_info()
    }
}

/// The beacon's bytes.
impl<T> Encode<'_, Postgres> for Beacon<T> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<T> Decode<'_, Postgres> for Beacon<T> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Beacon::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}
