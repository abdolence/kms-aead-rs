use sqlx_core::decode::Decode;
use sqlx_core::encode::{Encode, IsNull};
use sqlx_core::error::BoxDynError;
use sqlx_core::types::Type;
use sqlx_postgres::{PgArgumentBuffer, PgHasArrayType, PgTypeInfo, PgValueRef, Postgres};

use super::Encrypted;
use crate::formats::Format;

/// `BYTEA`.
impl<T, F: Format> Type<Postgres> for Encrypted<T, F> {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// `BYTEA[]`, which an `= ANY($1)` takes.
impl<T, F: Format> PgHasArrayType for Encrypted<T, F> {
    fn array_type_info() -> PgTypeInfo {
        <Vec<u8> as PgHasArrayType>::array_type_info()
    }
}

/// The value's bytes.
impl<T, F: Format> Encode<'_, Postgres> for Encrypted<T, F> {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(&self.bytes, buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes: a malformed stored value fails here, before
/// any decryption.
impl<T, F: Format> Decode<'_, Postgres> for Encrypted<T, F> {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(Encrypted::try_from(<Vec<u8> as Decode<Postgres>>::decode(
            value,
        )?)?)
    }
}
