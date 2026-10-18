use sqlx_core::decode::Decode;
use sqlx_core::encode::{Encode, IsNull};
use sqlx_core::error::BoxDynError;
use sqlx_core::types::Type;
use sqlx_postgres::{PgArgumentBuffer, PgTypeInfo, PgValueRef, Postgres};

use super::SealMarker;

/// `BYTEA`.
impl Type<Postgres> for SealMarker {
    fn type_info() -> PgTypeInfo {
        <Vec<u8> as Type<Postgres>>::type_info()
    }

    fn compatible(ty: &PgTypeInfo) -> bool {
        <Vec<u8> as Type<Postgres>>::compatible(ty)
    }
}

/// The marker's bytes.
impl Encode<'_, Postgres> for SealMarker {
    fn encode_by_ref(&self, buf: &mut PgArgumentBuffer) -> Result<IsNull, BoxDynError> {
        <&[u8] as Encode<Postgres>>::encode(self.value(), buf)
    }
}

/// Checked as `TryFrom<Vec<u8>>` checks the bytes.
impl Decode<'_, Postgres> for SealMarker {
    fn decode(value: PgValueRef<'_>) -> Result<Self, BoxDynError> {
        Ok(SealMarker::try_from(
            <Vec<u8> as Decode<Postgres>>::decode(value)?,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use sqlx::{Connection, PgConnection};

    use super::*;
    use crate::test_support::TestResult;
    use crate::KeyringError;

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn a_marker_round_trips_through_sqlx_as_bytea() -> TestResult {
        let mut connection =
            PgConnection::connect(&std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?).await?;
        sqlx::query("CREATE TEMPORARY TABLE users (id TEXT PRIMARY KEY, seal BYTEA NOT NULL)")
            .execute(&mut connection)
            .await?;
        for epoch in [65_536_u32, 3, 0, u32::MAX, 255, 256, 1] {
            sqlx::query("INSERT INTO users (id, seal) VALUES ($1, $2)")
                .bind(format!("epoch-{epoch}"))
                .bind(SealMarker::of_epoch(epoch))
                .execute(&mut connection)
                .await?;
        }

        let behind: Vec<SealMarker> = sqlx::query_scalar::<Postgres, SealMarker>(
            "SELECT seal FROM users WHERE seal < $1 ORDER BY seal",
        )
        .bind(SealMarker::of_epoch(256))
        .fetch_all(&mut connection)
        .await?;

        assert_eq!(behind, [0, 1, 3, 255].map(SealMarker::of_epoch));
        let malformed = sqlx::query_scalar::<Postgres, SealMarker>("SELECT '\\x02'::bytea")
            .fetch_one(&mut connection)
            .await;
        assert!(matches!(
            malformed,
            Err(sqlx::Error::ColumnDecode { source, .. })
                if matches!(source.downcast_ref::<KeyringError>(), Some(KeyringError::InvalidSealMarker))
        ));
        Ok(())
    }
}
