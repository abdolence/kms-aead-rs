use std::error::Error;

use bytes::BytesMut;
use tokio_postgres::types::{to_sql_checked, FromSql, IsNull, ToSql, Type};

use super::EncryptionMarker;

/// As `BYTEA`.
impl ToSql for EncryptionMarker {
    fn to_sql(
        &self,
        ty: &Type,
        out: &mut BytesMut,
    ) -> Result<IsNull, Box<dyn Error + Sync + Send>> {
        self.value().to_sql(ty, out)
    }

    fn accepts(ty: &Type) -> bool {
        <&[u8] as ToSql>::accepts(ty)
    }

    to_sql_checked!();
}

/// From `BYTEA`, checked as `TryFrom<Vec<u8>>` checks the bytes.
impl<'a> FromSql<'a> for EncryptionMarker {
    fn from_sql(ty: &Type, raw: &'a [u8]) -> Result<Self, Box<dyn Error + Sync + Send>> {
        Ok(EncryptionMarker::try_from(Vec::<u8>::from_sql(ty, raw)?)?)
    }

    fn accepts(ty: &Type) -> bool {
        <Vec<u8> as FromSql>::accepts(ty)
    }
}

#[cfg(test)]
mod tests {
    use tokio_postgres::NoTls;

    use super::*;
    use crate::test_support::TestResult;
    use crate::KeyringError;

    #[test]
    fn bytea_holds_the_marker_bytes_and_is_read_through_the_marker_check(
    ) -> Result<(), Box<dyn Error + Sync + Send>> {
        let marker = EncryptionMarker::of_epoch(258);
        let mut written = BytesMut::new();

        marker.to_sql(&Type::BYTEA, &mut written)?;

        assert_eq!(written.as_ref(), [0x01, 0, 0, 1, 2]);
        assert_eq!(EncryptionMarker::from_sql(&Type::BYTEA, &written)?, marker);
        let malformed = EncryptionMarker::from_sql(&Type::BYTEA, &[0x02, 0, 0, 1, 2]);
        assert!(malformed.is_err_and(|error| matches!(
            error.downcast_ref::<KeyringError>(),
            Some(KeyringError::InvalidEncryptionMarker)
        )));
        Ok(())
    }

    #[tokio::test]
    #[ignore = "needs PostgreSQL at KMS_AEAD_KEYRING_POSTGRES_URL"]
    async fn postgres_orders_markers_as_their_epochs() -> TestResult {
        let (client, connection) =
            tokio_postgres::connect(&std::env::var("KMS_AEAD_KEYRING_POSTGRES_URL")?, NoTls)
                .await?;
        tokio::spawn(connection);
        client
            .batch_execute(
                "CREATE TEMPORARY TABLE users (id TEXT PRIMARY KEY, \
                 encryption_marker BYTEA NOT NULL DEFAULT '\\x0100000000')",
            )
            .await?;
        for epoch in [65_536_u32, 3, 0, u32::MAX, 255, 256, 1] {
            client
                .execute(
                    "INSERT INTO users (id, encryption_marker) VALUES ($1, $2)",
                    &[
                        &format!("epoch-{epoch}"),
                        &EncryptionMarker::of_epoch(epoch),
                    ],
                )
                .await?;
        }
        client
            .execute("INSERT INTO users (id) VALUES ('unmarked')", &[])
            .await?;

        let behind: Vec<String> = client
            .query(
                "SELECT id FROM users WHERE encryption_marker < $1 ORDER BY encryption_marker, id",
                &[&EncryptionMarker::of_epoch(256)],
            )
            .await?
            .iter()
            .map(|row| row.try_get(0))
            .collect::<Result<_, _>>()?;
        assert_eq!(
            behind,
            ["epoch-0", "unmarked", "epoch-1", "epoch-3", "epoch-255"]
        );
        let unmarked: EncryptionMarker = client
            .query_one(
                "SELECT encryption_marker FROM users WHERE id = 'unmarked'",
                &[],
            )
            .await?
            .try_get(0)?;
        assert_eq!(unmarked, EncryptionMarker::ENVELOPE);
        Ok(())
    }
}
