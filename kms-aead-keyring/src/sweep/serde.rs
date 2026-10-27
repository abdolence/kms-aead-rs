use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_bytes::ByteBuf;

use super::EncryptionMarker;

/// As bytes, through `serialize_bytes`: a `bytes` value in Firestore, and an array of numbers in
/// serde_json.
impl Serialize for EncryptionMarker {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(self.value())
    }
}

/// From bytes, or from a sequence of byte numbers as serde_json writes them, checked as
/// `TryFrom<Vec<u8>>` checks them.
impl<'de> Deserialize<'de> for EncryptionMarker {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes = ByteBuf::deserialize(deserializer)?;
        EncryptionMarker::try_from(bytes.into_vec()).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;
    use crate::test_support::TestResult;

    /// A record stored before it had a marker reads as envelope values.
    #[derive(Deserialize)]
    struct UserRow {
        #[serde(default)]
        encryption_marker: EncryptionMarker,
    }

    #[test]
    fn a_marker_round_trips_through_serde_json_as_a_byte_array() -> TestResult {
        let marker = EncryptionMarker::of_epoch(258);

        let json = serde_json::to_string(&marker)?;

        assert_eq!(json, "[1,0,0,1,2]");
        assert_eq!(serde_json::from_str::<EncryptionMarker>(&json)?, marker);
        assert!(serde_json::from_str::<EncryptionMarker>("[2,0,0,1,2]").is_err());
        assert_eq!(
            serde_json::from_str::<UserRow>("{}")?.encryption_marker,
            EncryptionMarker::ENVELOPE
        );
        Ok(())
    }

    /// A marker in Firestore through firestore-rs, on the emulator `FIRESTORE_EMULATOR_HOST`
    /// names, or on Firestore with application default credentials when it is unset, in the
    /// project `PROJECT_ID`. Each run writes to a collection of its own and deletes its documents.
    #[cfg(feature = "firestore")]
    mod on_firestore {
        use firestore::gcloud_sdk::google::firestore::v1::value::ValueType;
        use firestore::FirestoreDb;
        use serde::Serialize;

        use super::*;
        use crate::sweep::ReencryptRange;

        /// The epochs the documents are written with, out of order.
        const EPOCHS: [u32; 7] = [65_536, 3, 0, u32::MAX, 255, 256, 1];

        #[derive(Serialize, Deserialize)]
        struct UserDoc {
            #[serde(rename = "_firestore_id", skip_serializing)]
            id: String,
            #[serde(default)]
            encryption_marker: EncryptionMarker,
        }

        /// A document written before its collection had markers.
        #[derive(Serialize, Deserialize)]
        struct UnmarkedDoc {
            name: String,
        }

        const UNMARKED: &str = "unmarked";

        fn document_id(epoch: u32) -> String {
            format!("epoch-{epoch}")
        }

        async fn check(db: &FirestoreDb, collection: &str) -> TestResult {
            for epoch in EPOCHS {
                let doc = UserDoc {
                    id: document_id(epoch),
                    encryption_marker: EncryptionMarker::of_epoch(epoch),
                };
                let _: UserDoc = db
                    .fluent()
                    .insert()
                    .into(collection)
                    .document_id(&doc.id)
                    .object(&doc)
                    .execute()
                    .await?;
            }
            let _: UnmarkedDoc = db
                .fluent()
                .insert()
                .into(collection)
                .document_id(UNMARKED)
                .object(&UnmarkedDoc {
                    name: "ada".to_string(),
                })
                .execute()
                .await?;

            let stored = db
                .fluent()
                .select()
                .by_id_in(collection)
                .one(document_id(256))
                .await?
                .ok_or("the document of epoch 256 is missing")?;
            assert_eq!(
                stored
                    .fields
                    .get("encryption_marker")
                    .and_then(|encryption_marker| encryption_marker.value_type.clone()),
                Some(ValueType::BytesValue(vec![0x01, 0, 0, 1, 0]))
            );

            let unmarked: Option<UserDoc> = db
                .fluent()
                .select()
                .by_id_in(collection)
                .obj()
                .one(UNMARKED)
                .await?;
            assert_eq!(
                unmarked.map(|doc| doc.encryption_marker),
                Some(EncryptionMarker::ENVELOPE)
            );

            let behind: Vec<UserDoc> = db
                .fluent()
                .select()
                .from(collection)
                .filter(|q| {
                    q.field("encryption_marker")
                        .less_than(EncryptionMarker::of_epoch(256))
                })
                .order(|order| order.fields([order.field("encryption_marker").asc()]))
                .obj()
                .query()
                .await?;
            assert_eq!(
                behind
                    .iter()
                    .map(|doc| doc.id.as_str())
                    .collect::<Vec<&str>>(),
                ["epoch-0", "epoch-1", "epoch-3", "epoch-255"]
            );

            // The range query of a version: Firestore takes two inequality filters on one field.
            for (range, expected) in [
                (
                    ReencryptRange::new(
                        EncryptionMarker::of_epoch(3),
                        Some(EncryptionMarker::of_epoch(256)),
                    ),
                    vec!["epoch-3", "epoch-255"],
                ),
                (
                    ReencryptRange::new(EncryptionMarker::of_epoch(256), None),
                    vec!["epoch-256", "epoch-65536", "epoch-4294967295"],
                ),
            ] {
                let within: Vec<UserDoc> = db
                    .fluent()
                    .select()
                    .from(collection)
                    .filter(|q| {
                        q.for_all([
                            q.field("encryption_marker")
                                .greater_than_or_equal(range.start()),
                            range
                                .end()
                                .and_then(|end| q.field("encryption_marker").less_than(end)),
                        ])
                    })
                    .order(|order| order.fields([order.field("encryption_marker").asc()]))
                    .obj()
                    .query()
                    .await?;
                assert_eq!(
                    within
                        .iter()
                        .map(|doc| doc.id.as_str())
                        .collect::<Vec<&str>>(),
                    expected
                );
            }
            Ok(())
        }

        #[tokio::test]
        #[ignore = "needs a Firestore emulator or project, see the module docs"]
        async fn firestore_stores_bytes_that_order_as_the_epochs() -> TestResult {
            let db = FirestoreDb::new(std::env::var("PROJECT_ID")?).await?;
            let collection = format!(
                "kms_aead_rs_ci_seal_markers_{}",
                uuid::Uuid::now_v7().simple()
            );
            let outcome = check(&db, &collection).await;
            for id in EPOCHS
                .into_iter()
                .map(document_id)
                .chain([UNMARKED.to_string()])
            {
                db.fluent()
                    .delete()
                    .from(collection.as_str())
                    .document_id(&id)
                    .execute()
                    .await?;
            }
            outcome
        }
    }
}
