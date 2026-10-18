use std::fmt::{Display, Formatter};
use std::sync::Arc;

use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
use gcloud_sdk::google::storage::v2::{
    write_object_request, write_object_response, ChecksummedData, Object, ReadObjectRequest,
    WriteObjectRequest, WriteObjectSpec,
};
use gcloud_sdk::tonic::metadata::{Ascii, MetadataValue};
use gcloud_sdk::tonic::{self, Code};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};

use super::{KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap};
use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult};
use crate::record::stored::MAX_RECORD_DOCUMENT_LEN;
use crate::{KeyringId, KeyringRecord};

/// The most a read returns of an object: one byte past the record cap, so that an object over
/// the cap still reads as over it, and a read never buffers more than that. The cap is 1 MiB, so
/// the cast cannot overflow.
const MAX_OBJECT_READ_LEN: i64 = MAX_RECORD_DOCUMENT_LEN as i64 + 1;

/// The name of a Cloud Storage bucket, such as `my-keyrings`: lowercase ASCII letters, digits,
/// `-`, `_` and `.`, the characters Cloud Storage allows. The other bucket rules are the
/// service's to check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GcsBucketName(String);

impl TryFrom<String> for GcsBucketName {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `name` breaks.
    fn try_from(name: String) -> KeyringResult<Self> {
        let invalid = |rule| KeyringError::invalid_identifier(Identifier::GcsBucketName, rule);
        if name.is_empty() {
            return Err(invalid(IdentifierRule::Length));
        }
        if !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"-_.".contains(&byte)
        }) {
            return Err(invalid(IdentifierRule::Character));
        }
        Ok(Self(name))
    }
}

impl Display for GcsBucketName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The revision of a record in a [`GcsKeyringStore`]: the generation of its object, which
/// Cloud Storage changes on every write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcsGeneration(i64);

impl Display for GcsGeneration {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

/// A keyring store in a Cloud Storage bucket, through the `google.storage.v2` gRPC API. Each
/// record is the object `<prefix><keyring id>.json`, and its revision is the object's
/// generation: a write is conditional on the generation the writer read, and a revalidation
/// reads the object only when its generation is another.
///
/// Cloud Storage has no change notification this store listens to, so
/// [`watch`](KeyringStore::watch) returns `None` and a process sees a change once its record is
/// older than the keyring's `record_ttl`.
///
/// The serving principal needs `storage.objects.get` on the bucket, and the administrative one
/// `storage.objects.create` and `storage.objects.delete` as well, since a write replaces the
/// object. With object versioning on the bucket, every record written is kept as a noncurrent
/// version.
#[derive(Clone)]
pub struct GcsKeyringStore {
    client: GoogleApi<StorageClient<GoogleAuthMiddleware>>,
    // `projects/_/buckets/<name>`, the bucket as `google.storage.v2` names it.
    bucket: String,
    // `bucket=<bucket>`, the `x-goog-request-params` routing header every request carries.
    routing: MetadataValue<Ascii>,
    prefix: String,
}

impl GcsKeyringStore {
    /// The prefix of [`new`](Self::new): the object of a keyring is
    /// `kms-keyrings/<keyring id>.json`.
    pub const DEFAULT_PREFIX: &'static str = "kms-keyrings/";

    /// A store of the records in `bucket` under [`DEFAULT_PREFIX`](Self::DEFAULT_PREFIX), that
    /// sends its requests with `client`.
    ///
    /// `client` is the integration point with gcloud-sdk: the application builds it with the
    /// credentials, endpoint and TLS stack it chooses, and the store uses it as given. With the
    /// application default credentials:
    ///
    /// ```rust,no_run
    /// # async fn store() -> Result<(), Box<dyn std::error::Error>> {
    /// use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
    /// use gcloud_sdk::GoogleApi;
    /// use kms_aead_keyring::store::{GcsBucketName, GcsKeyringStore};
    ///
    /// let client =
    ///     GoogleApi::from_function(StorageClient::new, "https://storage.googleapis.com", None)
    ///         .await?;
    /// let store =
    ///     GcsKeyringStore::new(client, GcsBucketName::try_from("my-keyrings".to_string())?)?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] when `bucket` is no valid header value, which the
    /// characters [`GcsBucketName`] allows always are.
    pub fn new(
        client: GoogleApi<StorageClient<GoogleAuthMiddleware>>,
        bucket: GcsBucketName,
    ) -> KeyringResult<Self> {
        let bucket = format!("projects/_/buckets/{bucket}");
        let routing = MetadataValue::try_from(format!("bucket={bucket}")).map_err(|_| {
            KeyringError::invalid_identifier(Identifier::GcsBucketName, IdentifierRule::Character)
        })?;
        Ok(Self {
            client,
            bucket,
            routing,
            prefix: Self::DEFAULT_PREFIX.to_string(),
        })
    }

    /// The store with its records under `prefix` instead: the object of a keyring is
    /// `<prefix><keyring id>.json`. A prefix that should read as a folder ends with `/`.
    pub fn with_prefix(self, prefix: String) -> Self {
        Self { prefix, ..self }
    }

    fn object_name(&self, id: &KeyringId) -> String {
        format!("{}{id}.json", self.prefix)
    }

    fn request<T>(&self, message: T) -> tonic::Request<T> {
        let mut request = tonic::Request::new(message);
        request
            .metadata_mut()
            .insert("x-goog-request-params", self.routing.clone());
        request
    }

    /// The live record of `id` as [`Revalidation::Changed`], or [`Revalidation::Missing`] when
    /// there is none. With `if_generation_not_match`, [`Revalidation::Unchanged`] when the live
    /// generation is that one: the service then refuses the read with `FAILED_PRECONDITION`.
    async fn read(
        &self,
        id: &KeyringId,
        if_generation_not_match: Option<GcsGeneration>,
        operation: StoreOperation,
    ) -> KeyringResult<Revalidation<GcsGeneration>> {
        let request = self.request(ReadObjectRequest {
            bucket: self.bucket.clone(),
            object: self.object_name(id),
            if_generation_not_match: if_generation_not_match.map(|generation| generation.0),
            read_limit: MAX_OBJECT_READ_LEN,
            ..Default::default()
        });
        let refused = |status: tonic::Status| match status.code() {
            Code::NotFound => Ok(Revalidation::Missing),
            Code::FailedPrecondition => Ok(Revalidation::Unchanged),
            _ => Err(KeyringError::store_caused_by(
                StoreKind::Gcs,
                operation,
                Arc::new(status),
            )),
        };
        let mut stream = match self.client.get().read_object(request).await {
            Ok(response) => response.into_inner(),
            Err(status) => return refused(status),
        };
        let mut document = Vec::new();
        let mut generation = None;
        loop {
            match stream.message().await {
                Ok(Some(response)) => {
                    if let Some(object) = response.metadata {
                        generation = Some(GcsGeneration(object.generation));
                    }
                    if let Some(data) = response.checksummed_data {
                        document.extend_from_slice(&data.content);
                    }
                }
                Ok(None) => break,
                Err(status) => return refused(status),
            }
        }
        let revision = generation.ok_or_else(|| {
            KeyringError::store(
                StoreKind::Gcs,
                operation,
                "The read returned no object metadata",
            )
        })?;
        Ok(Revalidation::Changed(Stored {
            record: KeyringRecord::from_json(id, &document)?,
            revision,
        }))
    }
}

impl KeyringStore for GcsKeyringStore {
    type Revision = GcsGeneration;

    const KIND: StoreKind = StoreKind::Gcs;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<GcsGeneration>>> {
        match self.read(id, None, StoreOperation::Load).await? {
            Revalidation::Changed(stored) => Ok(Some(stored)),
            Revalidation::Missing => Ok(None),
            Revalidation::Unchanged => Err(KeyringError::store(
                StoreKind::Gcs,
                StoreOperation::Load,
                "A read without a precondition failed a precondition",
            )),
        }
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &GcsGeneration,
    ) -> KeyringResult<Revalidation<GcsGeneration>> {
        self.read(id, Some(*known), StoreOperation::Revalidate)
            .await
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&GcsGeneration>,
    ) -> KeyringResult<Swap<GcsGeneration>> {
        let document = record.to_json()?;
        let request = self.request(tokio_stream::once(WriteObjectRequest {
            write_offset: 0,
            finish_write: true,
            first_message: Some(write_object_request::FirstMessage::WriteObjectSpec(
                WriteObjectSpec {
                    resource: Some(Object {
                        bucket: self.bucket.clone(),
                        name: self.object_name(record.id()),
                        content_type: "application/json".to_string(),
                        ..Default::default()
                    }),
                    // Zero matches no live object, so a create never replaces a record.
                    if_generation_match: Some(expected.map_or(0, |generation| generation.0)),
                    ..Default::default()
                },
            )),
            data: Some(write_object_request::Data::ChecksummedData(
                ChecksummedData {
                    content: document,
                    crc32c: None,
                },
            )),
            ..Default::default()
        }));
        let response = match self.client.get().write_object(request).await {
            Ok(response) => response,
            Err(status) if status.code() == Code::FailedPrecondition => return Ok(Swap::Conflict),
            Err(status) => {
                return Err(KeyringError::store_caused_by(
                    StoreKind::Gcs,
                    StoreOperation::CompareAndSwap,
                    Arc::new(status),
                ))
            }
        };
        match response.into_inner().write_status {
            Some(write_object_response::WriteStatus::Resource(object)) => {
                Ok(Swap::Written(GcsGeneration(object.generation)))
            }
            _ => Err(KeyringError::store(
                StoreKind::Gcs,
                StoreOperation::CompareAndSwap,
                "The write returned no finalised object",
            )),
        }
    }

    async fn watch(&self, _id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        Ok(None)
    }
}
