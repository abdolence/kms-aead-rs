use std::fmt::{Display, Formatter};
use std::sync::Arc;

use gcloud_sdk::google::storage::v2::storage_client::StorageClient;
use gcloud_sdk::google::storage::v2::{
    write_object_request, write_object_response, ChecksummedData, DeleteObjectRequest,
    ListObjectsRequest, Object, ReadObjectRequest, WriteObjectRequest, WriteObjectSpec,
};
use gcloud_sdk::tonic::metadata::{Ascii, MetadataValue};
use gcloud_sdk::tonic::{self, Code};
use gcloud_sdk::{GoogleApi, GoogleAuthMiddleware};

use super::{
    Deletion, KeyringStore, KeyringWatch, ObjectPrefix, Revalidation, StoreKind, StoreOperation,
    Stored, Swap,
};
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

/// The generations of one object a bucket holds, as a listing with versions returns them.
struct ObjectGenerations {
    /// The live generation, the one without a `delete_time`.
    live: Option<GcsGeneration>,
    /// The generations that became noncurrent, which a bucket with versioning keeps.
    noncurrent: Vec<GcsGeneration>,
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
/// The application's principal needs `storage.objects.get` on the bucket, and the administrative
/// one `storage.objects.create` and `storage.objects.delete` as well, since a write replaces the
/// object, and `storage.objects.list` for [`delete`](KeyringStore::delete), which lists the
/// generations of the object. With object versioning on the bucket, every record written is kept
/// as a noncurrent version.
#[derive(Clone)]
pub struct GcsKeyringStore {
    client: GoogleApi<StorageClient<GoogleAuthMiddleware>>,
    // `projects/_/buckets/<name>`, the bucket as `google.storage.v2` names it.
    bucket: String,
    // `bucket=<bucket>`, the `x-goog-request-params` routing header every request carries.
    routing: MetadataValue<Ascii>,
    prefix: ObjectPrefix,
}

impl GcsKeyringStore {
    /// The prefix of [`new`](Self::new): the object of a keyring is
    /// `kms-keyrings/<keyring id>.json`.
    pub const DEFAULT_PREFIX: ObjectPrefix = ObjectPrefix::from_static("kms-keyrings/");

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
            prefix: Self::DEFAULT_PREFIX,
        })
    }

    /// The store with its records under `prefix` instead: the object of a keyring is
    /// `<prefix><keyring id>.json`.
    pub fn with_prefix(self, prefix: ObjectPrefix) -> Self {
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

    /// Every generation of the object `name`, live and noncurrent, paginated.
    async fn generations(&self, name: &str) -> KeyringResult<ObjectGenerations> {
        let mut found = ObjectGenerations {
            live: None,
            noncurrent: Vec::new(),
        };
        let mut page_token = String::new();
        loop {
            let request = self.request(ListObjectsRequest {
                parent: self.bucket.clone(),
                prefix: name.to_string(),
                versions: true,
                page_token,
                ..Default::default()
            });
            let page = self
                .client
                .get()
                .list_objects(request)
                .await
                .map_err(|status| {
                    KeyringError::store_caused_by(
                        StoreKind::Gcs,
                        StoreOperation::Delete,
                        Arc::new(status),
                    )
                })?
                .into_inner();
            // An id may contain `.`, so `<id>.json` is also the prefix of another id's object.
            for object in page
                .objects
                .into_iter()
                .filter(|object| object.name == name)
            {
                let generation = GcsGeneration(object.generation);
                if object.delete_time.is_none() {
                    found.live = Some(generation);
                } else {
                    found.noncurrent.push(generation);
                }
            }
            if page.next_page_token.is_empty() {
                return Ok(found);
            }
            page_token = page.next_page_token;
        }
    }

    /// Deletes one `generation` of the object `name` permanently, also when it is gone already.
    async fn delete_generation(&self, name: &str, generation: GcsGeneration) -> KeyringResult<()> {
        let request = self.request(DeleteObjectRequest {
            bucket: self.bucket.clone(),
            object: name.to_string(),
            generation: generation.0,
            ..Default::default()
        });
        match self.client.get().delete_object(request).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::NotFound => Ok(()),
            Err(status) => Err(KeyringError::store_caused_by(
                StoreKind::Gcs,
                StoreOperation::Delete,
                Arc::new(status),
            )),
        }
    }

    /// Deletes the live object `name` when its generation is `expected`. A bucket with versioning
    /// keeps the generation as a noncurrent one.
    async fn delete_live(&self, name: &str, expected: GcsGeneration) -> KeyringResult<Deletion> {
        let request = self.request(DeleteObjectRequest {
            bucket: self.bucket.clone(),
            object: name.to_string(),
            if_generation_match: Some(expected.0),
            ..Default::default()
        });
        match self.client.get().delete_object(request).await {
            Ok(_) => Ok(Deletion::Deleted),
            Err(status) if status.code() == Code::NotFound => Ok(Deletion::Deleted),
            Err(status) if status.code() == Code::FailedPrecondition => Ok(Deletion::Conflict),
            Err(status) => Err(KeyringError::store_caused_by(
                StoreKind::Gcs,
                StoreOperation::Delete,
                Arc::new(status),
            )),
        }
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

    /// Deletes the object of `id` when its live generation is `expected`, with every noncurrent
    /// generation the bucket keeps. It lists the generations of the object first and returns
    /// [`Deletion::Conflict`] when the live one is another, before deleting anything. Then it
    /// deletes the noncurrent generations permanently, the live object under the precondition of
    /// its generation, and the generation `expected` that a bucket with versioning kept as
    /// noncurrent. A failure part-way leaves the live object, and the repeated call starts again.
    ///
    /// A bucket with soft delete keeps every generation this call deletes restorable for its
    /// retention, 7 days by default, outside this API, and a backup of the bucket keeps what it
    /// copied: both are the operator's.
    async fn delete(&self, id: &KeyringId, expected: &GcsGeneration) -> KeyringResult<Deletion> {
        let name = self.object_name(id);
        let found = self.generations(&name).await?;
        if found.live.is_some_and(|live| live != *expected) {
            return Ok(Deletion::Conflict);
        }
        // The noncurrent generations hold the encrypted DEKs a shred destroys, and a keyring
        // whose live object is gone reads as shredded, so that no shred deletes again: they go
        // before the live object, which a shred wrote without any DEK. Generation numbers are
        // unique but need not increase, so the listing, not the number, says which is live.
        for generation in found.noncurrent {
            self.delete_generation(&name, generation).await?;
        }
        if found.live.is_some() && self.delete_live(&name, *expected).await? == Deletion::Conflict {
            return Ok(Deletion::Conflict);
        }
        self.delete_generation(&name, *expected).await?;
        Ok(Deletion::Deleted)
    }

    async fn watch(&self, _id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        Ok(None)
    }
}
