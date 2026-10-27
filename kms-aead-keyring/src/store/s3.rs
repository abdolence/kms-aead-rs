use std::fmt::{Display, Formatter};
use std::sync::Arc;

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;

use super::{
    Deletion, KeyringStore, KeyringWatch, ObjectPrefix, Revalidation, StoreKind, StoreOperation,
    Stored, Swap,
};
use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult};
use crate::record::stored::MAX_RECORD_DOCUMENT_LEN;
use crate::{KeyringId, KeyringRecord};

/// The name of an S3 bucket, such as `my-keyrings`: lowercase ASCII letters, digits, `-`, `_`
/// and `.`. The other bucket rules are the service's to check.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct S3BucketName(String);

impl TryFrom<String> for S3BucketName {
    type Error = KeyringError;

    /// # Errors
    ///
    /// [`KeyringError::InvalidIdentifier`] naming the rule `name` breaks.
    fn try_from(name: String) -> KeyringResult<Self> {
        let invalid = |rule| KeyringError::invalid_identifier(Identifier::S3BucketName, rule);
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

impl Display for S3BucketName {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The revision of a record in an [`S3KeyringStore`]: the ETag of its object, as the service
/// returned it, quotes included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3ETag(String);

impl Display for S3ETag {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The entries of one key in a version listing.
struct ObjectVersions {
    /// The latest entry when it is a stored version rather than a delete marker.
    live: Option<LiveVersion>,
    /// The version ids of every other entry, stored versions and delete markers.
    others: Vec<String>,
}

struct LiveVersion {
    version_id: String,
    etag: S3ETag,
}

/// A keyring store in an Amazon S3 bucket, or in a bucket of an S3-compatible server with
/// conditional writes, such as MinIO. Each record is the object `<prefix><keyring id>.json`,
/// and its revision is the object's ETag: a create is conditional on no object existing, an
/// update on the ETag the writer read, and a revalidation reads the object only when its ETag
/// is another.
///
/// S3 has no change notification this store listens to, so [`watch`](KeyringStore::watch)
/// returns `None` and a process sees a change once its record is older than the keyring's
/// `record_ttl`.
///
/// The application's principal needs `s3:GetObject` on the objects, and the administrative one
/// `s3:PutObject` as well, and for [`delete`](KeyringStore::delete) `s3:ListBucketVersions` on
/// the bucket, and `s3:DeleteObject` and `s3:DeleteObjectVersion` on the objects. With versioning
/// on the bucket, every record written is kept as a noncurrent version.
///
/// The compare-and-swap holds only on a server that refuses a write with `If-Match` when no
/// object exists, as S3 does. A server that writes it instead recreates a deleted record on an
/// update. The condition of a [delete](KeyringStore::delete) holds only on a server that honours
/// `If-Match` on `DeleteObject`, as S3 does for general purpose buckets: another deletes the
/// object whatever its ETag, after the listing that found it unchanged.
#[derive(Clone)]
pub struct S3KeyringStore {
    client: aws_sdk_s3::Client,
    bucket: S3BucketName,
    prefix: ObjectPrefix,
}

impl S3KeyringStore {
    /// The prefix of [`new`](Self::new): the object of a keyring is
    /// `kms-keyrings/<keyring id>.json`.
    pub const DEFAULT_PREFIX: ObjectPrefix = ObjectPrefix::from_static("kms-keyrings/");

    /// A store of the records in `bucket` under [`DEFAULT_PREFIX`](Self::DEFAULT_PREFIX), that
    /// sends its requests with `client`.
    ///
    /// `client` is the integration point with aws-sdk-s3: the application builds it with the
    /// credentials, region, endpoint and HTTP client it chooses, and the store uses it as given.
    /// A server that serves buckets only by path, as MinIO does by default, needs
    /// `force_path_style(true)` on the client's config. With the credentials and region of the
    /// environment:
    ///
    /// ```rust,no_run
    /// # async fn store() -> Result<(), Box<dyn std::error::Error>> {
    /// use kms_aead_keyring::store::{S3BucketName, S3KeyringStore};
    ///
    /// let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    /// let store = S3KeyringStore::new(
    ///     aws_sdk_s3::Client::new(&config),
    ///     S3BucketName::try_from("my-keyrings".to_string())?,
    /// );
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(client: aws_sdk_s3::Client, bucket: S3BucketName) -> Self {
        Self {
            client,
            bucket,
            prefix: Self::DEFAULT_PREFIX,
        }
    }

    /// The store with its records under `prefix` instead: the object of a keyring is
    /// `<prefix><keyring id>.json`.
    pub fn with_prefix(self, prefix: ObjectPrefix) -> Self {
        Self { prefix, ..self }
    }

    fn object_key(&self, id: &KeyringId) -> String {
        format!("{}{id}.json", self.prefix)
    }

    /// Every stored version and delete marker of the object `key`, paginated.
    async fn versions(&self, key: &str) -> KeyringResult<ObjectVersions> {
        let mut found = ObjectVersions {
            live: None,
            others: Vec::new(),
        };
        let mut key_marker = None;
        let mut version_id_marker = None;
        loop {
            let page = self
                .client
                .list_object_versions()
                .bucket(self.bucket.to_string())
                .prefix(key)
                .set_key_marker(key_marker)
                .set_version_id_marker(version_id_marker)
                .send()
                .await
                .map_err(|error| {
                    KeyringError::store_caused_by(
                        StoreKind::S3,
                        StoreOperation::Delete,
                        Arc::new(error),
                    )
                })?;
            // An id may contain `.`, so `<id>.json` is also the prefix of another id's object.
            for version in page
                .versions()
                .iter()
                .filter(|version| version.key() == Some(key))
            {
                let version_id = version
                    .version_id()
                    .ok_or_else(|| {
                        KeyringError::store(
                            StoreKind::S3,
                            StoreOperation::Delete,
                            "The version listing returned an entry without a version id",
                        )
                    })?
                    .to_string();
                if version.is_latest() == Some(true) {
                    let etag = version.e_tag().ok_or_else(|| {
                        KeyringError::store(
                            StoreKind::S3,
                            StoreOperation::Delete,
                            "The version listing returned the latest version without an ETag",
                        )
                    })?;
                    found.live = Some(LiveVersion {
                        version_id,
                        etag: S3ETag(etag.to_string()),
                    });
                } else {
                    found.others.push(version_id);
                }
            }
            for marker in page
                .delete_markers()
                .iter()
                .filter(|marker| marker.key() == Some(key))
            {
                found.others.push(
                    marker
                        .version_id()
                        .ok_or_else(|| {
                            KeyringError::store(
                                StoreKind::S3,
                                StoreOperation::Delete,
                                "The version listing returned an entry without a version id",
                            )
                        })?
                        .to_string(),
                );
            }
            if page.is_truncated() != Some(true) {
                return Ok(found);
            }
            key_marker = page.next_key_marker().map(str::to_string);
            version_id_marker = page.next_version_id_marker().map(str::to_string);
        }
    }

    /// Deletes one version or delete marker of the object `key` permanently, also when it is gone
    /// already.
    async fn delete_version(&self, key: &str, version_id: &str) -> KeyringResult<()> {
        match self
            .client
            .delete_object()
            .bucket(self.bucket.to_string())
            .key(key)
            .version_id(version_id)
            .send()
            .await
        {
            Ok(_) => Ok(()),
            Err(error) if matches!(error.code(), Some("NoSuchKey" | "NoSuchVersion")) => Ok(()),
            Err(error) => Err(KeyringError::store_caused_by(
                StoreKind::S3,
                StoreOperation::Delete,
                Arc::new(error),
            )),
        }
    }

    /// The live record of `id` as [`Revalidation::Changed`], or [`Revalidation::Missing`] when
    /// there is none. With `if_none_match`, [`Revalidation::Unchanged`] when the live ETag is
    /// that one: the service then answers `304 Not Modified` with no body.
    async fn read(
        &self,
        id: &KeyringId,
        if_none_match: Option<&S3ETag>,
        operation: StoreOperation,
    ) -> KeyringResult<Revalidation<S3ETag>> {
        let response = match self
            .client
            .get_object()
            .bucket(self.bucket.to_string())
            .key(self.object_key(id))
            .set_if_none_match(if_none_match.map(|etag| etag.0.clone()))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(GetObjectError::is_no_such_key) =>
            {
                return Ok(Revalidation::Missing)
            }
            Err(error)
                if error
                    .raw_response()
                    .is_some_and(|response| response.status().as_u16() == 304) =>
            {
                return Ok(Revalidation::Unchanged)
            }
            Err(error) => {
                return Err(KeyringError::store_caused_by(
                    StoreKind::S3,
                    operation,
                    Arc::new(error),
                ))
            }
        };
        let revision = S3ETag(response.e_tag.ok_or_else(|| {
            KeyringError::store(StoreKind::S3, operation, "The read returned no ETag")
        })?);
        // Reads until past the record cap, so that an object over the cap still reads as over
        // it, and a read never buffers more than the cap and one chunk.
        let mut body = response.body;
        let mut document = Vec::new();
        while document.len() <= MAX_RECORD_DOCUMENT_LEN {
            match body.try_next().await {
                Ok(Some(chunk)) => document.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => {
                    return Err(KeyringError::store_caused_by(
                        StoreKind::S3,
                        operation,
                        Arc::new(error),
                    ))
                }
            }
        }
        Ok(Revalidation::Changed(Stored {
            record: KeyringRecord::from_json(id, &document)?,
            revision,
        }))
    }
}

impl KeyringStore for S3KeyringStore {
    type Revision = S3ETag;

    const KIND: StoreKind = StoreKind::S3;

    async fn load(&self, id: &KeyringId) -> KeyringResult<Option<Stored<S3ETag>>> {
        match self.read(id, None, StoreOperation::Load).await? {
            Revalidation::Changed(stored) => Ok(Some(stored)),
            Revalidation::Missing => Ok(None),
            Revalidation::Unchanged => Err(KeyringError::store(
                StoreKind::S3,
                StoreOperation::Load,
                "A read without a precondition was not modified",
            )),
        }
    }

    async fn revalidate(
        &self,
        id: &KeyringId,
        known: &S3ETag,
    ) -> KeyringResult<Revalidation<S3ETag>> {
        self.read(id, Some(known), StoreOperation::Revalidate).await
    }

    async fn compare_and_swap(
        &self,
        record: &KeyringRecord,
        expected: Option<&S3ETag>,
    ) -> KeyringResult<Swap<S3ETag>> {
        let request = self
            .client
            .put_object()
            .bucket(self.bucket.to_string())
            .key(self.object_key(record.id()))
            .content_type("application/json")
            .body(ByteStream::from(record.to_json()?));
        let request = match expected {
            Some(etag) => request.if_match(etag.0.clone()),
            None => request.if_none_match("*"),
        };
        let response = match request.send().await {
            Ok(response) => response,
            // `PreconditionFailed` when the precondition fails, `ConditionalRequestConflict`
            // when a concurrent conditional write to the object won, and `NoSuchKey` when
            // `If-Match` finds no object.
            Err(error)
                if matches!(
                    error.code(),
                    Some("PreconditionFailed" | "ConditionalRequestConflict" | "NoSuchKey")
                ) =>
            {
                return Ok(Swap::Conflict)
            }
            Err(error) => {
                return Err(KeyringError::store_caused_by(
                    StoreKind::S3,
                    StoreOperation::CompareAndSwap,
                    Arc::new(error),
                ))
            }
        };
        match response.e_tag {
            Some(etag) => Ok(Swap::Written(S3ETag(etag))),
            None => Err(KeyringError::store(
                StoreKind::S3,
                StoreOperation::CompareAndSwap,
                "The write returned no ETag",
            )),
        }
    }

    /// Deletes the object of `id` when its latest version has the ETag `expected`, with every
    /// earlier version and delete marker of the key. It lists the versions of the key first and
    /// returns [`Deletion::Conflict`] when the latest one has another ETag, before deleting
    /// anything. Then it deletes the earlier versions and markers permanently by version id, the
    /// object under `If-Match: expected`, and the version and then the delete marker that the
    /// delete left in a bucket with versioning. A failure part-way leaves the live object or only
    /// a delete marker, and the repeated call starts again.
    ///
    /// S3 keeps nothing of a version deleted by id. A replica in another bucket, a backup and a
    /// server that keeps its own history are the operator's to delete.
    async fn delete(&self, id: &KeyringId, expected: &S3ETag) -> KeyringResult<Deletion> {
        let key = self.object_key(id);
        let found = self.versions(&key).await?;
        if found
            .live
            .as_ref()
            .is_some_and(|live| live.etag != *expected)
        {
            return Ok(Deletion::Conflict);
        }
        // The earlier versions hold the encrypted DEKs a shred destroys, and a keyring whose live
        // object is gone reads as shredded, so that no shred deletes again: they go before the
        // live object, which a shred wrote without any DEK.
        for version_id in &found.others {
            self.delete_version(&key, version_id).await?;
        }
        let Some(live) = found.live else {
            return Ok(Deletion::Deleted);
        };
        let marker = match self
            .client
            .delete_object()
            .bucket(self.bucket.to_string())
            .key(&key)
            .if_match(expected.0.clone())
            .send()
            .await
        {
            // A bucket without versioning removed the object itself.
            Ok(response) if response.version_id().is_none() => return Ok(Deletion::Deleted),
            Ok(response) => response.version_id().map(str::to_string),
            Err(error) if error.code() == Some("PreconditionFailed") => {
                return Ok(Deletion::Conflict)
            }
            Err(error) if error.code() == Some("NoSuchKey") => None,
            Err(error) => {
                return Err(KeyringError::store_caused_by(
                    StoreKind::S3,
                    StoreOperation::Delete,
                    Arc::new(error),
                ))
            }
        };
        // A bucket with versioning answered the delete with a marker and kept the version. The
        // version goes first: a failure between the two then leaves a marker, which holds
        // nothing, where the other order would make the version the live record again.
        self.delete_version(&key, &live.version_id).await?;
        if let Some(marker) = marker {
            self.delete_version(&key, &marker).await?;
        }
        Ok(Deletion::Deleted)
    }

    async fn watch(&self, _id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        Ok(None)
    }
}
