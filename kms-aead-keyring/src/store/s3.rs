use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

use aws_sdk_s3::error::{DisplayErrorContext, ProvideErrorMetadata};
use aws_sdk_s3::operation::get_object::GetObjectError;
use aws_sdk_s3::primitives::ByteStream;

use super::{KeyringStore, KeyringWatch, Revalidation, StoreKind, StoreOperation, Stored, Swap};
use crate::errors::{Identifier, IdentifierRule, KeyringError, KeyringResult, KeyringStoreError};
use crate::record::stored::MAX_DOCUMENT_LEN;
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
/// The serving principal needs `s3:GetObject` on the objects, and the administrative one
/// `s3:PutObject` as well. With versioning on the bucket, every record written is kept as a
/// noncurrent version.
///
/// The compare-and-swap holds only on a server that refuses a write with `If-Match` when no
/// object exists, as S3 does. A server that writes it instead recreates a deleted record on an
/// update.
#[derive(Clone)]
pub struct S3KeyringStore {
    client: aws_sdk_s3::Client,
    bucket: S3BucketName,
    prefix: String,
}

impl S3KeyringStore {
    /// The prefix of [`new`](Self::new): the object of a keyring is
    /// `kms-keyrings/<keyring id>.json`.
    pub const DEFAULT_PREFIX: &'static str = "kms-keyrings/";

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
            prefix: Self::DEFAULT_PREFIX.to_string(),
        }
    }

    /// The store with its records under `prefix` instead: the object of a keyring is
    /// `<prefix><keyring id>.json`. A prefix that should read as a folder ends with `/`.
    pub fn with_prefix(self, prefix: String) -> Self {
        Self { prefix, ..self }
    }

    fn object_key(&self, id: &KeyringId) -> String {
        format!("{}{id}.json", self.prefix)
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
            Err(error) => return Err(store_error(operation, error)),
        };
        let revision = S3ETag(response.e_tag.ok_or_else(|| {
            KeyringError::Store(KeyringStoreError::new(
                StoreKind::S3,
                operation,
                "The read returned no ETag".to_string(),
            ))
        })?);
        // Reads until past the record cap, so that an object over the cap still reads as over
        // it, and a read never buffers more than the cap and one chunk.
        let mut body = response.body;
        let mut document = Vec::new();
        while document.len() <= MAX_DOCUMENT_LEN {
            match body.try_next().await {
                Ok(Some(chunk)) => document.extend_from_slice(&chunk),
                Ok(None) => break,
                Err(error) => return Err(store_error(operation, error)),
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
            Revalidation::Unchanged => Err(KeyringError::Store(KeyringStoreError::new(
                StoreKind::S3,
                StoreOperation::Load,
                "A read without a precondition was not modified".to_string(),
            ))),
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
            Err(error) => return Err(store_error(StoreOperation::CompareAndSwap, error)),
        };
        match response.e_tag {
            Some(etag) => Ok(Swap::Written(S3ETag(etag))),
            None => Err(KeyringError::Store(KeyringStoreError::new(
                StoreKind::S3,
                StoreOperation::CompareAndSwap,
                "The write returned no ETag".to_string(),
            ))),
        }
    }

    async fn watch(&self, _id: &KeyringId) -> KeyringResult<Option<KeyringWatch>> {
        Ok(None)
    }
}

/// The client's `error` as a store error. The message is the service's, which names the object
/// at most, never its content.
fn store_error(
    operation: StoreOperation,
    error: impl Error + Send + Sync + 'static,
) -> KeyringError {
    KeyringError::Store(
        KeyringStoreError::new(
            StoreKind::S3,
            operation,
            DisplayErrorContext(&error).to_string(),
        )
        .with_root_cause(Arc::new(error)),
    )
}
