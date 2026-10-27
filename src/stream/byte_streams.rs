//! The adapters of a streamed value on `futures::Stream`s of [`Bytes`]: [`EncryptingStream`] and
//! [`DecryptingStream`], for the bodies and downloads of web code. Each holds one chunk in memory
//! and the item of its source in progress, whatever the length of the value.

use std::error::Error;
use std::fmt::{Debug, Formatter};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use bytes::{Buf, Bytes};
use futures_core::Stream;
use secret_vault_value::SecretValue;

use super::adapters::inner_kms_aead_error;
use super::gatherer::{ChunkGatherer, DecryptedChunk};
use super::{StreamDecryptor, StreamEncryptor};
use crate::backends::AeadBackend;
use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::KmsAeadResult;

type BoxError = Box<dyn Error + Send + Sync>;

/// The error a stream yields for an error of its source: one of the value, which came through the
/// source as itself or inside an `io::Error`, stays that error, and any other is `STREAM_IO` with
/// the source's error as the root cause.
fn source_error(error: BoxError) -> KmsAeadError {
    let error = match error.downcast::<KmsAeadError>() {
        Ok(error) => return *error,
        Err(error) => error,
    };
    if let Some(inner) = error
        .downcast_ref::<io::Error>()
        .and_then(inner_kms_aead_error)
    {
        return inner.clone();
    }
    KmsAeadSystemError::stream_io(
        "Reading the source of the streamed value failed",
        Arc::from(error),
    )
}

/// A `Stream` of [`Bytes`] that encrypts the plaintext its source yields and yields the streamed
/// value: the header first, then one item per encrypted chunk, the final chunk when the source
/// ends.
///
/// Memory is one chunk, in the encryptor's buffer, zeroised when the stream is dropped, and the
/// item of the source in progress, which the source's `Bytes` owns. An item of any size is taken,
/// an empty one included. A chunk is encrypted as soon as it is full and yielded on the same
/// poll.
///
/// A value is complete when the stream has ended with `None` and yielded no error. An error ends
/// the stream: it is the last item, and the stream yields `None` after it. A caller that stops
/// reading at an error, or drops the stream before its end, has a value that no decryptor
/// decrypts whole.
///
/// # Errors
///
/// An item of the source that is an `Err` ends the stream with `STREAM_IO`, the source's error
/// the root cause. An error that is a [`KmsAeadError`], or an `io::Error` that carries one, is
/// yielded as itself, since a retry of the stream would only meet it again. The encryptor's own
/// errors, `STREAM_LENGTH` and `ENCRYPT`, are yielded as themselves.
///
/// `S` must be `Unpin`; `Box::pin` a stream that is not. `Send` when `S` is. `Debug` shows no key
/// and no plaintext.
///
/// ```rust
/// # #[cfg(feature = "ring")]
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// use bytes::Bytes;
/// use futures::{stream, TryStreamExt};
/// use kms_aead::backends::Ring;
/// use kms_aead::stream::EncryptingStream;
/// use kms_aead::{AeadAlgorithm, AeadCipher};
///
/// let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
/// let dek = cipher.generate_dek()?;
/// let encryptor = cipher.stream_encryptor_bare(b"uploads/7", &dek)?;
///
/// let body = stream::iter([Ok::<_, std::io::Error>(Bytes::from_static(b"the request body"))]);
/// let stored: Vec<Bytes> = EncryptingStream::new(encryptor, body).try_collect().await?;
/// // The header, then the final chunk.
/// assert_eq!(stored.len(), 2);
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "ring"))]
/// # fn main() {}
/// ```
pub struct EncryptingStream<B, S> {
    encryptor: StreamEncryptor<B>,
    source: S,
    /// The part of the source's last item that the encryptor has not taken.
    pending: Bytes,
    state: EncryptingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EncryptingState {
    /// The header is next.
    Header,
    /// Taking plaintext from the source.
    Chunks,
    /// The final chunk was yielded, or an error was.
    Ended,
}

impl<B: AeadBackend, S, E> EncryptingStream<B, S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    /// A stream that encrypts `plaintext` with `encryptor`, and yields `encryptor.header()` in
    /// front of the first chunk.
    pub fn new(encryptor: StreamEncryptor<B>, plaintext: S) -> Self {
        Self {
            encryptor,
            source: plaintext,
            pending: Bytes::new(),
            state: EncryptingState::Header,
        }
    }

    /// The encrypted chunk in the encryptor's buffer as an item, which frees the buffer.
    fn take_encrypted_chunk(&mut self) -> Bytes {
        let chunk = Bytes::copy_from_slice(self.encryptor.encrypted_chunk());
        self.encryptor.release_encrypted();
        chunk
    }

    fn end_with(&mut self, error: KmsAeadError) -> Poll<Option<KmsAeadResult<Bytes>>> {
        self.state = EncryptingState::Ended;
        Poll::Ready(Some(Err(error)))
    }
}

impl<B: AeadBackend, S, E> Stream for EncryptingStream<B, S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    type Item = KmsAeadResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        loop {
            match stream.state {
                EncryptingState::Header => {
                    stream.state = EncryptingState::Chunks;
                    return Poll::Ready(Some(Ok(Bytes::copy_from_slice(
                        stream.encryptor.header(),
                    ))));
                }
                EncryptingState::Ended => return Poll::Ready(None),
                EncryptingState::Chunks if stream.pending.is_empty() => {
                    match ready!(Pin::new(&mut stream.source).poll_next(cx)) {
                        Some(Ok(item)) => stream.pending = item,
                        Some(Err(error)) => return stream.end_with(source_error(error.into())),
                        None => {
                            if let Err(error) = stream.encryptor.encrypt_final() {
                                return stream.end_with(error);
                            }
                            stream.state = EncryptingState::Ended;
                            return Poll::Ready(Some(Ok(stream.take_encrypted_chunk())));
                        }
                    }
                }
                EncryptingState::Chunks => {
                    match stream.encryptor.take_plaintext(&stream.pending) {
                        Ok(taken) => stream.pending.advance(taken),
                        Err(error) => return stream.end_with(error),
                    }
                    if !stream.encryptor.encrypted_chunk().is_empty() {
                        return Poll::Ready(Some(Ok(stream.take_encrypted_chunk())));
                    }
                }
            }
        }
    }
}

/// No key and no plaintext.
impl<B, S> Debug for EncryptingStream<B, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingStream")
            .field("encryptor", &self.encryptor)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

/// Reads the header of a streamed value from the front of a `Stream` of [`Bytes`] and keeps the
/// rest of the item it ended in, for [`DecryptingStream`] to start from, so that no byte of the
/// value is lost or read twice whatever the sizes of the items. Not part of the API: it serves
/// `KmsAeadEnvelope::decrypting_stream` and kms-aead-keyring, and changes only in a minor release
/// of kms-aead, which kms-aead-keyring requires to match its own.
#[doc(hidden)]
pub struct __HeaderGatherer<S> {
    source: S,
    /// The part of the source's last item that the header did not take.
    pending: Bytes,
    header: Vec<u8>,
}

impl<S, E> __HeaderGatherer<S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    pub fn new(source: S) -> Self {
        Self {
            source,
            pending: Bytes::new(),
            header: Vec::new(),
        }
    }

    /// The first `len` bytes of the value, reading the source only as far as they need. `len` does
    /// not shrink between calls: a caller that learns the header's length from its first bytes
    /// reads those, then the whole header.
    ///
    /// # Errors
    ///
    /// `STREAM_LENGTH` when the source ends before `len` bytes, and `STREAM_IO` for an error of
    /// the source, as [`DecryptingStream`] yields them.
    pub async fn read(&mut self, len: usize) -> KmsAeadResult<&[u8]> {
        while self.header.len() < len {
            if self.pending.is_empty() {
                match poll_fn(|cx| Pin::new(&mut self.source).poll_next(cx)).await {
                    Some(Ok(item)) => self.pending = item,
                    Some(Err(error)) => return Err(source_error(error.into())),
                    None => {
                        return Err(KmsAeadEncryptionError::stream_length(
                            "The source ended inside the header of the streamed value",
                        ))
                    }
                }
                continue;
            }
            let taken = self.pending.len().min(len - self.header.len());
            self.header.extend_from_slice(&self.pending[..taken]);
            self.pending.advance(taken);
        }
        Ok(&self.header[..len])
    }

    /// A stream of the plaintext that `decryptor` decrypts from what follows the header.
    pub fn into_stream<B: AeadBackend>(
        self,
        decryptor: Arc<StreamDecryptor<B>>,
    ) -> DecryptingStream<B, S> {
        DecryptingStream {
            pending: self.pending,
            ..DecryptingStream::new(decryptor, self.source)
        }
    }
}

/// A `Stream` of [`Bytes`] that reads a streamed value from `stored` and yields its plaintext, one
/// item per chunk.
///
/// `stored` yields the value's stored bytes after the header, as [`DecryptingReader`] takes them,
/// in items of any size, and ends where the value ends;
/// [`KmsAeadEnvelope::decrypting_stream`](crate::KmsAeadEnvelope::decrypting_stream) takes the
/// whole value instead and reads the header itself. The stream gathers one chunk in a buffer of
/// [`STORED_STREAM_CHUNK_LEN`] bytes, and yields nothing of a chunk until the whole chunk is
/// authentic. The plaintext it yields owns the buffer it was decrypted in, which is zeroised when
/// the last `Bytes` over it is dropped.
///
/// Like the reader, the stream needs no stored length: a full chunk is decrypted as soon as it is
/// gathered, and the bytes after the last full chunk are the final chunk, decrypted when the source
/// ends. After the final chunk the stream yields `None`. An empty final chunk yields no item.
///
/// A value cut, modified or extended is never a clean end. An error ends the stream: it is the
/// last item, and the stream yields `None` after it. A value that has been yielded whole without
/// an error is authentic and complete, its length included; a caller that stops at an error has
/// the plaintext of the chunks before it, which it should write to a place it can discard.
///
/// # Errors
///
/// `STREAM_LENGTH` when the source ends at a chunk boundary or less than a tag into a chunk,
/// `DECRYPT` for a chunk that is not authentic, among them a final chunk that the source cut or
/// extended, and `DECRYPT_KEY` when the backend refuses the key. An item of the source that is an
/// `Err` is `STREAM_IO` with the source's error as the root cause, or yielded as itself when it is
/// a [`KmsAeadError`] or an `io::Error` that carries one.
///
/// `S` must be `Unpin`; `Box::pin` a stream that is not. `Send` when `S` is. `Debug` shows no
/// key.
///
/// ```rust
/// # #[cfg(feature = "ring")]
/// # #[tokio::main(flavor = "current_thread")]
/// # async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
/// use std::sync::Arc;
///
/// use bytes::Bytes;
/// use futures::{stream, TryStreamExt};
/// use kms_aead::backends::Ring;
/// use kms_aead::stream::{DecryptingStream, StreamFormat};
/// use kms_aead::{AeadAlgorithm, AeadCipher};
///
/// let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
/// let dek = cipher.generate_dek()?;
/// let mut encryptor = cipher.stream_encryptor_bare(b"uploads/7", &dek)?;
/// let mut stored = encryptor.header().to_vec();
/// stored.extend(encryptor.push(b"the response body")?);
/// stored.extend(encryptor.finish()?);
///
/// let header_len = StreamFormat::Bare.header_len();
/// let decryptor = cipher.stream_decryptor_bare(b"uploads/7", &stored[..header_len], &dek)?;
/// let after_header = Bytes::from(stored).slice(header_len..);
/// let after_header = stream::iter([Ok::<_, std::io::Error>(after_header)]);
/// let plaintext: Vec<Bytes> = DecryptingStream::new(Arc::new(decryptor), after_header)
///     .try_collect()
///     .await?;
/// assert_eq!(plaintext.concat(), b"the response body");
/// # Ok(())
/// # }
/// # #[cfg(not(feature = "ring"))]
/// # fn main() {}
/// ```
///
/// [`DecryptingReader`]: super::DecryptingReader
/// [`STORED_STREAM_CHUNK_LEN`]: super::STORED_STREAM_CHUNK_LEN
pub struct DecryptingStream<B, S> {
    chunks: ChunkGatherer<B>,
    source: S,
    /// The part of the source's last item that the stream has not taken.
    pending: Bytes,
    state: DecryptingState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecryptingState {
    Gathering,
    /// The final chunk was yielded, or an error was.
    Ended,
}

/// The buffer a chunk was decrypted in, as the `Bytes` that yields its plaintext: the first `len`
/// bytes. The buffer is zeroised when the last `Bytes` over it is dropped.
struct PlaintextChunk {
    buffer: SecretValue,
    len: usize,
}

impl AsRef<[u8]> for PlaintextChunk {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.as_sensitive_bytes()[..self.len]
    }
}

impl<B: AeadBackend, S, E> DecryptingStream<B, S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    /// A stream over `stored`, which yields the value's stored bytes after the header the
    /// decryptor was made from and ends where the value ends. One decryptor serves many streams,
    /// readers and ranges at once.
    pub fn new(decryptor: Arc<StreamDecryptor<B>>, stored: S) -> Self {
        Self {
            chunks: ChunkGatherer::new(decryptor),
            source: stored,
            pending: Bytes::new(),
            state: DecryptingState::Gathering,
        }
    }

    fn end_with(&mut self, error: KmsAeadError) -> Poll<Option<KmsAeadResult<Bytes>>> {
        self.state = DecryptingState::Ended;
        Poll::Ready(Some(Err(error)))
    }

    /// The plaintext of `chunk`, just decrypted, as an item: none for an empty final chunk.
    fn plaintext_item(&mut self, chunk: DecryptedChunk) -> Option<Bytes> {
        if chunk.last {
            self.state = DecryptingState::Ended;
        }
        let buffer = self.chunks.take_buffer(chunk);
        (chunk.len > 0).then(|| {
            Bytes::from_owner(PlaintextChunk {
                buffer,
                len: chunk.len,
            })
        })
    }
}

impl<B: AeadBackend, S, E> Stream for DecryptingStream<B, S>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<BoxError>,
{
    type Item = KmsAeadResult<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let stream = self.get_mut();
        loop {
            if stream.state == DecryptingState::Ended {
                return Poll::Ready(None);
            }
            if stream.pending.is_empty() {
                match ready!(Pin::new(&mut stream.source).poll_next(cx)) {
                    Some(Ok(item)) => stream.pending = item,
                    Some(Err(error)) => return stream.end_with(source_error(error.into())),
                    None => match stream.chunks.source_ended() {
                        Ok(chunk) => return Poll::Ready(stream.plaintext_item(chunk).map(Ok)),
                        Err(error) => return stream.end_with(error.into()),
                    },
                }
                continue;
            }
            let unfilled = stream.chunks.unfilled();
            let taken = stream.pending.len().min(unfilled.len());
            unfilled[..taken].copy_from_slice(&stream.pending[..taken]);
            stream.pending.advance(taken);
            match stream.chunks.gathered(taken) {
                Ok(Some(chunk)) => {
                    if let Some(plaintext) = stream.plaintext_item(chunk) {
                        return Poll::Ready(Some(Ok(plaintext)));
                    }
                }
                Ok(None) => {}
                Err(error) => return stream.end_with(error.into()),
            }
        }
    }
}

/// No key.
impl<B, S> Debug for DecryptingStream<B, S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingStream")
            .field("chunk_index", &self.chunks.next_index())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
