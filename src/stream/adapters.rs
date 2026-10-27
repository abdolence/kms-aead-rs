//! The tokio adapters of a streamed value: [`EncryptingWriter`] and [`DecryptingReader`] on tokio's
//! `AsyncWrite` and `AsyncRead`, and [`encrypt_stream`] and [`decrypt_stream`], which run a whole
//! value through them. Each holds one chunk in memory at a time, whatever the value's length.

use std::fmt::{Debug, Formatter};
use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use super::gatherer::{ChunkError, ChunkGatherer};
use super::{StreamDecryptor, StreamEncryptor};
use crate::backends::{AeadBackend, Failure};
use crate::errors::{KmsAeadEncryptionError, KmsAeadError, KmsAeadSystemError};
use crate::KmsAeadResult;

/// A failure inside an adapter: of the streamed value, or of the source or the sink the caller
/// gave it. The wrappers return each as an `io::Error`, and the two functions as a
/// `KmsAeadError`.
enum AdapterError {
    /// An encryptor's or a decryptor's error, with the kind of the `io::Error` that carries it.
    Stream {
        kind: io::ErrorKind,
        error: KmsAeadError,
    },
    Source(io::Error),
    Sink(io::Error),
}

impl AdapterError {
    /// An encryptor's error, which a writer returns as an `io::Error` of kind `Other`.
    fn encryptor(error: KmsAeadError) -> Self {
        AdapterError::Stream {
            kind: io::ErrorKind::Other,
            error,
        }
    }

    fn broken_pipe() -> io::Error {
        io::Error::from(io::ErrorKind::BrokenPipe)
    }

    /// The error a wrapper returns: the value's behind an `io::Error` of its kind, and the
    /// source's or the sink's as they gave it.
    fn into_io(self) -> io::Error {
        match self {
            AdapterError::Stream { kind, error } => io::Error::new(kind, error),
            AdapterError::Source(error) | AdapterError::Sink(error) => error,
        }
    }

    /// The error a function returns: the value's as itself, an error of the value that came
    /// through the source or the sink as itself too (a source that is a [`DecryptingReader`] fails
    /// with the decryptor's `DECRYPT`, which a retry of the stream would only meet again), and any
    /// other failure of the source or the sink as `STREAM_IO`.
    fn into_stream(self) -> KmsAeadError {
        match self {
            AdapterError::Stream { error, .. } => error,
            AdapterError::Source(error) => {
                inner_kms_aead_error(&error).cloned().unwrap_or_else(|| {
                    KmsAeadSystemError::stream_io(
                        "Reading the source of the streamed value failed",
                        Arc::new(error),
                    )
                })
            }
            AdapterError::Sink(error) => {
                inner_kms_aead_error(&error).cloned().unwrap_or_else(|| {
                    KmsAeadSystemError::stream_io(
                        "Writing the sink of the streamed value failed",
                        Arc::new(error),
                    )
                })
            }
        }
    }
}

/// An `AsyncWrite` that encrypts what is written to it and writes the streamed value to `sink`.
///
/// The writer has no plaintext buffer of its own: it fills the encryptor's chunk buffer, the
/// encryptor encrypts the chunk there, and the writer hands the encrypted bytes to the sink from
/// the same buffer.
///
/// - `poll_write` first drives the encrypted bytes still unwritten, the header among them, into the
///   sink, and returns `Pending` while the sink does, before it takes any byte of `buf`. Then it
///   takes from `buf` at most what the chunk in progress still takes, and returns `Ready(n)` on
///   the same call; a chunk it fills is encrypted on that call, and its bytes are driven into the
///   sink by the next call, whichever of `poll_write`, `poll_flush` or `poll_shutdown` comes;
/// - `poll_flush` writes the encrypted bytes still unwritten and flushes the sink. It encrypts
///   nothing: only the final chunk is short, so up to `STREAM_CHUNK_LEN - 1` bytes of plaintext
///   stay in the writer, and a reader of the sink sees the header and the full chunks only;
/// - `poll_shutdown` encrypts the plaintext still held as the final chunk, writes it, flushes the
///   sink and shuts it down, resuming where it was after each `Pending`. Once it has returned
///   `Ready(Ok(()))` it does so again, and a `poll_write` after the shutdown has started fails
///   with `ErrorKind::BrokenPipe`. A value is complete through the shutdown and in no other way:
///   a writer dropped before it leaves a value no reader decrypts whole.
///
/// An error of the encryptor, `STREAM_LENGTH` for a full chunk at index 2^38 - 1 or `ENCRYPT`, is
/// an `io::Error` of kind `Other` that carries the `KmsAeadError` as its inner error, which
/// `get_ref` and `downcast_ref::<KmsAeadError>` find, and every later call returns it again. An
/// error of the sink is returned as the sink gave it, and every later call fails with
/// `ErrorKind::BrokenPipe`.
///
/// `Send` when `W` is. `Debug` shows the chunk index and the bytes written, no key and no
/// plaintext.
pub struct EncryptingWriter<B, W> {
    encryptor: StreamEncryptor<B>,
    pub(super) sink: W,
    /// The bytes of the header written to the sink.
    header_written: usize,
    /// The bytes of the encrypted chunk in the encryptor's buffer written to the sink.
    chunk_written: usize,
    stored_len_written: u64,
    state: WriterState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriterState {
    /// Taking plaintext.
    Open,
    /// `poll_shutdown` has encrypted the final chunk and runs the step it names.
    ShuttingDown(ShutdownStep),
    /// The value is complete and the sink is shut down.
    Closed,
    /// The sink failed.
    SinkFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ShutdownStep {
    WriteFinalChunk,
    FlushSink,
    ShutDownSink,
}

impl<B: AeadBackend, W: AsyncWrite + Unpin> EncryptingWriter<B, W> {
    /// A writer that writes `encryptor.header()` to `sink` in front of its first chunk.
    pub fn new(encryptor: StreamEncryptor<B>, sink: W) -> Self {
        Self {
            encryptor,
            sink,
            header_written: 0,
            chunk_written: 0,
            stored_len_written: 0,
            state: WriterState::Open,
        }
    }

    /// The bytes of the value written to the sink so far: `Z` once `poll_shutdown` has returned
    /// `Ready(Ok(()))`.
    pub fn stored_len_written(&self) -> u64 {
        self.stored_len_written
    }

    /// The sink, once the value is complete or given up.
    pub fn into_inner(self) -> W {
        self.sink
    }

    /// The error of a call after a failure of the encryptor or the sink.
    fn failed(&self) -> Option<AdapterError> {
        if let Some(error) = self.encryptor.failure() {
            return Some(AdapterError::encryptor(error.clone()));
        }
        (self.state == WriterState::SinkFailed)
            .then(|| AdapterError::Sink(AdapterError::broken_pipe()))
    }

    /// The error of a write: [`failed`](Self::failed), or the shutdown has started.
    fn refused_write(&self) -> Option<AdapterError> {
        self.failed().or_else(|| {
            matches!(
                self.state,
                WriterState::ShuttingDown(_) | WriterState::Closed
            )
            .then(|| AdapterError::Sink(AdapterError::broken_pipe()))
        })
    }

    /// Writes the header and the encrypted chunk still unwritten into the sink, and frees the
    /// encryptor's buffer once the chunk is written.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AdapterError>> {
        loop {
            let header_len = self.encryptor.header().len();
            let unwritten = if self.header_written < header_len {
                &self.encryptor.header()[self.header_written..]
            } else {
                let chunk_len = self.encryptor.encrypted_chunk().len();
                if self.chunk_written == chunk_len {
                    if chunk_len > 0 {
                        self.encryptor.release_encrypted();
                        self.chunk_written = 0;
                    }
                    return Poll::Ready(Ok(()));
                }
                &self.encryptor.encrypted_chunk()[self.chunk_written..]
            };
            let written = match ready!(Pin::new(&mut self.sink).poll_write(cx, unwritten)) {
                Ok(0) => Err(io::Error::from(io::ErrorKind::WriteZero)),
                Ok(written) => Ok(written.min(unwritten.len())),
                Err(error) => Err(error),
            };
            match written {
                Ok(written) => {
                    if self.header_written < header_len {
                        self.header_written += written;
                    } else {
                        self.chunk_written += written;
                    }
                    self.stored_len_written += written as u64;
                }
                Err(error) => {
                    self.state = WriterState::SinkFailed;
                    return Poll::Ready(Err(AdapterError::Sink(error)));
                }
            }
        }
    }

    fn poll_write_plaintext(
        &mut self,
        cx: &mut Context<'_>,
        plaintext: &[u8],
    ) -> Poll<Result<usize, AdapterError>> {
        if let Some(error) = self.refused_write() {
            return Poll::Ready(Err(error));
        }
        ready!(self.poll_drain(cx))?;
        if plaintext.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(
            self.encryptor
                .take_plaintext(plaintext)
                .map_err(AdapterError::encryptor),
        )
    }

    /// Reads plaintext from `source` straight into the encryptor's chunk buffer, and returns how
    /// many bytes it read, 0 at the source's end: [`encrypt_stream`] encrypts with no buffer
    /// besides the encryptor's.
    fn poll_fill_from<R: AsyncRead + Unpin>(
        &mut self,
        cx: &mut Context<'_>,
        source: &mut R,
    ) -> Poll<Result<usize, AdapterError>> {
        if let Some(error) = self.refused_write() {
            return Poll::Ready(Err(error));
        }
        ready!(self.poll_drain(cx))?;
        let mut space = ReadBuf::new(self.encryptor.plaintext_space());
        ready!(Pin::new(source).poll_read(cx, &mut space)).map_err(AdapterError::Source)?;
        let read = space.filled().len();
        self.encryptor
            .commit_plaintext(read)
            .map_err(AdapterError::encryptor)?;
        Poll::Ready(Ok(read))
    }

    fn poll_flush_sink(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AdapterError>> {
        if let Some(error) = self.failed() {
            return Poll::Ready(Err(error));
        }
        if self.state == WriterState::Closed {
            return Poll::Ready(Ok(()));
        }
        ready!(self.poll_drain(cx))?;
        self.poll_sink(cx, AsyncWrite::poll_flush)
    }

    fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AdapterError>> {
        loop {
            if let Some(error) = self.failed() {
                return Poll::Ready(Err(error));
            }
            self.state = match self.state {
                WriterState::Open => {
                    ready!(self.poll_drain(cx))?;
                    self.encryptor
                        .encrypt_final()
                        .map_err(AdapterError::encryptor)?;
                    WriterState::ShuttingDown(ShutdownStep::WriteFinalChunk)
                }
                WriterState::ShuttingDown(ShutdownStep::WriteFinalChunk) => {
                    ready!(self.poll_drain(cx))?;
                    WriterState::ShuttingDown(ShutdownStep::FlushSink)
                }
                WriterState::ShuttingDown(ShutdownStep::FlushSink) => {
                    ready!(self.poll_sink(cx, AsyncWrite::poll_flush))?;
                    WriterState::ShuttingDown(ShutdownStep::ShutDownSink)
                }
                WriterState::ShuttingDown(ShutdownStep::ShutDownSink) => {
                    ready!(self.poll_sink(cx, AsyncWrite::poll_shutdown))?;
                    WriterState::Closed
                }
                WriterState::Closed | WriterState::SinkFailed => return Poll::Ready(Ok(())),
            };
        }
    }

    /// Runs `poll` on the sink, and marks the sink failed when it fails.
    fn poll_sink(
        &mut self,
        cx: &mut Context<'_>,
        poll: impl FnOnce(Pin<&mut W>, &mut Context<'_>) -> Poll<io::Result<()>>,
    ) -> Poll<Result<(), AdapterError>> {
        ready!(poll(Pin::new(&mut self.sink), cx)).map_err(|error| {
            self.state = WriterState::SinkFailed;
            AdapterError::Sink(error)
        })?;
        Poll::Ready(Ok(()))
    }
}

impl<B: AeadBackend, W: AsyncWrite + Unpin> AsyncWrite for EncryptingWriter<B, W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.get_mut()
            .poll_write_plaintext(cx, buf)
            .map_err(AdapterError::into_io)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut()
            .poll_flush_sink(cx)
            .map_err(AdapterError::into_io)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_close(cx).map_err(AdapterError::into_io)
    }
}

/// The chunk index and the bytes written, no key and no plaintext.
impl<B, W> Debug for EncryptingWriter<B, W> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptingWriter")
            .field("chunk_index", &self.encryptor.next_index)
            .field("stored_len_written", &self.stored_len_written)
            .finish_non_exhaustive()
    }
}

/// An `AsyncRead` that reads a streamed value from `source` and yields its plaintext.
///
/// The reader has one buffer of [`STORED_STREAM_CHUNK_LEN`](super::STORED_STREAM_CHUNK_LEN) bytes,
/// allocated when it is made and zeroised when it is dropped, in which a chunk's stored bytes are
/// gathered, decrypted in place and served from.
///
/// - `poll_read` reads from the source until the buffer holds one whole chunk, or the source
///   ends, returning `Pending` while the source does, and only then decrypts it: no byte of a
///   chunk reaches the caller before the whole chunk is authentic. The plaintext of an authentic
///   chunk is then served across as many reads as the caller's buffers take. A value cut or
///   modified further on has already given its earlier chunks out when the error comes, so write
///   to a place that can be discarded;
/// - the reader needs no stored length. Every chunk but the final one is full and the final one
///   is shorter, so the bytes the source holds after the last full chunk when it ends are the
///   final chunk. The source ends where the value ends: bytes after the value are read as part of
///   its final chunk, which then fails as not authentic. A value inside a longer source is read
///   through a source cut to its length, such as `AsyncReadExt::take`;
/// - once the final chunk has been served the reader is at its clean end, `Ready(Ok(()))` with
///   nothing filled. The length is authenticated there alone, where the final chunk has
///   decrypted. A reader stopped before it has authenticated the chunks it yielded and nothing of
///   the length, and [`plaintext_len_read`](Self::plaintext_len_read) says how far it got;
/// - a source that ends at a chunk boundary, or less than a tag into a chunk, is `STREAM_LENGTH`
///   as an `io::Error` of kind `UnexpectedEof`, a source of more chunks than a value holds
///   `STREAM_LENGTH` of kind `InvalidData`, a chunk that is not authentic `DECRYPT` of kind
///   `InvalidData`, and a backend that refuses the key `DECRYPT_KEY` of kind `Other`, each
///   carrying the `KmsAeadError` as its inner error. A cut or unauthentic value is never a clean
///   end: every read after the error returns it again. An error of the source is returned as the
///   source gave it, and every later read fails with `ErrorKind::BrokenPipe`.
///
/// `Send` when `R` is. `Debug` shows the chunk index and the bytes read, no key.
pub struct DecryptingReader<B, R> {
    chunks: ChunkGatherer<B>,
    pub(super) source: R,
    state: ReaderState,
    plaintext_len_read: u64,
}

enum ReaderState {
    /// Gathering the stored bytes of the chunk in progress.
    Gathering,
    /// The plaintext of the chunk just decrypted, `len` bytes at the start of the gatherer's
    /// buffer, of which `served` have been yielded; the final chunk when `last`.
    Serving {
        served: usize,
        len: usize,
        last: bool,
    },
    /// The final chunk has been yielded: the clean end.
    Done,
    /// The value is cut or not authentic.
    Failed {
        kind: io::ErrorKind,
        error: KmsAeadError,
    },
    /// The source failed.
    SourceFailed,
}

impl<B: AeadBackend, R: AsyncRead + Unpin> DecryptingReader<B, R> {
    /// A reader over `source`, positioned right after the header the decryptor was made from, at
    /// byte [`decryptor.form().header_len()`](super::StreamFormat::header_len), and ending where the
    /// value ends. One decryptor serves many readers and ranges at once.
    pub fn new(decryptor: Arc<StreamDecryptor<B>>, source: R) -> Self {
        Self {
            chunks: ChunkGatherer::new(decryptor),
            source,
            state: ReaderState::Gathering,
            plaintext_len_read: 0,
        }
    }

    /// The plaintext bytes yielded so far: the value's plaintext length after the clean end.
    pub fn plaintext_len_read(&self) -> u64 {
        self.plaintext_len_read
    }

    /// The decryptor and the source.
    pub fn into_inner(self) -> (Arc<StreamDecryptor<B>>, R) {
        (self.chunks.into_decryptor(), self.source)
    }

    /// Gathers and decrypts chunks until the buffer holds plaintext not yet yielded, and returns
    /// how many bytes of it there are, 0 at the clean end.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<Result<usize, AdapterError>> {
        loop {
            match self.state {
                ReaderState::Serving { served, len, last } => {
                    if served < len {
                        return Poll::Ready(Ok(len - served));
                    }
                    self.state = if last {
                        ReaderState::Done
                    } else {
                        ReaderState::Gathering
                    };
                }
                ReaderState::Done => return Poll::Ready(Ok(0)),
                ReaderState::Failed { kind, ref error } => {
                    return Poll::Ready(Err(AdapterError::Stream {
                        kind,
                        error: error.clone(),
                    }))
                }
                ReaderState::SourceFailed => {
                    return Poll::Ready(Err(AdapterError::Source(AdapterError::broken_pipe())))
                }
                ReaderState::Gathering => ready!(self.poll_gather(cx))?,
            }
        }
    }

    /// Reads the next stored bytes of the chunk in progress, and decrypts the chunk once it is
    /// whole or the source has ended.
    fn poll_gather(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), AdapterError>> {
        let mut unfilled = ReadBuf::new(self.chunks.unfilled());
        if let Err(error) = ready!(Pin::new(&mut self.source).poll_read(cx, &mut unfilled)) {
            self.state = ReaderState::SourceFailed;
            return Poll::Ready(Err(AdapterError::Source(error)));
        }
        let read = unfilled.filled().len();
        let decrypted = if read == 0 {
            self.chunks.source_ended().map(Some)
        } else {
            self.chunks.gathered(read)
        };
        Poll::Ready(match decrypted {
            Ok(Some(chunk)) => {
                self.state = ReaderState::Serving {
                    served: 0,
                    len: chunk.len,
                    last: chunk.last,
                };
                Ok(())
            }
            Ok(None) => Ok(()),
            Err(error) => Err(self.fail(error)),
        })
    }

    fn fail(&mut self, error: ChunkError) -> AdapterError {
        let kind = match error {
            ChunkError::Cut => io::ErrorKind::UnexpectedEof,
            ChunkError::TooManyChunks | ChunkError::Failed(Failure::Operation) => {
                io::ErrorKind::InvalidData
            }
            ChunkError::Failed(Failure::Key) => io::ErrorKind::Other,
        };
        let error = KmsAeadError::from(error);
        self.state = ReaderState::Failed {
            kind,
            error: error.clone(),
        };
        AdapterError::Stream { kind, error }
    }

    /// The plaintext in the buffer not yet yielded.
    fn unread_plaintext(&self) -> &[u8] {
        match self.state {
            ReaderState::Serving { served, len, .. } => self.chunks.plaintext(served..len),
            _ => &[],
        }
    }

    /// Counts `yielded` bytes of [`unread_plaintext`](Self::unread_plaintext) as read.
    fn consume(&mut self, yielded: usize) {
        if let ReaderState::Serving { served, len, last } = self.state {
            let yielded = yielded.min(len - served);
            self.state = ReaderState::Serving {
                served: served + yielded,
                len,
                last,
            };
            self.plaintext_len_read += yielded as u64;
        }
    }
}

impl<B: AeadBackend, R: AsyncRead + Unpin> AsyncRead for DecryptingReader<B, R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let reader = self.get_mut();
        let unread = ready!(reader.poll_fill(cx)).map_err(AdapterError::into_io)?;
        let yielded = unread.min(buf.remaining());
        buf.put_slice(&reader.unread_plaintext()[..yielded]);
        reader.consume(yielded);
        Poll::Ready(Ok(()))
    }
}

/// The chunk index and the bytes read, no key.
impl<B, R> Debug for DecryptingReader<B, R> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptingReader")
            .field("chunk_index", &self.chunks.next_index())
            .field("plaintext_len_read", &self.plaintext_len_read)
            .finish_non_exhaustive()
    }
}

/// The `KmsAeadError` that an `io::Error` of the adapters carries as its inner error; `None` for
/// an error of the sink or the source.
pub(super) fn inner_kms_aead_error(error: &io::Error) -> Option<&KmsAeadError> {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<KmsAeadError>())
}

/// Reads from `source` until `header` holds `len` bytes, the header of a streamed value, and no
/// further, so that the source stays positioned after it. Not part of the API, as
/// [`__HeaderGatherer`](super::__HeaderGatherer).
///
/// # Errors
///
/// `STREAM_LENGTH` when the source ends first, and `STREAM_IO` for an error of the source, as
/// [`DecryptingReader`] returns them.
#[doc(hidden)]
pub async fn __read_header<R: AsyncRead + Unpin>(
    source: &mut R,
    header: &mut Vec<u8>,
    len: usize,
) -> KmsAeadResult<()> {
    let mut filled = header.len();
    header.resize(len, 0);
    while filled < len {
        match source.read(&mut header[filled..]).await {
            Ok(0) => {
                return Err(KmsAeadEncryptionError::stream_length(
                    "The source ended inside the header of the streamed value",
                ))
            }
            Ok(read) => filled += read,
            Err(error) => return Err(AdapterError::Source(error).into_stream()),
        }
    }
    Ok(())
}

/// Encrypts `source` into an [`EncryptingWriter`] over `sink`, then shuts it down, and returns `Z`,
/// the stored length. The plaintext is read from the source straight into the encryptor's chunk
/// buffer, with no buffer besides it.
///
/// # Errors
///
/// `STREAM_IO` when `source` or `sink` fails, with the `std::io::Error` as the root cause, and the
/// encryptor's errors as themselves. The retry is the whole value again with a new encryptor: a
/// sink that holds part of a value holds nothing a reader decrypts.
pub async fn encrypt_stream<B, R, W>(
    encryptor: StreamEncryptor<B>,
    mut source: R,
    sink: W,
) -> KmsAeadResult<u64>
where
    B: AeadBackend,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut writer = EncryptingWriter::new(encryptor, sink);
    while poll_fn(|cx| writer.poll_fill_from(cx, &mut source))
        .await
        .map_err(AdapterError::into_stream)?
        > 0
    {}
    poll_fn(|cx| writer.poll_close(cx))
        .await
        .map_err(AdapterError::into_stream)?;
    Ok(writer.stored_len_written())
}

/// Decrypts the value whose stored bytes after the header `source` yields, through a
/// [`DecryptingReader`], into `sink`, then flushes `sink`, and returns `L`, which the final chunk
/// has authenticated. It reads the source to its end, which is the end of the value, and writes
/// the plaintext to the sink from the reader's buffer.
///
/// # Errors
///
/// `STREAM_IO` as [`encrypt_stream`]; the reader's `STREAM_LENGTH`, `DECRYPT` and `DECRYPT_KEY` as
/// themselves, after the plaintext of the chunks before the failing one has been written. The retry
/// is a fresh read of the value from the start. As with [`DecryptingReader`], the plaintext of the
/// chunks before an unauthentic one is already in the sink when the error comes.
pub async fn decrypt_stream<B, R, W>(
    decryptor: Arc<StreamDecryptor<B>>,
    source: R,
    mut sink: W,
) -> KmsAeadResult<u64>
where
    B: AeadBackend,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut reader = DecryptingReader::new(decryptor, source);
    loop {
        let unread = poll_fn(|cx| reader.poll_fill(cx))
            .await
            .map_err(AdapterError::into_stream)?;
        if unread == 0 {
            break;
        }
        sink.write_all(reader.unread_plaintext())
            .await
            .map_err(|error| AdapterError::Sink(error).into_stream())?;
        reader.consume(unread);
    }
    sink.flush()
        .await
        .map_err(|error| AdapterError::Sink(error).into_stream())?;
    Ok(reader.plaintext_len_read())
}
