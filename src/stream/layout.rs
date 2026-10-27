//! The three forms of a streamed value, the length rules that tie a stored length to its chunks,
//! and the seeking rules that tie a plaintext range to the stored bytes that cover it.

use std::ops::{Bound, Range, RangeBounds};

use super::{
    BARE_HEADER_LEN, MAX_STREAM_CHUNKS, PREFIXED_HEADER_LEN, STORED_STREAM_CHUNK_LEN,
    STREAM_CHUNK_LEN,
};
use crate::errors::KmsAeadEncryptionError;
use crate::formats::envelope::ENCRYPTED_DEK_LEN_FIELD_SIZE;
use crate::{AeadAlgorithm, KmsAeadResult};

/// `STREAM_CHUNK_LEN`, `STORED_STREAM_CHUNK_LEN` and the tag, in the `u64` that stored lengths are
/// counted in.
pub(super) const FULL_CHUNK_PLAINTEXT_LEN: u64 = STREAM_CHUNK_LEN as u64;
pub(super) const FULL_CHUNK_STORED_LEN: u64 = STORED_STREAM_CHUNK_LEN as u64;
pub(super) const CHUNK_TAG_LEN: u64 = AeadAlgorithm::TAG_LEN as u64;

/// The layouts of a streamed value, which differ in the key reference in front of the Cobblestone
/// header and nowhere else. An encryptor and a decryptor carry the form of their value, so the
/// chunk read plans, the wrappers and the functions take the header's length from it and no type
/// exists twice.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum StreamFormat {
    /// `[0x01][key id: u32 BE]` and the Cobblestone-256 message: the form of `AeadCipher`'s
    /// unsuffixed calls, and the keyring's.
    Prefixed,
    /// The Cobblestone-256 message alone, for a caller that keeps the key reference itself, a key
    /// id or an encrypted DEK.
    Bare,
    /// `[w: u32 BE][encrypted DEK: w]`, the framing of Tink's KMS envelope, and the Cobblestone-256
    /// message: the form of `KmsAeadEnvelope`'s unsuffixed calls, a value that carries the
    /// encrypted DEK that decrypts it. Only the library makes this variant: an encryptor, a
    /// decryptor and an [`EnvelopeStreamHeader`](super::EnvelopeStreamHeader) of the envelope form
    /// report it.
    #[non_exhaustive]
    Envelope {
        /// `w`, the length of the encrypted DEK: 1 to 4,096 bytes.
        encrypted_dek_len: usize,
    },
}

impl StreamFormat {
    /// The length of the header: 61 bytes in the prefixed form, 56 in the bare form, and
    /// `4 + w + 56` in the envelope form. It is the offset of chunk 0, and the `H` of the length
    /// and seeking rules.
    pub const fn header_len(self) -> usize {
        match self {
            StreamFormat::Prefixed => PREFIXED_HEADER_LEN,
            StreamFormat::Bare => BARE_HEADER_LEN,
            StreamFormat::Envelope { encrypted_dek_len } => {
                ENCRYPTED_DEK_LEN_FIELD_SIZE + encrypted_dek_len + BARE_HEADER_LEN
            }
        }
    }

    /// [`header_len`](Self::header_len) as stored offsets count it.
    const fn header_offset(self) -> u64 {
        self.header_len() as u64
    }

    /// The chunk read plan of a plaintext range of the value of `stored_len` bytes in this form,
    /// with its header: the chunks that cover the range and the stored bytes to fetch for them,
    /// with the range and the stored length kept in the plan. `..` is the whole plaintext.
    ///
    /// `stored_len` is the store's word, and so is the plaintext length the rules derive from it,
    /// until the final chunk decrypts. A range that ends at that plaintext length covers the final
    /// chunk, an empty one included, so decrypting its plan authenticates the length. Any other
    /// empty range gives an empty plan at the chunk that holds the range's start.
    ///
    /// The plan needs no key, so a caller plans and validates the length before any KMS call,
    /// fetches [`ciphertext()`](ChunkReadPlan::ciphertext), then makes a decryptor and gives it
    /// the plan and the bytes.
    ///
    /// # Errors
    ///
    /// `STREAM_LENGTH` for a `stored_len` the length rules refuse, and `STREAM_RANGE` for a range
    /// past the plaintext length or with `start > end`.
    pub fn plan_chunk_read(
        self,
        stored_len: u64,
        plaintext: impl RangeBounds<u64>,
    ) -> KmsAeadResult<ChunkReadPlan> {
        StreamLayout::new(self, stored_len)?.plan(plaintext)
    }

    /// The plan of the final chunk alone of the value of `stored_len` bytes in this form, for its
    /// whole plaintext: its [`plaintext()`](ChunkReadPlan::plaintext) ends at the plaintext length
    /// the rules derive from `stored_len`. Decrypting it with
    /// [`decrypt_chunk_read`](super::StreamDecryptor::decrypt_chunk_read) authenticates that
    /// length: a value whose stored length is not the one it was encrypted with fails there.
    ///
    /// # Errors
    ///
    /// `STREAM_LENGTH` for a `stored_len` the length rules refuse.
    pub fn plan_final_chunk_read(self, stored_len: u64) -> KmsAeadResult<ChunkReadPlan> {
        Ok(StreamLayout::new(self, stored_len)?.plan_final_chunk_read())
    }
}

/// The layout of one stored value: its form, its stored length, and the chunks and the
/// plaintext length that the length rules derive from them. A value of this type holds a stored
/// length the rules accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StreamLayout {
    form: StreamFormat,
    stored_len: u64,
    chunk_count: u64,
    plaintext_len: u64,
    final_chunk_len: usize,
}

impl StreamLayout {
    /// The layout of a value of `stored_len` bytes in `form`. Every step is arithmetic on
    /// `stored_len`, so a stored length of any size is refused or accepted without an
    /// allocation.
    ///
    /// # Errors
    ///
    /// `STREAM_LENGTH` for a stored length shorter than the header and one tag, one that ends
    /// at a chunk boundary or 1 to 15 bytes after one, which no encryptor writes, and one of more
    /// than [`MAX_STREAM_CHUNKS`] chunks.
    pub(crate) fn new(form: StreamFormat, stored_len: u64) -> KmsAeadResult<Self> {
        let body = stored_len
            .checked_sub(form.header_offset())
            .filter(|body| *body >= CHUNK_TAG_LEN)
            .ok_or_else(|| {
                KmsAeadEncryptionError::stream_length(
                    "The stored length is shorter than the header and one tag",
                )
            })?;
        let chunk_count = body / FULL_CHUNK_STORED_LEN + 1;
        let final_chunk_len = body % FULL_CHUNK_STORED_LEN;
        if final_chunk_len == 0 {
            return Err(KmsAeadEncryptionError::stream_length(
                "The stored length ends at a chunk boundary, so the final chunk is missing",
            ));
        }
        if final_chunk_len < CHUNK_TAG_LEN {
            return Err(KmsAeadEncryptionError::stream_length(
                "The stored length ends 1 to 15 bytes after a chunk boundary, which no encryptor writes",
            ));
        }
        if chunk_count > MAX_STREAM_CHUNKS {
            return Err(KmsAeadEncryptionError::stream_length(
                "The stored length holds more than 2^38 chunks",
            ));
        }
        let final_chunk_len = usize::try_from(final_chunk_len).map_err(|_| {
            KmsAeadEncryptionError::stream_length("The final chunk is longer than memory")
        })?;
        Ok(Self {
            form,
            stored_len,
            chunk_count,
            plaintext_len: body - CHUNK_TAG_LEN * chunk_count,
            final_chunk_len,
        })
    }

    pub(crate) fn form(&self) -> StreamFormat {
        self.form
    }

    /// The stored length of chunk `index`: [`STORED_STREAM_CHUNK_LEN`], or 16 to 16,399 bytes for
    /// the final chunk.
    ///
    /// # Errors
    ///
    /// `STREAM_RANGE` for an index past the final chunk.
    pub(crate) fn encrypted_chunk_len(&self, index: u64) -> KmsAeadResult<usize> {
        if index >= self.chunk_count {
            Err(KmsAeadEncryptionError::stream_range(
                "The chunk index is past the final chunk",
            ))
        } else if index + 1 == self.chunk_count {
            Ok(self.final_chunk_len)
        } else {
            Ok(STORED_STREAM_CHUNK_LEN)
        }
    }

    /// The chunk read plan of `plaintext`, as "Seeking" computes it. A range that ends at the
    /// plaintext length covers the final chunk, an empty one included, so that decrypting the plan
    /// authenticates the length.
    ///
    /// # Errors
    ///
    /// `STREAM_RANGE` for a range past the plaintext length or with `start > end`.
    pub(crate) fn plan(&self, plaintext: impl RangeBounds<u64>) -> KmsAeadResult<ChunkReadPlan> {
        let out_of_range = || {
            KmsAeadEncryptionError::stream_range(
                "The plaintext range is past the value's length or ends before it starts",
            )
        };
        let start = match plaintext.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start.checked_add(1).ok_or_else(out_of_range)?,
            Bound::Unbounded => 0,
        };
        let end = match plaintext.end_bound() {
            Bound::Included(end) => end.checked_add(1).ok_or_else(out_of_range)?,
            Bound::Excluded(end) => *end,
            Bound::Unbounded => self.plaintext_len,
        };
        let plaintext = start..end;
        if plaintext.start > plaintext.end || plaintext.end > self.plaintext_len {
            return Err(out_of_range());
        }
        let first = plaintext.start / FULL_CHUNK_PLAINTEXT_LEN;
        let end = if plaintext.end == self.plaintext_len {
            self.chunk_count
        } else if plaintext.is_empty() {
            first
        } else {
            (plaintext.end - 1) / FULL_CHUNK_PLAINTEXT_LEN + 1
        };
        Ok(self.plan_of_chunks(plaintext, first..end))
    }

    /// The plan of the final chunk alone, for its whole plaintext, which may be empty.
    pub(crate) fn plan_final_chunk_read(&self) -> ChunkReadPlan {
        let last = self.chunk_count - 1;
        self.plan_of_chunks(
            last * FULL_CHUNK_PLAINTEXT_LEN..self.plaintext_len,
            last..self.chunk_count,
        )
    }

    fn plan_of_chunks(&self, plaintext: Range<u64>, chunks: Range<u64>) -> ChunkReadPlan {
        let header = self.form.header_offset();
        let start = header + chunks.start * FULL_CHUNK_STORED_LEN;
        let end = self
            .stored_len
            .min(header + chunks.end * FULL_CHUNK_STORED_LEN);
        ChunkReadPlan {
            layout: *self,
            plaintext,
            plaintext_start: chunks.start * FULL_CHUNK_PLAINTEXT_LEN,
            chunks,
            ciphertext: start..end,
        }
    }
}

/// A chunk read plan: the answer to the question which stored bytes cover a plaintext range.
/// It holds the range itself, the chunk indices to decrypt, the bytes of the stored value to fetch,
/// and where the first of those chunks starts in the plaintext, all from the stored length the
/// plan was made for.
///
/// Only a form makes one, from [`StreamFormat::plan_chunk_read`] or
/// [`StreamFormat::plan_final_chunk_read`], and
/// [`decrypt_chunk_read`](super::StreamDecryptor::decrypt_chunk_read) takes it back with the bytes
/// it asked for, so neither the range nor the stored length is passed twice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChunkReadPlan {
    /// The layout of the value, from the stored length the plan was made for.
    layout: StreamLayout,
    plaintext: Range<u64>,
    chunks: Range<u64>,
    ciphertext: Range<u64>,
    plaintext_start: u64,
}

impl ChunkReadPlan {
    /// The plaintext range the plan was made for: `decrypt_chunk_read` returns exactly these bytes.
    pub fn plaintext(&self) -> Range<u64> {
        self.plaintext.clone()
    }

    /// The chunk indices to decrypt, half-open; empty for an empty range short of the plaintext
    /// length.
    pub fn chunks(&self) -> Range<u64> {
        self.chunks.clone()
    }

    /// The bytes of the stored value to fetch, as offsets from the start of the value. The
    /// header, the form's `header_len()` bytes, is counted in the offsets and never
    /// inside the range: chunk `chunks().start` is at `ciphertext().start`. An HTTP `Range` header
    /// names `ciphertext().start` to `ciphertext().end - 1`, since its end is inclusive.
    pub fn ciphertext(&self) -> Range<u64> {
        self.ciphertext.clone()
    }

    /// The plaintext offset of the first byte of chunk `chunks().start`.
    pub fn plaintext_start(&self) -> u64 {
        self.plaintext_start
    }

    pub(super) fn layout(&self) -> &StreamLayout {
        &self.layout
    }
}
