//! [`ChunkGatherer`]: the decryption chunk by chunk that [`DecryptingReader`] and
//! [`DecryptingStream`] share; the two differ only in how they hand the plaintext out.
//!
//! A sequential read needs no stored length. Every chunk but the final one is full, and the final
//! one is shorter, so a chunk is decrypted as non-final the moment it is whole, and the bytes the
//! source holds when it ends are the final chunk. A value cut at a chunk boundary therefore ends
//! with no final chunk, and the bytes of a value cut inside a chunk or followed by more bytes do
//! not decrypt as one.
//!
//! [`DecryptingReader`]: super::DecryptingReader
//! [`DecryptingStream`]: super::DecryptingStream

use std::mem;
use std::ops::Range;
use std::sync::Arc;

use secret_vault_value::SecretValue;

use super::{StreamDecryptor, MAX_STREAM_CHUNKS, STORED_STREAM_CHUNK_LEN};
use crate::backends::{AeadBackend, Failure};
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::AeadAlgorithm;

/// The chunks of one value, one at a time: the stored bytes of the chunk in progress are gathered
/// from a source into a buffer of [`STORED_STREAM_CHUNK_LEN`] bytes and decrypted there in place.
/// The buffer is zeroised when it is dropped.
pub(super) struct ChunkGatherer<B> {
    decryptor: Arc<StreamDecryptor<B>>,
    buffer: SecretValue,
    /// The stored bytes of the chunk in progress that the buffer holds.
    filled: usize,
    /// The index of the chunk in progress.
    next_index: u64,
}

/// A chunk decrypted in the gatherer's buffer.
#[derive(Debug, Clone, Copy)]
pub(super) struct DecryptedChunk {
    /// The length of its plaintext, at the start of the buffer.
    pub(super) len: usize,
    /// Whether it is the final chunk.
    pub(super) last: bool,
}

/// Why the chunk in progress yields no plaintext.
#[derive(Debug, Clone, Copy)]
pub(super) enum ChunkError {
    /// The source ended at a chunk boundary or less than a tag into a chunk, where no value ends.
    Cut,
    /// A full chunk at index 2^38 - 1, which leaves no index for the final chunk.
    TooManyChunks,
    /// The chunk did not decrypt.
    Failed(Failure),
}

impl From<ChunkError> for KmsAeadError {
    fn from(error: ChunkError) -> Self {
        match error {
            ChunkError::Cut => KmsAeadEncryptionError::stream_length(
                "The source ended at a chunk boundary or less than a tag into a chunk, where no streamed value ends",
            ),
            ChunkError::TooManyChunks => KmsAeadEncryptionError::stream_length(
                "The source holds more chunks than a streamed value",
            ),
            ChunkError::Failed(failure) => failure.decrypting(),
        }
    }
}

impl<B: AeadBackend> ChunkGatherer<B> {
    pub(super) fn new(decryptor: Arc<StreamDecryptor<B>>) -> Self {
        Self {
            decryptor,
            buffer: SecretValue::new(vec![0; STORED_STREAM_CHUNK_LEN]),
            filled: 0,
            next_index: 0,
        }
    }

    /// The part of the buffer that the stored bytes of the chunk in progress still fill. It is
    /// never empty, since a whole chunk is decrypted as soon as it is gathered, as long as the
    /// caller gathers nothing more after an error.
    pub(super) fn unfilled(&mut self) -> &mut [u8] {
        &mut self.buffer.ref_sensitive_value_mut()[self.filled..]
    }

    /// Counts `len` bytes written at the start of [`unfilled`](Self::unfilled) as gathered, and
    /// decrypts the chunk once it is whole. A whole chunk is never the final one. The plaintext is
    /// the first `len` bytes of the buffer until the next gather writes over them.
    pub(super) fn gathered(&mut self, len: usize) -> Result<Option<DecryptedChunk>, ChunkError> {
        self.filled += len;
        if self.filled < STORED_STREAM_CHUNK_LEN {
            return Ok(None);
        }
        if self.next_index >= MAX_STREAM_CHUNKS - 1 {
            return Err(ChunkError::TooManyChunks);
        }
        self.decrypt(false).map(Some)
    }

    /// Decrypts the bytes gathered when the source ended as the final chunk.
    pub(super) fn source_ended(&mut self) -> Result<DecryptedChunk, ChunkError> {
        if self.filled < AeadAlgorithm::TAG_LEN {
            return Err(ChunkError::Cut);
        }
        self.decrypt(true)
    }

    /// Decrypts the chunk in progress in place, and moves on to the next chunk.
    fn decrypt(&mut self, last: bool) -> Result<DecryptedChunk, ChunkError> {
        let chunk = &mut self.buffer.ref_sensitive_value_mut()[..self.filled];
        let len = self
            .decryptor
            .decrypt_in_place(self.next_index, chunk)
            .map_err(ChunkError::Failed)?;
        self.filled = 0;
        self.next_index += 1;
        Ok(DecryptedChunk { len, last })
    }

    /// The plaintext of the decrypted chunk in `range`.
    pub(super) fn plaintext(&self, range: Range<usize>) -> &[u8] {
        &self.buffer.as_sensitive_bytes()[range]
    }

    /// The buffer of `chunk`, the chunk just decrypted, to hand its plaintext out without a copy;
    /// a new buffer takes its place for the next chunk, none after the final one.
    pub(super) fn take_buffer(&mut self, chunk: DecryptedChunk) -> SecretValue {
        let next = if chunk.last {
            Vec::new()
        } else {
            vec![0; STORED_STREAM_CHUNK_LEN]
        };
        mem::replace(&mut self.buffer, SecretValue::new(next))
    }
}

impl<B> ChunkGatherer<B> {
    /// The index of the chunk in progress.
    pub(super) fn next_index(&self) -> u64 {
        self.next_index
    }

    pub(super) fn into_decryptor(self) -> Arc<StreamDecryptor<B>> {
        self.decryptor
    }
}
