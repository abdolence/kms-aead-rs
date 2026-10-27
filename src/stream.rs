//! Streamed values, with the `stream` feature: values of any length, encrypted and decrypted chunk
//! by chunk, in the chunked encryption of [C2SP](https://c2sp.org/chunked-encryption) on
//! AES-256-GCM, Cobblestone-256.
//!
//! A streamed value is a header, then chunks of [`STREAM_CHUNK_LEN`] bytes of plaintext, each one
//! authenticated on its own and bound to its position, the last one shorter. A reader decrypts any
//! plaintext range by fetching only the chunks that cover it, and a writer encrypts a value whose
//! length it does not know in advance. The [`StreamFormat::Prefixed`] form puts Tink's output
//! prefix, `[0x01][key id: u32 BE]`, in front of the specification's message, as every
//! `Randomized` value starts with it; the [`StreamFormat::Envelope`] form puts the encrypted DEK
//! there, as Tink's KMS envelope does; the [`StreamFormat::Bare`] form is the message alone.
//!
//! The core is sans-IO: a [`StreamEncryptor`] and a [`StreamDecryptor`] take bytes and return bytes
//! and read and write nothing themselves, so they run under any runtime. On top of them sit the
//! tokio adapters, [`EncryptingWriter`], [`DecryptingReader`], [`encrypt_stream`] and
//! [`decrypt_stream`], and the adapters on a `Stream` of `Bytes`, [`EncryptingStream`] and
//! [`DecryptingStream`]. [`AeadCipher::stream_encryptor`] and [`AeadCipher::stream_decryptor`] make
//! them under a DEK the caller holds,
//! [`KmsAeadEnvelope::stream_encryptor`](crate::KmsAeadEnvelope::stream_encryptor) and
//! [`stream_decryptor`](crate::KmsAeadEnvelope::stream_decryptor) under a DEK the KMS encrypts, and
//! the keyring of kms-aead-keyring under its key versions. A caller that holds the whole stored
//! value gets the decrypting adapter from
//! [`KmsAeadEnvelope::decrypting_stream`](crate::KmsAeadEnvelope::decrypting_stream) or
//! [`decrypting_reader`](crate::KmsAeadEnvelope::decrypting_reader), which read the header
//! themselves.
//!
//! The book's [Streaming encryption](https://kms-aead-rust.abdolence.dev/streaming.html) chapter
//! walks through these calls, and
//! [Formats](https://kms-aead-rust.abdolence.dev/formats.html#streamed-values) has the bytes and
//! the length and seeking rules.
//!
//! ```rust
//! # #[cfg(feature = "ring")]
//! # fn example() -> kms_aead::KmsAeadResult<()> {
//! use kms_aead::backends::Ring;
//! use kms_aead::stream::StreamFormat;
//! use kms_aead::{AeadAlgorithm, AeadCipher};
//!
//! let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
//! let dek = cipher.generate_dek()?;
//! let plaintext = vec![7_u8; 100_000];
//!
//! let mut encryptor = cipher.stream_encryptor_bare(b"backups/2026-10", &dek)?;
//! let mut stored = encryptor.header().to_vec();
//! stored.extend(encryptor.push(&plaintext)?);
//! stored.extend(encryptor.finish()?);
//!
//! let plan = StreamFormat::Bare.plan_chunk_read(stored.len() as u64, 40_000..40_010)?;
//! let decryptor = cipher.stream_decryptor_bare(
//!     b"backups/2026-10",
//!     &stored[..StreamFormat::Bare.header_len()],
//!     &dek,
//! )?;
//! let bytes = &stored[plan.ciphertext().start as usize..plan.ciphertext().end as usize];
//! let decrypted: Vec<u8> = decryptor.decrypt_chunk_read(&plan, bytes)?;
//! assert_eq!(decrypted, plaintext[40_000..40_010]);
//! # Ok(())
//! # }
//! ```

use std::fmt::{Debug, Formatter};

use secret_vault_value::SecretValue;
use subtle::ConstantTimeEq;

use crate::backends::{AeadBackend, Failure};
use crate::errors::{KmsAeadEncryptionError, KmsAeadError};
use crate::formats::envelope::envelope_header;
use crate::formats::{split_tink_output_prefix, tink_output_prefix};
use crate::types::checked_key_bytes;
use crate::{
    AeadCipher, DataEncryptionKey, EncryptedDataEncryptionKey, KeyId, KmsAeadResult, Plaintext,
};

mod adapters;
mod byte_streams;
mod cipher;
mod gatherer;
mod header;
mod layout;

#[cfg(test)]
pub(crate) mod tests;
#[cfg(test)]
mod vectors;

#[doc(hidden)]
pub use adapters::__read_header;
pub use adapters::{decrypt_stream, encrypt_stream, DecryptingReader, EncryptingWriter};
#[doc(hidden)]
pub use byte_streams::__HeaderGatherer;
pub use byte_streams::{DecryptingStream, EncryptingStream};
pub use header::{EnvelopeStreamHeader, PrefixedStreamHeader};
pub use layout::{ChunkReadPlan, StreamFormat};

use cipher::{ChunkCipher, Salt, CHUNK_ALGORITHM, STREAM_SALT_LEN};
pub(crate) use header::CobblestoneHeader;

/// The header of the prefixed form: the prefix and the Cobblestone header.
pub(crate) const PREFIXED_HEADER_LEN: usize = 61;
/// The header of the bare form: the Cobblestone header alone.
pub(crate) const BARE_HEADER_LEN: usize = 56;
/// The plaintext of a full chunk.
pub const STREAM_CHUNK_LEN: usize = 16_384;
/// A full chunk as stored: [`STREAM_CHUNK_LEN`] and the tag.
pub const STORED_STREAM_CHUNK_LEN: usize = 16_400;
/// The chunks a value holds at most.
pub const MAX_STREAM_CHUNKS: u64 = 1 << 38;

/// `STREAM_ALGORITHM` unless `cipher`'s algorithm is AES-256-GCM, the one algorithm of a streamed
/// value, for kms-aead-keyring to check before it calls the KMS. Not part of the API, so it changes
/// only in a minor release of kms-aead, which kms-aead-keyring requires to match its own.
#[doc(hidden)]
pub fn __check_stream_algorithm<B: AeadBackend>(cipher: &AeadCipher<B>) -> KmsAeadResult<()> {
    cipher.check_stream_algorithm()
}

/// Encrypts one value from plaintext given in pieces of any size, without knowing its length in
/// advance. The value is [`header`](Self::header), then the bytes of every
/// [`push`](Self::push), then [`finish`](Self::finish).
///
/// The encryptor holds at most one chunk of plaintext, in one buffer of [`STORED_STREAM_CHUNK_LEN`]
/// bytes allocated once and zeroised when it is dropped, in which a full chunk is encrypted in
/// place with its tag; the derived key is zeroised too. An error leaves the encryptor unusable:
/// every later call returns it again, and the value is encrypted again from the start with a new
/// encryptor.
///
/// `Send`. `Debug` shows the form, the key id of a prefixed value and the chunk index, no key.
/// It is not `Clone`, since a second encryptor in the same state would encrypt other bytes under a
/// nonce already used:
///
/// ```compile_fail,E0599
/// use kms_aead::backends::AeadBackend;
/// use kms_aead::stream::StreamEncryptor;
///
/// fn duplicate<B: AeadBackend>(encryptor: StreamEncryptor<B>) -> StreamEncryptor<B> {
///     encryptor.clone()
/// }
/// ```
pub struct StreamEncryptor<B> {
    form: StreamFormat,
    cipher: ChunkCipher<B>,
    /// `form.header_len()` bytes: the key reference of the form, then the Cobblestone header.
    header: Vec<u8>,
    /// [`STORED_STREAM_CHUNK_LEN`] bytes: the plaintext of the chunk in progress, then that chunk
    /// encrypted in place with its tag.
    buffer: SecretValue,
    state: EncryptorState,
    /// The index of the chunk in progress.
    next_index: u64,
}

/// What the encryptor's buffer holds.
enum EncryptorState {
    /// `held` bytes of the plaintext of chunk `next_index`, fewer than [`STREAM_CHUNK_LEN`].
    Filling { held: usize },
    /// An encrypted chunk of `len` bytes, not yet taken: chunk `next_index - 1`, the final chunk
    /// when `last`.
    Encrypted { len: usize, last: bool },
    /// Nothing more: the final chunk has been taken.
    Finished,
    /// An encryption failed, and every later call returns its error.
    Failed(KmsAeadError),
}

/// The key reference a streamed value carries in front of its Cobblestone header, which makes
/// its form; a bare value carries none.
pub(crate) enum KeyReference<'a> {
    /// Tink's output prefix naming the key id: the prefixed form.
    KeyId(KeyId),
    /// The encrypted DEK in the framing of Tink's KMS envelope: the envelope form.
    EncryptedDek(&'a EncryptedDataEncryptionKey),
}

impl<B: AeadBackend> StreamEncryptor<B> {
    /// An encryptor under `dek` and `aad` with a salt from the backend's CSPRNG, of a value that
    /// carries `reference`, or of a bare one for `None`.
    pub(crate) fn new(
        aead: &AeadCipher<B>,
        reference: Option<KeyReference<'_>>,
        aad: &[u8],
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<Self> {
        let dek = aead.stream_key(dek)?;
        let random = B::generate_random_bytes(STREAM_SALT_LEN)?;
        let mut salt: Salt = [0; STREAM_SALT_LEN];
        salt.copy_from_slice(random.as_sensitive_bytes());
        Self::with_salt(reference, aad, dek, &salt)
    }

    /// An encryptor with `salt`, which must not repeat under `dek`: two values encrypted with one
    /// salt, one DEK and one AAD share their key and nonces.
    ///
    /// # Errors
    ///
    /// `INVALID_CIPHER_TEXT_FORMAT` for an encrypted DEK that is not 1 to 4,096 bytes, and
    /// `ENCRYPT_KEY` when the backend fails to derive the key.
    fn with_salt(
        reference: Option<KeyReference<'_>>,
        aad: &[u8],
        dek: &[u8],
        salt: &Salt,
    ) -> KmsAeadResult<Self> {
        let (form, mut header) = match reference {
            None => (StreamFormat::Bare, Vec::new()),
            Some(KeyReference::KeyId(key_id)) => {
                (StreamFormat::Prefixed, tink_output_prefix(key_id).to_vec())
            }
            Some(KeyReference::EncryptedDek(encrypted_dek)) => (
                StreamFormat::Envelope {
                    encrypted_dek_len: encrypted_dek.value().len(),
                },
                envelope_header(encrypted_dek)?,
            ),
        };
        let (cipher, commitment) =
            ChunkCipher::derive(dek, salt, aad).map_err(|_| Failure::Key.encrypting())?;
        header.extend_from_slice(
            &CobblestoneHeader {
                salt: *salt,
                commitment,
            }
            .to_bytes(),
        );
        Ok(Self {
            form,
            cipher,
            header,
            buffer: SecretValue::new(vec![0; STORED_STREAM_CHUNK_LEN]),
            state: EncryptorState::Filling { held: 0 },
            next_index: 0,
        })
    }

    #[cfg(test)]
    fn starting_at(self, index: u64) -> Self {
        Self {
            next_index: index,
            ..self
        }
    }

    /// Takes the next bytes of the plaintext and returns the full chunks they complete, zero or
    /// more, each [`STORED_STREAM_CHUNK_LEN`] bytes, to write after the header and the chunks
    /// returned before.
    ///
    /// # Errors
    ///
    /// `STREAM_LENGTH` when the value would need a chunk after index 2^38 - 1, and `ENCRYPT`
    /// when the backend fails to encrypt.
    pub fn push(&mut self, plaintext: &[u8]) -> KmsAeadResult<Vec<u8>> {
        let held = match &self.state {
            EncryptorState::Filling { held } => *held,
            EncryptorState::Failed(error) => return Err(error.clone()),
            EncryptorState::Encrypted { .. } | EncryptorState::Finished => {
                return Err(KmsAeadEncryptionError::create(
                    "ENCRYPT",
                    "The encryptor has encrypted its final chunk",
                ))
            }
        };
        let full_chunks = held.saturating_add(plaintext.len()) / STREAM_CHUNK_LEN;
        let mut encrypted = Vec::with_capacity(full_chunks.saturating_mul(STORED_STREAM_CHUNK_LEN));
        let mut rest = plaintext;
        while !rest.is_empty() {
            let taken = self.take_plaintext(rest)?;
            encrypted.extend_from_slice(self.encrypted_chunk());
            self.release_encrypted();
            rest = &rest[taken..];
        }
        Ok(encrypted)
    }

    /// The final chunk, 16 to 16,399 bytes: the tag and the plaintext the encryptor still held, to
    /// write after every chunk [`push`](Self::push) returned. A value with no plaintext is the
    /// header and one tag.
    ///
    /// # Errors
    ///
    /// `ENCRYPT` when the backend fails to encrypt.
    pub fn finish(mut self) -> KmsAeadResult<Vec<u8>> {
        self.encrypt_final()?;
        Ok(self.encrypted_chunk().to_vec())
    }

    /// The part of the buffer that the plaintext of the chunk in progress still fills: empty
    /// unless the encryptor is filling a chunk.
    fn plaintext_space(&mut self) -> &mut [u8] {
        match self.state {
            EncryptorState::Filling { held } => {
                &mut self.buffer.ref_sensitive_value_mut()[held..STREAM_CHUNK_LEN]
            }
            _ => &mut [],
        }
    }

    /// Counts `taken` bytes written into [`plaintext_space`](Self::plaintext_space) as held, and
    /// encrypts the chunk in place once it holds [`STREAM_CHUNK_LEN`] bytes.
    fn commit_plaintext(&mut self, taken: usize) -> KmsAeadResult<()> {
        let held = match &self.state {
            EncryptorState::Filling { held } => held + taken,
            EncryptorState::Failed(error) => return Err(error.clone()),
            EncryptorState::Encrypted { .. } | EncryptorState::Finished => return Ok(()),
        };
        if held < STREAM_CHUNK_LEN {
            self.state = EncryptorState::Filling { held };
            return Ok(());
        }
        if self.next_index >= MAX_STREAM_CHUNKS - 1 {
            return self.fail(KmsAeadEncryptionError::stream_length(
                "A full chunk at index 2^38 - 1 leaves no index for the final chunk",
            ));
        }
        self.encrypt_held(held, false)
    }

    /// Copies as much of `plaintext` as the chunk in progress takes into the buffer, and encrypts
    /// the chunk once it is full. Returns how many bytes it took, none while an encrypted chunk
    /// waits.
    fn take_plaintext(&mut self, plaintext: &[u8]) -> KmsAeadResult<usize> {
        let space = self.plaintext_space();
        let taken = space.len().min(plaintext.len());
        space[..taken].copy_from_slice(&plaintext[..taken]);
        self.commit_plaintext(taken)?;
        Ok(taken)
    }

    /// Encrypts the plaintext still held as the final chunk, in place. An encryptor that has
    /// encrypted its final chunk already leaves it as it is.
    fn encrypt_final(&mut self) -> KmsAeadResult<()> {
        match &self.state {
            EncryptorState::Filling { held } => self.encrypt_held(*held, true),
            EncryptorState::Failed(error) => Err(error.clone()),
            EncryptorState::Encrypted { .. } | EncryptorState::Finished => Ok(()),
        }
    }

    fn encrypt_held(&mut self, held: usize, last: bool) -> KmsAeadResult<()> {
        let (chunk, rest) = self.buffer.ref_sensitive_value_mut().split_at_mut(held);
        match self.cipher.encrypt_in_place(self.next_index, chunk) {
            Ok(tag) => {
                rest[..tag.len()].copy_from_slice(&tag);
                self.state = EncryptorState::Encrypted {
                    len: held + tag.len(),
                    last,
                };
                self.next_index += 1;
                Ok(())
            }
            Err(failure) => self.fail(failure.encrypting()),
        }
    }

    fn fail(&mut self, error: KmsAeadError) -> KmsAeadResult<()> {
        self.state = EncryptorState::Failed(error.clone());
        Err(error)
    }

    /// The encrypted chunk waiting in the buffer, empty when there is none.
    fn encrypted_chunk(&self) -> &[u8] {
        match self.state {
            EncryptorState::Encrypted { len, .. } => &self.buffer.as_sensitive_bytes()[..len],
            _ => &[],
        }
    }

    /// Frees the buffer of the encrypted chunk once it has been written.
    fn release_encrypted(&mut self) {
        if let EncryptorState::Encrypted { last, .. } = self.state {
            self.state = if last {
                EncryptorState::Finished
            } else {
                EncryptorState::Filling { held: 0 }
            };
        }
    }

    /// The failure that left the encryptor unusable.
    fn failure(&self) -> Option<&KmsAeadError> {
        match &self.state {
            EncryptorState::Failed(error) => Some(error),
            _ => None,
        }
    }
}

impl<B> StreamEncryptor<B> {
    /// The form the encryptor writes.
    pub fn form(&self) -> StreamFormat {
        self.form
    }

    /// The header, the first bytes of the value, to write before the chunks:
    /// `form().header_len()` bytes, 61 in the prefixed form, 56 in the bare form and `4 + w + 56`
    /// in the envelope form.
    pub fn header(&self) -> &[u8] {
        &self.header
    }
}

/// The form, the key id of a prefixed value and the chunk index, no key.
impl<B> Debug for StreamEncryptor<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("StreamEncryptor");
        debug.field("form", &self.form);
        if let (StreamFormat::Prefixed, Some((key_id, _))) =
            (self.form, split_tink_output_prefix(&self.header))
        {
            debug.field("key_id", &key_id);
        }
        debug
            .field("chunk_index", &self.next_index)
            .finish_non_exhaustive()
    }
}

/// Decrypts the chunks of one value, any of them, in any order and from any thread: its methods
/// take `&self`. It holds the key and the base nonce derived for the value, zeroised on drop, and
/// the value's form, and no length. A sequential read, through [`DecryptingStream`],
/// [`DecryptingReader`] or [`decrypt_stream`], finds the final chunk at the end of its source. A
/// ranged read is planned by the value's [`StreamFormat`] from the stored length, and the decryptor
/// takes the plan back in [`decrypt_chunk_read`](Self::decrypt_chunk_read).
///
/// A caller makes one decryptor per request, in an `Arc`, and shares it between the ranges that
/// request serves and a [`DecryptingReader`] over the whole value. The decryptor decrypts until it
/// is dropped, whatever becomes of the key it was made from, so one cached across requests outlives
/// a shred of its keyring.
///
/// `Send + Sync`. Not `Clone`. `Debug` shows the form, no key.
pub struct StreamDecryptor<B> {
    form: StreamFormat,
    cipher: ChunkCipher<B>,
}

impl<B: AeadBackend> StreamDecryptor<B> {
    /// The decryptor of the value in `form` whose Cobblestone header is `header`, under `dek` and
    /// `aad`: the key, then the commitment.
    pub(crate) fn new(
        aead: &AeadCipher<B>,
        form: StreamFormat,
        header: &CobblestoneHeader,
        aad: &[u8],
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<Self> {
        let dek = aead.stream_key(dek)?;
        let (cipher, commitment) =
            ChunkCipher::derive(dek, &header.salt, aad).map_err(|_| Failure::Key.decrypting())?;
        if bool::from(commitment.ct_eq(&header.commitment)) {
            Ok(Self { form, cipher })
        } else {
            Err(KmsAeadEncryptionError::stream_key_commitment())
        }
    }

    /// The form of the value: the one the call that made the decryptor named. Its
    /// [`header_len`](StreamFormat::header_len) is the offset of chunk 0 in every plan.
    pub fn form(&self) -> StreamFormat {
        self.form
    }

    /// The chunks of `plan` decrypted in order and cut to the range the plan was made for, as a
    /// `T`; `bytes` is exactly the bytes of `plan.ciphertext()`. An empty plan with no bytes
    /// gives the `T` of no bytes.
    ///
    /// Each chunk is decrypted in a working buffer of its own, zeroised once the plan is decrypted,
    /// and only the bytes of the range are copied into the `T`, which holds nothing else. A
    /// `SecretValue` is zeroised when it is dropped and a `Vec<u8>` is the caller's to keep. The
    /// `T` decodes the cut bytes as they are: `JsonEncoded<T>`, `bool` and the integers decode a whole
    /// value only from the plan of the whole plaintext, and a `String` decodes any range that cuts
    /// no multi-byte character, failing with `INVALID_PLAINTEXT` on one that does.
    ///
    /// # Errors
    ///
    /// `STREAM_RANGE` for a plan of a value in another form, `STREAM_LENGTH` when `bytes` has
    /// another length than `plan.ciphertext()`, `DECRYPT` on the first chunk that is not authentic,
    /// with nothing of the chunks before it returned, and `INVALID_PLAINTEXT` when the cut bytes
    /// are not an encoding of `T`.
    pub fn decrypt_chunk_read<T: Plaintext>(
        &self,
        plan: &ChunkReadPlan,
        bytes: &[u8],
    ) -> KmsAeadResult<T> {
        let layout = plan.layout();
        if layout.form() != self.form {
            return Err(KmsAeadEncryptionError::stream_range(
                "The chunk read plan is of a value in another form",
            ));
        }
        let ciphertext = plan.ciphertext();
        if bytes.len() as u64 != ciphertext.end - ciphertext.start {
            return Err(KmsAeadEncryptionError::stream_length(
                "The bytes given are not the stored bytes of the chunk read plan",
            ));
        }
        let wanted = plan.plaintext();
        let cut = plaintext_len_as_usize(wanted.start - plan.plaintext_start())?
            ..plaintext_len_as_usize(wanted.end - plan.plaintext_start())?;
        let mut decrypted = SecretValue::new(Vec::with_capacity(cut.len()));
        let mut working = SecretValue::new(Vec::with_capacity(STORED_STREAM_CHUNK_LEN));
        let (mut chunk_start, mut chunk_offset) = (0, 0);
        for index in plan.chunks() {
            let chunk_end = chunk_start + layout.encrypted_chunk_len(index)?;
            let buffer = working.ref_sensitive_value_mut();
            buffer.clear();
            buffer.extend_from_slice(bytes.get(chunk_start..chunk_end).ok_or_else(|| {
                KmsAeadEncryptionError::stream_length(
                    "The bytes given are not the stored bytes of the chunk read plan",
                )
            })?);
            let len = self
                .decrypt_in_place(index, buffer)
                .map_err(Failure::decrypting)?;
            let in_chunk = chunk_offset..chunk_offset + len;
            let from = cut.start.clamp(in_chunk.start, in_chunk.end) - chunk_offset;
            let to = cut.end.clamp(in_chunk.start, in_chunk.end) - chunk_offset;
            decrypted
                .ref_sensitive_value_mut()
                .extend_from_slice(&buffer[from..to]);
            chunk_start = chunk_end;
            chunk_offset = in_chunk.end;
        }
        T::from_plaintext(decrypted)
    }

    /// Decrypts chunk `index`, the stored bytes `chunk` holds, in place, and returns the length of
    /// its plaintext at the start of `chunk`. Every chunk the decryptor and its adapters decrypt
    /// goes through here.
    fn decrypt_in_place(&self, index: u64, chunk: &mut [u8]) -> Result<usize, Failure> {
        self.cipher.decrypt_in_place(index, chunk)
    }
}

/// The form, no key.
impl<B> Debug for StreamDecryptor<B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StreamDecryptor")
            .field("form", &self.form)
            .finish_non_exhaustive()
    }
}

/// `len` bytes of plaintext as a length in memory.
///
/// # Errors
///
/// `STREAM_RANGE` for a length past the address space, which no buffer can hold.
fn plaintext_len_as_usize(len: u64) -> KmsAeadResult<usize> {
    usize::try_from(len).map_err(|_| {
        KmsAeadEncryptionError::stream_range("The plaintext range is larger than memory")
    })
}

/// The stream calls: their parameters follow `encrypt` and `decrypt`, the key id first where
/// there is one, then the AAD, then the value's own bytes or lengths, and the DEK last. They open
/// no span, as the other calls of `AeadCipher` do not.
impl<B: AeadBackend> AeadCipher<B> {
    /// An encryptor of one new value under `dek` and `aad`, whose header names it by `key_id`, with
    /// a salt from the backend's CSPRNG. The value decrypts only with the same DEK and AAD.
    ///
    /// # Errors
    ///
    /// `STREAM_ALGORITHM` when the cipher's algorithm is not AES-256-GCM, `INVALID_KEY_LENGTH`
    /// when `dek` is not 32 bytes, `RANDOM_GENERATOR` when the CSPRNG fails, and `ENCRYPT_KEY`
    /// when the backend fails to derive the key.
    pub fn stream_encryptor(
        &self,
        key_id: KeyId,
        aad: &(impl AsRef<[u8]> + ?Sized),
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<StreamEncryptor<B>> {
        StreamEncryptor::new(self, Some(KeyReference::KeyId(key_id)), aad.as_ref(), dek)
    }

    /// A decryptor of the value `header` starts, encrypted under `dek` and `aad`. The caller picks
    /// `dek` by [`header.key_id()`](PrefixedStreamHeader::key_id). The decryptor checks the key
    /// commitment before any chunk is read.
    ///
    /// # Errors
    ///
    /// `STREAM_ALGORITHM`, `INVALID_KEY_LENGTH`, `DECRYPT_KEY` when the backend fails to derive the
    /// key, and `STREAM_KEY_COMMITMENT` when `dek`, `aad` or the header's bytes are not the ones
    /// the value was encrypted with.
    pub fn stream_decryptor(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        header: &PrefixedStreamHeader,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<StreamDecryptor<B>> {
        StreamDecryptor::new(
            self,
            StreamFormat::Prefixed,
            &header.cobblestone(),
            aad.as_ref(),
            dek,
        )
    }

    /// [`stream_encryptor`](Self::stream_encryptor) for the bare form: an encryptor of one new
    /// value under `dek` and `aad` with no prefix, whose [`header`](StreamEncryptor::header) is the
    /// 56 bytes of the Cobblestone header. The caller keeps any key id itself, as with
    /// [`encrypt_bare`](Self::encrypt_bare).
    ///
    /// # Errors
    ///
    /// The errors of [`stream_encryptor`](Self::stream_encryptor).
    pub fn stream_encryptor_bare(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<StreamEncryptor<B>> {
        StreamEncryptor::new(self, None, aad.as_ref(), dek)
    }

    /// [`stream_decryptor`](Self::stream_decryptor) for the bare form: a decryptor of the value
    /// whose first 56 bytes are `header`, encrypted under `dek` and `aad`.
    ///
    /// # Errors
    ///
    /// `INVALID_CIPHER_TEXT_FORMAT` when `header` is not 56 bytes, before anything else, then
    /// the errors of [`stream_decryptor`](Self::stream_decryptor).
    pub fn stream_decryptor_bare(
        &self,
        aad: &(impl AsRef<[u8]> + ?Sized),
        header: &[u8],
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<StreamDecryptor<B>> {
        StreamDecryptor::new(
            self,
            StreamFormat::Bare,
            &CobblestoneHeader::try_from(header)?,
            aad.as_ref(),
            dek,
        )
    }

    /// `STREAM_ALGORITHM` unless the cipher's algorithm is AES-256-GCM, the one algorithm of a
    /// streamed value, for a caller to check before it calls the KMS.
    pub(crate) fn check_stream_algorithm(&self) -> KmsAeadResult<()> {
        if self.algorithm() == CHUNK_ALGORITHM {
            Ok(())
        } else {
            Err(KmsAeadEncryptionError::stream_algorithm(self.algorithm()))
        }
    }

    /// The bytes of `dek` as the key of a streamed value, checked against the format's one
    /// algorithm before any key is derived.
    fn stream_key<'k>(&self, dek: &'k DataEncryptionKey) -> KmsAeadResult<&'k [u8]> {
        self.check_stream_algorithm()?;
        checked_key_bytes(
            dek.value().ref_sensitive_value(),
            CHUNK_ALGORITHM,
            CHUNK_ALGORITHM.key_len(),
        )
    }
}
