# Streaming encryption

Feature `stream`.

The library encrypts a value of any length as a streamed value: a header, then chunks of 16 KiB,
each one authenticated on its own and bound to its position. A writer encrypts a value whose length
it does not know in advance, holding one chunk in memory. A reader decrypts any byte range by
fetching only the chunks that cover it.

Streaming fits files, uploads, backups and other objects in a store that serves `Range` requests.
Fields of a record are `Encrypted` values, see [Stored values](./stored-values.md).

The value comes in three forms, which differ in the bytes in front of the Cobblestone message: the
salt, the key commitment and the chunks that every form shares, see [Format](#format).

- the prefixed form starts with Tink's output prefix, `0x01` and a key id, as every keyring value
  does. `AeadCipher::stream_encryptor` writes it, and it is the only form a keyring writes and
  reads;
- the envelope form starts with the encrypted DEK, as Tink's KMS envelope does, so the value
  decrypts with nothing stored beside it. `KmsAeadEnvelope::stream_encryptor` writes it;
- the bare form is the Cobblestone message alone, for a caller that keeps the key id or the
  encrypted DEK itself. The `_bare` calls of `AeadCipher` and `KmsAeadEnvelope` write it.

Every form uses AES-256-GCM, so the DEK is 32 bytes. The derivation binds the AAD into the value, and
the decryptor refuses a wrong key, a wrong AAD or a modified header with `STREAM_KEY_COMMITMENT`
before it decrypts a chunk.

## Encrypting and decrypting

A value that arrives as a `Stream` of `Bytes`, such as a request body or an object-store download,
goes through two types that need no bridge to tokio's I/O traits, and comes back out as a `Stream`.
Each holds one chunk in memory, whatever the length of the value:

- `EncryptingStream` takes a `Stream` of plaintext and yields the value: the header first, then
  one item per chunk, the final chunk when its source ends;
- `DecryptingStream` takes the stored bytes after the header and yields the plaintext, one item
  per chunk, and only once the chunk is authentic. It reads its source to the end, which is the
  end of the value.

Both yield `KmsAeadResult<Bytes>`. A value that is cut, modified or extended ends in an error item,
`STREAM_LENGTH` or `DECRYPT`, never in a clean end. The error is the last item. An error of the
source is `STREAM_IO`. A source that is not `Unpin` goes through `Box::pin`.

The encryptor and the decryptor come from the cipher: `AeadCipher::stream_encryptor` and
`stream_decryptor` make the prefixed form, `stream_encryptor_bare` and `stream_decryptor_bare` the
bare one. A decryptor is made from the header and the DEK.

A value read from start to end needs no stored length. Every chunk but the last is 16,400 bytes as
stored and the last one is shorter, so a chunk is decrypted as soon as 16,400 bytes of it have
arrived, and the bytes left when the source ends are the final chunk. A value cut at a chunk
boundary, or less than a tag (16 bytes) into a chunk, ends without that shorter chunk,
`STREAM_LENGTH`. A value cut further into a chunk, or followed by more bytes, ends in a final chunk
that is not authentic, `DECRYPT`. A ranged read does
need the stored length: it fetches the chunks of a range without reading what comes before, so only
the length tells it where the final chunk is and how long it is, see
[Reading a range](#reading-a-range).

```rust
# use kms_aead::backends::Ring;
# use kms_aead::{AeadAlgorithm, AeadCipher};
use std::sync::Arc;

use bytes::Bytes;
use futures::{stream, StreamExt, TryStreamExt};
use kms_aead::stream::{DecryptingStream, EncryptingStream, StreamFormat};

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
# let dek = cipher.generate_dek()?;
let body = stream::iter([Bytes::from_static(b"a request "), Bytes::from_static(b"body")])
    .map(Ok::<_, std::io::Error>);
let encryptor = cipher.stream_encryptor_bare(b"upload/7/file", &dek)?;
let stored: Vec<Bytes> = EncryptingStream::new(encryptor, body).try_collect().await?;
let stored = stored.concat();

let header_len = StreamFormat::Bare.header_len();
let header = &stored[..header_len];
let decryptor = cipher.stream_decryptor_bare(b"upload/7/file", header, &dek)?;
let after_header = stream::iter([Bytes::copy_from_slice(&stored[header_len..])]).map(Ok::<_, std::io::Error>);
let response: Vec<Bytes> = DecryptingStream::new(Arc::new(decryptor), after_header).try_collect().await?;
# assert_eq!(response.concat(), b"a request body");
# Ok(())
# }
```

A caller that holds the whole stored value from its first byte, such as a download, does not split
the header off: `KmsAeadEnvelope` and `Keyring` have `decrypting_stream` and `decrypting_reader`,
which read the header from the front of the source, make the decryptor and return the stream or the
reader positioned at the first chunk, see [With an envelope](#with-an-envelope) and
[With a keyring](#with-a-keyring).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/stream_body.rs).

## The tokio adapters

Two wrapper types and two functions put the encryptor and the decryptor on tokio's `AsyncWrite` and
`AsyncRead`. Each holds one chunk in memory, whatever the length of the value:

- `EncryptingWriter` encrypts what is written to it and writes the value to a sink. Call `shutdown`
  on it: only the shutdown writes the final chunk;
- `DecryptingReader` reads a value from a source positioned after the header and yields its
  plaintext;
- `encrypt_stream` and `decrypt_stream` run a whole source through a writer or a reader into a sink.

A `std::io::Error` that a wrapper returns for a failure of the value, such as a chunk that is not
authentic, carries the `KmsAeadError` as its inner error: `error.get_ref()` and
`downcast_ref::<KmsAeadError>()` find it.

## Reading a range

A ranged read has three steps:

- `plan_chunk_read` on the value's `StreamFormat` takes the stored length of the value, as the
  store reports it, and a plaintext range, and returns a `ChunkReadPlan`: the chunks that cover the
  range and the stored bytes to fetch. `..` is the whole plaintext. It needs no key, so a stored
  length that the length rules refuse fails before any KMS call. `StreamFormat::Prefixed` and
  `StreamFormat::Bare` are the prefixed and bare forms, and `EnvelopeStreamHeader::form` is the
  form of an envelope value;
- the caller fetches `plan.ciphertext()` from the store, a byte range counted from the start of the
  value;
- `decrypt_chunk_read` on a decryptor takes the plan and the fetched bytes, and returns the
  plaintext of exactly the range asked for, as a `Plaintext` type: `Vec<u8>` or `SecretValue`.

One zip entry of 63 KB at offset 1,000,000 of a value of 5,000,000 bytes covers four chunks, and
the read fetches 65,600 bytes. An entry that starts in the last byte of a chunk covers five chunks.

```rust
# use kms_aead::backends::Ring;
# use kms_aead::stream::StreamFormat;
# use kms_aead::{AeadAlgorithm, AeadCipher};
use kms_aead::stream::encrypt_stream;
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
let dek = cipher.generate_dek()?;
# let plaintext = vec![7_u8; 5_000_000];
# let source = &plaintext[..];

// Encrypting: the bare form, with a DEK the caller holds, from any `AsyncRead` such as a file
let encryptor = cipher.stream_encryptor_bare(b"backups/2026-10", &dek)?;
let mut stored = Vec::new();
encrypt_stream(encryptor, source, &mut stored).await?;

// Decrypting: the stored length goes into the plan, which needs no key, and the header comes from
// the store
let plan = StreamFormat::Bare.plan_chunk_read(stored.len() as u64, 1_000_000..1_064_512)?;
assert_eq!(plan.chunks(), 61..65);
assert_eq!(plan.ciphertext(), 1_000_456..1_066_056);

let fetched = &stored[plan.ciphertext().start as usize..plan.ciphertext().end as usize];
let decryptor = cipher.stream_decryptor_bare(
    b"backups/2026-10",
    &stored[..StreamFormat::Bare.header_len()],
    &dek,
)?;
let entry: Vec<u8> = decryptor.decrypt_chunk_read(&plan, fetched)?;
# assert_eq!(entry, plaintext[1_000_000..1_064_512]);
# Ok(())
# }
```

Make one decryptor per request, in an `Arc`: its methods take `&self`, and the ranges, threads and
`DecryptingReader` of that request share it. The header is read once per request and no range
fetches it again. Do not cache the decryptor across requests: it decrypts until it is dropped, see
[Limits](#limits).

## With an envelope

Streamed values come in the same modes as other values, an envelope or a keyring, see
[Choosing a mode](./intro.md#choosing-a-mode). An envelope chooses and encrypts the DEK as
`encrypt` does, and writes one of two forms:

- `stream_encryptor` writes the envelope form, one object that holds everything a reader needs. A
  reader learns the header's length from its first 4 bytes, the length `w` of the encrypted DEK,
  and every chunk sits `4 + w` bytes after its place in the bare form. A KEK rotation rewrites
  every object;
- `stream_encryptor_bare` writes the bare form and returns the encrypted DEK, which the application
  stores beside the object, such as in its metadata or its database row. The chunks sit at fixed
  offsets, and a KEK rotation re-encrypts the stored DEKs with `reencrypt_encrypted_dek` and leaves
  the objects as they are.

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::KmsAeadEnvelope;
use kms_aead::stream::{encrypt_stream, EnvelopeStreamHeader};
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("backups".to_string())?)?;
# let plaintext = vec![7_u8; 5_000_000];
# let source = &plaintext[..];
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

// Encrypting: the envelope form, with the encrypted DEK inside the value, from any `AsyncRead`
let encryptor = envelope.stream_encryptor(b"backups/2026-10").await?;
let mut stored = Vec::new();
encrypt_stream(encryptor, source, &mut stored).await?;

// Decrypting: the header's length from its first 4 bytes, then the header
let header_len = EnvelopeStreamHeader::header_len(&stored[..4])?;
let header = EnvelopeStreamHeader::try_from(&stored[..header_len])?;
let plan = header.form().plan_chunk_read(stored.len() as u64, 1_000_000..1_064_512)?;
let fetched = &stored[plan.ciphertext().start as usize..plan.ciphertext().end as usize];
let decryptor = envelope.stream_decryptor(b"backups/2026-10", &header).await?;
let entry: Vec<u8> = decryptor.decrypt_chunk_read(&plan, fetched)?;
# assert_eq!(entry, plaintext[1_000_000..1_064_512]);
# Ok(())
# }
```

A caller that reads the value from its first byte fetches no header separately: `decrypting_stream`
takes the stored value as a `Stream` of `Bytes`, and `decrypting_reader` as an `AsyncRead`. Each
reads the first 4 bytes, `w`, and checks it before it reads on or calls the KMS, then reads the
header and returns the adapter at the first chunk.

```rust
# use bytes::Bytes;
# use futures::{stream, StreamExt, TryStreamExt};
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::stream::EncryptingStream;
# use kms_aead::KmsAeadEnvelope;
# #[tokio::main(flavor = "current_thread")]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("backups".to_string())?)?;
# let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
# let upload = stream::iter([Bytes::from_static(b"a request body")]).map(Ok::<_, std::io::Error>);
# let encryptor = envelope.stream_encryptor(b"backups/2026-10").await?;
# let stored: Vec<Bytes> = EncryptingStream::new(encryptor, upload).try_collect().await?;
# let download = stream::iter(stored).map(Ok::<_, std::io::Error>);
// The download streams the object from its first byte to its last
let response = envelope.decrypting_stream(b"backups/2026-10", download).await?;
let plaintext: Vec<Bytes> = response.try_collect().await?;
# assert_eq!(plaintext.concat(), b"a request body");
# Ok(())
# }
```

`stream_decryptor_bare` decrypts the bare form from its 56-byte header and the stored encrypted DEK,
see [Large files](./use-cases/large-files.md#the-dek-beside-the-object). Full example of reading a
range from both forms available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/stream_range_read.rs).

## With a keyring

The `stream` feature of kms-aead-keyring adds `Encryptor::stream_encryptor`,
`Keyring::stream_decryptor` and, for a value served whole, `Keyring::decrypting_stream` and
`decrypting_reader`, which read the 61-byte header from the front of the source. The first two
return the same `StreamEncryptor` and `StreamDecryptor`, in the prefixed form, under the active
version for a write and under the version the header names for a read. The keyring applies its
lifecycle states and its `compromised_reads` policy as `decrypt` does, and a `FieldAad` that carries
an `Interop` is refused, since neither Tink nor BigQuery reads a streamed value.

The lifecycle states and the policy apply when the decryptor is made. A decryptor holds the key
derived for its value, never the DEK, and keeps decrypting after the version is retired, destroyed
or flagged compromised, and after a shred of the keyring, until it is dropped. Make it per request,
as above, so that a shred takes effect for the next request. A request that serves only the whole
value, with no ranges, calls `decrypting_stream` or `decrypting_reader`, which make their own
decryptor.

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead_keyring::testing::MemoryKeyringStore;
# use kms_aead_keyring::{
#     EntityId, EntityKind, FieldName, FieldSpec, KeyringAlgorithms, KeyringId, KeyringRegistry,
#     KeyringRegistryOptions,
# };
use std::sync::Arc;

use kms_aead_keyring::stream::{
    ChunkReadPlan, DecryptingReader, EncryptingWriter, PrefixedStreamHeader, StreamDecryptor,
    StreamEncryptor, StreamFormat,
};
use tokio::io::AsyncWriteExt;
# /// An object of an object store that serves `Range` requests, held in memory.
# struct Object(Vec<u8>);
# impl Object {
#     async fn read(&self, range: std::ops::Range<u64>) -> std::io::Result<Vec<u8>> {
#         Ok(self.0[range.start as usize..range.end as usize].to_vec())
#     }
#     async fn read_from(&self, offset: u64) -> std::io::Result<&[u8]> {
#         Ok(&self.0[offset as usize..])
#     }
#     fn size(&self) -> u64 {
#         self.0.len() as u64
#     }
# }
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("uploads".to_string())?)?;
# let admin = registry
#     .open_or_create(provider, KeyringId::from_static("tenant-42"), KeyringAlgorithms::new())
#     .await?;
# let keyring = admin.keyring();
# let upload_id = EntityId::try_from("upload-7")?;
# let upload = vec![7_u8; 1_200_000];
# let mut body = &upload[..];
# let mut object_writer = Vec::new();

const UPLOAD_FILE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("upload"),
    FieldName::from_static("file"),
);

// Encrypting an upload: the length is not known in advance and nothing of the body is held whole
let aad = UPLOAD_FILE.aad(&upload_id);
let encryptor: StreamEncryptor<Ring> = keyring.encryptor().await.stream_encryptor(&aad).await?;
let mut writer = EncryptingWriter::new(encryptor, &mut object_writer);
tokio::io::copy(&mut body, &mut writer).await?;
writer.shutdown().await?;
let stored_len: u64 = writer.stored_len_written();
# let object = Object(object_writer);
# assert_eq!(object.size(), stored_len);

// Serving one zip entry: the plans first, from the store's size, so that a size the length rules
// refuse reaches neither the store nor the KMS
let last: ChunkReadPlan = StreamFormat::Prefixed.plan_final_chunk_read(object.size())?;
let plan: ChunkReadPlan = StreamFormat::Prefixed.plan_chunk_read(object.size(), 1_000_000..1_064_512)?;

// Then the header once and one decryptor per request, which reads the final chunk, so that the
// length is authentic before any range is served
let head: Vec<u8> = object.read(0..StreamFormat::Prefixed.header_len() as u64).await?;
let header = PrefixedStreamHeader::try_from(head.as_slice())?;
let decryptor: Arc<StreamDecryptor<Ring>> = Arc::new(keyring.stream_decryptor(&aad, &header).await?);
decryptor.decrypt_chunk_read::<Vec<u8>>(&last, &object.read(last.ciphertext()).await?)?;
let bytes: Vec<u8> = object.read(plan.ciphertext()).await?;
let entry: Vec<u8> = decryptor.decrypt_chunk_read(&plan, &bytes)?;

// The whole value as a response body, over the same decryptor
let body = DecryptingReader::new(
    decryptor.clone(),
    object.read_from(StreamFormat::Prefixed.header_len() as u64).await?,
);
# assert_eq!(entry, upload[1_000_000..1_064_512]);
# drop(body);
# registry.shutdown(None).await;
# Ok(())
# }
```

A write stores the encryption marker of the encryptor's record beside the object's own record, as
it does for fields, so that a sweep finds the object by the marker, see
[Sweeps](./operations/sweeps.md#the-encryption-marker).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/stream.rs).

## Driving the I/O yourself

`StreamEncryptor` and `StreamDecryptor` take bytes and return bytes, and read and write nothing
themselves, so they run under any runtime; the adapters above are built on them. An application that
reads its source with another runtime, or in a loop of its own, calls them directly.

An encryptor takes the plaintext in pieces of any size: the value is `header()`, the bytes every
`push` returns, then the bytes `finish` returns. A decryptor decrypts the chunks of a plan from
`plan_chunk_read`, as in [Reading a range](#reading-a-range), and `..` plans the whole value.

```rust
# use kms_aead::backends::Ring;
# use kms_aead::stream::StreamFormat;
# use kms_aead::{AeadAlgorithm, AeadCipher};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
# let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
# let dek = cipher.generate_dek()?;
let mut encryptor = cipher.stream_encryptor_bare(b"backups/2026-10", &dek)?;
let mut stored = encryptor.header().to_vec();
for piece in [b"first piece, ".as_slice(), b"second piece".as_slice()] {
    stored.extend(encryptor.push(piece)?);
}
stored.extend(encryptor.finish()?);

let header = &stored[..StreamFormat::Bare.header_len()];
let decryptor = cipher.stream_decryptor_bare(b"backups/2026-10", header, &dek)?;
let plan = StreamFormat::Bare.plan_chunk_read(stored.len() as u64, ..)?;
let plaintext: Vec<u8> = decryptor.decrypt_chunk_read(&plan, &stored[plan.ciphertext().start as usize..])?;
# assert_eq!(plaintext, b"first piece, second piece");
# Ok(())
# }
```

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/stream_range_read.rs).

## Limits

Be aware of these when serving streamed values:

- the stored length a ranged read plans with is the store's word until the final chunk has been
  decrypted. A store that cuts an object inside a chunk and reports the shorter size passes the
  length rules and every range that stays clear of the cut chunk. A range counted from the end of
  the value needs the final chunk first. Read the final chunk through `plan_final_chunk_read` once
  per object before the first range, or keep the length and a hash of the plaintext in a record
  you trust and compare the end of the final chunk's `plaintext()` with it;
- `DecryptingReader`, `DecryptingStream` and `decrypt_stream` yield the plaintext of a chunk as soon
  as the chunk is authentic, so a value cut or modified further on has already given its earlier
  bytes out when the error comes. Write to a place you can discard. A reader stopped before its clean end has
  authenticated the chunks it yielded and nothing of the length;
- the same three read their source to its end and decrypt the final chunk only then. Bytes after
  the value make its final chunk fail with `DECRYPT`, so a value inside a longer source goes
  through a source cut to its length, such as tokio's `AsyncReadExt::take`, and a source that
  stays open after the value holds its final chunk back;
- an `EncryptingWriter` dropped before its shutdown leaves a value that no reader decrypts whole;
- a decryptor keeps the key derived for its value until it is dropped, and decrypts with it after
  a shred, a destroy or a compromised flag of its version. A decryptor cached across requests
  outlives them, so build one per request;
- an encryptor, and an `EncryptingWriter` or `EncryptingStream` over it, keeps the key derived for
  its value until it is dropped: a compromised flag or a destroy of its version does not stop an
  upload in progress;
- `STREAM_IO` names a failure of the source or the sink of `encrypt_stream` or `decrypt_stream`,
  or of the source of an `EncryptingStream` or a `DecryptingStream`. The
  retry is the whole stream again from the start, with a new encryptor or a fresh read of the
  source;
- a streamed value is not an `Encrypted<T, F>`: it has no plaintext type and carries no signature
  or MAC. Origin or integrity that a party without the DEK can check is a detached `Signature<T>`
  or `Mac<T>` over a digest of the plaintext, see
  [Signatures and MACs](./signing.md);
- one DEK is an AES-256-GCM key for randomised values and the key of HMAC-SHA-512 for streamed
  values. A deployment that wants one key per primitive keeps a keyring for streamed values apart
  from the keyring of its fields;
- a sweep re-encrypts a streamed value whole: decrypt it under the version it names and encrypt it
  again under the active one. This release has no helper for that.

The errors a streamed value adds are in [Error handling](./errors.md#codes).

## Format

A streamed value is one message of [C2SP chunked encryption](https://c2sp.org/chunked-encryption),
Cobblestone-256: keys derived with HKDF-SHA-512 and chunks of AES-256-GCM. C2SP is the Community
Cryptography Specification Project, a home for small specifications that come with test vectors.
The prefixed form puts Tink's output prefix, 5 bytes, in front and the envelope form `4 + w` bytes
of the encrypted DEK, so an implementation of Cobblestone-256, such as the
[`cryptography.cobblestone`](https://cryptography.io/en/latest/cobblestone/) module of
pyca/cryptography, decrypts a prefixed value from offset 5 and an envelope-form value from offset
`4 + w`, with the DEK. The Go package
[filippo.io/cobblestone](https://pkg.go.dev/filippo.io/cobblestone) implements Cobblestone-128
only, on AES-128-GCM, and reads none of these values. The bytes, the length rules and the seeking
rules are in [Formats](./formats.md#streamed-values).

The library runs the 35 vectors of Project Wycheproof for the specification, in every form, on
every backend, see
[`c2sp_chunked_encryption_aes_256_gcm_test.json`](https://github.com/C2SP/wycheproof/blob/b61843a9a5115bb758134b6a1f5d5e502d445342/testvectors_v1/c2sp_chunked_encryption_aes_256_gcm_test.json).
