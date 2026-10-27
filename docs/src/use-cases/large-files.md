# Encrypt large files and serve ranges

Uploads of any size are encrypted as they arrive, with one chunk of 16 KiB in memory, and a reader
fetches only the chunks that cover the bytes it needs: one entry of a zip archive, or the range a
video player asks for. The object store holds the encrypted object and serves `Range` requests as it
does for any object. Feature `stream`, see [Streaming encryption](../streaming.md).

## Keyring or envelope

| | Keyring | Envelope |
|---|---|---|
| Key | the keyring's active version, named by a 4-byte key id in the object's header | a DEK of the object's own, or a reused one under a `DekReusePolicy` |
| Stored beside the object | the encryption marker, see [The encryption marker](../operations/sweeps.md#the-encryption-marker) | the encrypted DEK, in the object's metadata or in the row that names the object |
| KMS calls | one decryption per key version per DEK cache TTL | one encryption per new DEK, one decryption per object per DEK cache TTL |
| Rotation | the keyring's | the KEK's, by re-encrypting the stored DEKs |

Both give the same `StreamEncryptor` and `StreamDecryptor`. There is no size cap: the encryptor does
not need the length in advance.

## Upload

An `EncryptingWriter` wraps the sink that writes the object. Copy the request body into it and call
`shutdown`, which writes the final chunk; a writer dropped before its shutdown leaves an object
that no reader decrypts whole. The object's AAD names where it belongs, such as `upload/<id>/file`.
A handler that holds the body as a `Stream` of `Bytes` uses an `EncryptingStream` instead, see
[Encrypting and decrypting](../streaming.md#encrypting-and-decrypting).

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead_keyring::testing::MemoryKeyringStore;
# use kms_aead_keyring::{
#     EntityId, EntityKind, FieldName, FieldSpec, KeyringAlgorithms, KeyringId, KeyringRegistry,
#     KeyringRegistryOptions,
# };
use kms_aead_keyring::stream::{ChunkReadPlan, EncryptingWriter, PrefixedStreamHeader, StreamFormat};
use tokio::io::AsyncWriteExt;
# /// An object store that serves `Range` requests, held in memory.
# struct Store(Vec<u8>);
# impl Store {
#     fn get(&self, range: std::ops::Range<u64>) -> &[u8] {
#         &self.0[range.start as usize..range.end as usize]
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
# let mut body = &vec![7_u8; 1_200_000][..];
# let mut sink = Vec::new();

const UPLOAD_FILE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("upload"),
    FieldName::from_static("file"),
);
let aad = UPLOAD_FILE.aad(&EntityId::try_from("upload-7")?);

let encryptor = keyring.encryptor().await.stream_encryptor(&aad).await?;
let mut writer = EncryptingWriter::new(encryptor, &mut sink);
tokio::io::copy(&mut body, &mut writer).await?;
writer.shutdown().await?;
# let stored_len = writer.stored_len_written();
# let store = Store(sink);
# assert_eq!(store.size(), stored_len);

// Serving: plan from the size the store reports first, so that a length the rules refuse
// reaches neither the store nor the KMS. One zip entry, or the range of a video request
let last: ChunkReadPlan = StreamFormat::Prefixed.plan_final_chunk_read(store.size())?;
let plan = StreamFormat::Prefixed.plan_chunk_read(store.size(), 1_000_000..1_064_512)?;

// The header once per request, then the decryptor
let header = PrefixedStreamHeader::try_from(store.get(0..StreamFormat::Prefixed.header_len() as u64))?;
let decryptor = keyring.stream_decryptor(&aad, &header).await?;

// The final chunk authenticates the length the store reports before any range is served
decryptor.decrypt_chunk_read::<Vec<u8>>(&last, store.get(last.ciphertext()))?;
let entry: Vec<u8> = decryptor.decrypt_chunk_read(&plan, store.get(plan.ciphertext()))?;
# assert_eq!(entry.len(), 64_512);
# registry.shutdown(None).await;
# Ok(())
# }
```

A download that serves the whole object takes it from its first byte to its last with
`decrypting_stream` or `decrypting_reader` of the keyring or the envelope, and needs no stored
length, see [Encrypting and decrypting](../streaming.md#encrypting-and-decrypting).

## The DEK beside the object

An envelope takes the place of the keyring. `stream_encryptor_bare` returns the encrypted DEK with
the encryptor, and `stream_decryptor_bare` takes it back; the application stores it beside the
object and hands it to the reader. The rest is as above:

```rust
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead::stream::{EncryptingWriter, StreamFormat};
# use kms_aead::KmsAeadEnvelope;
# use tokio::io::AsyncWriteExt;
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("uploads".to_string())?)?;
# let mut body = &vec![7_u8; 1_200_000][..];
# let mut object = Vec::new();
let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
let aad = b"upload/7/file";

let (encryptor, encrypted_dek) = envelope.stream_encryptor_bare(aad).await?;
let mut writer = EncryptingWriter::new(encryptor, &mut object);
tokio::io::copy(&mut body, &mut writer).await?;
writer.shutdown().await?;
# let stored_len = writer.stored_len_written();

let header = &object[..StreamFormat::Bare.header_len()];
let decryptor = envelope.stream_decryptor_bare(aad, header, &encrypted_dek).await?;
# let last = StreamFormat::Bare.plan_final_chunk_read(stored_len)?;
# assert_eq!(last.plaintext().end, 1_200_000);
# Ok(())
# }
```

The envelope's `stream_encryptor`, without the `_bare` suffix, writes the encrypted DEK inside the
object instead, so that nothing is stored beside it, and `decrypting_stream` or `decrypting_reader`
reads the whole object back, see [Streaming encryption](../streaming.md#with-an-envelope). A
store-less envelope, one with a `DekReusePolicy`, encrypts many objects under one DEK in either
form.

## What to watch for

- The stored length a range is planned with is the object store's word until the final chunk has
  been decrypted. A store that cuts an object inside a chunk and reports the shorter size passes
  every range that stays clear of the cut. Read the final chunk through `plan_final_chunk_read`
  once per object before the first range. A zip reader that counts from the end of the archive
  needs it first;
- make one decryptor per request, in an `Arc`: its methods take `&self`. Do not cache it across
  requests: a decryptor, like an encryptor, keeps decrypting after a shred, a destroy or a
  compromised flag of its version until it is dropped, see
  [Streaming encryption](../streaming.md#limits);
- `DecryptingReader`, `DecryptingStream` and `decrypt_stream` yield the plaintext of a chunk as soon
  as the chunk is authentic, so write the response to a place you can discard. A failure of the source or the sink
  is `STREAM_IO`, and the retry is the whole stream again. They take the end of their source as
  the end of the object;
- the object carries no signature. A party without the DEK that must check it gets a `Signature<T>`
  over a document that lists the object's SHA-256 digest, see
  [Publish content anyone can verify](./publish-verifiable.md);
- a sweep re-encrypts a streamed object whole: decrypt it under the version it names and encrypt it
  again under the active one, with no helper.

The limits are in [Streaming encryption](../streaming.md#limits).

Full examples available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/stream.rs) for
a keyring, [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/stream_range_read.rs)
for reading a range from an envelope, and
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/stream_body.rs) for a request
body as a `Stream`.
