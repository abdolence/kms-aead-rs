//! Encrypts a request body on its way to an object store and decrypts a stored object into a
//! response body, as an axum or hyper handler does, with `Stream`s of `Bytes` and no tokio-util
//! bridge. The object is in the envelope form, so the encrypted DEK travels inside it and the
//! store keeps nothing beside it; `stream_range_read` keeps the bare form, with the encrypted DEK
//! in the object's metadata. The bodies are simulated with `futures::stream::iter`, so it needs no
//! server and no cloud credentials.
//!
//! ```sh
//! cargo run --example stream_body --features stream,ring
//! ```

use std::io;

use bytes::Bytes;
use futures::{stream, Stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::stream::EncryptingStream;
use kms_aead::{KmsAeadEnvelope, KmsAeadResult};

const AAD: &[u8] = b"uploads/7/report.pdf";

/// A body of `len` bytes that arrives in frames of 1,400 bytes, as it would off a socket.
fn request_body(len: usize) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
    let body: Vec<u8> = (0..len).map(|offset| (offset % 251) as u8).collect();
    let frames: Vec<Bytes> = body.chunks(1_400).map(Bytes::copy_from_slice).collect();
    stream::iter(frames).map(Ok)
}

/// An object store that keeps what an upload streams to it.
struct ObjectStore {
    object: Vec<u8>,
}

impl ObjectStore {
    /// The object in frames of 8,000 bytes, as a download streams it.
    fn download(&self) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
        let frames: Vec<Bytes> = self
            .object
            .chunks(8_000)
            .map(Bytes::copy_from_slice)
            .collect();
        stream::iter(frames).map(Ok)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("uploads-kek".to_string())?)?;
    let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;

    // The upload: the request body is encrypted into the stream the store receives.
    let body = request_body(1_000_000);
    let encryptor = envelope.stream_encryptor(AAD).await?;
    let mut upload = EncryptingStream::new(encryptor, body);
    let mut object = Vec::new();
    let mut items = 0;
    while let Some(item) = upload.next().await {
        object.extend_from_slice(&item?);
        items += 1;
    }
    let store = ObjectStore { object };
    println!(
        "upload: {items} items, {} stored bytes, the encrypted DEK among them",
        store.object.len()
    );

    // The download: the whole object is decrypted into the response body. The stream reads the
    // header, with the encrypted DEK, from the front of the download, and the final chunk is the one
    // the download ends in, so the object's size is not needed.
    let response_body = envelope.decrypting_stream(AAD, store.download()).await?;
    let frames: Vec<Bytes> = response_body.try_collect().await?;
    println!(
        "download: {} response frames, {} plaintext bytes, authenticated",
        frames.len(),
        frames.iter().map(Bytes::len).sum::<usize>()
    );
    let mut expected = Vec::new();
    request_body(1_000_000)
        .try_for_each(|frame| {
            expected.extend_from_slice(&frame);
            async { Ok(()) }
        })
        .await?;
    assert_eq!(frames.concat(), expected);

    // A download cut short: the response body ends in an error item, never in a clean end.
    let cut = ObjectStore {
        object: store.object[..store.object.len() - 20_000].to_vec(),
    };
    let cut_body: Vec<KmsAeadResult<Bytes>> = envelope
        .decrypting_stream(AAD, cut.download())
        .await?
        .collect()
        .await;
    let last = cut_body.last().ok_or("an empty response body")?;
    println!(
        "cut object: {} items, the last one is the error {}",
        cut_body.len(),
        last.as_ref().err().map_or("none", |error| error.code())
    );
    assert!(last.is_err());
    Ok(())
}
