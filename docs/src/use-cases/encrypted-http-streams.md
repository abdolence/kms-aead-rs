# Send a large export over HTTP, encrypted

A handler streams a large export, one record at a time, and the body leaves the server encrypted.
The client decrypts it as it arrives and decodes the records one by one. Neither side holds the
export in memory, and the encrypted DEK travels inside the body. Feature `stream`, see
[Streaming encryption](../streaming.md).

The encryption sits on the bytes of the body, between the format and the socket:

- the server turns its items into bytes with a streaming format, such as JSON lines (one JSON
  document per line) of [axum-streams](https://github.com/abdolence/axum-streams-rs), and passes
  the bytes through an `EncryptingStream`, which yields the header and then one encrypted chunk at
  a time;
- the client passes the bytes of the response to `decrypting_stream` of the envelope, and hands
  the plaintext to the decoder of [reqwest-streams](https://github.com/abdolence/reqwest-streams-rs);
- the format knows nothing about encryption, and the envelope knows nothing about items. The
  body is one Cobblestone stream in the envelope form, the chunked encryption format of the C2SP
  specification, see [Format](../streaming.md#format), so the KMS is called as for any streamed
  value: one encryption per new DEK, one decryption per response per DEK cache TTL, see
  [DEK caching and reuse](../dek-caching.md).

## The server

The handler takes the body of the `StreamBodyAs` response, the encoded bytes, and sends it with an
opaque content type, since the body is ciphertext. The format is part of the endpoint's contract,
so the response does not name it. The AAD names the export, so that a body of another export does
not decrypt under it:

```rust
use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum_streams::StreamBodyAs;
use futures::stream;
use kms_aead::stream::EncryptingStream;
# use kms_aead::backends::Ring;
# use kms_aead::providers::LocalKmsProvider;
# use kms_aead::KmsAeadEnvelope;
# use serde::Serialize;
#
# type Envelope = KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>;
# #[derive(Serialize)]
# struct Order {
#     id: u64,
# }

const EXPORT_AAD: &[u8] = b"exports/orders/2026-10";

async fn export_orders(
    State(envelope): State<Arc<Envelope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let orders = stream::iter((0..50_000).map(|id| Order { id }));
    let encoded = StreamBodyAs::json_nl(orders).into_response().into_body();

    let encryptor = envelope
        .stream_encryptor(EXPORT_AAD)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.code().to_string()))?;
    let ciphertext = EncryptingStream::new(encryptor, encoded.into_data_stream());

    Ok((
        [(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"))],
        Body::from_stream(ciphertext),
    ))
}
```

The route is `get(export_orders)`, with the envelope in an `Arc` as the router's state.
`EncryptingStream` takes its source as a `Stream` of `Result<Bytes, _>` whose error converts into
a boxed error, and `Body::from_stream` takes the encrypted chunks the same way, so no error is
mapped by hand. An error in the items ends the body with an error, never with a clean end.

## The client

reqwest-streams decodes a `reqwest::Response`, so the decrypted bytes are wrapped in one. The
decoder reads the body only, in the format the client asks for. The source of `decrypting_stream` is
`Unpin`, so the byte stream of the response goes through `Box::pin`. The decoder takes the longest
record it accepts, which bounds what a server can make the client buffer:

```rust
use axum::http::Response;
use futures::TryStreamExt;
use kms_aead::backends::Ring;
use kms_aead::providers::LocalKmsProvider;
use kms_aead::KmsAeadEnvelope;
use reqwest_streams::JsonStreamResponse;
use serde::Deserialize;

# #[derive(Deserialize)]
# struct Order {
#     amount_cents: u64,
# }
# const EXPORT_AAD: &[u8] = b"exports/orders/2026-10";
const MAX_ORDER_LEN: usize = 64 * 1024;

async fn download_orders(
    envelope: &KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>,
    url: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let response = reqwest::get(url).await?.error_for_status()?;

    let plaintext = envelope
        .decrypting_stream(EXPORT_AAD, Box::pin(response.bytes_stream()))
        .await?
        .map_err(std::io::Error::other);
    let decrypted = Response::new(reqwest::Body::wrap_stream(plaintext));

    let mut orders = reqwest::Response::from(decrypted).json_nl_stream::<Order>(MAX_ORDER_LEN);
    let mut total_cents = 0;
    while let Some(order) = orders.try_next().await? {
        total_cents += order.amount_cents;
    }
    Ok(total_cents)
}
```

The example runs both sides in one process, on a loopback port, with the local KMS and no
credentials. It decodes 50,000 orders from a body of about 3.8 MB and compares each one with the
order that was sent. Run it with `cargo run --example axum_encrypted_stream --features stream,ring`.

## What to watch for

- Cobblestone releases a chunk only when 16 KiB of plaintext has gathered or the stream ends, and
  `EncryptingStream` has no flush. This fits exports, reports and bulk downloads. A feed that sends
  a small record every few seconds delivers nothing until 16 KiB of records have gathered, so
  server-sent events and notifications do not fit;
- the client's decoder receives records in groups of one chunk, and only once the chunk is
  authentic. A body that is cut, modified or extended ends in an error item, `STREAM_LENGTH` or
  `DECRYPT`, after the records of the earlier chunks were already decoded. The retry is the whole
  download again, so write what the client decodes to a place it can discard;
- the status and the headers are sent before the first record. A failure while the items stream
  ends the body with an error and cannot change the status;
- the content type convention belongs to the two sides. The name of the header is not a standard,
  and the client should check its value against the formats it decodes;
- ciphertext does not compress, so a compression layer on the route gains nothing;
- the AAD must be the same on both sides. A value that names the export, the tenant or the user
  keeps a body from decrypting under another route, see [AAD](../envelope-encryption.md#aad).

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/axum_encrypted_stream.rs).
