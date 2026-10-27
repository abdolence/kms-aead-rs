//! An axum handler streams 50,000 orders as JSON lines with axum-streams, and the body leaves the
//! server encrypted as one Cobblestone stream: the encoded bytes go through an `EncryptingStream`
//! before they reach the socket. A reqwest client in the same process downloads the body,
//! decrypts it with `decrypting_stream` and decodes the orders with reqwest-streams, one at a
//! time. Neither side holds the export in memory. The server binds a loopback port, and the local
//! KMS needs no cloud credentials.
//!
//! The response carries `application/octet-stream`, since the body is ciphertext, and names the
//! format of the plaintext in `X-Inner-Content-Type`, which the client hands to the decoder.
//!
//! ```sh
//! cargo run --example axum_encrypted_stream --features stream,ring
//! ```

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{body::Body, Router};
use futures::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::stream::EncryptingStream;
use kms_aead::KmsAeadEnvelope;
use reqwest_streams::JsonStreamResponse;
use serde::{Deserialize, Serialize};

type Envelope = KmsAeadEnvelope<LocalKmsProvider<Ring>, Ring>;

/// Binds the plaintext to this export, so that the body of another export, or of another route,
/// does not decrypt under it.
const EXPORT_AAD: &[u8] = b"exports/orders/2026-10";
const INNER_CONTENT_TYPE: &str = "x-inner-content-type";
const ORDERS: u64 = 50_000;
/// The longest line the client's decoder accepts, which bounds what a hostile server makes it
/// buffer.
const MAX_ORDER_LEN: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Order {
    id: u64,
    customer: String,
    amount_cents: u64,
    currency: String,
}

impl Order {
    fn sample(id: u64) -> Self {
        Self {
            id,
            customer: format!("customer-{}", id % 997),
            amount_cents: 1_000 + id * 7 % 90_000,
            currency: "EUR".to_string(),
        }
    }
}

async fn export_orders(
    State(envelope): State<Arc<Envelope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let orders = stream::iter((0..ORDERS).map(Order::sample)).map(Ok::<_, axum::Error>);
    let encoded =
        axum_streams::StreamBodyAs::new(axum_streams::JsonNewLineStreamFormat::new(), orders)
            .into_response();
    let (mut parts, encoded_body) = encoded.into_parts();
    let inner_content_type = parts.headers.remove(CONTENT_TYPE);

    let encryptor = envelope
        .stream_encryptor(EXPORT_AAD)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.code().to_string()))?;
    let ciphertext = EncryptingStream::new(encryptor, encoded_body.into_data_stream());

    let mut response = Response::new(Body::from_stream(ciphertext));
    response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    if let Some(inner_content_type) = inner_content_type {
        response
            .headers_mut()
            .insert(INNER_CONTENT_TYPE, inner_content_type);
    }
    Ok(response)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("exports-kek".to_string())?)?;
    // The client shares the server's envelope because both run in this process; in a deployment
    // each side builds its own against the same KMS key.
    let envelope = Arc::new(KmsAeadEnvelope::<_, Ring>::new(provider)?);

    let app = Router::new()
        .route("/orders", get(export_orders))
        .with_state(envelope.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let response = reqwest::get(format!("http://{address}/orders"))
        .await?
        .error_for_status()?;
    let content_type = response.headers().get(CONTENT_TYPE).cloned();
    let inner_content_type = response
        .headers()
        .get(INNER_CONTENT_TYPE)
        .cloned()
        .ok_or("the response names no inner content type")?;
    println!("content-type: {content_type:?}, {INNER_CONTENT_TYPE}: {inner_content_type:?}");

    let wire_bytes = Arc::new(AtomicU64::new(0));
    let counted = {
        let wire_bytes = wire_bytes.clone();
        response.bytes_stream().inspect_ok(move |frame| {
            wire_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
        })
    };
    // The stream reads the header, with the encrypted DEK, from the front of the body; the end of
    // the body is the end of the export.
    let plaintext = envelope
        .decrypting_stream(EXPORT_AAD, Box::pin(counted))
        .await?
        .map_err(io::Error::other);

    // reqwest-streams decodes a `reqwest::Response`, so the decrypted frames are wrapped in one
    // that carries the inner content type.
    let decrypted_response = Response::builder()
        .header(CONTENT_TYPE, inner_content_type)
        .body(reqwest::Body::wrap_stream(plaintext))?;
    let mut orders =
        reqwest::Response::from(decrypted_response).json_nl_stream::<Order>(MAX_ORDER_LEN);

    let mut count = 0;
    let mut sample = None;
    while let Some(order) = orders.try_next().await? {
        assert_eq!(order, Order::sample(count), "order {count} differs");
        if count == 31_337 {
            sample = Some(order);
        }
        count += 1;
    }
    assert_eq!(count, ORDERS);
    println!(
        "{count} orders decrypted and decoded from {} bytes on the wire",
        wire_bytes.load(Ordering::Relaxed)
    );
    println!("order 31337: {:?}", sample.ok_or("no sample order")?);

    server.abort();
    Ok(())
}
