//! A local HTTP server for the tests of the providers that speak HTTP, so that a test sees the
//! request a provider sends and controls the response it gets.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Answers every request on `listener` with `status` and the JSON `body`, and returns the request
/// heads it receives.
pub(crate) fn answer_with(
    listener: TcpListener,
    status: u16,
    body: String,
) -> Arc<Mutex<Vec<String>>> {
    let heads = Arc::new(Mutex::new(Vec::new()));
    let received = heads.clone();
    tokio::spawn(async move {
        loop {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let read = connection.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            received
                .lock()
                .unwrap()
                .push(String::from_utf8_lossy(&request).into_owned());
            let response = format!(
                "HTTP/1.1 {status} Status\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            connection.write_all(response.as_bytes()).await.unwrap();
        }
    });
    heads
}
