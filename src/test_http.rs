//! A local HTTP server for the tests of the providers that speak HTTP, so that a test sees the
//! request a provider sends and controls the response it gets.

use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// A request as the server received it.
#[cfg_attr(
    not(any(
        feature = "hashicorp-vault-transit-kms-encryption-base",
        feature = "aws-kms-encryption"
    )),
    allow(dead_code, reason = "only the Vault and AWS tests read the requests")
)]
pub(crate) struct ReceivedRequest {
    /// The request line and the headers.
    pub(crate) head: String,
    /// The body, read to its `content-length`.
    pub(crate) body: Vec<u8>,
}

/// Answers every request on `listener` with `status` and the JSON `body`, and returns the
/// requests it receives.
pub(crate) fn answer_with(
    listener: TcpListener,
    status: u16,
    body: String,
) -> Arc<Mutex<Vec<ReceivedRequest>>> {
    let requests = Arc::new(Mutex::new(Vec::new()));
    let received = requests.clone();
    tokio::spawn(async move {
        loop {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0u8; 4096];
            let head_end = loop {
                if let Some(end) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break end + 4;
                }
                let read = connection.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
            };
            let head = String::from_utf8_lossy(&request[..head_end]).into_owned();
            let content_length = head
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map_or(0, |(_, value)| value.trim().parse::<usize>().unwrap());
            while request.len() < head_end + content_length {
                let read = connection.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..read]);
            }
            received.lock().unwrap().push(ReceivedRequest {
                head,
                body: request[head_end..head_end + content_length].to_vec(),
            });
            let response = format!(
                "HTTP/1.1 {status} Status\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            connection.write_all(response.as_bytes()).await.unwrap();
        }
    });
    requests
}
