//! The `INFO` event of the local KMS provider, in a test binary of its own. tracing caches each
//! callsite's interest for the whole process: a test thread that reaches the callsite first, with
//! no subscriber of its own, caches it as never, and the event never reaches this subscriber.
#![cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]

use std::io::Write;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex};

use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
use secret_vault_value::SecretValue;
use tracing_subscriber::fmt::MakeWriter;

#[cfg(feature = "ring")]
type Backend = kms_aead::backend::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
type Backend = kms_aead::backend::AwsLc;
#[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
type Backend = kms_aead::backend::RustCrypto;

#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedLog {
    type Writer = Self;

    fn make_writer(&'a self) -> Self {
        self.clone()
    }
}

fn kek(version: u32, material: [u8; 32]) -> LocalKek {
    let version = LocalKekVersion::from(NonZeroU32::new(version).unwrap());
    LocalKek::from_secret(version, SecretValue::new(material.to_vec())).unwrap()
}

/// The forms in which a key could reach a log line.
fn renderings(material: &[u8]) -> Vec<String> {
    let base64 = SecretValue::new(material.to_vec())
        .as_sensitive_base64_str()
        .to_string();
    vec![
        hex::encode(material),
        hex::encode_upper(material),
        base64,
        format!("{material:?}"),
    ]
}

#[test]
fn the_info_event_names_the_source_kind() {
    let captured = CapturedLog::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(captured.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        LocalKmsProvider::<Backend>::new(
            LocalKekId::try_from("orders".to_string()).unwrap(),
            vec![kek(2, [0x5A; 32]), kek(1, [0x5B; 32])],
        )
        .unwrap();
        LocalKmsProvider::<Backend>::ephemeral(LocalKekId::try_from("tests".to_string()).unwrap())
            .unwrap();
    });
    let log = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();

    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines.iter().all(|line| line.contains("INFO")), "{log}");
    assert!(lines[0].contains("orders"), "{log}");
    assert!(lines[0].contains("1 (secret), 2 (secret)"), "{log}");
    assert!(lines[1].contains("tests"), "{log}");
    assert!(lines[1].contains("1 (ephemeral)"), "{log}");
    for rendering in renderings(&[0x5A; 32])
        .into_iter()
        .chain(renderings(&[0x5B; 32]))
    {
        assert!(!log.contains(&rendering), "{log}");
    }
}
