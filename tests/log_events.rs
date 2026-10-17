//! The log events of the crate, in a test binary of their own. tracing caches each callsite's
//! interest for the whole process: a test thread that reaches a callsite first, with no
//! subscriber of its own, caches it as never, and the event never reaches the subscriber of the
//! test waiting for it. Each test here reaches only its own callsites.
#![cfg(any(
    feature = "ring",
    feature = "aws-lc",
    feature = "rustcrypto",
    feature = "legacy-formats"
))]

use std::io::Write;
use std::sync::{Arc, Mutex};

use secret_vault_value::SecretValue;
use tracing_subscriber::fmt::MakeWriter;

/// The log lines of one test, captured by a subscriber of its own.
#[derive(Clone, Default)]
struct CapturedLog(Arc<Mutex<Vec<u8>>>);

impl CapturedLog {
    /// A subscriber that writes every event to this log, without colours.
    fn subscriber(&self) -> impl tracing::Subscriber {
        tracing_subscriber::fmt()
            .with_writer(self.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .finish()
    }

    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

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

/// The forms in which stored or secret bytes could reach a log line: as text, as lowercase and
/// uppercase hex, as standard base64, and as the `Debug` list of a byte slice without its
/// brackets, which also finds the list with them.
// A copy of the list in the lib's test support, which an integration test cannot import.
fn renderings(bytes: &[u8]) -> Vec<String> {
    vec![
        String::from_utf8_lossy(bytes).into_owned(),
        hex::encode(bytes),
        hex::encode_upper(bytes),
        SecretValue::new(bytes.to_vec())
            .as_sensitive_base64_str()
            .to_string(),
        format!("{bytes:?}").trim_matches(['[', ']']).to_string(),
    ]
}

#[cfg(any(feature = "ring", feature = "aws-lc", feature = "rustcrypto"))]
mod local_kms {
    use std::num::NonZeroU32;

    use kms_aead::providers::{LocalKek, LocalKekId, LocalKekVersion, LocalKmsProvider};
    use kms_aead::AeadBackend;
    use secret_vault_value::SecretValue;

    use super::{renderings, CapturedLog};

    #[cfg(feature = "ring")]
    const BACKEND: AeadBackend = AeadBackend::Ring;
    #[cfg(all(not(feature = "ring"), feature = "aws-lc"))]
    const BACKEND: AeadBackend = AeadBackend::AwsLc;
    #[cfg(all(not(feature = "ring"), not(feature = "aws-lc"), feature = "rustcrypto"))]
    const BACKEND: AeadBackend = AeadBackend::RustCrypto;

    fn kek(version: u32, material: [u8; 32]) -> LocalKek {
        let version = LocalKekVersion::from(NonZeroU32::new(version).unwrap());
        LocalKek::from_secret(version, SecretValue::new(material.to_vec())).unwrap()
    }

    #[test]
    fn the_info_event_names_the_source_kind() {
        let captured = CapturedLog::default();
        tracing::subscriber::with_default(captured.subscriber(), || {
            LocalKmsProvider::new(
                LocalKekId::try_from("orders".to_string()).unwrap(),
                vec![kek(2, [0x5A; 32]), kek(1, [0x5B; 32])],
                BACKEND,
            )
            .unwrap();
            LocalKmsProvider::ephemeral(
                LocalKekId::try_from("tests".to_string()).unwrap(),
                BACKEND,
            )
            .unwrap();
        });
        let log = captured.text();

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
}

/// The deprecation `WARN` is logged once per process and per layout.
#[cfg(feature = "legacy-formats")]
mod legacy_formats {
    use kms_aead::{CipherTextWithEncryptedKey, EncryptedDataEncryptionKey};

    use super::{renderings, CapturedLog};

    const WRAPPED_KEY_MARKER: &[u8] = b"zq-key-marker-zq";
    const CIPHER_TEXT_MARKER: &[u8] = b"zq-cipher-marker-zq";

    #[test]
    fn the_first_read_of_each_legacy_layout_warns() {
        let mut length_prefixed_envelope = vec![0x00; 7];
        length_prefixed_envelope.push(u8::try_from(WRAPPED_KEY_MARKER.len()).unwrap());
        length_prefixed_envelope.extend_from_slice(WRAPPED_KEY_MARKER);
        length_prefixed_envelope.extend_from_slice(CIPHER_TEXT_MARKER);
        let bare_key = [&[0x0a], WRAPPED_KEY_MARKER].concat();
        let captured = CapturedLog::default();

        tracing::subscriber::with_default(captured.subscriber(), || {
            for _ in 0..2 {
                CipherTextWithEncryptedKey::from(length_prefixed_envelope.clone())
                    .separate()
                    .unwrap();
                EncryptedDataEncryptionKey::try_from(bare_key.as_slice()).unwrap();
            }
        });
        let log = captured.text();

        let lines: Vec<&str> = log.lines().collect();
        assert_eq!(lines.len(), 2, "{log}");
        assert!(lines.iter().all(|line| line.contains("WARN")), "{log}");
        for marker in [WRAPPED_KEY_MARKER, CIPHER_TEXT_MARKER] {
            for rendering in renderings(marker) {
                assert!(!log.contains(&rendering), "{log}");
            }
        }
    }
}
