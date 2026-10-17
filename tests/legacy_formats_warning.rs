//! The deprecation `WARN` of the legacy readers, in a test binary of its own: it is logged once
//! per process, and tracing caches each callsite's interest for the whole process, so a read on
//! another test thread would take the one event or cache the callsite as never.
#![cfg(feature = "legacy-formats")]

use std::io::Write;
use std::sync::Mutex;

use kms_aead::{CipherTextWithEncryptedKey, EncryptedDataEncryptionKey};

static LOG: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct CapturedLog;

impl Write for CapturedLog {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        LOG.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

const WRAPPED_KEY_MARKER: &[u8] = b"zq-key-marker-zq";
const CIPHER_TEXT_MARKER: &[u8] = b"zq-cipher-marker-zq";

#[test]
fn the_first_read_of_each_legacy_layout_warns_with_its_upgrade_call() {
    let mut length_prefixed_envelope = vec![0x00; 7];
    length_prefixed_envelope.push(WRAPPED_KEY_MARKER.len() as u8);
    length_prefixed_envelope.extend_from_slice(WRAPPED_KEY_MARKER);
    length_prefixed_envelope.extend_from_slice(CIPHER_TEXT_MARKER);
    let bare_key = [&[0x0a], WRAPPED_KEY_MARKER].concat();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(|| CapturedLog)
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();

    tracing::subscriber::with_default(subscriber, || {
        for _ in 0..2 {
            CipherTextWithEncryptedKey::from(length_prefixed_envelope.clone())
                .separate()
                .unwrap();
            EncryptedDataEncryptionKey::try_from(bare_key.as_slice()).unwrap();
        }
    });
    let log = String::from_utf8(LOG.lock().unwrap().clone()).unwrap();

    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines.iter().all(|line| line.contains("WARN")), "{log}");
    assert!(
        lines[0].contains("CipherTextWithEncryptedKey::upgrade_legacy_layout"),
        "{log}"
    );
    assert!(
        lines[1].contains("EncryptedDataEncryptionKey::upgrade_legacy_layout"),
        "{log}"
    );
    for marker in [WRAPPED_KEY_MARKER, CIPHER_TEXT_MARKER] {
        for rendering in [
            String::from_utf8_lossy(marker).into_owned(),
            hex::encode(marker),
            hex::encode_upper(marker),
            format!("{marker:?}").trim_matches(['[', ']']).to_string(),
        ] {
            assert!(!log.contains(&rendering), "{log}");
        }
    }
}
