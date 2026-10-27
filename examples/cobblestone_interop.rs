//! kms-aead's streamed values against `cryptography.cobblestone` of pyca/cryptography, both ways:
//!
//! - `encrypt` writes a value in each form for plaintexts that end before, on and after a chunk
//!   boundary, with the DEK that decrypts it, which
//!   `python -I tests/cobblestone_interop.py decrypt` strips the key reference from and decrypts;
//! - `decrypt` reads the bare values that `python -I tests/cobblestone_interop.py encrypt`
//!   writes.
//!
//! The script lists the commands. It is an example and not a test because the other side is a
//! Python process, as in `tink_interop`, and it runs in its own CI job.

use std::io::BufRead;
use std::sync::Arc;

use bytes::Bytes;
use futures::{stream, StreamExt, TryStreamExt};
use kms_aead::backends::Ring;
use kms_aead::cache::DekCache;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::stream::{
    DecryptingStream, EncryptingStream, EnvelopeStreamHeader, StreamEncryptor, StreamFormat,
};
use kms_aead::{AeadAlgorithm, AeadCipher, DataEncryptionKey, KeyId, KmsAeadEnvelope};
use secret_vault_value::SecretValue;
use serde_json::{json, Value};

type Failure = Box<dyn std::error::Error + Send + Sync>;

/// Plaintext lengths on both sides of the chunk size, 16,384: a value of whole chunks ends in an
/// empty final chunk.
const LENGTHS: [usize; 7] = [0, 1, 16_383, 16_384, 16_385, 32_768, 40_000];

const KEY_ID: KeyId = KeyId::new(1042);

/// The size of the frames a source delivers, which no chunk boundary divides.
const FRAME_LEN: usize = 1_400;

#[tokio::main]
async fn main() -> Result<(), Failure> {
    match std::env::args().nth(1).as_deref() {
        Some("encrypt") => encrypt().await,
        Some("decrypt") => decrypt().await,
        _ => {
            eprintln!("usage: cobblestone_interop encrypt|decrypt");
            std::process::exit(2);
        }
    }
}

fn frames(bytes: &[u8]) -> impl futures::Stream<Item = Result<Bytes, std::io::Error>> + Unpin {
    stream::iter(
        bytes
            .chunks(FRAME_LEN)
            .map(Bytes::copy_from_slice)
            .collect::<Vec<_>>(),
    )
    .map(Ok)
}

async fn encrypt() -> Result<(), Failure> {
    let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("interop".to_string())?)?;
    let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
    for length in LENGTHS {
        let plain_text: Vec<u8> = (0..length).map(|offset| (offset % 251) as u8).collect();
        let aad = format!("interop/{length}");
        let dek = cipher.generate_dek()?;

        let bare = seal(cipher.stream_encryptor_bare(&aad, &dek)?, &plain_text).await?;
        print_case("bare", &aad, &dek, &plain_text, &bare);
        let prefixed = seal(cipher.stream_encryptor(KEY_ID, &aad, &dek)?, &plain_text).await?;
        print_case("prefixed", &aad, &dek, &plain_text, &prefixed);

        // The envelope picks its own DEK, which only the encrypted DEK in the header names.
        let enveloped = seal(envelope.stream_encryptor(&aad).await?, &plain_text).await?;
        let header = EnvelopeStreamHeader::try_from(
            &enveloped[..EnvelopeStreamHeader::header_len(&enveloped)?],
        )?;
        let (envelope_dek, _) = DekCache::disabled()
            .with_dek(envelope.provider(), header.encrypted_dek(), Clone::clone)
            .await?;
        print_case("envelope", &aad, &envelope_dek, &plain_text, &enveloped);
    }
    Ok(())
}

/// The whole value `encryptor` writes for `plain_text`.
async fn seal(encryptor: StreamEncryptor<Ring>, plain_text: &[u8]) -> Result<Vec<u8>, Failure> {
    let value: Vec<Bytes> = EncryptingStream::new(encryptor, frames(plain_text))
        .try_collect()
        .await?;
    Ok(value.concat())
}

fn print_case(form: &str, aad: &str, dek: &DataEncryptionKey, plain_text: &[u8], value: &[u8]) {
    println!(
        "{}",
        json!({
            "form": form,
            "aad": hex::encode(aad),
            "dek": hex::encode(dek.value().ref_sensitive_value()),
            "plain_text": hex::encode(plain_text),
            "value": hex::encode(value),
        })
    );
}

async fn decrypt() -> Result<(), Failure> {
    let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
    let mut failures = 0;
    for line in std::io::stdin().lock().lines() {
        let case: Value = serde_json::from_str(&line?)?;
        let field = |name: &str| -> Result<Vec<u8>, Failure> {
            Ok(hex::decode(
                case[name].as_str().ok_or("a field is not a string")?,
            )?)
        };
        let dek = DataEncryptionKey::from(SecretValue::new(field("dek")?));
        let value = field("value")?;
        let (header, chunks) = value.split_at(StreamFormat::Bare.header_len());
        let decryptor = cipher.stream_decryptor_bare(&field("aad")?, header, &dek)?;
        let plain_text: Vec<Bytes> = DecryptingStream::new(Arc::new(decryptor), frames(chunks))
            .try_collect()
            .await?;
        let expected = field("plain_text")?;
        let name = format!("{} bytes", expected.len());
        if plain_text.concat() == expected {
            println!("{name}: ok");
        } else {
            println!("{name}: another plain text");
            failures += 1;
        }
    }
    std::process::exit(i32::from(failures > 0));
}
