//! Reads one byte range of a stored object by fetching only the chunks that cover it, through an
//! envelope over the local KMS, in both of the envelope's forms: the envelope form, which carries
//! its encrypted DEK, and the bare form, whose encrypted DEK the writer stores beside it. The
//! envelope form also decrypts whole. Building the object from one `Vec` is the set-up; to encrypt
//! a `Stream` of `Bytes`, such as a request body, see the `stream_body` example. Needs no cloud
//! credentials.
//!
//! ```sh
//! cargo run --example stream_range_read --features stream,ring
//! ```

use std::ops::Range;
use std::sync::Arc;

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::stream::{decrypt_stream, EnvelopeStreamHeader, StreamEncryptor, StreamFormat};
use kms_aead::{KmsAeadEnvelope, KmsAeadResult};

const AAD: &[u8] = b"backups/2026-10";
const PLAINTEXT_RANGE: Range<u64> = 1_000_000..1_064_512;

/// An object of an object store that serves `Range` requests, held in memory.
struct Object(Vec<u8>);

impl Object {
    fn read(&self, range: Range<u64>) -> &[u8] {
        &self.0[range.start as usize..range.end as usize]
    }

    fn size(&self) -> u64 {
        self.0.len() as u64
    }
}

/// The object an encryptor writes for `plaintext`, fed in pieces of any size: the encryptor is
/// sans-IO.
fn write_object(mut encryptor: StreamEncryptor<Ring>, plaintext: &[u8]) -> KmsAeadResult<Object> {
    let mut stored = encryptor.header().to_vec();
    for piece in plaintext.chunks(100_000) {
        stored.extend(encryptor.push(piece)?);
    }
    stored.extend(encryptor.finish()?);
    Ok(Object(stored))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("backups-kek".to_string())?)?;
    let envelope = KmsAeadEnvelope::<_, Ring>::new(provider)?;
    let plaintext: Vec<u8> = (0..3_000_000_u32).map(|i| (i % 251) as u8).collect();
    let expected = &plaintext[PLAINTEXT_RANGE.start as usize..PLAINTEXT_RANGE.end as usize];

    // The envelope form: the object carries its encrypted DEK, so a reader needs nothing else.
    let object = write_object(envelope.stream_encryptor(AAD).await?, &plaintext)?;
    let header_len = EnvelopeStreamHeader::header_len(object.read(0..4))?;
    let header = EnvelopeStreamHeader::try_from(object.read(0..header_len as u64))?;
    // The plan is made from the header and the object's size alone, so a size the length rules
    // refuse costs no KMS call.
    let plan = header
        .form()
        .plan_chunk_read(object.size(), PLAINTEXT_RANGE)?;
    let decryptor = Arc::new(envelope.stream_decryptor(AAD, &header).await?);
    let part: Vec<u8> = decryptor.decrypt_chunk_read(&plan, object.read(plan.ciphertext()))?;
    assert_eq!(part, expected);
    println!(
        "envelope form: {} stored bytes behind a {header_len}-byte header, bytes {PLAINTEXT_RANGE:?} read \
         from stored bytes {:?}",
        object.size(),
        plan.ciphertext()
    );

    let mut decrypted = Vec::new();
    let after_header = object.read(header_len as u64..object.size());
    let length = decrypt_stream(decryptor.clone(), after_header, &mut decrypted).await?;
    assert_eq!(decrypted, plaintext);
    println!("envelope form: decrypted whole, {length} bytes, authenticated");

    // The bare form: the writer stores the encrypted DEK beside the object, such as in its
    // metadata, and every chunk sits at a fixed offset.
    let (encryptor, encrypted_dek) = envelope.stream_encryptor_bare(AAD).await?;
    let object = write_object(encryptor, &plaintext)?;
    let plan = StreamFormat::Bare.plan_chunk_read(object.size(), PLAINTEXT_RANGE)?;
    let decryptor = envelope
        .stream_decryptor_bare(
            AAD,
            object.read(0..StreamFormat::Bare.header_len() as u64),
            &encrypted_dek,
        )
        .await?;
    let part: Vec<u8> = decryptor.decrypt_chunk_read(&plan, object.read(plan.ciphertext()))?;
    assert_eq!(part, expected);
    println!(
        "bare form: {} stored bytes and a {}-byte encrypted DEK beside them, bytes {PLAINTEXT_RANGE:?} \
         read from stored bytes {:?}",
        object.size(),
        encrypted_dek.value().len(),
        plan.ciphertext()
    );

    Ok(())
}
