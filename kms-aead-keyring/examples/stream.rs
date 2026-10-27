//! A keyring on the memory store with a local KEK encrypts a streamed value through an
//! `EncryptingWriter`, then decrypts its final chunk and one byte range by fetching only the chunks
//! that cover it, and the whole value from its first byte. Needs no cloud credentials.
//!
//! ```sh
//! cargo run -p kms-aead-keyring --example stream --features ring,admin,stream
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead_keyring::stream::{EncryptingWriter, PrefixedStreamHeader, StreamFormat};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    EntityId, EntityKind, FieldName, FieldSpec, KeyringAlgorithms, KeyringId, KeyringRegistry,
    KeyringRegistryOptions,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");
const UPLOAD_FILE: FieldSpec = FieldSpec::new(
    EntityKind::from_static("upload"),
    FieldName::from_static("file"),
);

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
        MemoryKeyringStore::new(),
        KeyringRegistryOptions::new(),
    )?;
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("uploads-kek".to_string())?)?;
    let admin = registry
        .create(provider, TENANT, KeyringAlgorithms::new())
        .await?;
    let keyring = admin.keyring();

    let aad = UPLOAD_FILE.aad(&EntityId::try_from("upload-7")?);
    let plaintext: Vec<u8> = (0..1_200_000_u32).map(|i| (i % 251) as u8).collect();

    // The writer is the upload's sink: its length is not known in advance, and its shutdown writes
    // the final chunk.
    let encryptor = keyring.encryptor().await.stream_encryptor(&aad).await?;
    let mut object = Vec::new();
    let mut writer = EncryptingWriter::new(encryptor, &mut object);
    writer.write_all(&plaintext).await?;
    writer.shutdown().await?;
    let stored_len = writer.stored_len_written();
    println!(
        "encrypted {} plaintext bytes into {stored_len} stored bytes",
        plaintext.len()
    );

    // A ranged reader plans from the stored length the store reports, before any KMS call, then
    // reads the header to pick the key version.
    let last = StreamFormat::Prefixed.plan_final_chunk_read(stored_len)?;
    let header = PrefixedStreamHeader::try_from(&object[..StreamFormat::Prefixed.header_len()])?;
    let decryptor = keyring.stream_decryptor(&aad, &header).await?;

    // The final chunk authenticates the stored length before any range is served.
    let tail: Vec<u8> = decryptor.decrypt_chunk_read(
        &last,
        &object[last.ciphertext().start as usize..last.ciphertext().end as usize],
    )?;
    println!(
        "key version {}: final chunk {:?} decrypted, {} plaintext bytes",
        header.key_id().as_u32(),
        last.chunks(),
        tail.len()
    );

    let range = 1_000_000..1_064_512;
    let plan = StreamFormat::Prefixed.plan_chunk_read(stored_len, range.clone())?;
    let fetched = &object[plan.ciphertext().start as usize..plan.ciphertext().end as usize];
    let part: Vec<u8> = decryptor.decrypt_chunk_read(&plan, fetched)?;
    assert_eq!(part, plaintext[range.start as usize..range.end as usize]);
    println!(
        "bytes {range:?}: chunks {:?}, fetched stored bytes {:?}",
        plan.chunks(),
        plan.ciphertext()
    );

    // A download of the whole object needs no stored length: the reader reads the header from the
    // front and finds the final chunk where the object ends.
    let mut reader = keyring.decrypting_reader(&aad, &object[..]).await?;
    let mut whole = Vec::new();
    reader.read_to_end(&mut whole).await?;
    assert_eq!(whole, plaintext);
    println!(
        "whole object: {} plaintext bytes, authenticated",
        whole.len()
    );

    registry.shutdown(None).await;
    Ok(())
}
