//! An operator who holds only the public key computes the fingerprint to pin in a producer's
//! configuration, and a producer pinned to it writes values the reader decrypts.

use kms_aead::backends::AwsLc;
use kms_aead::providers::{LocalAsymmetricKmsProvider, LocalKekId, PublicKeyKekProvider};
use kms_aead::{AsymmetricKekAlgorithm, AsymmetricKekPublicKey};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn a_producer_pinned_to_the_fingerprint_of_the_key_accepts_it() -> TestResult {
    let kms = LocalAsymmetricKmsProvider::<AwsLc>::ephemeral(
        LocalKekId::try_from("orders-kek".to_string())?,
        AsymmetricKekAlgorithm::RsaOaepSha256,
    )?;
    let public_key = kms.public_key(None)?;
    let json = public_key.to_json()?;
    let operators_copy = AsymmetricKekPublicKey::try_from_json(&json)?;

    let producer = PublicKeyKekProvider::<AwsLc>::pinned(
        operators_copy.clone(),
        operators_copy.fingerprint(),
    )?;

    assert_eq!(producer.fingerprint(), public_key.fingerprint());
    Ok(())
}

/// A public-key KEK encrypts the DEK as an RSA block of 256 bytes or more, so the stream header's
/// `w` is above 255.
#[cfg(feature = "stream")]
#[tokio::test]
async fn a_producers_stream_decrypts_through_the_reader() -> TestResult {
    use kms_aead::stream::{EnvelopeStreamHeader, STREAM_CHUNK_LEN};
    use kms_aead::KmsAeadEnvelope;

    const AAD: &[u8] = b"submissions/1042";

    let reader_provider = LocalAsymmetricKmsProvider::<AwsLc>::ephemeral(
        LocalKekId::try_from("submissions".to_string())?,
        AsymmetricKekAlgorithm::RsaOaepSha256,
    )?;
    let producer = KmsAeadEnvelope::<_, AwsLc>::new(PublicKeyKekProvider::<AwsLc>::new(
        reader_provider.public_key(None)?,
    )?)?;
    let reader = KmsAeadEnvelope::<_, AwsLc>::new(reader_provider)?;
    let plaintext: Vec<u8> = (0..2 * STREAM_CHUNK_LEN + 100)
        .map(|offset| (offset % 251) as u8)
        .collect();

    let mut encryptor = producer.stream_encryptor(AAD).await?;
    let mut stored = encryptor.header().to_vec();
    stored.extend(encryptor.push(&plaintext)?);
    stored.extend(encryptor.finish()?);

    let header_len = EnvelopeStreamHeader::header_len(&stored[..4])?;
    let header = EnvelopeStreamHeader::try_from(&stored[..header_len])?;
    assert!(header.encrypted_dek().value().len() > 255);
    let whole = header.form().plan_chunk_read(stored.len() as u64, ..)?;
    let decryptor = reader.stream_decryptor(AAD, &header).await?;
    let decrypted: Vec<u8> = decryptor.decrypt_chunk_read(
        &whole,
        &stored[whole.ciphertext().start as usize..whole.ciphertext().end as usize],
    )?;

    assert_eq!(decrypted, plaintext);
    Ok(())
}
