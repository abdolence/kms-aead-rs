//! The Wycheproof vectors of Cobblestone-256, applied as the vector file's procedure says: every
//! vector runs as a stored value of each form, through the public calls of `AeadCipher` in the
//! prefixed and bare forms and through the envelope's parse and decryptor with the vector's DEK in
//! the envelope form, on every backend the build enables.

use std::error::Error;
use std::sync::{Arc, LazyLock};

use futures::StreamExt;
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use tokio::io::AsyncReadExt;

#[cfg(feature = "aws-lc-rs")]
use crate::backends::AwsLc;
#[cfg(feature = "ring")]
use crate::backends::Ring;
#[cfg(feature = "rustcrypto")]
use crate::backends::RustCrypto;
use crate::formats::tink_output_prefix;
use crate::AeadAlgorithm;

use super::tests::{fetch, pieces};
use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const VECTOR_FILE: &str =
    include_str!("../../tests/vectors/c2sp_chunked_encryption_aes_256_gcm_test.json");

/// The SHA-256 of the vector file at Wycheproof commit `b61843a`, as the book pins it.
const VECTOR_FILE_SHA256: &str = "0f8e35568d59649fb55fb0e5602dc678dc8910d6822beef4945aee0b5994ef05";

/// The key id of every vector's prefixed form.
const VECTOR_KEY_ID: KeyId = KeyId::new(7);

/// The encrypted DEK of every vector's envelope form, the one of the book's vector.
const VECTOR_ENCRYPTED_DEK: &[u8] = b"wrapped";
const VECTOR_ENVELOPE: StreamFormat = StreamFormat::Envelope {
    encrypted_dek_len: VECTOR_ENCRYPTED_DEK.len(),
};

/// The code each invalid vector fails with, by id, as the book's table gives it.
const EXPECTED_FAILURES: [(&str, &[u64]); 5] = [
    ("STREAM_LENGTH", &[16, 17, 19, 20, 31]),
    ("INVALID_CIPHER_TEXT_FORMAT", &[27, 28, 29, 30]),
    ("STREAM_KEY_COMMITMENT", &[21, 22, 25, 26]),
    ("INVALID_KEY_LENGTH", &[23, 24]),
    ("DECRYPT", &[11, 12, 13, 14, 15, 18, 32, 33, 34, 35]),
];

struct Vector {
    id: u64,
    valid: bool,
    flags: Vec<String>,
    dek: DataEncryptionKey,
    context: Vec<u8>,
    /// The vector's cipher text, decompressed: the stored value of the bare form.
    bare: Vec<u8>,
    /// The message of a valid vector, or the prefix an invalid one with `PartialPlaintext`
    /// yields before its error.
    message: Option<Message>,
    /// `aeadKey` and `baseNonce`, where the vector has them.
    derived: Option<Vec<u8>>,
}

struct Message {
    len: usize,
    sha512: Vec<u8>,
}

impl Vector {
    fn flagged(&self, flag: &str) -> bool {
        self.flags.iter().any(|vector_flag| vector_flag == flag)
    }

    /// The vector's stored value in `form`: its cipher text, behind the prefix of key id 7 in
    /// the prefixed form and behind `[w][wrapped]` in the envelope form.
    fn stored(&self, form: StreamFormat) -> Vec<u8> {
        match form {
            StreamFormat::Prefixed => [&tink_output_prefix(VECTOR_KEY_ID)[..], &self.bare].concat(),
            StreamFormat::Bare => self.bare.clone(),
            StreamFormat::Envelope { .. } => [
                &(VECTOR_ENCRYPTED_DEK.len() as u32).to_be_bytes()[..],
                VECTOR_ENCRYPTED_DEK,
                &self.bare,
            ]
            .concat(),
        }
    }

    /// The code the vector fails with, `None` for a valid one.
    fn expected_failure(&self) -> Option<&'static str> {
        EXPECTED_FAILURES
            .iter()
            .find(|(_, ids)| ids.contains(&self.id))
            .map(|(code, _)| *code)
    }

    /// Whether `decrypted`, the bytes a decryptor yielded, is the message or the valid prefix the
    /// vector describes; an invalid vector without one yields nothing.
    fn yielded(&self, decrypted: &[u8]) -> bool {
        match &self.message {
            Some(message) => {
                decrypted.len() == message.len
                    && Sha512::digest(decrypted)[..] == message.sha512[..]
            }
            None => decrypted.is_empty(),
        }
    }
}

fn hex_field(test: &Value, field: &str) -> Option<Vec<u8>> {
    test[field]
        .as_str()
        .map(|text| hex::decode(text).expect("hex"))
}

static VECTORS: LazyLock<Vec<Vector>> = LazyLock::new(|| {
    let file: Value = serde_json::from_str(VECTOR_FILE).expect("the vector file is JSON");
    file["testGroups"]
        .as_array()
        .expect("test groups")
        .iter()
        .flat_map(|group| group["tests"].as_array().expect("tests"))
        .map(|test| {
            let compressed = hex_field(test, "ct").expect("ct");
            Vector {
                id: test["tcId"].as_u64().expect("tcId"),
                valid: test["result"] == "valid",
                flags: test["flags"]
                    .as_array()
                    .expect("flags")
                    .iter()
                    .map(|flag| flag.as_str().expect("flag").to_string())
                    .collect(),
                dek: DataEncryptionKey::from(SecretValue::new(
                    hex_field(test, "key").expect("key"),
                )),
                context: hex_field(test, "ctx").expect("ctx"),
                bare: miniz_oxide::inflate::decompress_to_vec_zlib(&compressed)
                    .expect("ct is zlib"),
                message: test["msgLength"].as_u64().map(|len| Message {
                    len: usize::try_from(len).expect("a message length fits usize"),
                    sha512: hex_field(test, "msgSha512").expect("msgSha512"),
                }),
                derived: hex_field(test, "aeadKey")
                    .map(|key| [key, hex_field(test, "baseNonce").expect("baseNonce")].concat()),
            }
        })
        .collect()
});

#[test]
fn the_vector_file_is_the_pinned_one() {
    assert_eq!(
        hex::encode(Sha256::digest(VECTOR_FILE.as_bytes())),
        VECTOR_FILE_SHA256
    );
    assert_eq!(VECTORS.len(), 35);
    assert_eq!(VECTORS.iter().filter(|vector| vector.valid).count(), 10);
    for vector in VECTORS.iter() {
        assert_eq!(
            vector.valid,
            vector.expected_failure().is_none(),
            "vector {}",
            vector.id
        );
    }
}

/// The decryptor of `vector`'s stored value in `form`: the header from the first bytes, then the
/// decryptor.
fn decryptor<B: AeadBackend>(
    vector: &Vector,
    stored: &[u8],
    form: StreamFormat,
) -> KmsAeadResult<StreamDecryptor<B>> {
    let cipher = AeadCipher::<B>::new(AeadAlgorithm::Aes256Gcm)?;
    let header = &stored[..stored.len().min(form.header_len())];
    match form {
        StreamFormat::Prefixed => cipher.stream_decryptor(
            &vector.context,
            &PrefixedStreamHeader::try_from(header)?,
            &vector.dek,
        ),
        StreamFormat::Bare => cipher.stream_decryptor_bare(&vector.context, header, &vector.dek),
        StreamFormat::Envelope { .. } => {
            let header = EnvelopeStreamHeader::try_from(header)?;
            StreamDecryptor::new(
                &cipher,
                header.form(),
                &CobblestoneHeader::try_from(header.bare_header())?,
                &vector.context,
                &vector.dek,
            )
        }
    }
}

/// What a whole read of `vector` through one of the calls returned: the bytes it yielded and
/// the code it failed with.
struct WholeRead {
    yielded: Vec<u8>,
    failure: Option<String>,
}

/// The value through `decrypt_chunk_read` of the plan of the whole plaintext, as a ranged reader
/// that knows the stored length reads a value whole.
fn read_by_plan<B: AeadBackend>(decryptor: &StreamDecryptor<B>, stored: &[u8]) -> WholeRead {
    let stored_len = stored.len() as u64;
    let decrypted = decryptor
        .form()
        .plan_chunk_read(stored_len, ..)
        .and_then(|plan| decryptor.decrypt_chunk_read::<Vec<u8>>(&plan, fetch(stored, &plan)));
    match decrypted {
        Ok(yielded) => WholeRead {
            yielded,
            failure: None,
        },
        Err(error) => WholeRead {
            yielded: Vec::new(),
            failure: Some(error.code().to_string()),
        },
    }
}

/// The value through `decrypt_stream`, from a source positioned after the header.
async fn read_by_decrypt_stream<B: AeadBackend>(
    decryptor: &Arc<StreamDecryptor<B>>,
    stored: &[u8],
    form: StreamFormat,
) -> WholeRead {
    let mut yielded = Vec::new();
    let result = decrypt_stream(
        decryptor.clone(),
        &stored[form.header_len()..],
        &mut yielded,
    )
    .await;
    WholeRead {
        yielded,
        failure: result.err().map(|error| error.code().to_string()),
    }
}

/// The value through a `DecryptingReader` read into buffers of `buffer_len` bytes. After the
/// first error, three more reads must fail too, and the reader never ends cleanly.
async fn read_by_reader<B: AeadBackend>(
    decryptor: &Arc<StreamDecryptor<B>>,
    stored: &[u8],
    form: StreamFormat,
    buffer_len: usize,
) -> WholeRead {
    let mut reader = DecryptingReader::new(decryptor.clone(), &stored[form.header_len()..]);
    let mut buffer = vec![0; buffer_len];
    let mut yielded = Vec::new();
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => {
                return WholeRead {
                    yielded,
                    failure: None,
                }
            }
            Ok(read) => yielded.extend_from_slice(&buffer[..read]),
            Err(error) => {
                for _ in 0..3 {
                    let again = reader.read(&mut buffer).await;
                    assert!(again.is_err(), "a read after an error: {again:?}");
                }
                return WholeRead {
                    yielded,
                    failure: adapters::inner_kms_aead_error(&error)
                        .map(|error| error.code().to_string()),
                };
            }
        }
    }
}

/// The value through a `DecryptingStream` over a source of `piece_len`-byte items. After the
/// first error the stream must end.
async fn read_by_stream<B: AeadBackend>(
    decryptor: &Arc<StreamDecryptor<B>>,
    stored: &[u8],
    form: StreamFormat,
    piece_len: usize,
) -> WholeRead {
    let items = pieces(&stored[form.header_len()..], &[piece_len]);
    let mut stream = DecryptingStream::new(
        decryptor.clone(),
        futures::stream::iter(items.into_iter().map(Ok::<_, std::io::Error>)),
    );
    let mut yielded = Vec::new();
    while let Some(item) = stream.next().await {
        match item {
            Ok(plaintext) => yielded.extend_from_slice(&plaintext),
            Err(error) => {
                assert!(stream.next().await.is_none(), "an item after an error");
                return WholeRead {
                    yielded,
                    failure: Some(error.code().to_string()),
                };
            }
        }
    }
    WholeRead {
        yielded,
        failure: None,
    }
}

/// Every vector on `B` in `form`: decrypted whole through each call, its length authenticated
/// through the final chunk.
async fn check_vectors<B: AeadBackend>(form: StreamFormat) -> TestResult {
    for vector in VECTORS.iter() {
        let context = format!("{} vector {} in the {form:?} form", B::NAME, vector.id);
        let stored = vector.stored(form);
        let expected = vector.expected_failure();
        let decryptor = match decryptor::<B>(vector, &stored, form) {
            Ok(decryptor) => Arc::new(decryptor),
            Err(error) => {
                assert_eq!(Some(error.code()), expected, "{context}");
                assert!(vector.flagged("HeaderFailure"), "{context}");
                continue;
            }
        };
        assert!(
            !vector.flagged("HeaderFailure"),
            "{context}: the decryptor did not fail with {expected:?}"
        );

        let reads = [
            ("plan", read_by_plan(&decryptor, &stored)),
            (
                "decrypt_stream",
                read_by_decrypt_stream(&decryptor, &stored, form).await,
            ),
            (
                "1-byte reader",
                read_by_reader(&decryptor, &stored, form, 1).await,
            ),
            (
                "64 KiB reader",
                read_by_reader(&decryptor, &stored, form, 64 * 1024).await,
            ),
            (
                "1-byte stream",
                read_by_stream(&decryptor, &stored, form, 1).await,
            ),
            (
                "one-item stream",
                read_by_stream(&decryptor, &stored, form, usize::MAX).await,
            ),
        ];
        for (call, read) in reads {
            assert_eq!(read.failure.as_deref(), expected, "{context}, {call}");
            if call == "plan" && expected.is_some() {
                assert!(read.yielded.is_empty(), "{context}, {call}");
            } else {
                assert!(vector.yielded(&read.yielded), "{context}, {call}");
            }
        }

        let authenticated = decryptor
            .form()
            .plan_final_chunk_read(stored.len() as u64)
            .and_then(|final_plan| {
                decryptor.decrypt_chunk_read::<Vec<u8>>(&final_plan, fetch(&stored, &final_plan))
            });
        assert_eq!(
            authenticated.is_ok(),
            vector.valid || vector.flagged("ValidFinalChunk"),
            "{context}, final chunk: {authenticated:?}"
        );
    }
    Ok(())
}

/// Every valid vector's message, encrypted again with the vector's salt, is the vector's cipher
/// text, behind the key reference of the form.
fn check_encrypting<B: AeadBackend>(form: StreamFormat) -> TestResult {
    for vector in VECTORS.iter().filter(|vector| vector.valid) {
        let context = format!("{} vector {} in the {form:?} form", B::NAME, vector.id);
        let stored = vector.stored(form);
        let decryptor = decryptor::<B>(vector, &stored, form)?;
        let message = read_by_plan(&decryptor, &stored).yielded;
        let salt: Salt = vector.bare[..cipher::STREAM_SALT_LEN].try_into()?;
        let encrypted_dek = EncryptedDataEncryptionKey::new(VECTOR_ENCRYPTED_DEK.to_vec());
        let reference = match form {
            StreamFormat::Prefixed => Some(KeyReference::KeyId(VECTOR_KEY_ID)),
            StreamFormat::Bare => None,
            StreamFormat::Envelope { .. } => Some(KeyReference::EncryptedDek(&encrypted_dek)),
        };

        let mut encryptor = StreamEncryptor::<B>::with_salt(
            reference,
            &vector.context,
            vector.dek.value().ref_sensitive_value(),
            &salt,
        )?;
        let mut encrypted = encryptor.header().to_vec();
        for piece in message.chunks(7_000) {
            encrypted.extend(encryptor.push(piece)?);
        }
        encrypted.extend(encryptor.finish()?);

        assert!(encrypted == stored, "{context}");
    }
    Ok(())
}

async fn check_backend<B: AeadBackend>() -> TestResult {
    for form in [StreamFormat::Prefixed, StreamFormat::Bare, VECTOR_ENVELOPE] {
        check_vectors::<B>(form).await?;
        check_encrypting::<B>(form)?;
    }
    Ok(())
}

#[tokio::test]
async fn every_vector_decrypts_or_fails_as_the_procedure_says() -> TestResult {
    #[cfg(feature = "ring")]
    check_backend::<Ring>().await?;
    #[cfg(feature = "aws-lc-rs")]
    check_backend::<AwsLc>().await?;
    #[cfg(feature = "rustcrypto")]
    check_backend::<RustCrypto>().await?;
    Ok(())
}

#[test]
fn the_derived_key_and_base_nonce_are_the_vectors() -> TestResult {
    fn check<B: AeadBackend>() -> TestResult {
        let mut checked = 0;
        for vector in VECTORS.iter() {
            let (Some(derived), Some(salt)) =
                (&vector.derived, vector.bare.get(..cipher::STREAM_SALT_LEN))
            else {
                continue;
            };
            let (cipher, _) = ChunkCipher::<B>::derive(
                vector.dek.value().ref_sensitive_value(),
                &salt.try_into()?,
                &vector.context,
            )
            .map_err(|failure| failure.decrypting())?;
            assert_eq!(cipher.derived(), &derived[..], "vector {}", vector.id);
            checked += 1;
        }
        assert!(checked >= 10, "{checked} vectors carry aeadKey");
        Ok(())
    }

    #[cfg(feature = "ring")]
    check::<Ring>()?;
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>()?;
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>()?;
    Ok(())
}
