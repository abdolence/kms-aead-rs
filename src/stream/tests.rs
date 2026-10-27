//! The encryptor, the decryptor and the tokio adapters, with the in-memory sinks and sources that
//! drive the adapters through each of their states.

use std::collections::VecDeque;
use std::error::Error;
use std::future::Future;
use std::io;
use std::ops::Bound;
use std::pin::{pin, Pin};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::{Buf, Bytes};
use futures::executor::block_on;
use futures::{stream, Stream, StreamExt};
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[cfg(feature = "aws-lc-rs")]
use crate::backends::AwsLc;
#[cfg(feature = "ring")]
use crate::backends::Ring;
#[cfg(feature = "rustcrypto")]
use crate::backends::RustCrypto;
use crate::errors::KmsAeadError;
use crate::test_provider::{error_code_of, renderings, TestBackend};
use crate::AeadAlgorithm;

use super::layout::{CHUNK_TAG_LEN, FULL_CHUNK_PLAINTEXT_LEN, FULL_CHUNK_STORED_LEN};
use super::*;

type TestResult = Result<(), Box<dyn Error>>;

const AAD: &[u8] = b"backups/2026-10";
const KEY_ID: KeyId = KeyId::new(7);
/// The encrypted DEK that every value of the envelope form here carries, as a KMS returns one.
const ENCRYPTED_DEK: &[u8] = b"the KMS ciphertext of a DEK";
const ENVELOPE: StreamFormat = StreamFormat::Envelope {
    encrypted_dek_len: ENCRYPTED_DEK.len(),
};
const FORMS: [StreamFormat; 3] = [StreamFormat::Prefixed, StreamFormat::Bare, ENVELOPE];

/// A plaintext of `len` bytes that differs from chunk to chunk, so that a chunk decrypted in the
/// wrong place shows.
fn plaintext_of(len: u64) -> Vec<u8> {
    (0..len).map(|offset| (offset % 251) as u8).collect()
}

/// The stored length of a plaintext of `len` bytes, by the rules of "Lengths".
fn stored_len_of(form: StreamFormat, len: u64) -> u64 {
    form.header_len() as u64 + len + CHUNK_TAG_LEN * (len / FULL_CHUNK_PLAINTEXT_LEN + 1)
}

fn cipher<B: AeadBackend>() -> KmsAeadResult<AeadCipher<B>> {
    AeadCipher::new(AeadAlgorithm::Aes256Gcm)
}

fn encryptor<B: AeadBackend>(
    form: StreamFormat,
    dek: &DataEncryptionKey,
) -> KmsAeadResult<StreamEncryptor<B>> {
    match form {
        StreamFormat::Prefixed => cipher::<B>()?.stream_encryptor(KEY_ID, AAD, dek),
        StreamFormat::Bare => cipher::<B>()?.stream_encryptor_bare(AAD, dek),
        StreamFormat::Envelope { .. } => StreamEncryptor::new(
            &cipher::<B>()?,
            Some(KeyReference::EncryptedDek(
                &EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec()),
            )),
            AAD,
            dek,
        ),
    }
}

/// A decryptor of the value whose header starts `stored`. The envelope form decrypts as the
/// envelope decrypts it, with the DEK given in place of the one the KMS would decrypt.
fn decryptor<B: AeadBackend>(
    form: StreamFormat,
    dek: &DataEncryptionKey,
    stored: &[u8],
) -> KmsAeadResult<StreamDecryptor<B>> {
    let header = &stored[..stored.len().min(form.header_len())];
    match form {
        StreamFormat::Prefixed => {
            cipher::<B>()?.stream_decryptor(AAD, &PrefixedStreamHeader::try_from(header)?, dek)
        }
        StreamFormat::Bare => cipher::<B>()?.stream_decryptor_bare(AAD, header, dek),
        StreamFormat::Envelope { .. } => {
            let header = EnvelopeStreamHeader::try_from(header)?;
            StreamDecryptor::new(
                &cipher::<B>()?,
                header.form(),
                &CobblestoneHeader::try_from(header.bare_header())?,
                AAD,
                dek,
            )
        }
    }
}

/// `plaintext` encrypted through `push` in pieces of `piece_len` bytes and `finish`.
fn encrypt_in_pieces<B: AeadBackend>(
    mut encryptor: StreamEncryptor<B>,
    plaintext: &[u8],
    piece_len: usize,
) -> KmsAeadResult<Vec<u8>> {
    let mut stored = encryptor.header().to_vec();
    for piece in plaintext.chunks(piece_len.max(1)) {
        stored.extend(encryptor.push(piece)?);
    }
    stored.extend(encryptor.finish()?);
    Ok(stored)
}

/// A new DEK and `plaintext` encrypted under it in `form`.
fn encrypted<B: AeadBackend>(
    form: StreamFormat,
    plaintext: &[u8],
) -> KmsAeadResult<(DataEncryptionKey, Vec<u8>)> {
    let dek = cipher::<B>()?.generate_dek()?;
    let stored = encrypt_in_pieces(encryptor::<B>(form, &dek)?, plaintext, 5_000)?;
    Ok((dek, stored))
}

/// The bytes of `plan` in `stored`, which is all a decryptor ever reads of a stored value.
pub(super) fn fetch<'s>(stored: &'s [u8], plan: &ChunkReadPlan) -> &'s [u8] {
    &stored[plan.ciphertext().start as usize..plan.ciphertext().end as usize]
}

/// The whole plaintext of a value through `plan_chunk_read` and `decrypt_chunk_read`.
fn read_whole<B: AeadBackend>(
    decryptor: &StreamDecryptor<B>,
    stored: &[u8],
) -> KmsAeadResult<Vec<u8>> {
    let stored_len = stored.len() as u64;
    let plan = decryptor.form().plan_chunk_read(stored_len, ..)?;
    decryptor.decrypt_chunk_read(&plan, fetch(stored, &plan))
}

#[test]
fn a_value_round_trips_through_push_in_pieces_of_any_size() {
    fn check<B: AeadBackend>() {
        let inputs = (
            0..=5 * FULL_CHUNK_PLAINTEXT_LEN,
            1..=3 * STREAM_CHUNK_LEN,
            prop::sample::select(FORMS.to_vec()),
        );
        TestRunner::new(Config::with_cases(48))
            .run(&inputs, |(len, piece_len, form)| {
                let plaintext = plaintext_of(len);
                let dek = cipher::<B>()?.generate_dek()?;
                let stored = encrypt_in_pieces(encryptor::<B>(form, &dek)?, &plaintext, piece_len)?;

                prop_assert_eq!(stored.len() as u64, stored_len_of(form, len));
                let decryptor = decryptor::<B>(form, &dek, &stored)?;
                let final_plan = form.plan_final_chunk_read(stored.len() as u64)?;
                prop_assert_eq!(final_plan.chunks().end, len / FULL_CHUNK_PLAINTEXT_LEN + 1);
                prop_assert_eq!(final_plan.plaintext().end, len);
                prop_assert_eq!(read_whole(&decryptor, &stored)?, plaintext);
                Ok(())
            })
            .unwrap_or_else(|failure| panic!("{}: {failure}", B::NAME));
    }

    #[cfg(feature = "ring")]
    check::<Ring>();
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>();
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>();
}

#[test]
fn a_plan_refuses_a_stored_length_the_rules_refuse() -> TestResult {
    for form in FORMS {
        let header_len = form.header_len() as u64;
        let mut refused = vec![
            header_len + 15,
            1 << 60,
            header_len + MAX_STREAM_CHUNKS * FULL_CHUNK_STORED_LEN + CHUNK_TAG_LEN,
        ];
        for chunk_count in 1..4 {
            refused.extend((0..CHUNK_TAG_LEN).map(|final_len| {
                header_len + (chunk_count - 1) * FULL_CHUNK_STORED_LEN + final_len
            }));
        }

        for stored_len in refused {
            let final_plan = form.plan_final_chunk_read(stored_len);
            let plan = form.plan_chunk_read(stored_len, 0..0);
            for result in [final_plan, plan] {
                assert_eq!(
                    error_code_of(result),
                    "STREAM_LENGTH",
                    "{form:?}, {stored_len}"
                );
            }
        }
        let longest = header_len + (MAX_STREAM_CHUNKS - 1) * FULL_CHUNK_STORED_LEN + CHUNK_TAG_LEN;
        let final_plan = form.plan_final_chunk_read(longest)?;
        assert_eq!(final_plan.chunks().end, MAX_STREAM_CHUNKS);
        assert_eq!(
            final_plan.plaintext().end,
            (MAX_STREAM_CHUNKS - 1) * FULL_CHUNK_PLAINTEXT_LEN
        );
    }
    Ok(())
}

#[test]
fn a_range_decrypts_to_its_slice_of_the_plaintext_from_its_plan_alone() {
    let inputs = (
        0..=5 * FULL_CHUNK_PLAINTEXT_LEN,
        any::<(u64, u64)>(),
        prop::sample::select(FORMS.to_vec()),
    );
    TestRunner::new(Config::with_cases(64))
        .run(&inputs, |(len, (start, end), form)| {
            let plaintext = plaintext_of(len);
            let (dek, mut stored) = encrypted::<TestBackend>(form, &plaintext)?;
            let decryptor = decryptor::<TestBackend>(form, &dek, &stored)?;
            let (start, end) = (start % (len + 1), end % (len + 1));
            let range = start.min(end)..start.max(end);

            let stored_len = stored.len() as u64;
            let plan = form.plan_chunk_read(stored_len, range.clone())?;
            prop_assert_eq!(plan.plaintext(), range.clone());
            prop_assert!(plan.ciphertext().start >= form.header_len() as u64);
            prop_assert!(plan.ciphertext().end <= stored.len() as u64);
            prop_assert_eq!(
                plan.plaintext_start(),
                plan.chunks().start * FULL_CHUNK_PLAINTEXT_LEN
            );
            prop_assert_eq!(plan.chunks().start, range.start / FULL_CHUNK_PLAINTEXT_LEN);
            let decrypted: Vec<u8> = decryptor.decrypt_chunk_read(&plan, fetch(&stored, &plan))?;
            prop_assert_eq!(
                &decrypted[..],
                &plaintext[range.start as usize..range.end as usize]
            );

            let final_plan = form.plan_final_chunk_read(stored_len)?;
            prop_assert_eq!(
                final_plan.chunks(),
                len / FULL_CHUNK_PLAINTEXT_LEN..len / FULL_CHUNK_PLAINTEXT_LEN + 1
            );
            decryptor.decrypt_chunk_read::<Vec<u8>>(&final_plan, fetch(&stored, &final_plan))?;
            if let Some(last) = stored.last_mut() {
                *last ^= 1;
            }
            let flipped =
                decryptor.decrypt_chunk_read::<Vec<u8>>(&final_plan, fetch(&stored, &final_plan));
            prop_assert_eq!(error_code_of(flipped), "DECRYPT");
            Ok(())
        })
        .unwrap_or_else(|failure| panic!("{failure}"));
}

#[test]
fn the_plans_of_edge_ranges_follow_the_seeking_rules() -> TestResult {
    let len = 3 * FULL_CHUNK_PLAINTEXT_LEN + 100;
    let plaintext = plaintext_of(len);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, &plaintext)?;
    let decryptor = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &stored)?;
    let header_len = PREFIXED_HEADER_LEN as u64;
    let stored_len = stored.len() as u64;

    for at in [0, FULL_CHUNK_PLAINTEXT_LEN] {
        let plan = StreamFormat::Prefixed.plan_chunk_read(stored_len, at..at)?;
        let chunk = at / FULL_CHUNK_PLAINTEXT_LEN;
        assert_eq!(plan.chunks(), chunk..chunk);
        let offset = header_len + chunk * FULL_CHUNK_STORED_LEN;
        assert_eq!(plan.ciphertext(), offset..offset);
        assert_eq!(plan.plaintext_start(), chunk * FULL_CHUNK_PLAINTEXT_LEN);
        assert!(decryptor
            .decrypt_chunk_read::<Vec<u8>>(&plan, &[])?
            .is_empty());
    }
    for range in [len..len, 0..len, len - 1..len] {
        let plan = StreamFormat::Prefixed.plan_chunk_read(stored_len, range.clone())?;
        assert_eq!(plan.chunks().end, 4, "{range:?}");
        assert_eq!(plan.ciphertext().end, stored.len() as u64, "{range:?}");
    }
    for at in [
        FULL_CHUNK_PLAINTEXT_LEN - 1,
        FULL_CHUNK_PLAINTEXT_LEN,
        2 * FULL_CHUNK_PLAINTEXT_LEN - 1,
        2 * FULL_CHUNK_PLAINTEXT_LEN,
    ] {
        let plan = StreamFormat::Prefixed.plan_chunk_read(stored_len, at..at + 1)?;
        assert_eq!(plan.chunks().count(), 1, "{at}");
        let decrypted: Vec<u8> = decryptor.decrypt_chunk_read(&plan, fetch(&stored, &plan))?;
        assert_eq!(decrypted, [plaintext[at as usize]]);
    }
    let reversed = std::ops::Range { start: 2, end: 1 };
    for refused in [reversed, len..len + 1, 0..len + 1] {
        let result = StreamFormat::Prefixed.plan_chunk_read(stored_len, refused.clone());
        assert_eq!(error_code_of(result), "STREAM_RANGE", "{refused:?}");
    }
    Ok(())
}

#[test]
fn a_plan_takes_any_kind_of_range() -> TestResult {
    let len = 2 * FULL_CHUNK_PLAINTEXT_LEN + 100;
    let form = StreamFormat::Bare;
    let stored_len = stored_len_of(form, len);

    assert_eq!(
        form.plan_chunk_read(stored_len, ..)?,
        form.plan_chunk_read(stored_len, 0..len)?
    );
    assert_eq!(
        form.plan_chunk_read(stored_len, 7..)?,
        form.plan_chunk_read(stored_len, 7..len)?
    );
    assert_eq!(
        form.plan_chunk_read(stored_len, ..=len - 1)?,
        form.plan_chunk_read(stored_len, 0..len)?
    );
    assert_eq!(
        form.plan_chunk_read(stored_len, 7..=9)?,
        form.plan_chunk_read(stored_len, 7..10)?
    );
    assert_eq!(
        form.plan_chunk_read(stored_len, (Bound::Excluded(7), Bound::Unbounded))?,
        form.plan_chunk_read(stored_len, 8..len)?
    );
    for overflowing in [
        form.plan_chunk_read(stored_len, ..=u64::MAX),
        form.plan_chunk_read(stored_len, (Bound::Excluded(u64::MAX), Bound::Unbounded)),
    ] {
        assert_eq!(error_code_of(overflowing), "STREAM_RANGE");
    }
    Ok(())
}

#[test]
fn a_value_cut_at_a_chunk_boundary_fails_the_plan_of_the_whole_plaintext() -> TestResult {
    for form in FORMS {
        for chunks in 0..3 {
            let (dek, stored) = encrypted::<TestBackend>(
                form,
                &plaintext_of(chunks * FULL_CHUNK_PLAINTEXT_LEN + 100),
            )?;
            let cut_len = form.header_len() + chunks as usize * STORED_STREAM_CHUNK_LEN + 16;
            let cut = &stored[..cut_len];
            let decryptor = decryptor::<TestBackend>(form, &dek, cut)?;
            let plan = form.plan_chunk_read(cut_len as u64, ..)?;
            assert_eq!(plan.plaintext(), 0..chunks * FULL_CHUNK_PLAINTEXT_LEN);
            let result = decryptor.decrypt_chunk_read::<Vec<u8>>(&plan, fetch(cut, &plan));

            assert_eq!(
                error_code_of(result),
                "DECRYPT",
                "{form:?}, {chunks} chunks"
            );
        }
    }
    Ok(())
}

/// The book's worked example: one zip entry of 64,512 bytes at offset 1,000,000 of a value of
/// 5,000,000 bytes.
#[test]
fn the_worked_example_fetches_four_chunks() -> TestResult {
    for (form, stored_len, ciphertext) in [
        (StreamFormat::Prefixed, 5_004_957, 1_000_461..1_066_061),
        (StreamFormat::Bare, 5_004_952, 1_000_456..1_066_056),
    ] {
        assert_eq!(form.plan_final_chunk_read(stored_len)?.chunks().end, 306);

        let plan = form.plan_chunk_read(stored_len, 1_000_000..1_064_512)?;

        assert_eq!(plan.chunks(), 61..65);
        assert_eq!(plan.plaintext_start(), 999_424);
        assert_eq!(plan.ciphertext(), ciphertext);
    }
    Ok(())
}

#[test]
fn a_flipped_byte_fails_at_the_step_that_reads_it() -> TestResult {
    let plaintext = plaintext_of(FULL_CHUNK_PLAINTEXT_LEN + 10);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, &plaintext)?;
    let chunk_bytes = (PREFIXED_HEADER_LEN..stored.len()).step_by(97).chain([
        PREFIXED_HEADER_LEN + STORED_STREAM_CHUNK_LEN - 1,
        PREFIXED_HEADER_LEN + STORED_STREAM_CHUNK_LEN,
        stored.len() - 1,
    ]);
    let flipped = |position: usize| {
        let mut bytes = stored.clone();
        bytes[position] ^= 0x10;
        bytes
    };

    let header = PrefixedStreamHeader::try_from(&flipped(0)[..PREFIXED_HEADER_LEN]);
    assert_eq!(error_code_of(header), "INVALID_CIPHER_TEXT_FORMAT");
    for position in 5..PREFIXED_HEADER_LEN {
        let result = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &flipped(position));
        assert_eq!(error_code_of(result), "STREAM_KEY_COMMITMENT", "{position}");
    }
    for position in chunk_bytes {
        let bytes = flipped(position);
        let decryptor = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &bytes)?;
        let result = read_whole(&decryptor, &bytes);
        assert_eq!(error_code_of(result), "DECRYPT", "{position}");
    }
    Ok(())
}

#[test]
fn the_forms_differ_in_their_key_reference_alone() -> TestResult {
    let plaintext = plaintext_of(2 * FULL_CHUNK_PLAINTEXT_LEN + 3);
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let encrypted_dek = EncryptedDataEncryptionKey::new(ENCRYPTED_DEK.to_vec());
    let encrypt_under = |reference| -> KmsAeadResult<Vec<u8>> {
        let encryptor = StreamEncryptor::<TestBackend>::with_salt(
            reference,
            AAD,
            dek.value().ref_sensitive_value(),
            &[0x5a; cipher::STREAM_SALT_LEN],
        )?;
        encrypt_in_pieces(encryptor, &plaintext, 1_000)
    };
    let bare = encrypt_under(None)?;
    let prefixed = encrypt_under(Some(KeyReference::KeyId(KEY_ID)))?;
    let embedded = encrypt_under(Some(KeyReference::EncryptedDek(&encrypted_dek)))?;

    assert_eq!(prefixed[..5], tink_prefix());
    assert_eq!(prefixed[5..], bare[..]);
    let framing = [
        &(ENCRYPTED_DEK.len() as u32).to_be_bytes()[..],
        ENCRYPTED_DEK,
    ]
    .concat();
    assert_eq!(embedded[..framing.len()], framing[..]);
    assert_eq!(embedded[framing.len()..], bare[..]);
    let bare_decryptor = decryptor::<TestBackend>(StreamFormat::Bare, &dek, &bare)?;
    let bare_len = bare.len() as u64;
    let len = plaintext.len() as u64;
    for (form, stored) in [(StreamFormat::Prefixed, &prefixed), (ENVELOPE, &embedded)] {
        let shift = (form.header_len() - BARE_HEADER_LEN) as u64;
        let stored_len = stored.len() as u64;
        let decryptor = decryptor::<TestBackend>(form, &dek, stored)?;
        for range in [
            0..0,
            0..1,
            5..FULL_CHUNK_PLAINTEXT_LEN + 7,
            FULL_CHUNK_PLAINTEXT_LEN..FULL_CHUNK_PLAINTEXT_LEN,
            FULL_CHUNK_PLAINTEXT_LEN - 1..2 * FULL_CHUNK_PLAINTEXT_LEN + 1,
            len..len,
            0..len,
        ] {
            let plan = form.plan_chunk_read(stored_len, range.clone())?;
            let bare_plan = StreamFormat::Bare.plan_chunk_read(bare_len, range.clone())?;
            assert_eq!(plan.chunks(), bare_plan.chunks(), "{form:?} {range:?}");
            assert_eq!(plan.plaintext_start(), bare_plan.plaintext_start());
            assert_eq!(
                plan.ciphertext(),
                bare_plan.ciphertext().start + shift..bare_plan.ciphertext().end + shift,
                "{form:?} {range:?}"
            );
        }
        let final_plan = form.plan_final_chunk_read(stored_len)?;
        decryptor.decrypt_chunk_read::<Vec<u8>>(&final_plan, fetch(stored, &final_plan))?;
    }
    let final_plan = StreamFormat::Bare.plan_final_chunk_read(bare_len)?;
    bare_decryptor.decrypt_chunk_read::<Vec<u8>>(&final_plan, fetch(&bare, &final_plan))?;
    let sixth_byte_on = decryptor::<TestBackend>(StreamFormat::Bare, &dek, &prefixed[5..])?;
    assert_eq!(read_whole(&sixth_byte_on, &prefixed[5..])?, plaintext);
    Ok(())
}

fn tink_prefix() -> [u8; 5] {
    crate::formats::tink_output_prefix(KEY_ID)
}

#[test]
fn a_bare_header_is_56_bytes() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let stored =
        encrypted::<TestBackend>(StreamFormat::Bare, b"short").map(|(_, stored)| stored)?;

    for header_len in [55, 57] {
        let result =
            cipher::<TestBackend>()?.stream_decryptor_bare(AAD, &stored[..header_len], &dek);
        assert_eq!(
            error_code_of(result),
            "INVALID_CIPHER_TEXT_FORMAT",
            "{header_len}"
        );
    }
    Ok(())
}

/// No byte tells the forms apart: a bare value read as a prefixed one fails at its first byte,
/// or, when its salt happens to start with `0x01`, at the commitment.
#[test]
fn a_bare_value_read_as_a_prefixed_one_never_decrypts() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let plaintext = plaintext_of(100);
    for first_salt_byte in [0x00, 0x01] {
        let mut salt: Salt = [0x33; cipher::STREAM_SALT_LEN];
        salt[0] = first_salt_byte;
        let encryptor = StreamEncryptor::<TestBackend>::with_salt(
            None,
            AAD,
            dek.value().ref_sensitive_value(),
            &salt,
        )?;
        let bare = encrypt_in_pieces(encryptor, &plaintext, 100)?;

        let result = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &bare);

        let expected = match first_salt_byte {
            0x01 => "STREAM_KEY_COMMITMENT",
            _ => "INVALID_CIPHER_TEXT_FORMAT",
        };
        assert_eq!(error_code_of(result), expected);
    }
    Ok(())
}

#[test]
fn an_encryptor_refuses_a_full_chunk_with_no_index_after_it() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let full_chunk = vec![0; STREAM_CHUNK_LEN];
    let at = |index| {
        StreamEncryptor::<TestBackend>::with_salt(
            Some(KeyReference::KeyId(KEY_ID)),
            AAD,
            dek.value().ref_sensitive_value(),
            &[0; cipher::STREAM_SALT_LEN],
        )
        .map(|encryptor| encryptor.starting_at(index))
    };

    let mut last_but_one = at(MAX_STREAM_CHUNKS - 2)?;
    assert_eq!(
        last_but_one.push(&full_chunk)?.len(),
        STORED_STREAM_CHUNK_LEN
    );
    assert_eq!(last_but_one.finish()?.len(), 16);

    let mut last = at(MAX_STREAM_CHUNKS - 1)?;
    let refused = last.push(&full_chunk);
    assert_eq!(error_code_of(refused), "STREAM_LENGTH");
    let again = last.push(b"more");
    assert_eq!(error_code_of(again), "STREAM_LENGTH");
    Ok(())
}

#[test]
fn another_algorithm_or_key_length_is_refused() -> TestResult {
    let header = encrypted::<TestBackend>(StreamFormat::Prefixed, b"short")?.1;
    let header = PrefixedStreamHeader::try_from(&header[..PREFIXED_HEADER_LEN])?;
    for algorithm in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::ChaCha20Poly1305] {
        let other = AeadCipher::<TestBackend>::new(algorithm)?;
        let dek = other.generate_dek()?;
        let encryptor = other.stream_encryptor(KEY_ID, AAD, &dek);
        let decryptor = other.stream_decryptor(AAD, &header, &dek);
        assert_eq!(error_code_of(encryptor), "STREAM_ALGORITHM", "{algorithm}");
        assert_eq!(error_code_of(decryptor), "STREAM_ALGORITHM", "{algorithm}");
    }
    let short_key = DataEncryptionKey::from(SecretValue::new(vec![7; 16]));
    let encryptor = cipher::<TestBackend>()?.stream_encryptor_bare(AAD, &short_key);
    assert_eq!(error_code_of(encryptor), "INVALID_KEY_LENGTH");
    Ok(())
}

#[test]
fn a_plan_decrypts_only_with_its_own_bytes_and_a_decryptor_of_its_value() -> TestResult {
    let plaintext = plaintext_of(FULL_CHUNK_PLAINTEXT_LEN + 5);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, &plaintext)?;
    let (other_dek, other_stored) =
        encrypted::<TestBackend>(StreamFormat::Prefixed, &plaintext[..9])?;
    let other = decryptor::<TestBackend>(StreamFormat::Prefixed, &other_dek, &other_stored)?;
    let other_form = decryptor::<TestBackend>(StreamFormat::Bare, &dek, &stored[5..])?;
    let own = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &stored)?;

    let plan = StreamFormat::Prefixed
        .plan_chunk_read(stored.len() as u64, 3..FULL_CHUNK_PLAINTEXT_LEN + 2)?;
    let short = own.decrypt_chunk_read::<Vec<u8>>(&plan, &fetch(&stored, &plan)[1..]);
    assert_eq!(error_code_of(short), "STREAM_LENGTH");
    let foreign = other.decrypt_chunk_read::<Vec<u8>>(&plan, fetch(&stored, &plan));
    assert_eq!(error_code_of(foreign), "DECRYPT");
    let shifted = other_form.decrypt_chunk_read::<Vec<u8>>(&plan, fetch(&stored, &plan));
    assert_eq!(error_code_of(shifted), "STREAM_RANGE");
    Ok(())
}

#[test]
fn a_plan_decrypts_as_any_plaintext_type() -> TestResult {
    let text = "é".repeat(20_000);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, text.as_bytes())?;
    let decryptor = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &stored)?;
    let stored_len = stored.len() as u64;
    let whole = StreamFormat::Prefixed.plan_chunk_read(stored_len, ..)?;
    let cut = StreamFormat::Prefixed.plan_chunk_read(stored_len, 1..)?;

    let secret: SecretValue = decryptor.decrypt_chunk_read(&whole, fetch(&stored, &whole))?;
    let bytes: Vec<u8> = decryptor.decrypt_chunk_read(&whole, fetch(&stored, &whole))?;
    let string: String = decryptor.decrypt_chunk_read(&whole, fetch(&stored, &whole))?;
    let cut_string = decryptor.decrypt_chunk_read::<String>(&cut, fetch(&stored, &cut));

    assert_eq!(secret.as_sensitive_bytes(), &bytes[..]);
    assert_eq!(string, text);
    assert_eq!(error_code_of(cut_string), "INVALID_PLAINTEXT");
    Ok(())
}

#[test]
fn debug_shows_no_key_and_no_plaintext() -> TestResult {
    let plaintext = b"zq-plaintext-marker-zq".repeat(10);
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let writer = EncryptingWriter::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        Vec::new(),
    );
    let mut value_encryptor = encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?;
    let mut stored = value_encryptor.header().to_vec();
    stored.extend(value_encryptor.push(&plaintext)?);
    let encryptor_debug = format!("{value_encryptor:?}");
    stored.extend(value_encryptor.finish()?);
    let decryptor = Arc::new(decryptor::<TestBackend>(
        StreamFormat::Prefixed,
        &dek,
        &stored,
    )?);
    let header = PrefixedStreamHeader::try_from(&stored[..PREFIXED_HEADER_LEN])?;
    let reader = DecryptingReader::new(decryptor.clone(), &stored[PREFIXED_HEADER_LEN..]);

    for debug in [
        encryptor_debug,
        format!("{decryptor:?}"),
        format!("{header:?}"),
        format!("{writer:?}"),
        format!("{reader:?}"),
    ] {
        for secret in [
            dek.value().as_sensitive_bytes(),
            decryptor.cipher.derived(),
            &plaintext,
        ] {
            for rendering in renderings(secret) {
                assert!(!debug.contains(&rendering), "{debug}");
            }
        }
    }
    Ok(())
}

/// A sink that takes every write whole, or nothing while it is `pending`, and logs the length of
/// each write.
#[derive(Default)]
struct LoggingSink {
    bytes: Vec<u8>,
    writes: Vec<usize>,
    pending: bool,
}

impl AsyncWrite for LoggingSink {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let sink = self.get_mut();
        if sink.pending {
            return Poll::Pending;
        }
        sink.bytes.extend_from_slice(buf);
        sink.writes.push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The plaintext lengths at the chunk edges: none, one byte, and either side of one and of two
/// full chunks.
pub(crate) const EDGE_LENGTHS: [u64; 7] = [
    0,
    1,
    FULL_CHUNK_PLAINTEXT_LEN - 1,
    FULL_CHUNK_PLAINTEXT_LEN,
    FULL_CHUNK_PLAINTEXT_LEN + 1,
    2 * FULL_CHUNK_PLAINTEXT_LEN,
    2 * FULL_CHUNK_PLAINTEXT_LEN + 1,
];

/// The ways a source hands a value out: the lengths of its pieces, repeated to the end. The
/// irregular pieces end on either side of a chunk boundary.
pub(crate) const PIECE_LENS: [(&str, &[usize]); 3] = [
    ("1-byte pieces", &[1]),
    (
        "irregular pieces",
        &[
            1,
            999,
            STORED_STREAM_CHUNK_LEN - 1,
            2,
            STORED_STREAM_CHUNK_LEN + 1,
            7_000,
        ],
    ),
    ("one piece", &[usize::MAX]),
];

/// `bytes` cut into pieces of `lens`, repeated.
pub(crate) fn pieces(bytes: &[u8], lens: &[usize]) -> Vec<Bytes> {
    let mut pieces = Vec::new();
    let mut rest = bytes;
    for len in lens.iter().cycle() {
        if rest.is_empty() {
            break;
        }
        let (piece, after) = rest.split_at((*len).min(rest.len()));
        pieces.push(Bytes::copy_from_slice(piece));
        rest = after;
    }
    pieces
}

/// A source that yields its pieces, each over as many reads as the caller's buffers take, and
/// counts the bytes it yielded.
pub(crate) struct PiecesSource {
    pieces: VecDeque<Bytes>,
    yielded: usize,
}

impl PiecesSource {
    pub(crate) fn new(pieces: Vec<Bytes>) -> Self {
        Self {
            pieces: pieces.into(),
            yielded: 0,
        }
    }
}

impl AsyncRead for PiecesSource {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let source = self.get_mut();
        if let Some(piece) = source.pieces.front_mut() {
            let len = piece.len().min(buf.remaining());
            buf.put_slice(&piece[..len]);
            piece.advance(len);
            source.yielded += len;
            if piece.is_empty() {
                source.pieces.pop_front();
            }
        }
        Poll::Ready(Ok(()))
    }
}

/// A source or sink whose every call fails with the error of a disk.
struct FailingIo;

const DISK_ERROR: &str = "disk unreadable";

impl AsyncRead for FailingIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(DISK_ERROR)))
    }
}

impl AsyncWrite for FailingIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::other(DISK_ERROR)))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(DISK_ERROR)))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(DISK_ERROR)))
    }
}

/// Polls `future` once, with a waker that does nothing.
fn poll_once<F: Future>(future: F) -> Poll<F::Output> {
    let waker = futures::task::noop_waker();
    pin!(future).poll(&mut Context::from_waker(&waker))
}

/// `plaintext` through an `EncryptingWriter` in writes of `write_len` bytes and its shutdown.
async fn encrypt_through_writer<B: AeadBackend>(
    encryptor: StreamEncryptor<B>,
    plaintext: &[u8],
    write_len: usize,
) -> io::Result<(Vec<u8>, u64)> {
    let mut writer = EncryptingWriter::new(encryptor, Vec::new());
    for piece in plaintext.chunks(write_len) {
        writer.write_all(piece).await?;
    }
    writer.shutdown().await?;
    let stored_len = writer.stored_len_written();
    Ok((writer.into_inner(), stored_len))
}

/// What a `DecryptingReader` yields read into buffers of `read_len` bytes, to its clean end.
async fn read_through_reader<B: AeadBackend, R: AsyncRead + Unpin>(
    reader: &mut DecryptingReader<B, R>,
    read_len: usize,
) -> io::Result<Vec<u8>> {
    let mut buffer = vec![0; read_len];
    let mut decrypted = Vec::new();
    loop {
        match reader.read(&mut buffer).await? {
            0 => return Ok(decrypted),
            read => decrypted.extend_from_slice(&buffer[..read]),
        }
    }
}

#[test]
fn the_wrappers_round_trip_in_writes_and_reads_of_any_size() {
    fn check<B: AeadBackend>() {
        let inputs = (
            0..=5 * FULL_CHUNK_PLAINTEXT_LEN,
            1..=100 * 1024_usize,
            1..=64 * 1024_usize,
        );
        TestRunner::new(Config::with_cases(24))
            .run(&inputs, |(len, write_len, read_len)| {
                let plaintext = plaintext_of(len);
                let dek = cipher::<B>()?.generate_dek()?;
                let (stored, stored_len) = block_on(encrypt_through_writer(
                    encryptor::<B>(StreamFormat::Prefixed, &dek)?,
                    &plaintext,
                    write_len,
                ))?;
                prop_assert_eq!(stored_len, stored_len_of(StreamFormat::Prefixed, len));
                prop_assert_eq!(stored.len() as u64, stored_len);

                let decryptor = Arc::new(decryptor::<B>(StreamFormat::Prefixed, &dek, &stored)?);
                let mut reader = DecryptingReader::new(decryptor, &stored[PREFIXED_HEADER_LEN..]);
                prop_assert_eq!(
                    block_on(read_through_reader(&mut reader, read_len))?,
                    plaintext
                );
                prop_assert_eq!(reader.plaintext_len_read(), len);
                Ok(())
            })
            .unwrap_or_else(|failure| panic!("{}: {failure}", B::NAME));
    }

    #[cfg(feature = "ring")]
    check::<Ring>();
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>();
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>();
}

#[tokio::test]
async fn the_writer_shutdown_writes_the_final_chunk() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    for (len, final_chunk_len) in [
        (0, 16),
        (1, 17),
        (FULL_CHUNK_PLAINTEXT_LEN, 16),
        (FULL_CHUNK_PLAINTEXT_LEN + 1, 17),
    ] {
        let encryptor = encryptor::<TestBackend>(StreamFormat::Bare, &dek)?;
        let (stored, _) = encrypt_through_writer(encryptor, &plaintext_of(len), 1_000).await?;

        let full_chunks = len / FULL_CHUNK_PLAINTEXT_LEN;
        let header_and_full_chunks = BARE_HEADER_LEN as u64 + full_chunks * FULL_CHUNK_STORED_LEN;
        assert_eq!(
            stored.len() as u64 - header_and_full_chunks,
            final_chunk_len,
            "{len}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_value_is_complete_through_the_shutdown_and_in_no_other_way() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let mut sink = Vec::new();
    let mut writer = EncryptingWriter::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        &mut sink,
    );
    writer
        .write_all(&plaintext_of(FULL_CHUNK_PLAINTEXT_LEN + 5))
        .await?;
    writer.flush().await?;
    drop(writer);

    assert_eq!(
        sink.len() as u64,
        PREFIXED_HEADER_LEN as u64 + FULL_CHUNK_STORED_LEN
    );
    let decryptor = Arc::new(decryptor::<TestBackend>(
        StreamFormat::Prefixed,
        &dek,
        &sink,
    )?);
    let incomplete = decrypt_stream(decryptor, &sink[PREFIXED_HEADER_LEN..], Vec::new()).await;
    assert_eq!(error_code_of(incomplete), "STREAM_LENGTH");

    let mut writer = EncryptingWriter::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        Vec::new(),
    );
    writer.write_all(b"value").await?;
    writer.shutdown().await?;
    writer.shutdown().await?;
    let after = writer.write(b"more").await;
    assert_eq!(
        after.map_err(|error| error.kind()).err(),
        Some(io::ErrorKind::BrokenPipe)
    );
    Ok(())
}

#[test]
fn a_write_takes_what_the_chunk_in_progress_takes_and_waits_for_the_sink() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let plaintext = plaintext_of(2 * FULL_CHUNK_PLAINTEXT_LEN);
    let mut writer = EncryptingWriter::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        LoggingSink::default(),
    );

    assert!(matches!(
        poll_once(writer.write(&plaintext[..100])),
        Poll::Ready(Ok(100))
    ));
    let filled = poll_once(writer.write(&plaintext[100..]));
    assert!(
        matches!(filled, Poll::Ready(Ok(taken)) if taken == STREAM_CHUNK_LEN - 100),
        "{filled:?}"
    );

    writer.sink.pending = true;
    assert!(poll_once(writer.write(&plaintext[STREAM_CHUNK_LEN..])).is_pending());
    assert!(poll_once(writer.write(&plaintext[STREAM_CHUNK_LEN..])).is_pending());
    writer.sink.pending = false;
    let after_wait = poll_once(writer.write(&plaintext[STREAM_CHUNK_LEN..STREAM_CHUNK_LEN + 30]));
    assert!(matches!(after_wait, Poll::Ready(Ok(30))), "{after_wait:?}");
    assert!(poll_once(writer.shutdown()).is_ready());

    assert_eq!(
        writer.sink.writes,
        [PREFIXED_HEADER_LEN, STORED_STREAM_CHUNK_LEN, 30 + 16]
    );
    let decryptor = decryptor::<TestBackend>(StreamFormat::Prefixed, &dek, &writer.sink.bytes)?;
    assert_eq!(
        read_whole(&decryptor, &writer.sink.bytes)?,
        plaintext[..STREAM_CHUNK_LEN + 30]
    );
    Ok(())
}

/// A value of three chunks, its decryptor, and its plaintext.
struct ThreeChunks {
    plaintext: Vec<u8>,
    stored: Vec<u8>,
    decryptor: Arc<StreamDecryptor<TestBackend>>,
}

impl ThreeChunks {
    fn new() -> KmsAeadResult<Self> {
        let plaintext = plaintext_of(2 * FULL_CHUNK_PLAINTEXT_LEN + 10);
        let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, &plaintext)?;
        let decryptor = Arc::new(decryptor::<TestBackend>(
            StreamFormat::Prefixed,
            &dek,
            &stored,
        )?);
        Ok(Self {
            plaintext,
            stored,
            decryptor,
        })
    }

    /// The source of a reader: the stored bytes after the header.
    fn body(&self) -> &[u8] {
        &self.stored[PREFIXED_HEADER_LEN..]
    }
}

/// Reads `reader` to its first error, checks that three more reads fail too, and returns the
/// plaintext before the error and the error.
async fn read_to_error<R: AsyncRead + Unpin>(
    reader: &mut DecryptingReader<TestBackend, R>,
) -> (Vec<u8>, io::Error) {
    let mut buffer = vec![0; 4_096];
    let mut decrypted = Vec::new();
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => panic!("a clean end after {} bytes", decrypted.len()),
            Ok(read) => decrypted.extend_from_slice(&buffer[..read]),
            Err(error) => {
                for _ in 0..3 {
                    let again = reader.read(&mut buffer).await;
                    assert!(again.is_err(), "{again:?}");
                }
                return (decrypted, error);
            }
        }
    }
}

#[tokio::test]
async fn a_modified_chunk_fails_after_the_chunks_before_it() -> TestResult {
    let value = ThreeChunks::new()?;
    let mut body = value.body().to_vec();
    body[STORED_STREAM_CHUNK_LEN + 7] ^= 1;
    let mut reader = DecryptingReader::new(value.decryptor.clone(), &body[..]);

    let (decrypted, error) = read_to_error(&mut reader).await;

    assert_eq!(decrypted, value.plaintext[..STREAM_CHUNK_LEN]);
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(
        adapters::inner_kms_aead_error(&error).map(KmsAeadError::code),
        Some("DECRYPT")
    );
    Ok(())
}

#[tokio::test]
async fn a_failing_source_returns_its_own_error() -> TestResult {
    let value = ThreeChunks::new()?;
    let mut reader = DecryptingReader::new(value.decryptor.clone(), FailingIo);

    let (decrypted, error) = read_to_error(&mut reader).await;

    assert!(decrypted.is_empty());
    assert_eq!(error.to_string(), DISK_ERROR);
    assert!(adapters::inner_kms_aead_error(&error).is_none());
    Ok(())
}

#[tokio::test]
async fn no_byte_of_a_chunk_is_released_before_the_chunk_is_authentic() -> TestResult {
    let plaintext = plaintext_of(FULL_CHUNK_PLAINTEXT_LEN + 10);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Bare, &plaintext)?;
    let decryptor = Arc::new(decryptor::<TestBackend>(StreamFormat::Bare, &dek, &stored)?);
    let source = PiecesSource::new(pieces(&stored[BARE_HEADER_LEN..], &[1]));
    let mut reader = DecryptingReader::new(decryptor, source);

    let mut byte = [0];
    let mut yielded_at = Vec::new();
    while reader.read(&mut byte).await? == 1 {
        yielded_at.push(reader.source.yielded);
    }

    assert_eq!(yielded_at.len(), plaintext.len());
    assert_eq!(yielded_at[0], STORED_STREAM_CHUNK_LEN);
    assert_eq!(yielded_at[STREAM_CHUNK_LEN - 1], STORED_STREAM_CHUNK_LEN);
    assert_eq!(
        yielded_at[STREAM_CHUNK_LEN],
        STORED_STREAM_CHUNK_LEN + 10 + 16
    );
    Ok(())
}

#[tokio::test]
async fn a_reader_stopped_early_has_not_authenticated_the_length() -> TestResult {
    let value = ThreeChunks::new()?;
    let mut body = value.body().to_vec();
    if let Some(final_tag_byte) = body.last_mut() {
        *final_tag_byte ^= 1;
    }
    let mut reader = DecryptingReader::new(value.decryptor.clone(), &body[..]);
    let half = value.plaintext.len() / 2;
    let mut decrypted = vec![0; half];

    reader.read_exact(&mut decrypted).await?;

    assert_eq!(decrypted, value.plaintext[..half]);
    assert_eq!(reader.plaintext_len_read(), half as u64);
    Ok(())
}

#[tokio::test]
async fn encrypt_stream_and_decrypt_stream_run_a_whole_value() -> TestResult {
    let plaintext = plaintext_of(3 * FULL_CHUNK_PLAINTEXT_LEN + 77);
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let mut stored = Vec::new();

    let stored_len = encrypt_stream(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        &plaintext[..],
        &mut stored,
    )
    .await?;
    let decryptor = Arc::new(decryptor::<TestBackend>(
        StreamFormat::Prefixed,
        &dek,
        &stored,
    )?);
    let mut decrypted = Vec::new();
    let plaintext_len =
        decrypt_stream(decryptor, &stored[PREFIXED_HEADER_LEN..], &mut decrypted).await?;

    assert_eq!(stored_len, stored.len() as u64);
    assert_eq!(plaintext_len, plaintext.len() as u64);
    assert_eq!(decrypted, plaintext);
    Ok(())
}

#[tokio::test]
async fn a_value_decrypts_whole_to_the_end_of_its_source() -> TestResult {
    for len in EDGE_LENGTHS {
        let plaintext = plaintext_of(len);
        let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Bare, &plaintext)?;
        let decryptor = Arc::new(decryptor::<TestBackend>(StreamFormat::Bare, &dek, &stored)?);
        let body = &stored[BARE_HEADER_LEN..];
        for (split, lens) in PIECE_LENS {
            let streamed = DecryptingStream::new(decryptor.clone(), source_of(pieces(body, lens)));
            let (decrypted, error) = collect_until_error(streamed).await;
            assert!(error.is_none(), "{len} bytes in {split}: {error:?}");
            assert_eq!(decrypted, plaintext, "{len} bytes in {split}");

            let source = PiecesSource::new(pieces(body, lens));
            let mut reader = DecryptingReader::new(decryptor.clone(), source);
            let read = read_through_reader(&mut reader, 4_096).await?;
            assert_eq!(read, plaintext, "{len} bytes in {split}");

            let mut sink = Vec::new();
            let source = PiecesSource::new(pieces(body, lens));
            let plaintext_len = decrypt_stream(decryptor.clone(), source, &mut sink).await?;
            assert_eq!(
                (plaintext_len, &sink),
                (len, &plaintext),
                "{len} bytes in {split}"
            );
        }
    }
    Ok(())
}

/// A value cut at a chunk boundary, or less than a tag into a chunk, ends where no value ends. Cut
/// further into a chunk, the bytes left are taken for the final chunk, which is not authentic.
/// Either way the plaintext of the whole chunks before the cut comes first.
#[tokio::test]
async fn a_value_cut_short_fails_after_the_chunks_before_the_cut() -> TestResult {
    let value = ThreeChunks::new()?;
    let tag_len = CHUNK_TAG_LEN as usize;
    let mut cuts = vec![STORED_STREAM_CHUNK_LEN - 1, value.body().len() - 1];
    for boundary in [0, STORED_STREAM_CHUNK_LEN, 2 * STORED_STREAM_CHUNK_LEN] {
        cuts.extend([
            boundary,
            boundary + 1,
            boundary + tag_len - 1,
            boundary + tag_len,
        ]);
    }

    for cut in cuts {
        let (code, kind) = if cut % STORED_STREAM_CHUNK_LEN < tag_len {
            ("STREAM_LENGTH", io::ErrorKind::UnexpectedEof)
        } else {
            ("DECRYPT", io::ErrorKind::InvalidData)
        };
        let whole_chunks = &value.plaintext[..cut / STORED_STREAM_CHUNK_LEN * STREAM_CHUNK_LEN];
        let cut_body = &value.body()[..cut];

        let mut reader = DecryptingReader::new(value.decryptor.clone(), cut_body);
        let (read, error) = read_to_error(&mut reader).await;
        assert_eq!(error.kind(), kind, "cut at {cut}");
        assert_eq!(
            adapters::inner_kms_aead_error(&error).map(KmsAeadError::code),
            Some(code),
            "cut at {cut}"
        );
        assert_eq!(read, whole_chunks, "cut at {cut}");

        let source = source_of(pieces(cut_body, &[5_000]));
        let (yielded, error) =
            collect_until_error(DecryptingStream::new(value.decryptor.clone(), source)).await;
        assert_eq!(
            error.as_ref().map(KmsAeadError::code),
            Some(code),
            "cut at {cut}"
        );
        assert_eq!(yielded, whole_chunks, "cut at {cut}");
    }
    Ok(())
}

/// The bytes after a value are taken for part of its final chunk, which then does not decrypt;
/// one more byte after a final chunk of 16,399 bytes makes it a full chunk, which is never the
/// final one.
#[tokio::test]
async fn a_value_followed_by_more_bytes_fails_after_its_whole_chunks() -> TestResult {
    let value = ThreeChunks::new()?;
    let longest_final_plaintext = plaintext_of(FULL_CHUNK_PLAINTEXT_LEN - 1);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Prefixed, &longest_final_plaintext)?;
    let longest_final = Arc::new(decryptor::<TestBackend>(
        StreamFormat::Prefixed,
        &dek,
        &stored,
    )?);
    let values = [
        (
            &value.decryptor,
            value.body(),
            &value.plaintext[..2 * STREAM_CHUNK_LEN],
        ),
        (&longest_final, &stored[PREFIXED_HEADER_LEN..], &[][..]),
    ];
    let another_chunk = &value.body()[..STORED_STREAM_CHUNK_LEN];

    for (decryptor, body, whole_chunks) in values {
        for more in [&[0][..], another_chunk] {
            let followed = [body, more].concat();

            let mut reader = DecryptingReader::new(decryptor.clone(), &followed[..]);
            let (read, error) = read_to_error(&mut reader).await;
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert_eq!(
                adapters::inner_kms_aead_error(&error).map(KmsAeadError::code),
                Some("DECRYPT")
            );
            assert_eq!(read, whole_chunks);

            let source = source_of(pieces(&followed, &[5_000]));
            let (yielded, error) =
                collect_until_error(DecryptingStream::new(decryptor.clone(), source)).await;
            assert_eq!(error.as_ref().map(KmsAeadError::code), Some("DECRYPT"));
            assert_eq!(yielded, whole_chunks);

            let streamed = decrypt_stream(decryptor.clone(), &followed[..], Vec::new()).await;
            assert_eq!(error_code_of(streamed), "DECRYPT");
        }
    }
    Ok(())
}

/// The `io::Error` a `STREAM_IO` error carries.
fn io_cause(error: &KmsAeadError) -> Option<&io::Error> {
    error
        .source()
        .and_then(|source| source.downcast_ref::<io::Error>())
}

#[tokio::test]
async fn a_value_error_through_the_source_or_the_sink_is_the_value_error() -> TestResult {
    let value = ThreeChunks::new()?;
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let mut body = value.body().to_vec();
    body[STORED_STREAM_CHUNK_LEN + 7] ^= 1;
    let tampered = DecryptingReader::new(value.decryptor.clone(), &body[..]);

    let reencrypted = encrypt_stream(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        tampered,
        Vec::new(),
    )
    .await;

    assert_eq!(error_code_of(reencrypted), "DECRYPT");
    Ok(())
}

#[tokio::test]
async fn a_failing_source_or_sink_is_stream_io() -> TestResult {
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let value = ThreeChunks::new()?;

    let failures = [
        encrypt_stream(
            encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
            FailingIo,
            Vec::new(),
        )
        .await,
        encrypt_stream(
            encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
            &b"value"[..],
            FailingIo,
        )
        .await,
        decrypt_stream(value.decryptor.clone(), FailingIo, Vec::new()).await,
        decrypt_stream(value.decryptor.clone(), value.body(), FailingIo).await,
    ];

    for failure in failures {
        let error = failure.err().ok_or("no error")?;
        assert_eq!(error.code(), "STREAM_IO");
        assert_eq!(
            io_cause(&error).map(ToString::to_string).as_deref(),
            Some(DISK_ERROR)
        );
    }
    Ok(())
}

#[test]
fn one_decryptor_serves_ranges_and_a_reader_at_once() -> TestResult {
    let value = Arc::new(ThreeChunks::new()?);
    let ranges = {
        let value = value.clone();
        std::thread::spawn(move || -> KmsAeadResult<Vec<Vec<u8>>> {
            (0..50)
                .map(|start| {
                    let plan = StreamFormat::Prefixed.plan_chunk_read(
                        value.stored.len() as u64,
                        start * 200..start * 200 + 10_000,
                    )?;
                    value
                        .decryptor
                        .decrypt_chunk_read(&plan, fetch(&value.stored, &plan))
                })
                .collect()
        })
    };
    let mut reader = DecryptingReader::new(value.decryptor.clone(), value.body());

    let whole = block_on(read_through_reader(&mut reader, 7_000))?;
    let ranges = ranges.join().map_err(|_| "the range thread panicked")??;

    assert_eq!(whole, value.plaintext);
    for (start, decrypted) in ranges.iter().enumerate() {
        let start = start * 200;
        assert_eq!(decrypted[..], value.plaintext[start..start + 10_000]);
    }
    Ok(())
}

/// A source `Stream` over `items` that counts the items taken from it.
fn counted(
    items: Vec<Bytes>,
    taken: &Arc<AtomicUsize>,
) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
    let taken = taken.clone();
    stream::iter(items).map(move |item| {
        taken.fetch_add(1, Ordering::SeqCst);
        Ok(item)
    })
}

fn source_of(items: Vec<Bytes>) -> impl Stream<Item = Result<Bytes, io::Error>> + Unpin {
    stream::iter(items.into_iter().map(Ok))
}

/// The bytes a `Stream` of `KmsAeadResult<Bytes>` yields before its first error, and the error. A
/// stream that goes on after an error fails the test.
async fn collect_until_error<S: Stream<Item = KmsAeadResult<Bytes>> + Unpin>(
    mut yielded: S,
) -> (Vec<u8>, Option<KmsAeadError>) {
    let mut bytes = Vec::new();
    let mut error = None;
    while let Some(item) = yielded.next().await {
        assert!(error.is_none(), "an item after the error: {item:?}");
        match item {
            Ok(item) => bytes.extend_from_slice(&item),
            Err(failure) => error = Some(failure),
        }
    }
    (bytes, error)
}

#[test]
fn the_streams_round_trip_in_items_of_any_size() {
    fn check<B: AeadBackend>() {
        let inputs = (
            0..=5 * FULL_CHUNK_PLAINTEXT_LEN,
            1..=100 * 1024_usize,
            1..=100 * 1024_usize,
        );
        TestRunner::new(Config::with_cases(24))
            .run(&inputs, |(len, plaintext_item_len, stored_item_len)| {
                let plaintext = plaintext_of(len);
                let dek = cipher::<B>()?.generate_dek()?;
                let encrypting = EncryptingStream::new(
                    encryptor::<B>(StreamFormat::Prefixed, &dek)?,
                    source_of(pieces(&plaintext, &[plaintext_item_len])),
                );

                let items: Vec<Bytes> = block_on(encrypting.collect::<Vec<_>>())
                    .into_iter()
                    .collect::<KmsAeadResult<_>>()?;
                let stored = items.concat();
                prop_assert_eq!(
                    stored.len() as u64,
                    stored_len_of(StreamFormat::Prefixed, len)
                );
                prop_assert_eq!(items[0].len(), PREFIXED_HEADER_LEN);
                prop_assert!(items[1..items.len() - 1]
                    .iter()
                    .all(|item| item.len() == STORED_STREAM_CHUNK_LEN));

                let decryptor = Arc::new(decryptor::<B>(StreamFormat::Prefixed, &dek, &stored)?);
                let decrypting = DecryptingStream::new(
                    decryptor,
                    source_of(pieces(&stored[PREFIXED_HEADER_LEN..], &[stored_item_len])),
                );
                let (decrypted, error) = block_on(collect_until_error(decrypting));
                prop_assert!(error.is_none(), "{error:?}");
                prop_assert_eq!(decrypted, plaintext);
                Ok(())
            })
            .unwrap_or_else(|failure| panic!("{}: {failure}", B::NAME));
    }

    #[cfg(feature = "ring")]
    check::<Ring>();
    #[cfg(feature = "aws-lc-rs")]
    check::<AwsLc>();
    #[cfg(feature = "rustcrypto")]
    check::<RustCrypto>();
}

#[tokio::test]
async fn a_tampered_chunk_is_a_decrypt_error_item_after_the_chunks_before_it() -> TestResult {
    let value = ThreeChunks::new()?;
    let mut body = value.body().to_vec();
    body[STORED_STREAM_CHUNK_LEN + 7] ^= 1;
    let decrypting =
        DecryptingStream::new(value.decryptor.clone(), source_of(pieces(&body, &[4_096])));

    let (decrypted, error) = collect_until_error(decrypting).await;

    assert_eq!(error.as_ref().map(KmsAeadError::code), Some("DECRYPT"));
    assert_eq!(decrypted, value.plaintext[..STREAM_CHUNK_LEN]);
    Ok(())
}

#[tokio::test]
async fn an_error_of_the_source_is_stream_io_with_the_error_as_the_root_cause() -> TestResult {
    let value = ThreeChunks::new()?;
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let failing = || stream::iter([Err::<Bytes, _>(io::Error::other(DISK_ERROR))]);

    let (_, encrypting_error) = collect_until_error(EncryptingStream::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        failing(),
    ))
    .await;
    let (decrypted, decrypting_error) =
        collect_until_error(DecryptingStream::new(value.decryptor.clone(), failing())).await;

    assert!(decrypted.is_empty());
    for error in [encrypting_error, decrypting_error] {
        let error = error.ok_or("no error")?;
        assert_eq!(error.code(), "STREAM_IO");
        assert_eq!(
            io_cause(&error).map(ToString::to_string).as_deref(),
            Some(DISK_ERROR)
        );
    }
    Ok(())
}

/// The code of the error that `EncryptingStream` over `source` ends in.
async fn encrypting_error_code<S, E>(source: S) -> KmsAeadResult<Option<String>>
where
    S: Stream<Item = Result<Bytes, E>> + Unpin,
    E: Into<Box<dyn Error + Send + Sync>>,
{
    let dek = cipher::<TestBackend>()?.generate_dek()?;
    let encrypting = EncryptingStream::new(
        encryptor::<TestBackend>(StreamFormat::Prefixed, &dek)?,
        source,
    );
    let (_, error) = collect_until_error(encrypting).await;
    Ok(error.as_ref().map(|error| error.code().to_string()))
}

#[tokio::test]
async fn an_error_of_the_value_through_the_source_is_that_error() -> TestResult {
    let value = ThreeChunks::new()?;
    let decrypt_error = Failure::Operation.decrypting();
    let wrapped = io::Error::new(io::ErrorKind::InvalidData, decrypt_error.clone());

    assert_eq!(
        encrypting_error_code(stream::iter([Err::<Bytes, _>(decrypt_error.clone())])).await?,
        Some("DECRYPT".to_string())
    );
    assert_eq!(
        encrypting_error_code(stream::iter([Err::<Bytes, _>(wrapped)])).await?,
        Some("DECRYPT".to_string())
    );
    let (_, error) = collect_until_error(DecryptingStream::new(
        value.decryptor.clone(),
        stream::iter([Err::<Bytes, _>(decrypt_error)]),
    ))
    .await;
    assert_eq!(error.as_ref().map(KmsAeadError::code), Some("DECRYPT"));
    Ok(())
}

#[tokio::test]
async fn no_item_is_released_before_its_chunk_is_authentic() -> TestResult {
    let plaintext = plaintext_of(FULL_CHUNK_PLAINTEXT_LEN + 10);
    let (dek, stored) = encrypted::<TestBackend>(StreamFormat::Bare, &plaintext)?;
    let decryptor = Arc::new(decryptor::<TestBackend>(StreamFormat::Bare, &dek, &stored)?);
    let taken = Arc::new(AtomicUsize::new(0));
    let single_bytes = pieces(&stored[BARE_HEADER_LEN..], &[1]);
    let mut decrypting = DecryptingStream::new(decryptor, counted(single_bytes, &taken));

    let first = decrypting.next().await.ok_or("no first item")??;
    let taken_for_first = taken.load(Ordering::SeqCst);
    let second = decrypting.next().await.ok_or("no second item")??;
    let taken_for_second = taken.load(Ordering::SeqCst);

    assert_eq!(first, plaintext[..STREAM_CHUNK_LEN]);
    assert_eq!(second, plaintext[STREAM_CHUNK_LEN..]);
    assert_eq!(taken_for_first, STORED_STREAM_CHUNK_LEN);
    assert_eq!(taken_for_second, STORED_STREAM_CHUNK_LEN + 10 + 16);
    assert!(decrypting.next().await.is_none());
    Ok(())
}
