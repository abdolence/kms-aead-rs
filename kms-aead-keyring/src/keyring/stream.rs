//! Streamed values under a keyring's versions: [`Encryptor::stream_encryptor`] and
//! [`Keyring::stream_decryptor`], with the version's DEK through the DEK cache. The keyring writes
//! and reads the prefixed form only, so a value always carries the key id of its version.

use std::error::Error;
use std::sync::Arc;

use bytes::Bytes;
use futures_util::Stream;
use kms_aead::backends::AeadBackend;
use kms_aead::stream::{
    __HeaderGatherer, __read_header, DecryptingReader, DecryptingStream, PrefixedStreamHeader,
    StreamDecryptor, StreamEncryptor, StreamFormat,
};
use kms_aead::KmsAeadDecryptionProvider;
use tokio::io::AsyncRead;

use crate::errors::{InteropRequirement, KeyringError, KeyringResult};
use crate::metrics::KeyringCall;
use crate::record_cache::VersionLookup;
use crate::spans;
use crate::store::KeyringStore;
use crate::{Encryptor, FieldAad, Keyring, Purpose};

impl<S, P, B> Encryptor<'_, S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// An encryptor of one streamed value under the record's active randomised version, whose key
    /// id goes into the header, with the version's DEK through the
    /// [`DekCache`](kms_aead::cache::DekCache). The encryptor is sync and holds the key derived for
    /// the one value, never the DEK, until it is dropped: a later change of the version, a
    /// compromised flag or a destroy, does not stop it. The write stores the encryption marker of
    /// this encryptor's record beside the object's own record, as for fields.
    ///
    /// # Errors
    ///
    /// [`KeyringError::NoActiveVersion`]; [`KeyringError::Interop`] with the requirement
    /// [`Format`](InteropRequirement::Format) when `aad` carries an
    /// [`Interop`](crate::Interop), since neither BigQuery nor Tink reads a streamed value;
    /// [`KeyringError::KmsAead`] with `STREAM_ALGORITHM` when the active version's algorithm is
    /// not AES-256-GCM, before any KMS call; and the provider's error when the version's key is not
    /// in the DEK cache and cannot be decrypted.
    pub async fn stream_encryptor(&self, aad: &FieldAad) -> KeyringResult<StreamEncryptor<B>> {
        let keyring = self.keyring;
        let call = KeyringCall::new(
            keyring.cache.keyring_attribute(),
            "stream_encrypt",
            Purpose::Randomized,
            B::NAME,
        );
        let span = spans::encrypt(keyring.id(), Purpose::Randomized, Some(B::NAME));
        let encryption = spans::in_span(span, async {
            let (version, encrypted_dek) =
                self.record.active_dek(Purpose::Randomized).ok_or_else(|| {
                    KeyringError::no_active_version(keyring.id(), Purpose::Randomized)
                })?;
            spans::record_encrypting_version(version);
            call.version(version);
            if let Some(interop) = aad.interop {
                return Err(KeyringError::interop(
                    keyring.id(),
                    interop,
                    InteropRequirement::Format,
                ));
            }
            let cipher = keyring.cipher(version)?;
            kms_aead::stream::__check_stream_algorithm(&cipher)?;
            let (encryptor, outcome) = keyring
                .with_cached_dek(&self.record, version.id(), encrypted_dek, |dek| {
                    cipher.stream_encryptor(version.id(), &aad.bytes, dek)
                })
                .await?;
            spans::record_dek_cache(outcome);
            Ok(encryptor?)
        });
        call.timed(encryption).await
    }
}

impl<S, P, B> Keyring<S, P, B>
where
    S: KeyringStore,
    P: KmsAeadDecryptionProvider + 'static,
    B: AeadBackend,
{
    /// A decryptor of the streamed value `header` starts, under the version
    /// [`header.key_id()`](PrefixedStreamHeader::key_id) names, applying the
    /// [`compromised_reads`](crate::KeyringOptions::compromised_reads) policy as
    /// [`decrypt`](Self::decrypt) does, with the version's DEK through the
    /// [`DekCache`](kms_aead::cache::DekCache). The checks run in this order: the key id, as
    /// `decrypt` checks it; the version's state and the policy; the version's algorithm; the DEK,
    /// decrypted through the cache; then the key commitment.
    ///
    /// The decryptor holds the key derived for its value, never the DEK, until it is dropped: a
    /// later destroy, shred or compromised flag of its version does not stop it. A caller makes one
    /// per request, so that a shred takes effect for the next request.
    ///
    /// # Errors
    ///
    /// - [`KeyringError::ReservedKeyId`] for an ordinal of zero and
    ///   [`KeyringError::KeyPurposeMismatch`] for an id of another purpose;
    /// - [`KeyringError::KeyVersionUnknown`], also after one reload,
    ///   [`KeyringError::KeyVersionRetired`], [`KeyringError::KeyVersionDestroyed`] and
    ///   [`KeyringError::KeyVersionCompromised`] under
    ///   [`CompromisedReadPolicy::Block`](crate::CompromisedReadPolicy::Block), before any
    ///   decryption;
    /// - [`KeyringError::KmsAead`] with `STREAM_ALGORITHM`, before any KMS call, and
    ///   `STREAM_KEY_COMMITMENT`, and the provider's error when the key cannot be decrypted.
    pub async fn stream_decryptor(
        &self,
        aad: &FieldAad,
        header: &PrefixedStreamHeader,
    ) -> KeyringResult<StreamDecryptor<B>> {
        let call = KeyringCall::new(
            self.cache.keyring_attribute(),
            "stream_decrypt",
            Purpose::Randomized,
            B::NAME,
        );
        call.timed(async {
            let key_id = Purpose::Randomized.check(header.key_id())?;
            spans::in_span(
                spans::decrypt(self.id(), Purpose::Randomized, key_id),
                async {
                    let (record, reload) = self.cache.find(key_id, VersionLookup::Any).await;
                    spans::record_reload(reload);
                    let (version, encrypted_dek, compromise) = self.readable(&record, key_id)?;
                    call.version(version);
                    self.apply_read_policy(version, compromise)?;
                    let cipher = self.cipher(version)?;
                    kms_aead::stream::__check_stream_algorithm(&cipher)?;
                    let (decryptor, outcome) = self
                        .with_cached_dek(&record, version.id(), encrypted_dek, |dek| {
                            cipher.stream_decryptor(&aad.bytes, header, dek)
                        })
                        .await?;
                    spans::record_dek_cache(outcome);
                    Ok(decryptor?)
                },
            )
            .await
        })
        .await
    }

    /// A [`DecryptingStream`] over the streamed value that `stored` yields from its first byte to
    /// its last, in items of any size. It reads the header from `stored`, no more than the header
    /// and the item that ends it, makes the decryptor as
    /// [`stream_decryptor`](Self::stream_decryptor) does and starts the stream at the first chunk,
    /// so the caller never splits the header off. No stored length is needed: the stream finds the
    /// final chunk where `stored` ends.
    ///
    /// # Errors
    ///
    /// [`KeyringError::KmsAead`] with `STREAM_LENGTH` when `stored` ends inside the header,
    /// `STREAM_IO` for an error of `stored`, or the `KmsAeadError` it carries as itself, and
    /// `INVALID_CIPHER_TEXT_FORMAT` for a header that does not start with Tink's output prefix;
    /// then the errors of [`stream_decryptor`](Self::stream_decryptor). Everything the stream
    /// yields later is as [`DecryptingStream`] documents.
    pub async fn decrypting_stream<Src, E>(
        &self,
        aad: &FieldAad,
        stored: Src,
    ) -> KeyringResult<DecryptingStream<B, Src>>
    where
        Src: Stream<Item = Result<Bytes, E>> + Unpin,
        E: Into<Box<dyn Error + Send + Sync>>,
    {
        let mut stored = __HeaderGatherer::new(stored);
        let header = PrefixedStreamHeader::try_from(
            stored.read(StreamFormat::Prefixed.header_len()).await?,
        )?;
        let decryptor = self.stream_decryptor(aad, &header).await?;
        Ok(stored.into_stream(Arc::new(decryptor)))
    }

    /// [`decrypting_stream`](Self::decrypting_stream) on tokio's `AsyncRead`: a
    /// [`DecryptingReader`] over the streamed value that `stored` yields from its first byte to its
    /// last. It reads exactly the header from `stored`, so the reader starts at the first chunk.
    ///
    /// # Errors
    ///
    /// As [`decrypting_stream`](Self::decrypting_stream); everything the reader returns later is
    /// as [`DecryptingReader`] documents.
    pub async fn decrypting_reader<R>(
        &self,
        aad: &FieldAad,
        mut stored: R,
    ) -> KeyringResult<DecryptingReader<B, R>>
    where
        R: AsyncRead + Unpin,
    {
        let mut header = Vec::new();
        __read_header(
            &mut stored,
            &mut header,
            StreamFormat::Prefixed.header_len(),
        )
        .await?;
        let header = PrefixedStreamHeader::try_from(&header[..])?;
        let decryptor = self.stream_decryptor(aad, &header).await?;
        Ok(DecryptingReader::new(Arc::new(decryptor), stored))
    }
}

#[cfg(all(
    test,
    feature = "admin",
    any(feature = "ring", feature = "aws-lc", feature = "rustcrypto")
))]
mod tests {
    use std::io;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use futures::TryStreamExt;
    use tokio::io::AsyncReadExt;

    use kms_aead::providers::{LocalKekId, LocalKmsProvider};
    use kms_aead::stream::{decrypt_stream, encrypt_stream, StreamFormat, STREAM_CHUNK_LEN};
    use kms_aead::AeadAlgorithm;

    use super::*;
    use crate::errors::InteropError;
    use crate::test_support::{
        email_of, error_code_of, TestAdmin, TestBackend, TestKeyring, TestProvider, TestRegistry,
        TestResult, TestStore, EMAIL, TENANT,
    };
    use crate::testing::MemoryKeyringStore;
    use crate::{
        EntityId, Interop, KeyId, KeyringAlgorithms, KeyringRegistry, KeyringRegistryOptions,
    };

    /// A plaintext of three chunks.
    fn upload() -> Vec<u8> {
        (0..2 * STREAM_CHUNK_LEN + 300)
            .map(|offset| (offset % 241) as u8)
            .collect()
    }

    /// A keyring on a store and a provider that count their calls.
    struct Fixture {
        store: TestStore,
        provider: TestProvider,
        admin: TestAdmin<TestStore>,
    }

    impl Fixture {
        async fn new(algorithms: KeyringAlgorithms) -> KeyringResult<Self> {
            let store = TestStore::new(&MemoryKeyringStore::new(), Duration::ZERO);
            let provider = TestProvider::new("tenant-42-kek")?;
            let registry = TestRegistry::new(
                store.clone(),
                KeyringRegistryOptions::new().with_watch(false),
            )?;
            let admin = registry
                .create(provider.clone(), TENANT, algorithms)
                .await?;
            Ok(Self {
                store,
                provider,
                admin,
            })
        }

        fn keyring(&self) -> &TestKeyring<TestStore> {
            self.admin.keyring()
        }

        /// The provider's decryptions and the store's loads so far.
        fn calls(&self) -> (usize, usize) {
            (
                self.provider.calls.decryptions.load(Ordering::SeqCst),
                self.store.calls.loads.load(Ordering::SeqCst),
            )
        }
    }

    async fn encrypt<S: KeyringStore, P: KmsAeadDecryptionProvider + 'static>(
        keyring: &Keyring<S, P, TestBackend>,
        aad: &FieldAad,
        plaintext: &[u8],
    ) -> KeyringResult<Vec<u8>> {
        let encryptor = keyring.encryptor().await.stream_encryptor(aad).await?;
        let mut stored = Vec::new();
        encrypt_stream(encryptor, plaintext, &mut stored).await?;
        Ok(stored)
    }

    async fn decryptor<S: KeyringStore, P: KmsAeadDecryptionProvider + 'static>(
        keyring: &Keyring<S, P, TestBackend>,
        aad: &FieldAad,
        stored: &[u8],
    ) -> KeyringResult<StreamDecryptor<TestBackend>> {
        let header =
            PrefixedStreamHeader::try_from(&stored[..StreamFormat::Prefixed.header_len()])?;
        keyring.stream_decryptor(aad, &header).await
    }

    async fn decrypt<S: KeyringStore, P: KmsAeadDecryptionProvider + 'static>(
        keyring: &Keyring<S, P, TestBackend>,
        aad: &FieldAad,
        stored: &[u8],
    ) -> KeyringResult<Vec<u8>> {
        let decryptor = Arc::new(decryptor(keyring, aad, stored).await?);
        let mut decrypted = Vec::new();
        decrypt_stream(
            decryptor,
            &stored[StreamFormat::Prefixed.header_len()..],
            &mut decrypted,
        )
        .await?;
        Ok(decrypted)
    }

    /// `stored` with the key id of its header changed to `key_id`.
    fn relabelled(stored: &[u8], key_id: u32) -> Vec<u8> {
        let mut bytes = stored.to_vec();
        bytes[1..5].copy_from_slice(&key_id.to_be_bytes());
        bytes
    }

    #[tokio::test]
    async fn a_value_decrypts_under_its_version_after_a_rotation() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let plaintext = upload();
        let stored = encrypt(fixture.keyring(), &aad, &plaintext).await?;

        let rotated = fixture.admin.rotate(Purpose::Randomized).await?;
        fixture.admin.promote_now(rotated).await?;
        fixture.keyring().dek_cache().clear();

        assert_eq!(
            PrefixedStreamHeader::try_from(&stored[..StreamFormat::Prefixed.header_len()])?
                .key_id(),
            KeyId::new(1)
        );
        assert_eq!(decrypt(fixture.keyring(), &aad, &stored).await?, plaintext);
        let reencrypted = encrypt(fixture.keyring(), &aad, &plaintext).await?;
        assert_eq!(
            PrefixedStreamHeader::try_from(&reencrypted[..StreamFormat::Prefixed.header_len()])?
                .key_id(),
            rotated
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_destroyed_version_decrypts_nothing() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let stored = encrypt(fixture.keyring(), &aad, &upload()).await?;
        let rotated = fixture.admin.rotate(Purpose::Randomized).await?;
        fixture.admin.promote_now(rotated).await?;
        fixture.admin.retire(KeyId::new(1)).await?;
        fixture.admin.destroy(KeyId::new(1)).await?;

        let result = decryptor(fixture.keyring(), &aad, &stored).await;

        assert!(
            matches!(result, Err(KeyringError::KeyVersionDestroyed(_))),
            "{result:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_compromised_version_is_refused_before_its_dek_is_decrypted() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let stored = encrypt(fixture.keyring(), &aad, &upload()).await?;
        fixture.admin.mark_compromised(KeyId::new(1), None).await?;
        let (decryptions, _) = fixture.calls();

        let result = decryptor(fixture.keyring(), &aad, &stored).await;

        assert!(
            matches!(result, Err(KeyringError::KeyVersionCompromised(_))),
            "{result:?}"
        );
        assert_eq!(fixture.calls().0, decryptions);
        Ok(())
    }

    #[tokio::test]
    async fn a_relabelled_key_id_decrypts_under_no_other_version() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let stored = encrypt(fixture.keyring(), &aad, &upload()).await?;
        let rotated = fixture.admin.rotate(Purpose::Randomized).await?;
        fixture.admin.promote_now(rotated).await?;

        let other_version = decryptor(
            fixture.keyring(),
            &aad,
            &relabelled(&stored, rotated.as_u32()),
        )
        .await;
        let unknown = decryptor(fixture.keyring(), &aad, &relabelled(&stored, 9)).await;

        assert!(
            matches!(&other_version, Err(KeyringError::KmsAead(error)) if error.code() == "STREAM_KEY_COMMITMENT"),
            "{other_version:?}"
        );
        assert!(
            matches!(unknown, Err(KeyringError::KeyVersionUnknown(_))),
            "{unknown:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_field_another_reader_decrypts_is_never_streamed() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        for interop in [Interop::BigQuery, Interop::Tink] {
            let aad = EMAIL.with_interop(interop).aad(&EntityId::try_from("42")?);

            let result = fixture
                .keyring()
                .encryptor()
                .await
                .stream_encryptor(&aad)
                .await;

            assert!(
                matches!(
                    &result,
                    Err(KeyringError::Interop(InteropError {
                        requirement: InteropRequirement::Format,
                        ..
                    }))
                ),
                "{result:?}"
            );
        }
        Ok(())
    }

    /// A ChaCha20-Poly1305 version streams nothing, and is refused before its DEK is decrypted.
    #[tokio::test]
    async fn a_chacha20_poly1305_version_is_refused_before_its_dek_is_decrypted() -> TestResult {
        let fixture =
            Fixture::new(KeyringAlgorithms::new().with_randomized(AeadAlgorithm::ChaCha20Poly1305))
                .await?;
        let aad = email_of("42")?;
        let mut forged = [0; 61];
        forged[..5].copy_from_slice(&[0x01, 0, 0, 0, 1]);
        let header = PrefixedStreamHeader::try_from(&forged[..])?;
        fixture.keyring().dek_cache().clear();
        let (decryptions, _) = fixture.calls();

        let encryptor = fixture
            .keyring()
            .encryptor()
            .await
            .stream_encryptor(&aad)
            .await;
        let decryptor = fixture.keyring().stream_decryptor(&aad, &header).await;

        for code in [
            encryptor.err().map(|error| error.code().to_string()),
            decryptor.err().map(|error| error.code().to_string()),
        ] {
            assert_eq!(code.as_deref(), Some("STREAM_ALGORITHM"));
        }
        assert_eq!(fixture.calls().0, decryptions);
        Ok(())
    }

    /// A decryptor made before a shred decrypts its value to the end, while a decryptor made after
    /// it is refused.
    #[tokio::test]
    async fn a_decryptor_made_before_a_shred_decrypts_until_it_is_dropped() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let plaintext = upload();
        let stored = encrypt(fixture.keyring(), &aad, &plaintext).await?;
        let live = Arc::new(decryptor(fixture.keyring(), &aad, &stored).await?);

        fixture.admin.dangerously_shred().await?;
        let mut decrypted = Vec::new();
        decrypt_stream(
            live,
            &stored[StreamFormat::Prefixed.header_len()..],
            &mut decrypted,
        )
        .await?;
        let new = decryptor(fixture.keyring(), &aad, &stored).await;

        assert_eq!(decrypted, plaintext);
        assert!(matches!(new, Err(KeyringError::KeyVersionDestroyed(_))));
        Ok(())
    }

    /// The stored value delivered as the `parts` it is cut into.
    fn items<'s>(
        parts: impl IntoIterator<Item = &'s [u8]>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, io::Error>> + Unpin {
        futures::stream::iter(
            parts
                .into_iter()
                .map(|part| Ok(bytes::Bytes::copy_from_slice(part)))
                .collect::<Vec<_>>(),
        )
    }

    #[tokio::test]
    async fn a_stream_reads_the_header_from_the_whole_value() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let plaintext = upload();
        let stored = encrypt(fixture.keyring(), &aad, &plaintext).await?;

        let decrypting = fixture
            .keyring()
            .decrypting_stream(&aad, items([&stored[..]]))
            .await?;
        let decrypted: Vec<bytes::Bytes> = decrypting.try_collect().await?;
        assert_eq!(decrypted.concat(), plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn a_reader_reads_the_header_from_the_whole_value() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let plaintext = upload();
        let stored = encrypt(fixture.keyring(), &aad, &plaintext).await?;

        let mut reader = fixture
            .keyring()
            .decrypting_reader(&aad, &stored[..])
            .await?;
        let mut decrypted = Vec::new();
        reader.read_to_end(&mut decrypted).await?;
        assert_eq!(decrypted, plaintext);
        Ok(())
    }

    #[tokio::test]
    async fn a_value_that_is_not_prefixed_is_refused_before_the_store() -> TestResult {
        let fixture = Fixture::new(KeyringAlgorithms::new()).await?;
        let aad = email_of("42")?;
        let mut stored = encrypt(fixture.keyring(), &aad, b"short").await?;
        stored[0] = 0x02;
        let calls = fixture.calls();

        let stream = fixture
            .keyring()
            .decrypting_stream(&aad, items([&stored[..]]))
            .await;
        let reader = fixture.keyring().decrypting_reader(&aad, &stored[..]).await;

        assert_eq!(error_code_of(stream), "INVALID_CIPHER_TEXT_FORMAT");
        assert_eq!(error_code_of(reader), "INVALID_CIPHER_TEXT_FORMAT");
        assert_eq!(fixture.calls(), calls);
        Ok(())
    }

    /// A keyring whose KEK is the local KMS's encrypts and decrypts a streamed value as any other.
    #[tokio::test]
    async fn a_keyring_on_the_local_kms_streams() -> TestResult {
        let registry = KeyringRegistry::<MemoryKeyringStore, TestBackend>::new(
            MemoryKeyringStore::new(),
            KeyringRegistryOptions::new(),
        )?;
        let provider = LocalKmsProvider::<TestBackend>::ephemeral(LocalKekId::try_from(
            "uploads".to_string(),
        )?)?;
        let admin = registry
            .open_or_create(provider, TENANT, KeyringAlgorithms::new())
            .await?;
        let keyring = admin.keyring();
        let aad = email_of("42")?;
        let plaintext = upload();

        let stored = encrypt(keyring, &aad, &plaintext).await?;
        let whole = decrypt(keyring, &aad, &stored).await?;
        let across = STREAM_CHUNK_LEN as u64 - 10..STREAM_CHUNK_LEN as u64 + 10;
        let plan = StreamFormat::Prefixed.plan_chunk_read(stored.len() as u64, across.clone())?;
        let bytes = &stored[plan.ciphertext().start as usize..plan.ciphertext().end as usize];
        let decryptor = decryptor(keyring, &aad, &stored).await?;
        let range: Vec<u8> = decryptor.decrypt_chunk_read(&plan, bytes)?;

        assert_eq!(whole, plaintext);
        assert_eq!(range, plaintext[across.start as usize..across.end as usize]);
        registry.shutdown(None).await;
        Ok(())
    }
}
