//! A provider for unit tests that need no KMS, whose "encrypted" key is the plaintext it is given,
//! the backend those tests run on, and the waits the concurrency tests share.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::LazyLock;
use std::time::Instant;

use secret_vault_value::SecretValue;
use tokio::sync::watch;

use crate::errors::KmsAeadEncryptionError;
use crate::formats::TinkKeyType;
use crate::{
    DataEncryptionKey, EncryptedDataEncryptionKey, KekRef, KmsAeadDecryptionProvider,
    KmsAeadEncryptionProvider, KmsAeadResult, KmsProvider,
};

#[cfg(feature = "ring")]
pub(crate) type TestBackend = crate::backends::Ring;
#[cfg(all(not(feature = "ring"), feature = "aws-lc-rs"))]
pub(crate) type TestBackend = crate::backends::AwsLc;
#[cfg(all(
    not(feature = "ring"),
    not(feature = "aws-lc-rs"),
    feature = "rustcrypto"
))]
pub(crate) type TestBackend = crate::backends::RustCrypto;

/// How many calls the concurrency tests start at once.
pub(crate) const CONCURRENT_CALLS: usize = 16;

static TEST_KEK: LazyLock<KekRef> =
    LazyLock::new(|| KekRef::new(KmsProvider::Other("test".to_string()), "test-kek"));

#[derive(Debug, Clone)]
pub(crate) enum TestKmsProvider {
    Working,
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    FailingToEncrypt,
    FailingToDecrypt,
    /// Returns its key material from `generate_key_material`, as a KMS generator would.
    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    Generating(SecretValue),
    /// Decrypts a key into its encrypted bytes followed by the nanoseconds from the instant it
    /// holds to the decryption, as a little-endian `u64`, so that a caller can tell how old the key
    /// it is given is.
    Stamping(Instant),
}

impl KmsAeadEncryptionProvider for TestKmsProvider {
    fn kek(&self) -> &KekRef {
        &TEST_KEK
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
            TestKmsProvider::FailingToEncrypt => Err(KmsAeadEncryptionError::create(
                "TEST_ENCRYPT",
                "The test provider fails to encrypt",
            )),
            _ => Ok(EncryptedDataEncryptionKey::new(
                dek.value().ref_sensitive_value().clone(),
            )),
        }
    }

    async fn generate_key_material(&self, _len: usize) -> KmsAeadResult<Option<SecretValue>> {
        match self {
            #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
            TestKmsProvider::Generating(key_material) => Ok(Some(key_material.clone())),
            _ => Ok(None),
        }
    }
}

impl KmsAeadDecryptionProvider for TestKmsProvider {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        match self {
            TestKmsProvider::FailingToDecrypt => Err(KmsAeadEncryptionError::create(
                "TEST_DECRYPT",
                "The test provider fails to decrypt",
            )),
            TestKmsProvider::Stamping(since) => {
                let nanos = u64::try_from(since.elapsed().as_nanos())
                    .expect("a test runs for less than 584 years");
                let mut key = encrypted_dek.value().to_vec();
                key.extend(nanos.to_le_bytes());
                Ok(DataEncryptionKey::from(SecretValue::new(key)))
            }
            _ => Ok(DataEncryptionKey::from(SecretValue::new(
                encrypted_dek.value().to_vec(),
            ))),
        }
    }
}

/// A [`TestKmsProvider`] under a KEK of its own, which counts its encryptions and decryptions and
/// can hold them, once counted, until the test opens its gate.
pub(crate) struct CountingKmsProvider {
    inner: TestKmsProvider,
    kek: KekRef,
    encryptions: AtomicUsize,
    decryptions: AtomicUsize,
    gate: watch::Sender<bool>,
}

impl CountingKmsProvider {
    /// A provider whose calls go through at once.
    pub(crate) fn new(inner: TestKmsProvider, kek: &str) -> Self {
        Self::with_kek(
            inner,
            KekRef::new(KmsProvider::Other("test".to_string()), kek),
        )
    }

    /// A provider that names `kek`, such as the KEK of a built-in provider, whose bytes kms-aead
    /// tells apart from the layouts of 0.29.
    pub(crate) fn with_kek(inner: TestKmsProvider, kek: KekRef) -> Self {
        Self {
            inner,
            kek,
            encryptions: AtomicUsize::new(0),
            decryptions: AtomicUsize::new(0),
            gate: watch::Sender::new(true),
        }
    }

    /// A provider whose calls wait until [`open_gate`](Self::open_gate).
    pub(crate) fn gated(inner: TestKmsProvider, kek: &str) -> Self {
        let provider = Self::new(inner, kek);
        provider.gate.send_replace(false);
        provider
    }

    pub(crate) fn open_gate(&self) {
        self.gate.send_replace(true);
    }

    #[cfg(any(feature = "ring", feature = "aws-lc-rs", feature = "rustcrypto"))]
    pub(crate) fn encryptions(&self) -> usize {
        self.encryptions.load(Ordering::SeqCst)
    }

    pub(crate) fn decryptions(&self) -> usize {
        self.decryptions.load(Ordering::SeqCst)
    }

    async fn pass_gate(&self) {
        self.gate.subscribe().wait_for(|open| *open).await.unwrap();
    }
}

impl KmsAeadEncryptionProvider for CountingKmsProvider {
    fn kek(&self) -> &KekRef {
        &self.kek
    }

    async fn encrypt_data_encryption_key(
        &self,
        dek: &DataEncryptionKey,
    ) -> KmsAeadResult<EncryptedDataEncryptionKey> {
        self.encryptions.fetch_add(1, Ordering::SeqCst);
        self.pass_gate().await;
        self.inner.encrypt_data_encryption_key(dek).await
    }
}

impl KmsAeadDecryptionProvider for CountingKmsProvider {
    async fn decrypt_data_encryption_key(
        &self,
        encrypted_dek: &EncryptedDataEncryptionKey,
    ) -> KmsAeadResult<DataEncryptionKey> {
        self.decryptions.fetch_add(1, Ordering::SeqCst);
        self.pass_gate().await;
        self.inner.decrypt_data_encryption_key(encrypted_dek).await
    }
}

/// What [`TestKmsProvider`] returns when kms-aead encrypts `key` as a key of `key_type`: the key as
/// Tink serialises it.
pub(crate) fn encrypted_by_test_provider(
    key_type: impl Into<TinkKeyType>,
    key: &[u8],
) -> EncryptedDataEncryptionKey {
    let dek = DataEncryptionKey::from(SecretValue::new(key.to_vec()));
    let serialized = crate::formats::serialize_tink_key(key_type.into(), &dek);
    EncryptedDataEncryptionKey::new(serialized.ref_sensitive_value().clone())
}

/// Lets every spawned task of a current-thread runtime run until it waits on something.
pub(crate) async fn let_spawned_tasks_wait() {
    for _ in 0..CONCURRENT_CALLS * 4 {
        tokio::task::yield_now().await;
    }
}

/// The forms in which stored or secret bytes could reach a message or a log line: as text,
/// as lowercase and uppercase hex, as standard base64, and as the `Debug` list of a byte slice
/// without its brackets, which also finds the list with them.
pub(crate) fn renderings(bytes: &[u8]) -> Vec<String> {
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

/// A value Tink's `KmsEnvelopeAead` wrote on a live KMS key.
#[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
pub(crate) struct TinkEnvelope {
    pub(crate) algorithm: crate::AeadAlgorithm,
    pub(crate) aad: &'static str,
    pub(crate) plain_text: &'static str,
    pub(crate) value: &'static str,
}

/// The bytes of an invoice the signing and MAC tests sign, under the payload type of the book's
/// test vectors.
pub(crate) struct Invoice(pub(crate) Vec<u8>);

impl crate::SignableType for Invoice {
    const PAYLOAD_TYPE: crate::SignedPayloadType =
        crate::SignedPayloadType::from_static("application/vnd.example.invoice+json");
}

impl crate::Signable for Invoice {
    fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
        Ok(self.0.clone())
    }

    fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
        Ok(Invoice(payload))
    }
}

/// The payload of the book's test vectors.
pub(crate) const INVOICE_PAYLOAD: &[u8] =
    br#"{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","total_cents":12500}"#;

/// [`INVOICE_PAYLOAD`] with another total.
pub(crate) const OTHER_INVOICE_PAYLOAD: &[u8] =
    br#"{"number":"INV-1042","customer":"Northwind Traders","currency":"EUR","total_cents":99900}"#;

/// The PKCS#8 of the RFC 8032 section 7.1 test 1 key, whose key id is `0x90facafe`.
pub(crate) const ED25519_PKCS8_DER: &str =
    "302e020100300506032b6570042204209d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";

/// The RFC 8032 test 1 signature of the pre-image of [`INVOICE_PAYLOAD`].
pub(crate) const ED25519_SIGNATURE: &str = "21c5f4d55977b19640f25f0e248d4c9765aa0d210f9c781b61b46dece74d4dec\
                                            b950acf3947659a9fff322b88ad8562e2c9ee4392440a4da901b7fec385f1102";

/// The PKCS#8 of the RFC 6979 A.2.5 key with its public point, as Python's `cryptography` writes
/// it. Its key id is `0x0cebf1bc`.
pub(crate) const P256_PKCS8_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02\
                                         01010420c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b\
                                         120f6721a1440342000460fed4ba255a9d31c961eb74c6356d68c049b8923b61\
                                         fa6ce669622e60f29fb67903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e\
                                         9f5177a3c294d4462299";

/// A P-256 signature of the pre-image of [`INVOICE_PAYLOAD`] under the RFC 6979 A.2.5 key, as
/// `r || s`.
pub(crate) const P256_SIGNATURE: &str = "409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7\
                                         af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976";

/// The DER `ECDSA-Sig-Value` of [`P256_SIGNATURE`], whose `s` takes the leading `0x00` that DER
/// gives an integer of `0x80` or more.
#[cfg(any(feature = "gcp-kms-encryption-base", feature = "aws-kms-encryption"))]
pub(crate) const P256_SIGNATURE_DER: &str = "30450220409b9927a7f27d61f6d7360b9b91941fa6dd14db553a55d0dd573fc9db7fccb7\
                                             022100af3a4aaab89c0684256afe5db6aa53e4569286bc2c2f6435fe7563db215b5976";

/// The verifying key of the PKCS#8 key `pkcs8_der`, in hex.
#[cfg(any(
    feature = "gcp-kms-encryption-base",
    feature = "aws-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption-base"
))]
pub(crate) fn verifying_key_of(pkcs8_der: &str) -> crate::signing::VerifyingKey {
    use std::num::NonZeroU32;

    use crate::formats::PrivateKeyFormat;
    use crate::providers::{LocalSigningKey, LocalSigningKeyVersion};

    LocalSigningKey::from_secret(
        LocalSigningKeyVersion::from(NonZeroU32::MIN),
        SecretValue::new(hex::decode(pkcs8_der).expect("the PKCS#8 test key is hex")),
        PrivateKeyFormat::Pkcs8Der,
    )
    .expect("the PKCS#8 test key is a signing key")
    .verifying_key()
    .clone()
}

/// The backend of the tests that need RSA, which ring does not have.
#[cfg(feature = "aws-lc-rs")]
pub(crate) type RsaTestBackend = crate::backends::AwsLc;
#[cfg(all(not(feature = "aws-lc-rs"), feature = "rustcrypto"))]
pub(crate) type RsaTestBackend = crate::backends::RustCrypto;

/// A Wycheproof `rsa_oaep_<bits>_sha256_mgf1sha256_test.json` suite of `C2SP/wycheproof`
/// `testvectors_v1` at commit `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9`, in `tests/vectors/`: one
/// key and its cases.
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RsaOaepSuite {
    test_groups: [RsaOaepGroup; 1],
}

#[cfg_attr(
    not(any(feature = "aws-lc-rs", feature = "rustcrypto")),
    expect(
        dead_code,
        reason = "only the tests on a backend with RSA decrypt the cases"
    )
)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct RsaOaepGroup {
    key_size: usize,
    private_key_pkcs8: String,
    private_key_jwk: RsaPrivateJwk,
    tests: Vec<RsaOaepCase>,
}

/// The public members of the suite's key.
#[derive(serde::Deserialize)]
struct RsaPrivateJwk {
    n: String,
    e: String,
}

/// One case: `ct` decrypts to `msg` under `label` when `result` is `valid`.
#[cfg_attr(
    not(any(feature = "aws-lc-rs", feature = "rustcrypto")),
    expect(
        dead_code,
        reason = "only the tests on a backend with RSA decrypt the cases"
    )
)]
#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct RsaOaepCase {
    pub(crate) tc_id: u32,
    pub(crate) msg: String,
    pub(crate) ct: String,
    pub(crate) label: String,
    pub(crate) result: String,
}

impl RsaOaepSuite {
    /// The suite of keys of `bits` bits: 2048, 3072 or 4096.
    pub(crate) fn of_bits(bits: usize) -> Self {
        let json = match bits {
            2048 => include_str!("../tests/vectors/rsa_oaep_2048_sha256_mgf1sha256_test.json"),
            3072 => include_str!("../tests/vectors/rsa_oaep_3072_sha256_mgf1sha256_test.json"),
            4096 => include_str!("../tests/vectors/rsa_oaep_4096_sha256_mgf1sha256_test.json"),
            _ => panic!("no Wycheproof RSA-OAEP suite of {bits} bits"),
        };
        let suite: Self = serde_json::from_str(json).expect("a vector file parses");
        assert_eq!(suite.test_groups[0].key_size, bits);
        suite
    }

    /// The key as a PKCS#8 `PrivateKeyInfo` in DER.
    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    pub(crate) fn pkcs8_der(&self) -> SecretValue {
        SecretValue::new(
            hex::decode(&self.test_groups[0].private_key_pkcs8).expect("the PKCS#8 is hex"),
        )
    }

    /// The public key as the JSON Web Key `{"kty":"RSA","n":…,"e":…}`.
    pub(crate) fn public_jwk(&self) -> Vec<u8> {
        let jwk = &self.test_groups[0].private_key_jwk;
        format!(r#"{{"kty":"RSA","n":"{}","e":"{}"}}"#, jwk.n, jwk.e).into_bytes()
    }

    /// The public key as a SubjectPublicKeyInfo in DER.
    #[cfg(any(
        feature = "aws-kms-encryption",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ))]
    pub(crate) fn spki_der(&self) -> Vec<u8> {
        self.public_key().spki_der().to_vec()
    }

    /// The public key as a SubjectPublicKeyInfo in a `PUBLIC KEY` PEM block.
    #[cfg(any(
        feature = "gcp-kms-encryption-base",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ))]
    pub(crate) fn spki_pem(&self) -> String {
        let pem = self
            .public_key()
            .encode(crate::formats::PublicKeyFormat::SpkiPem)
            .expect("a public key encodes as PEM");
        String::from_utf8(pem).expect("PEM is ASCII")
    }

    #[cfg(any(
        feature = "gcp-kms-encryption-base",
        feature = "aws-kms-encryption",
        feature = "hashicorp-vault-transit-kms-encryption-base"
    ))]
    fn public_key(&self) -> crate::AsymmetricKekPublicKey {
        crate::AsymmetricKekPublicKey::new(
            KekRef::new(KmsProvider::Aws, "key"),
            None,
            crate::AsymmetricKekAlgorithm::RsaOaepSha256,
            self.public_jwk(),
            crate::formats::PublicKeyFormat::Jwk,
        )
        .expect("the suite's key is a valid public key")
    }

    #[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
    pub(crate) fn cases(&self) -> &[RsaOaepCase] {
        &self.test_groups[0].tests
    }

    /// The case `tc_id`.
    pub(crate) fn case(&self, tc_id: u32) -> &RsaOaepCase {
        self.test_groups[0]
            .tests
            .iter()
            .find(|case| case.tc_id == tc_id)
            .expect("the suite has the case")
    }
}

/// A 2048-bit RSA block, which no key produced.
#[cfg(any(
    feature = "aws-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption-base"
))]
pub(crate) const ENCRYPTED_BLOCK: [u8; 256] = [0xB1; 256];

/// The `0x02` encrypted DEK that names `kek_id` and `kek_version` around [`ENCRYPTED_BLOCK`].
#[cfg(any(
    feature = "aws-kms-encryption",
    feature = "hashicorp-vault-transit-kms-encryption-base"
))]
pub(crate) fn public_key_encrypted_dek(
    kek_id: &[u8],
    kek_version: Option<&str>,
) -> KmsAeadResult<EncryptedDataEncryptionKey> {
    let bytes = crate::formats::asymmetric::PublicKeyEncryptedDek {
        algorithm: crate::AsymmetricKekAlgorithm::RsaOaepSha256,
        kek_id,
        kek_version: kek_version
            .map(|version| crate::providers::KmsKeyVersion::try_from(version.to_string()))
            .transpose()?,
        block: &ENCRYPTED_BLOCK,
    }
    .to_bytes()?;
    Ok(EncryptedDataEncryptionKey::new(bytes))
}

/// Asserts that `result` is an error with the code `code`.
pub(crate) fn assert_code<T: std::fmt::Debug>(result: KmsAeadResult<T>, code: &str) {
    assert!(
        matches!(&result, Err(error) if error.code() == code),
        "{code}: {result:?}"
    );
}

/// The code of the error in `result`, or `Ok(..)` with the value when it succeeded, so that a
/// comparison with a code shows the value that was wrongly returned.
pub(crate) fn error_code_of<V: std::fmt::Debug>(result: KmsAeadResult<V>) -> String {
    match result {
        Ok(value) => format!("Ok({value:?})"),
        Err(error) => error.code().to_string(),
    }
}

/// A 1024-bit RSA key, below the sizes an asymmetric KEK takes, as a PKCS#8 `PrivateKeyInfo`.
#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
/// Generated by `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024`.
pub(crate) const RSA_1024_PKCS8_DER: &str = "30820276020100300d06092a864886f70d0101010500048202603082025c0201\
                                         0002818100be7357847514654fdf259bb9e75e54aab2a1ecea11c3c3101f84db\
                                         ab0ec016658d4f3e4cfd711d4d174ca7a7f2dac4491390b813b091a8ccd34585\
                                         4df636f0bac75efebc0c082b2a56008c0e4fe2d930df58aa0994d80d68eb1995\
                                         607b96c8eaaf3f8e7a1fefaea4e911ae025416ebeaf6a58c23fa8a3b2e366aec\
                                         76c02ebb7b020301000102818100b6fda86792ff47e118add0152de40b420065\
                                         6977f61dbcbd2f2bbecd7b5cc1a84dc08841fd7ac406a08e7cc0f8ad8ed01046\
                                         8b380ffdc4cd196ac10d09b7fc50309ab32409f8cfc03b43b80e4cdd8fd6bc04\
                                         b3dd3482f79354505c0eea8a4880ca7cd34884844c112ca225883dec34ecbc33\
                                         79996c5755316bc704bdab9c91e1024100f31cf3a35b7a6d665801f733e68379\
                                         5e610f7c2e25d7bd4e17d808a6fd2ae8248b2480292ab31f09fff366000231fd\
                                         06615f417aa5ccc618b252ce6eb8eebd99024100c88bc23b9b6f33f17f16983a\
                                         36b7c73ab0d886cf214d53f94f6e8730bf2571be270ae05f1717134956ca3f8b\
                                         133206c920f63a58e8b1b5cd76eba19c3634663302401d56c01c55bcd7990343\
                                         f17644fa56da49f259752441fde97fbd2586298555109bee22bd5516dac71529\
                                         6584d8bef99f1c7f2762cac184a2945aa3e8fece68f902406aee1a22ae3e1cf4\
                                         274f64dba551586972e200ff70424b0423d64b3f32ac44799f57ad4b0684c743\
                                         d383035ea45d8840b5d29449d3c8eda72041836a477ca901024020eeb71c7807\
                                         4cd6c71dbc25e667c2a67f9a0c61e1618e669255029b3a3a4b37b420e8b29ce3\
                                         5a7e3d958992beb6ab240f3c1f6382eb6d9d6b832615ae9b78c8";
