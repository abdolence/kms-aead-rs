//! The Azure provider against canned Key Vault responses.

use azure_core::http::{ClientOptions, RetryOptions, StatusCode, Transport};
use azure_security_keyvault_keys::KeyClientOptions;
use kms_aead::errors::KmsAeadError;
use kms_aead::providers::{
    AzureKmsAlgorithm, AzureKmsKeyRef, AzureKmsProvider, AzureKmsProviderOptions, KmsKeyVersion,
};
use kms_aead::*;
use std::sync::Arc;

mod common;
use common::{Backend, CannedHttpClient, FixedTokenCredential};

const VAULT_URL: &str = "https://test-vault.vault.azure.net";
const KEY_NAME: &str = "dek-encrypting-key";
const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";
const LEAK_MARKER: &str = "body-marker-that-must-not-leak";

fn options_over(status: StatusCode, body: String) -> AzureKmsProviderOptions {
    options_with(Arc::new(CannedHttpClient::new(status, body)))
}

fn options_with(http_client: Arc<CannedHttpClient>) -> AzureKmsProviderOptions {
    common::install_crypto_provider();
    AzureKmsProviderOptions::new().with_client_options(KeyClientOptions {
        client_options: ClientOptions {
            transport: Some(Transport::new(http_client)),
            retry: RetryOptions::none(),
            ..Default::default()
        },
        ..Default::default()
    })
}

fn provider_over(status: StatusCode, body: String) -> KmsAeadResult<AzureKmsProvider> {
    AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
        options_over(status, body),
        Arc::new(FixedTokenCredential),
    )
}

/// `wrapped` in the layout of the provider's encrypted keys, after the key version `KEY_VERSION`:
/// `[0x01][k: u8][key version: k][encrypted DEK]`.
fn encrypted_key(wrapped: &[u8]) -> EncryptedDataEncryptionKey {
    let kek_version = KEY_VERSION.as_bytes();
    let header = [
        0x01,
        u8::try_from(kek_version.len()).expect("KEY_VERSION is 32 characters"),
    ];
    EncryptedDataEncryptionKey::new([&header[..], kek_version, wrapped].concat())
}

fn data_encryption_key() -> DataEncryptionKey {
    DataEncryptionKey::from(secret_vault_value::SecretValue::new(vec![7u8; 32]))
}

#[tokio::test]
async fn decrypt_names_the_configured_kek() -> KmsAeadResult<()> {
    let http_client = Arc::new(CannedHttpClient::new(
        StatusCode::Ok,
        format!(
            r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
            azure_core::base64::encode_url_safe([7u8; 32])
        ),
    ));
    let provider = AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
        options_with(http_client.clone()),
        Arc::new(FixedTokenCredential),
    )?;

    provider
        .decrypt_data_encryption_key(&encrypted_key(b"wrapped"))
        .await?;

    let urls = http_client.urls.lock().unwrap();
    assert!(
        urls.iter().all(|url| url.starts_with(&format!(
            "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}/unwrapkey?"
        ))),
        "{urls:?}"
    );
    assert!(!urls.is_empty());
    assert_eq!(
        *provider.kek(),
        KekRef::new(KmsProvider::Azure, format!("{VAULT_URL}/keys/{KEY_NAME}"))
    );
    Ok(())
}

#[tokio::test]
async fn provider_errors_carry_no_key_material() -> KmsAeadResult<()> {
    let key_marker = azure_core::base64::encode_url_safe(LEAK_MARKER);
    let encrypted_dek = encrypted_key(b"wrapped");
    let responses = [
        // A successful decryption whose body is not the expected model.
        (StatusCode::Ok, format!(r#"{{"value": ["{key_marker}"]}}"#)),
        (StatusCode::Ok, format!(r#"{{"value": "{key_marker}""#)),
        (
            StatusCode::InternalServerError,
            format!(r#"{{"value": "{key_marker}"}}"#),
        ),
    ];

    for (status, body) in responses {
        let err = provider_over(status, body)?
            .decrypt_data_encryption_key(&encrypted_dek)
            .await
            .unwrap_err();

        for text in [format!("{err}"), format!("{err:?}")] {
            assert!(!text.contains(&key_marker), "{status}: {text}");
        }
    }
    Ok(())
}

#[tokio::test]
async fn encryption_with_the_latest_key_version_carries_the_version_from_kid() -> KmsAeadResult<()>
{
    let wrapped = b"wrapped-data-encryption-key".to_vec();
    let body = format!(
        r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
        azure_core::base64::encode_url_safe(&wrapped)
    );

    let encrypted_dek = provider_over(StatusCode::Ok, body)?
        .encrypt_data_encryption_key(&data_encryption_key())
        .await?;

    assert_eq!(encrypted_dek, self::encrypted_key(&wrapped));
    assert_eq!(
        encrypted_dek.kek_version(),
        Some(&KmsKeyVersion::try_from(KEY_VERSION.to_string())?)
    );
    Ok(())
}

#[tokio::test]
async fn key_vault_encrypts_the_raw_key() -> Result<(), Box<dyn std::error::Error>> {
    for algorithm in [AeadAlgorithm::Aes128Gcm, AeadAlgorithm::Aes256Gcm] {
        let http_client = Arc::new(CannedHttpClient::new(
            StatusCode::Ok,
            format!(
                r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "d3JhcHBlZA"}}"#
            ),
        ));
        let provider = AzureKmsProvider::with_options(
            &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
            options_with(http_client.clone()),
            Arc::new(FixedTokenCredential),
        )?;
        let envelope = KmsAeadEnvelope::<_, Backend>::with_options(
            provider,
            KmsAeadEnvelopeOptions::new().with_algorithm(algorithm),
        )?;

        let (dek, _) = envelope.generate_encrypted_dek().await?;

        let request_bodies = http_client.request_bodies.lock().unwrap();
        let [request_body] = request_bodies.as_slice() else {
            panic!("{algorithm}: {} requests", request_bodies.len());
        };
        let parameters: serde_json::Value = serde_json::from_slice(request_body)?;
        let wrapped = azure_core::base64::decode_url_safe(
            parameters["value"]
                .as_str()
                .ok_or("no value in the encryption request")?,
        )?;
        assert_eq!(wrapped.len(), algorithm.key_len(), "{algorithm}");
        assert_eq!(wrapped, *dek.value().ref_sensitive_value(), "{algorithm}");
    }
    Ok(())
}

#[tokio::test]
async fn encrypted_key_outside_the_layout_is_rejected_before_any_request() -> KmsAeadResult<()> {
    // A request would be answered with 200 and a decrypted key, so an error here can only
    // come from the encrypted key.
    let provider = provider_over(
        StatusCode::Ok,
        format!(r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "AAAA"}}"#),
    )?;

    let err = provider
        .decrypt_data_encryption_key(&EncryptedDataEncryptionKey::new(b"wrapped".to_vec()))
        .await
        .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "AZURE_ENCRYPTED_DEK_FORMAT"),
        "{err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn error_response_body_is_absent_from_errors() -> KmsAeadResult<()> {
    // A body that is not an Azure error envelope is copied into the SDK error.
    let body = format!(r#"{{"value": "{LEAK_MARKER}"}}"#);
    let err = provider_over(StatusCode::Forbidden, body)?
        .decrypt_data_encryption_key(&encrypted_key(b"wrapped"))
        .await
        .unwrap_err();

    assert!(matches!(err, KmsAeadError::EncryptionError(_)));
    assert!(!err.to_string().contains(LEAK_MARKER), "{err}");
    assert!(!format!("{err:?}").contains(LEAK_MARKER), "{err:?}");
    Ok(())
}

#[tokio::test]
async fn server_errors_and_throttling_are_network_errors() -> KmsAeadResult<()> {
    for status in [StatusCode::ServiceUnavailable, StatusCode::TooManyRequests] {
        let err = provider_over(
            status,
            r#"{"error": {"code": "Throttled", "message": "Try later"}}"#.into(),
        )?
        .encrypt_data_encryption_key(&data_encryption_key())
        .await
        .unwrap_err();

        assert!(
            matches!(err, KmsAeadError::NetworkError(_)),
            "{status}: {err:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn client_errors_keep_the_key_vault_error_code() -> KmsAeadResult<()> {
    let err = provider_over(
        StatusCode::Forbidden,
        r#"{"error": {"code": "Forbidden", "message": "The user does not have keys wrapKey permission"}}"#
            .into(),
    )?
    .encrypt_data_encryption_key(&data_encryption_key())
    .await
    .unwrap_err();

    assert!(
        matches!(&err, KmsAeadError::EncryptionError(e) if e.public.code == "Forbidden"),
        "{err:?}"
    );
    Ok(())
}

#[tokio::test]
async fn key_vault_receives_the_configured_algorithm() -> Result<(), Box<dyn std::error::Error>> {
    for (algorithm, alg) in [
        (AzureKmsAlgorithm::RsaOaepSha256, "RSA-OAEP-256"),
        (AzureKmsAlgorithm::RsaOaepSha1, "RSA-OAEP"),
        (AzureKmsAlgorithm::Aes128KeyWrap, "A128KW"),
        (AzureKmsAlgorithm::Aes192KeyWrap, "A192KW"),
        (AzureKmsAlgorithm::Aes256KeyWrap, "A256KW"),
        (AzureKmsAlgorithm::Pkcs11AesKeyWrap, "CKM_AES_KEY_WRAP"),
        (
            AzureKmsAlgorithm::Pkcs11AesKeyWrapWithPadding,
            "CKM_AES_KEY_WRAP_PAD",
        ),
    ] {
        let http_client = Arc::new(CannedHttpClient::new(
            StatusCode::Ok,
            format!(
                r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "d3JhcHBlZA"}}"#
            ),
        ));
        let provider = AzureKmsProvider::with_options(
            &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
            options_with(http_client.clone()).with_algorithm(algorithm),
            Arc::new(FixedTokenCredential),
        )?;

        provider
            .encrypt_data_encryption_key(&data_encryption_key())
            .await?;

        let request_bodies = http_client.request_bodies.lock().unwrap();
        let [request_body] = request_bodies.as_slice() else {
            panic!("{algorithm:?}: {} requests", request_bodies.len());
        };
        let parameters: serde_json::Value = serde_json::from_slice(request_body)?;
        assert_eq!(parameters["alg"], alg, "{algorithm:?}");
    }
    Ok(())
}

#[test]
fn vault_url_without_a_scheme_is_a_configuration_error() {
    let result = AzureKmsProvider::with_options(
        &AzureKmsKeyRef::new("test-vault.vault.azure.net".into(), KEY_NAME.into()),
        options_over(StatusCode::Ok, String::new()),
        Arc::new(FixedTokenCredential),
    );

    assert!(
        matches!(&result, Err(KmsAeadError::SystemError(e)) if e.public.code == "AZURE_VAULT_URL"),
        "{:?}",
        result.err()
    );
}

/// The `0x02` layout and the public key need an RSA backend, which ring is not.
#[cfg(any(feature = "aws-lc-rs", feature = "rustcrypto"))]
mod asymmetric_kek {
    use super::common::RsaBackend;
    use super::*;
    use kms_aead::formats::PublicKeyFormat;
    use kms_aead::providers::{LocalAsymmetricKmsProvider, LocalKekId, PublicKeyKekProvider};
    use serde_json::json;

    /// The bytes of a DEK Key Vault returns for a `0x02` block: 32 bytes of 7.
    const UNWRAPPED_DEK: [u8; 32] = [7u8; 32];

    fn azure_kek() -> KekRef {
        KekRef::new(KmsProvider::Azure, format!("{VAULT_URL}/keys/{KEY_NAME}"))
    }

    fn key_version(version: &str) -> KmsAeadResult<KmsKeyVersion> {
        KmsKeyVersion::try_from(version.to_string())
    }

    /// The public key of a fresh RSA key, under the Azure KEK at `KEY_VERSION`.
    fn kek_public_key() -> KmsAeadResult<AsymmetricKekPublicKey> {
        let local = LocalAsymmetricKmsProvider::<RsaBackend>::ephemeral(
            LocalKekId::try_from("local".to_string())?,
            AsymmetricKekAlgorithm::RsaOaepSha256,
        )?;
        AsymmetricKekPublicKey::new(
            azure_kek(),
            Some(key_version(KEY_VERSION)?),
            AsymmetricKekAlgorithm::RsaOaepSha256,
            local.public_key(None)?.spki_der().to_vec(),
            PublicKeyFormat::SpkiDer,
        )
    }

    /// A `0x02` encrypted DEK of the key `kek_public_key` returns, with its RSA block.
    async fn asymmetric_encrypted_dek() -> KmsAeadResult<(EncryptedDataEncryptionKey, Vec<u8>)> {
        let encrypted_dek = PublicKeyKekProvider::<RsaBackend>::new(kek_public_key()?)?
            .encrypt_data_encryption_key(&data_encryption_key())
            .await?;
        let bytes = encrypted_dek.value();
        let block = bytes[bytes.len() - 256..].to_vec();
        Ok((encrypted_dek, block))
    }

    /// A `0x02` encrypted DEK of the RSA-OAEP-SHA-256 algorithm around a block of 256 zero bytes.
    fn layout(kek_id: &[u8], kek_version: &[u8]) -> EncryptedDataEncryptionKey {
        let length = |field: &[u8]| u8::try_from(field.len()).expect("the field is short");
        let mut bytes = vec![0x02, 0x01, length(kek_id)];
        bytes.extend_from_slice(kek_id);
        bytes.push(length(kek_version));
        bytes.extend_from_slice(kek_version);
        bytes.extend_from_slice(&[0u8; 256]);
        EncryptedDataEncryptionKey::new(bytes)
    }

    #[tokio::test]
    async fn an_asymmetric_dek_is_unwrapped_by_its_version_with_rsa_oaep_256(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (encrypted_dek, block) = asymmetric_encrypted_dek().await?;
        for algorithm in [
            AzureKmsAlgorithm::RsaOaepSha256,
            AzureKmsAlgorithm::RsaOaepSha1,
            AzureKmsAlgorithm::Aes256KeyWrap,
        ] {
            let http_client = Arc::new(CannedHttpClient::new(
                StatusCode::Ok,
                format!(
                    r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "{}"}}"#,
                    azure_core::base64::encode_url_safe(UNWRAPPED_DEK)
                ),
            ));
            let provider = AzureKmsProvider::with_options(
                &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into())
                    .with_kek_version(key_version("0123456789abcdef0123456789abcdef")?),
                options_with(http_client.clone()).with_algorithm(algorithm),
                Arc::new(FixedTokenCredential),
            )?;

            let dek = provider.decrypt_data_encryption_key(&encrypted_dek).await?;

            assert_eq!(
                *dek.value().ref_sensitive_value(),
                UNWRAPPED_DEK,
                "{algorithm:?}"
            );
            let urls = http_client.urls.lock().unwrap();
            assert!(
                !urls.is_empty()
                    && urls.iter().all(|url| url.starts_with(&format!(
                        "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}/unwrapkey?"
                    ))),
                "{algorithm:?}: {urls:?}"
            );
            let request_bodies = http_client.request_bodies.lock().unwrap();
            let [request_body] = request_bodies.as_slice() else {
                panic!("{algorithm:?}: {} requests", request_bodies.len());
            };
            let parameters: serde_json::Value = serde_json::from_slice(request_body)?;
            assert_eq!(parameters["alg"], "RSA-OAEP-256", "{algorithm:?}");
            assert_eq!(
                azure_core::base64::decode_url_safe(parameters["value"].as_str().unwrap())?,
                block,
                "{algorithm:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn an_asymmetric_dek_of_a_local_kek_or_without_a_version_is_refused_before_any_request(
    ) -> KmsAeadResult<()> {
        for (kek_id, kek_version) in [
            (&b"local"[..], KEY_VERSION.as_bytes()),
            (&b""[..], &b""[..]),
        ] {
            let http_client = Arc::new(CannedHttpClient::new(
                StatusCode::Ok,
                format!(
                    r#"{{"kid": "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}", "value": "AAAA"}}"#
                ),
            ));
            let provider = AzureKmsProvider::with_options(
                &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
                options_with(http_client.clone()),
                Arc::new(FixedTokenCredential),
            )?;

            let err = provider
                .decrypt_data_encryption_key(&layout(kek_id, kek_version))
                .await
                .unwrap_err();

            assert!(
                matches!(&err, KmsAeadError::EncryptionError(e)
                    if e.public.code == "ASYMMETRIC_ENCRYPTED_DEK_FORMAT"),
                "{err:?}"
            );
            assert!(http_client.urls.lock().unwrap().is_empty());
        }
        Ok(())
    }

    /// A `GetKey` response for the JSON Web Key of `public_key`.
    fn key_response(
        public_key: &AsymmetricKekPublicKey,
        kty: &str,
        key_ops: &[&str],
        kid: &str,
    ) -> KmsAeadResult<String> {
        let mut jwk: serde_json::Value =
            serde_json::from_slice(&public_key.encode(PublicKeyFormat::Jwk)?)
                .expect("the JWK is JSON");
        jwk["kty"] = json!(kty);
        jwk["kid"] = json!(kid);
        jwk["key_ops"] = json!(key_ops);
        Ok(json!({ "key": jwk }).to_string())
    }

    const KEY_OPERATIONS: [&str; 2] = ["wrapKey", "unwrapKey"];

    fn http_client_of(body: String) -> Arc<CannedHttpClient> {
        Arc::new(CannedHttpClient::new(StatusCode::Ok, body))
    }

    fn provider_with(http_client: &Arc<CannedHttpClient>) -> KmsAeadResult<AzureKmsProvider> {
        AzureKmsProvider::with_options(
            &AzureKmsKeyRef::new(VAULT_URL.into(), KEY_NAME.into()),
            options_with(http_client.clone()),
            Arc::new(FixedTokenCredential),
        )
    }

    #[tokio::test]
    async fn the_latest_public_key_of_an_rsa_or_rsa_hsm_key_has_the_version_of_its_kid(
    ) -> KmsAeadResult<()> {
        let expected = kek_public_key()?;
        for kty in ["RSA", "RSA-HSM"] {
            let http_client = http_client_of(key_response(
                &expected,
                kty,
                &KEY_OPERATIONS,
                &format!("{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}"),
            )?);
            let provider = provider_with(&http_client)?;

            let public_key = provider.public_key(None).await?;

            assert_eq!(public_key, expected, "{kty}");
            assert_eq!(public_key.kek(), provider.kek(), "{kty}");
            let urls = http_client.urls.lock().unwrap();
            assert!(
                !urls.is_empty()
                    && urls
                        .iter()
                        .all(|url| url.starts_with(&format!("{VAULT_URL}/keys/{KEY_NAME}/?"))),
                "{kty}: {urls:?}"
            );
        }
        Ok(())
    }

    #[tokio::test]
    async fn the_public_key_of_a_version_has_the_version_of_the_response() -> KmsAeadResult<()> {
        let requested = key_version("0123456789abcdef0123456789abcdef")?;
        let expected = kek_public_key()?;
        let http_client = http_client_of(key_response(
            &expected,
            "RSA",
            &KEY_OPERATIONS,
            &format!("{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}"),
        )?);

        let public_key = provider_with(&http_client)?
            .public_key(Some(&requested))
            .await?;

        assert_eq!(public_key.kek_version(), Some(&key_version(KEY_VERSION)?));
        let urls = http_client.urls.lock().unwrap();
        assert!(
            !urls.is_empty()
                && urls.iter().all(
                    |url| url.starts_with(&format!("{VAULT_URL}/keys/{KEY_NAME}/{requested}?"))
                ),
            "{urls:?}"
        );
        Ok(())
    }

    #[tokio::test]
    async fn a_key_that_cannot_unwrap_with_rsa_is_refused() -> KmsAeadResult<()> {
        let public_key = kek_public_key()?;
        let versioned = format!("{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}");
        let responses = [
            ("EC", &KEY_OPERATIONS[..], versioned.clone()),
            ("oct", &KEY_OPERATIONS[..], versioned.clone()),
            ("RSA", &["wrapKey", "encrypt"][..], versioned.clone()),
            ("RSA", &[][..], versioned.clone()),
            (
                "RSA",
                &KEY_OPERATIONS[..],
                format!("{VAULT_URL}/keys/{KEY_NAME}"),
            ),
            (
                "RSA",
                &KEY_OPERATIONS[..],
                format!("{VAULT_URL}/keys/other-key/{KEY_VERSION}"),
            ),
        ];
        for (kty, key_ops, kid) in responses {
            let http_client = http_client_of(key_response(&public_key, kty, key_ops, &kid)?);

            let result = provider_with(&http_client)?.public_key(None).await;

            assert!(
                matches!(&result, Err(KmsAeadError::SystemError(e))
                    if e.public.code == "ASYMMETRIC_KEK_PUBLIC_KEY"),
                "{kty} {key_ops:?} {kid}: {result:?}"
            );
        }
        Ok(())
    }
}
