//! The Azure signing provider against canned Key Vault responses.

use azure_core::http::{ClientOptions, RetryOptions, StatusCode, Transport};
use azure_security_keyvault_keys::KeyClientOptions;
use kms_aead::errors::KmsAeadError;
use kms_aead::formats::PublicKeyFormat;
use kms_aead::providers::{AzureKmsSigningKeyRef, AzureKmsSigningProvider, KmsKeyVersion};
use kms_aead::signing::{
    KmsSigningProvider, SigningAlgorithm, SigningInput, SigningKeyRef, VerifyingKey,
};
use kms_aead::{KmsAeadResult, KmsProvider};
use std::sync::Arc;

mod common;
use common::{CannedHttpClient, FixedTokenCredential};

const VAULT_URL: &str = "https://test-vault.vault.azure.net";
const KEY_NAME: &str = "signing-key";
const KEY_VERSION: &str = "4387e9f3d6e14c459867679a90fd0f79";
const OTHER_KEY_VERSION: &str = "0e9cf7d3a1b24c8f9a6b5d4e3c2b1a09";
const DIGEST: [u8; 32] = [0x5a; 32];
const PRE_IMAGE: [u8; 46] = [0x11; 46];
/// The x and y of the public key of the RFC 6979 A.2.5 key.
const P256_X: &str = "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6";
const P256_Y: &str = "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299";

fn key_id(version: &str) -> String {
    format!("{VAULT_URL}/keys/{KEY_NAME}/{version}")
}

fn provider_over(http_client: Arc<CannedHttpClient>) -> KmsAeadResult<AzureKmsSigningProvider> {
    common::install_crypto_provider();
    AzureKmsSigningProvider::with_client_options(
        &AzureKmsSigningKeyRef::new(
            VAULT_URL.into(),
            KEY_NAME.into(),
            KmsKeyVersion::try_from(KEY_VERSION.to_string())?,
        ),
        Some(KeyClientOptions {
            client_options: ClientOptions {
                transport: Some(Transport::new(http_client)),
                retry: RetryOptions::none(),
                ..Default::default()
            },
            ..Default::default()
        }),
        Arc::new(FixedTokenCredential),
    )
}

fn answering(status: StatusCode, body: String) -> Arc<CannedHttpClient> {
    Arc::new(CannedHttpClient::new(status, body))
}

fn signed_body(kid: &str, signature: &[u8]) -> String {
    format!(
        r#"{{"kid": "{kid}", "value": "{}"}}"#,
        azure_core::base64::encode_url_safe(signature)
    )
}

fn p256_input() -> SigningInput<'static> {
    SigningInput::EcdsaP256Sha256 {
        pre_image: &PRE_IMAGE,
        digest: &DIGEST,
    }
}

fn assert_code<T: std::fmt::Debug>(result: KmsAeadResult<T>, code: &str) {
    assert!(
        matches!(&result, Err(error) if error.code() == code),
        "expected {code}: {result:?}"
    );
}

fn p256_point() -> Vec<u8> {
    [
        &[0x04][..],
        &hex::decode(P256_X).expect("P256_X is hex"),
        &hex::decode(P256_Y).expect("P256_Y is hex"),
    ]
    .concat()
}

fn key_body(kid: &str, key_type: &str, curve: &str) -> String {
    format!(
        r#"{{"key": {{"kid": "{kid}", "kty": "{key_type}", "crv": "{curve}", "x": "{}", "y": "{}"}}}}"#,
        azure_core::base64::encode_url_safe(hex::decode(P256_X).expect("P256_X is hex")),
        azure_core::base64::encode_url_safe(hex::decode(P256_Y).expect("P256_Y is hex"))
    )
}

#[tokio::test]
async fn sign_sends_the_digest_as_es256_to_the_configured_version() -> KmsAeadResult<()> {
    let http_client = answering(StatusCode::Ok, signed_body(&key_id(KEY_VERSION), &[7; 64]));
    let provider = provider_over(http_client.clone())?;

    let signature = provider.sign(p256_input()).await?;

    assert_eq!(signature.value(), [7; 64]);
    let urls = http_client.urls.lock().unwrap();
    assert!(
        urls.iter().all(|url| url.starts_with(&format!(
            "{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}/sign?"
        ))),
        "{urls:?}"
    );
    let request_bodies = http_client.request_bodies.lock().unwrap();
    let [request_body] = request_bodies.as_slice() else {
        panic!("{} requests with a body", request_bodies.len());
    };
    let parameters: serde_json::Value = serde_json::from_slice(request_body).unwrap();
    assert_eq!(
        parameters,
        serde_json::json!({ "alg": "ES256", "value": azure_core::base64::encode_url_safe(DIGEST) })
    );
    assert_eq!(
        *provider.signing_key(),
        SigningKeyRef::new(KmsProvider::Azure, key_id(KEY_VERSION))
    );
    Ok(())
}

#[tokio::test]
async fn a_response_for_another_version_key_or_none_is_a_key_mismatch() -> KmsAeadResult<()> {
    for body in [
        signed_body(&key_id(OTHER_KEY_VERSION), &[7; 64]),
        signed_body(
            &format!("{VAULT_URL}/keys/other-key/{KEY_VERSION}"),
            &[7; 64],
        ),
        signed_body(
            &format!("https://other-vault.vault.azure.net/keys/{KEY_NAME}/{KEY_VERSION}"),
            &[7; 64],
        ),
        format!(
            r#"{{"value": "{}"}}"#,
            azure_core::base64::encode_url_safe([7; 64])
        ),
    ] {
        let provider = provider_over(answering(StatusCode::Ok, body.clone()))?;

        assert_code(provider.sign(p256_input()).await, "SIGNING_KEY_MISMATCH");
    }
    Ok(())
}

#[tokio::test]
async fn a_signature_of_another_length_is_refused() -> KmsAeadResult<()> {
    let provider = provider_over(answering(
        StatusCode::Ok,
        signed_body(&key_id(KEY_VERSION), &[7; 63]),
    ))?;

    assert_code(provider.sign(p256_input()).await, "SIGNATURE_ENCODING");
    Ok(())
}

#[tokio::test]
async fn an_ed25519_input_is_refused_before_any_request() -> KmsAeadResult<()> {
    let http_client = answering(StatusCode::Ok, signed_body(&key_id(KEY_VERSION), &[7; 64]));
    let provider = provider_over(http_client.clone())?;

    let result = provider
        .sign(SigningInput::Ed25519 {
            pre_image: &PRE_IMAGE,
        })
        .await;

    assert_code(result, "SIGNING_ALGORITHM_MISMATCH");
    assert!(http_client.urls.lock().unwrap().is_empty());
    Ok(())
}

#[tokio::test]
async fn the_jwk_of_the_configured_version_is_the_verifying_key() -> KmsAeadResult<()> {
    for key_type in ["EC", "EC-HSM"] {
        let http_client = answering(
            StatusCode::Ok,
            key_body(&key_id(KEY_VERSION), key_type, "P-256"),
        );

        let key = provider_over(http_client.clone())?.verifying_key().await?;

        assert_eq!(
            key,
            VerifyingKey::from_bytes(
                SigningAlgorithm::EcdsaP256Sha256,
                &p256_point(),
                PublicKeyFormat::Raw
            )?,
            "{key_type}"
        );
        let urls = http_client.urls.lock().unwrap();
        assert!(
            urls.iter()
                .all(|url| url.starts_with(&format!("{VAULT_URL}/keys/{KEY_NAME}/{KEY_VERSION}?"))),
            "{urls:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn a_key_that_is_not_ec_p256_or_is_another_version_is_refused() -> KmsAeadResult<()> {
    for (body, code) in [
        (
            key_body(&key_id(KEY_VERSION), "EC", "P-384"),
            "SIGNING_ALGORITHM_MISMATCH",
        ),
        (
            key_body(&key_id(KEY_VERSION), "RSA", "P-256"),
            "SIGNING_ALGORITHM_MISMATCH",
        ),
        (
            key_body(&key_id(OTHER_KEY_VERSION), "EC", "P-256"),
            "SIGNING_KEY_MISMATCH",
        ),
    ] {
        let provider = provider_over(answering(StatusCode::Ok, body))?;

        assert_code(provider.verifying_key().await, code);
    }
    Ok(())
}

#[tokio::test]
async fn a_refusal_is_a_signature_error_with_the_key_vault_code_and_throttling_a_network_error(
) -> KmsAeadResult<()> {
    let denied = provider_over(answering(
        StatusCode::Forbidden,
        r#"{"error": {"code": "Forbidden", "message": "The user does not have keys sign permission"}}"#
            .into(),
    ))?
    .sign(p256_input())
    .await;
    let throttled = provider_over(answering(
        StatusCode::TooManyRequests,
        r#"{"error": {"code": "Throttled", "message": "Try later"}}"#.into(),
    ))?
    .sign(p256_input())
    .await
    .unwrap_err();

    assert_code(denied, "Forbidden");
    assert!(
        matches!(throttled, KmsAeadError::NetworkError(_)),
        "{throttled:?}"
    );
    Ok(())
}

#[test]
fn a_key_name_or_vault_url_that_cannot_address_a_key_is_a_configuration_error() {
    common::install_crypto_provider();
    let version = KmsKeyVersion::try_from(KEY_VERSION.to_string()).unwrap();
    for (vault_url, key_name, code) in [
        (VAULT_URL, "name/with/slashes", "AZURE_KEY_NAME"),
        ("test-vault.vault.azure.net", KEY_NAME, "AZURE_VAULT_URL"),
    ] {
        let result = AzureKmsSigningProvider::new(
            &AzureKmsSigningKeyRef::new(vault_url.into(), key_name.into(), version.clone()),
            Arc::new(FixedTokenCredential),
        );

        assert!(
            matches!(&result, Err(KmsAeadError::SystemError(error)) if error.public.code == code),
            "{code}: {:?}",
            result.err()
        );
    }
}
