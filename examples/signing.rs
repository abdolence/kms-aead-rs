//! Signs an invoice with an ephemeral Ed25519 key of the local signing provider, publishes the
//! public key as a JWK Set, and verifies with a verifier built from that set alone. Logs the
//! `WARN` event of an invoice cut short. Needs no cloud credentials.
//!
//! ```sh
//! cargo run --example signing --features ring
//! ```

use kms_aead::backends::Ring;
use kms_aead::providers::{LocalSigningKeyName, LocalSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm, Verifier, VerifyingKeySet};
use kms_aead::{JsonEncoded, Signable, SignableType, SignedPayloadType};
use serde::{Deserialize, Serialize};

/// An invoice, signed as the JSON it serialises to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Invoice {
    number: String,
    customer: String,
    currency: String,
    lines: Vec<InvoiceLine>,
    total_cents: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct InvoiceLine {
    description: String,
    quantity: u32,
    unit_price_cents: u64,
}

impl SignableType for Invoice {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.invoice+json");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let provider = LocalSigningProvider::<Ring>::ephemeral(
        LocalSigningKeyName::try_from("invoices".to_string())?,
        SigningAlgorithm::Ed25519,
    )?;
    let signer = Signer::<_, Ring>::new(provider).await?;

    let invoice = JsonEncoded::new(Invoice {
        number: "INV-2026-0142".into(),
        customer: "Northwind Traders".into(),
        currency: "EUR".into(),
        lines: vec![
            InvoiceLine {
                description: "Standing desk".into(),
                quantity: 2,
                unit_price_cents: 54_900,
            },
            InvoiceLine {
                description: "Cable tray".into(),
                quantity: 4,
                unit_price_cents: 1_950,
            },
        ],
        total_cents: 117_600,
    });
    let signature = signer.sign(&invoice).await?;
    println!(
        "signed with key id {}: {} bytes",
        signature.key_id().as_u32(),
        signature.value().len()
    );

    // The verifying side holds no KMS and no key material, only what the signer published.
    let jwks = VerifyingKeySet::new([signer.verifying_key().clone()])?.to_jwks()?;
    println!("published {jwks}");
    let verifier = Verifier::<Ring>::new(VerifyingKeySet::from_jwks(&jwks)?)?;

    let key = verifier.verify(&invoice, &signature)?;
    println!("verified under {} {}", key.algorithm(), key.thumbprint());

    let tampered = JsonEncoded::new(Invoice {
        total_cents: 1,
        ..invoice.0.clone()
    });
    match verifier.verify(&tampered, &signature) {
        Ok(_) => return Err("a tampered invoice verified".into()),
        Err(error) => println!("tampered invoice refused: {}", error.code()),
    }

    // The attached form carries the payload; `verify_signed` verifies it and returns the decoded
    // value.
    let signed = signer.sign_attached(&invoice).await?;
    let (verified, _) = verifier.verify_signed(&signed)?;
    assert_eq!(verified, invoice);
    println!("attached form verified: {} bytes", signed.value().len());

    // A payload that does not decode fails with INVALID_PAYLOAD and logs a WARN event with an
    // outline of the JSON: its shape, and no value.
    tracing_subscriber::fmt().without_time().init();
    let payload = invoice.to_payload()?;
    let cut = &payload[..payload.len() / 2];
    match JsonEncoded::<Invoice>::from_payload(cut.to_vec()) {
        Ok(_) => return Err("a cut invoice decoded".into()),
        Err(error) => println!("cut invoice refused: {}", error.code()),
    }

    Ok(())
}
