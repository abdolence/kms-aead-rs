//! Encrypts a customer record as JSON on the local KMS, then decrypts a record written by an
//! older version of the application, whose `plan` was a number. The record does not decode, and
//! the `WARN` event shows which field differs without showing the email. Needs no cloud
//! credentials.
//!
//! The default policy, `ShapeOnly`, logs the shape of the JSON and no value, since an encrypted
//! plaintext is secret; a type opts into more with a `JsonRedaction` of its own, as `CustomerLog`
//! does for the fields that identify no one.
//!
//! ```sh
//! cargo run --example encrypted_json --features ring
//! ```

use kms_aead::backends::Ring;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::redaction::{FieldPaths, JsonRedaction};
use kms_aead::{Encrypted, JsonEncoded, KmsAeadEnvelope};
use serde::{Deserialize, Serialize};
use tracing_subscriber::filter::LevelFilter;

const EMAIL: &str = "ada.lovelace@example.com";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Customer {
    id: String,
    email: String,
    plan: String,
    renewal_date: String,
}

/// What the logs show of a customer record that does not decode: the field names, the lengths of
/// the values they hide, and the id and plan, which identify no one. The email shows only its
/// length.
struct CustomerLog;

impl JsonRedaction for CustomerLog {
    const FIELD_NAMES: bool = true;
    const SIZES: bool = true;
    const REVEALED_FIELDS: FieldPaths = FieldPaths::from_static(&["id", "plan"]);
}

type CustomerJson = JsonEncoded<Customer, CustomerLog>;

/// The record as an earlier version of the application wrote it, with the plan as a number.
#[derive(Serialize, Deserialize)]
struct CustomerV1 {
    id: String,
    email: String,
    plan: u32,
    renewal_date: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .without_time()
        .with_max_level(LevelFilter::WARN)
        .init();

    // An ephemeral KEK lives as long as the process, so nothing it encrypts outlives this run.
    let provider =
        LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("customers".to_string())?)?;
    let envelope = KmsAeadEnvelope::<LocalKmsProvider<Ring>, Ring>::new(provider)?;
    let aad = b"customers/4821";

    let customer = CustomerJson::from(Customer {
        id: "cus_4821".into(),
        email: EMAIL.into(),
        plan: "team".into(),
        renewal_date: "2027-03-01".into(),
    });
    let encrypted: Encrypted<CustomerJson, Envelope> = envelope.encrypt(aad, &customer).await?;
    let decrypted: CustomerJson = envelope.decrypt(aad, &encrypted).await?;
    assert_eq!(decrypted, customer);
    println!("customer record round-trips");

    let old_record = JsonEncoded::new(CustomerV1 {
        id: "cus_4821".into(),
        email: EMAIL.into(),
        plan: 2,
        renewal_date: "2027-03-01".into(),
    });
    let encrypted_v1: Encrypted<JsonEncoded<CustomerV1>, Envelope> =
        envelope.encrypt(aad, &old_record).await?;
    let stored = Encrypted::<CustomerJson, Envelope>::try_from(encrypted_v1.into_value())?;

    let Err(error) = envelope.decrypt(aad, &stored).await else {
        return Err("a record of the older schema decoded".into());
    };
    assert_eq!(error.code(), "INVALID_PLAINTEXT");
    println!("older record refused: {}", error.code());

    Ok(())
}
