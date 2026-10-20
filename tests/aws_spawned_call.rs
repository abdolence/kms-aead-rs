//! An envelope call on [`AwsKmsProvider`], spawned behind the layers of `async fn` an application
//! puts between its handler and the envelope, compiles at the compiler's default recursion limit.
//! The test fails at compile time, with E0275 on `…: Send`, when the AWS SDK's future reaches
//! the `Send` check of the spawned future.

use std::sync::Arc;

use kms_aead::backends::AwsLc;
use kms_aead::providers::AwsKmsProvider;
use kms_aead::{KmsAeadEnvelope, KmsAeadResult};
use secret_vault_value::SecretValue;
use tokio::task::JoinHandle;

type Envelope = KmsAeadEnvelope<AwsKmsProvider, AwsLc>;

async fn repository(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    let secret = SecretValue::from("order");
    let encrypted = envelope.encrypt("orders", &secret).await?;
    envelope.decrypt("orders", &encrypted).await
}

async fn service(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    repository(envelope).await
}

async fn layer_1(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    service(envelope).await
}

async fn layer_2(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_1(envelope).await
}

async fn layer_3(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_2(envelope).await
}

async fn layer_4(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_3(envelope).await
}

async fn layer_5(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_4(envelope).await
}

async fn layer_6(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_5(envelope).await
}

async fn layer_7(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_6(envelope).await
}

async fn layer_8(envelope: &Envelope) -> KmsAeadResult<SecretValue> {
    layer_7(envelope).await
}

async fn handler(envelope: Arc<Envelope>) -> KmsAeadResult<SecretValue> {
    layer_8(&envelope).await
}

fn spawn_handler(envelope: Arc<Envelope>) -> JoinHandle<KmsAeadResult<SecretValue>> {
    tokio::spawn(handler(envelope))
}

#[test]
fn aws_call_spawns_behind_nested_async_fns() {
    let _: fn(Arc<Envelope>) -> JoinHandle<KmsAeadResult<SecretValue>> = spawn_handler;
}
