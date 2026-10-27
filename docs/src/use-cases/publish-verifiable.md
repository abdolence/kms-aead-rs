# Publish content anyone can verify

A rate sheet, a data export or a release goes out with a signature, and whoever downloads it checks
that it came from the publisher and was not changed on the way, with no KMS and no secret. The
private key stays in a KMS. Verifiers need the public key, which the publisher serves as a JWK Set,
a JSON document that lists public keys. See [Signatures and MACs](../signing.md).

## Sign a document

A bank publishes its exchange rates as a JSON document. The type that holds the document implements
`SignableType`, which names its payload type, and is signed as `JsonEncoded::new(rates)`, which stands
for the compact JSON of the value. The payload type is signed with the bytes, so a signature over
the rates never verifies as another kind of document. Canonicalise the JSON before it is
signed if anything serialises it again. To publish large files, sign one document that lists their
SHA-256 digests instead of each file, and compare the digest of each downloaded file with its entry
once the document verifies.

The signing key is a KMS key version that signs, such as a Cloud KMS `EC_SIGN_P256_SHA256` version.
Every signing provider is built from a key reference that names one version, see "Signing" on the
page of [Google Cloud KMS](../providers/gcp.md#signing), [AWS KMS](../providers/aws.md#signing),
[Azure Key Vault](../providers/azure.md#signing) and
[Vault Transit](../providers/hc-vault-transit.md#signing):

```rust,no_run
use std::collections::BTreeMap;
use std::num::NonZeroU32;

use kms_aead::backends::Ring;
use kms_aead::providers::{GcpKmsSigningKeyRef, GcpKmsSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm, VerifyingKeySet};
use kms_aead::{JsonEncoded, KmsAeadResult, SignedPayloadType, SignableType};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct ExchangeRates {
    base: String,
    date: String,
    rates: BTreeMap<String, f64>,
}

impl SignableType for ExchangeRates {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.exchange-rates+json");
}

# #[tokio::main]
# async fn main() -> KmsAeadResult<()> {
let key_ref = GcpKmsSigningKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "rates".to_string(),
    "rates-signing".to_string(),
    NonZeroU32::MIN,
    SigningAlgorithm::EcdsaP256Sha256,
);
let signer = Signer::<_, Ring>::new(GcpKmsSigningProvider::new(&key_ref).await?).await?;

// Once per key: the JWK Set to serve at a stable URL, such as /.well-known/rate-keys.json
let jwks: String = VerifyingKeySet::new([signer.verifying_key().clone()])?.to_jwks()?;

// Per publication: the signature to publish beside the document
let rates = JsonEncoded::new(ExchangeRates {
    base: "EUR".to_string(),
    date: "2026-10-26".to_string(),
    rates: BTreeMap::from([("GBP".to_string(), 0.8412), ("USD".to_string(), 1.0873)]),
});
let signature: Vec<u8> = signer.sign(&rates).await?.into_value();
# let _ = (jwks, signature);
# Ok(())
# }
```

## Verify in Rust

A verifier is built from the JWK Set alone and needs no KMS client, so it runs in a CLI, a CI job
or another service on any crypto backend:

```rust
use kms_aead::backends::Ring;
use kms_aead::signing::{Signature, Verifier, VerifyingKeySet};
use kms_aead::{JsonEncoded, KmsAeadResult, SignedPayloadType, SignableType};
# use std::collections::BTreeMap;
# use kms_aead::providers::{LocalSigningKeyName, LocalSigningProvider};
# use kms_aead::signing::{Signer, SigningAlgorithm};
# use serde::{Deserialize, Serialize};

# #[derive(Serialize, Deserialize)]
# struct ExchangeRates {
#     base: String,
#     date: String,
#     rates: BTreeMap<String, f64>,
# }
# impl SignableType for ExchangeRates {
#     const PAYLOAD_TYPE: SignedPayloadType =
#         SignedPayloadType::from_static("application/vnd.example.exchange-rates+json");
# }
# #[tokio::main]
# async fn main() -> KmsAeadResult<()> {
# let provider = LocalSigningProvider::<Ring>::ephemeral(
#     LocalSigningKeyName::try_from("rates".to_string())?,
#     SigningAlgorithm::EcdsaP256Sha256,
# )?;
# let signer = Signer::<_, Ring>::new(provider).await?;
# let downloaded_jwks = VerifyingKeySet::new([signer.verifying_key().clone()])?.to_jwks()?;
# let rates = JsonEncoded::new(ExchangeRates {
#     base: "EUR".to_string(),
#     date: "2026-10-26".to_string(),
#     rates: BTreeMap::from([("GBP".to_string(), 0.8412), ("USD".to_string(), 1.0873)]),
# });
# let downloaded_signature = signer.sign(&rates).await?.into_value();
let verifier = Verifier::<Ring>::new(VerifyingKeySet::from_jwks(&downloaded_jwks)?)?;
let signature = Signature::<JsonEncoded<ExchangeRates>>::try_from(downloaded_signature)?;
verifier.verify(&rates, &signature)?;
# Ok(())
# }
```

A verification that fails returns `SIGNATURE_INVALID`, and a signature with a key id the set lacks
`SIGNING_KEY_UNKNOWN`.

## Verify in the browser

A page or a service worker verifies the same signature with WebCrypto: import the keys of the JWK
Set, hash the payload and call `verify`. The code is in
[In a browser](../signing.md#in-a-browser), with the browsers that support Ed25519 and P-256, and
the test vectors that run against it in CI. Use P-256 where every engine must verify.

## Rotate signing keys

A signing key rotates by publishing before signing:

1. create the new key version in the KMS;
2. add its public key to the served JWK Set beside the current one;
3. switch the signers to the new version once verifiers have fetched the set;
4. keep the old key in the set for as long as its signatures are verified.

A signature carries the id of its key, the first four bytes of the key's JWK thumbprint, so
verifiers pick the key with no coordination. Removing a key from the set revokes every signature
under it, which is the response to a compromised key. See
[Key ids and rotation](../signing.md#key-ids-and-rotation).

## What to watch for

- The JWK Set is the trust root. Serve it over HTTPS from a domain the publisher controls, and let
  a verifier that needs more pin it in its own configuration. The library does not sign the set;
- a signature has no expiry and the set has no revocation list. Put a version or a date in the
  document, such as the `date` of the rates, so that a verifier can refuse an old document that is
  still validly signed;
- ECDSA signatures are malleable: never use signature bytes as an identifier;
- the signature does not hide the document, see [Large files](./large-files.md) for the content.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/signing.rs).
