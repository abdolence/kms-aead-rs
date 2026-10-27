# Signatures and MACs

The library signs an application's bytes with an asymmetric key held by a KMS, or by the local
KMS, and verifies the signature without the KMS: in Rust on any crypto backend, and in a browser
with WebCrypto. Beside the signature it offers a MAC, a keyed hash, under a symmetric key version
of a keyring, for integrity inside one trust domain. Signatures are Ed25519 and ECDSA on P-256 with
SHA-256; MACs are HMAC-SHA256 and HMAC-SHA512. Neither hides the bytes, see
[Envelope encryption](./envelope-encryption.md) for that.

## Signature or MAC

| | Signature | MAC |
|---|---|---|
| Key | an asymmetric key: the private half signs, the public half verifies | one symmetric key: it computes and verifies |
| Who verifies | anyone holding the public key, with no KMS and no secret: another service, a browser, an offline tool | a holder of the key: a process with KMS decrypt on the keyring's KEK and read access to its record |
| Who can forge | the holder of the private key only | every verifier |
| Cost | one KMS call per signature | an HMAC in process |

Use a signature for a public archive, a document a browser checks, a bundle another organisation
verifies, or a record whose writer must be told apart from its readers, such as the
[keyring record](#signing-the-keyring-record). Use a MAC for bytes that one application's
processes hand each other: a cache entry, a job, a token, a row whose integrity must not depend on
the store. Be aware a MAC never proves origin to anyone who could not have computed it.

## Signing and verifying

A signed value has a payload type and the bytes that stand for it. The payload type is signed
with the bytes, so a signature over one kind of document never verifies as another kind. The
library signs the SHA-256 of the payload, so a KMS sees the same few bytes whatever the size of the
document. Canonicalise a document that may be serialised again before it is signed.

A serde type implements `SignableType` to name its payload type, and the call passes it as
`JsonEncoded::new(value)`, whose payload is the compact JSON of the value. `Signer::sign` and
`Verifier::verify_signed` take and return the `JsonEncoded`, and the outer type, `Signature` or
`Signed`, says what the bytes are for. A type with another encoding implements `Signable` itself,
see [Another encoding](#another-encoding).

A `Signer` signs through a signing provider. Its verifying key goes into a `VerifyingKeySet`, the
public keys a verifier trusts, which `to_jwks` writes as a JWK Set (RFC 7517, a JSON document that
lists public keys) and `from_jwks` reads back:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalSigningKeyName, LocalSigningProvider};
use kms_aead::signing::{Signature, Signer, SigningAlgorithm, Verifier, VerifyingKeySet};
use kms_aead::{JsonEncoded, KmsAeadResult, SignedPayloadType, SignableType};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct Invoice {
    number: String,
    customer: String,
    currency: String,
    total_cents: u64,
}

impl SignableType for Invoice {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("application/vnd.example.invoice+json");
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
// The local provider stands in for a KMS key, see the providers below
let provider = LocalSigningProvider::<Ring>::ephemeral(
    LocalSigningKeyName::try_from("invoices".to_string())?,
    SigningAlgorithm::Ed25519,
)?;
let signer = Signer::<_, Ring>::new(provider).await?;

// Once, by the signer's owner: the public key as a JWK Set, for verifiers and browsers
let jwks: String = VerifyingKeySet::new([signer.verifying_key().clone()])?.to_jwks()?;

let invoice = JsonEncoded::new(Invoice {
    number: "INV-1042".to_string(),
    customer: "Northwind Traders".to_string(),
    currency: "EUR".to_string(),
    total_cents: 12_500,
});
let stored: Vec<u8> = signer.sign(&invoice).await?.into_value();

// Anywhere: no KMS, no secret
let verifier = Verifier::<Ring>::new(VerifyingKeySet::from_jwks(&jwks)?)?;
let signature = Signature::<JsonEncoded<Invoice>>::try_from(stored)?;
verifier.verify(&invoice, &signature)?;

let forged = JsonEncoded::new(Invoice { total_cents: 1_250, ..invoice.0 });
assert_eq!(verifier.verify(&forged, &signature).unwrap_err().code(), "SIGNATURE_INVALID");
# Ok(())
# }
```

A verifier in another language checks the exact bytes that were signed. Publish the payload bytes
with the signature, as `to_payload` returned them, rather than rebuilding them from fields: another
serialiser may order the members or format numbers differently.

The signing providers sit beside the encryption providers, each in the feature of its KMS and
named by a key reference that names one key version, never "the latest": `GcpKmsSigningProvider`
(Ed25519 on software keys, P-256 on software and HSM keys), `AwsKmsSigningProvider` (name the key
by id or ARN, never by an alias), `AzureKmsSigningProvider` (P-256 only, since Key Vault signs no
Ed25519), `HcVaultTransitSigningProvider` and `LocalSigningProvider`, in every build. Be aware the
private key of a `LocalSigningProvider` is in process memory, with no IAM, no audit log and no HSM.

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/signing.rs).

## Attached and detached

`Signer::sign` returns a detached `Signature<T>`, a small value to store beside the bytes, and
`sign_attached` a `Signed<T>` that carries the payload. `Verifier::verify` checks a detached
signature against the payload as read; `Verifier::verify_signed` checks an attached value and only
then decodes and returns its payload. MACs have the same pair: a detached `Mac<T>`, checked with
`verify_mac` on a keyring, and an attached `WithMac<T>`, which `mac_attached` computes and
`verify_with_mac` checks before it returns the payload. The four types are stored as `Encrypted`
is, with serde, `postgres` and `sqlx`, and none implements `PartialEq`. The bytes are in
[Formats](./formats.md#signatures-and-macs).

## Another encoding

A type whose payload is not JSON implements `Signable` itself: `to_payload` returns the bytes that
are signed, and `from_payload` decodes the bytes of an attached value after they verified. Both
fail with `INVALID_PAYLOAD`. This statement is signed as its UTF-8 text:

```rust
use kms_aead::errors::KmsAeadEncryptionError;
use kms_aead::{KmsAeadResult, Signable, SignableType, SignedPayloadType};

struct Statement(String);

impl SignableType for Statement {
    const PAYLOAD_TYPE: SignedPayloadType =
        SignedPayloadType::from_static("text/vnd.example.statement");
}

impl Signable for Statement {
    fn to_payload(&self) -> KmsAeadResult<Vec<u8>> {
        Ok(self.0.clone().into_bytes())
    }

    fn from_payload(payload: Vec<u8>) -> KmsAeadResult<Self> {
        String::from_utf8(payload).map(Statement).map_err(|_| {
            KmsAeadEncryptionError::create("INVALID_PAYLOAD", "The payload is not UTF-8 text")
        })
    }
}
```

## Payloads that do not decode

`verify_signed` and `verify_with_mac` decode a payload after it verified. A `JsonEncoded` payload
that is not the JSON of its type fails with `INVALID_PAYLOAD`, which never quotes the payload, and
logs a `WARN` event with an outline of the JSON, which the type's policy sets as it does for an
encrypted value, see [JSON that does not decode](./stored-values.md#json-that-does-not-decode).

## Key ids and rotation

Every value starts with a key id that selects the key the verifier tries. The id of a signing key
is the first four bytes of its JWK thumbprint (RFC 7638), so a signer and every verifier agree on
it without a registry. A publisher with a numbering of its own sets it with `Signer::with_key_id`.
A key set holds one key per id, and a verifier refuses an id its set lacks with
`SIGNING_KEY_UNKNOWN`. The set is the trust root: a key in it verifies, and a key removed from it
verifies nothing, whatever the KMS still holds. Keep one set per publisher.

A signing key rotates by publishing before signing:

1. create the new key version in the KMS, or the new key on AWS KMS, or a new local version;
2. add the new signer's `verifying_key()` to the published key set beside the current key;
3. switch the signers to the new version once the verifiers have refreshed the set;
4. keep the old key in the set for as long as its signatures are verified. Removing it revokes every
   signature under it, which is the response to a compromised key.

### Key formats

Every loader of a key takes the format of its bytes as an enum from `kms_aead::formats`, and no
loader guesses it:

- `PrivateKeyFormat`: `Pkcs8Der` or `Pkcs8Pem`, for `LocalSigningKey` and `LocalAsymmetricKek`;
- `PublicKeyFormat`: `Raw`, `SpkiDer`, `SpkiPem` or `Jwk`, for `VerifyingKey`. An asymmetric KEK's
  public key takes all but `Raw`;
- `SymmetricKeyFormat`: `Raw`, `Base64` or `Jwk`, for `LocalKek`.

`openssl genpkey -algorithm ed25519` writes the PEM that `Pkcs8Pem` reads. `from_file` and
`from_env` read a key of up to 32 KiB from a file or a variable:

```rust
use std::num::NonZeroU32;

use kms_aead::formats::{PrivateKeyFormat, PublicKeyFormat};
use kms_aead::providers::{LocalSigningKey, LocalSigningKeyVersion};
use kms_aead::signing::{SigningAlgorithm, VerifyingKey};
use kms_aead::{KeyId, KmsAeadResult};
use secret_vault_value::SecretValue;

# fn main() -> KmsAeadResult<()> {
let pem = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJ1hsZ3v/VpguoRK9JLsLMREScVpezJpGXA7rAMcrn9g
-----END PRIVATE KEY-----
";
let key = LocalSigningKey::from_secret(
    LocalSigningKeyVersion::from(NonZeroU32::MIN),
    SecretValue::from(pem),
    PrivateKeyFormat::Pkcs8Pem,
)?;

// The public key out in one format and back in
let spki = key.verifying_key().encode(PublicKeyFormat::SpkiPem)?;
let verifying =
    VerifyingKey::from_bytes(SigningAlgorithm::Ed25519, &spki, PublicKeyFormat::SpkiPem)?;
assert_eq!(verifying.key_id(), KeyId::new(0x90fa_cafe));
# Ok(())
# }
```

## In a browser

A browser verifies a detached signature with WebCrypto: import the keys of the JWK Set, read the
key id from the signature, hash the payload, build the pre-image and call `verify`. WebCrypto takes
the signature as `r || s` for ECDSA and as the 64 bytes of RFC 8032 for Ed25519, which
`SubtleCrypto.verify` supports in Chrome 137, Firefox 129 and Safari 17. P-256 works in every
engine with WebCrypto.

```javascript
// jwks: the parsed JWK Set; payloadType: the type's payload type string;
// payload and signature: Uint8Array. Returns the JWK that verified, or null.
async function verifyDetached(jwks, payloadType, payload, signature) {
  if (signature.length < 6 || signature[0] !== 0x01) {
    throw new Error("not a detached signature");
  }
  const keyId = new DataView(signature.buffer, signature.byteOffset, 5).getUint32(1);
  const raw = signature.subarray(5);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", payload));
  const preImage = pae(payloadType, digest);
  const jwk = await keyWithId(jwks, keyId);
  if (jwk === null || raw.length !== 64) return null;
  const [importParams, verifyParams] = algorithmOf(jwk);
  const key = await crypto.subtle.importKey("jwk", jwk, importParams, false, ["verify"]);
  const verified = await crypto.subtle.verify(verifyParams, key, raw, preImage);
  return verified ? jwk : null;
}

// The one key of the set with this id, or null: a miss is a refusal, never a search.
async function keyWithId(jwks, keyId) {
  for (const jwk of jwks.keys) {
    if ((await keyIdOf(jwk)) === keyId) return jwk;
  }
  return null;
}

// "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body, lengths in ASCII decimal.
function pae(payloadType, body) {
  const ascii = new TextEncoder();
  const type = ascii.encode(payloadType);
  const head = ascii.encode(`DSSEv1 ${type.length} `);
  const middle = ascii.encode(` ${body.length} `);
  const out = new Uint8Array(head.length + type.length + middle.length + body.length);
  out.set(head, 0);
  out.set(type, head.length);
  out.set(middle, head.length + type.length);
  out.set(body, head.length + type.length + middle.length);
  return out;
}

function algorithmOf(jwk) {
  if (jwk.kty === "OKP" && jwk.crv === "Ed25519") {
    return [{ name: "Ed25519" }, { name: "Ed25519" }];
  }
  if (jwk.kty === "EC" && jwk.crv === "P-256") {
    return [{ name: "ECDSA", namedCurve: "P-256" }, { name: "ECDSA", hash: "SHA-256" }];
  }
  throw new Error("unsupported key");
}

// The id the publisher set, else the first four bytes of the RFC 7638 thumbprint: the members in
// lexicographic order, no whitespace. JSON.stringify keeps the insertion order, and base64url
// values need no escaping.
async function keyIdOf(jwk) {
  if (Number.isInteger(jwk.kms_aead_key_id)) return jwk.kms_aead_key_id;
  const members =
    jwk.kty === "OKP"
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y };
  const input = new TextEncoder().encode(JSON.stringify(members));
  const digest = await crypto.subtle.digest("SHA-256", input);
  return new DataView(digest).getUint32(0);
}
```

An attached value is split first: `w` is the big-endian `u16` at bytes 5 and 6, the signature the
`w` bytes after it, and the payload the rest; verify before using the payload. The test vectors of
[Formats](./formats.md#signature-and-mac-test-vectors) run against this code in CI.

## MACs in a keyring

A keyring holds MAC key versions beside its other versions, under the purpose `Mac`: HMAC-SHA256
keys of 32 bytes or HMAC-SHA512 keys of 64 bytes, encrypted by the KEK as every DEK is, with the
states, staged rotation and compromised flag of the others, see
[Key versions and lifecycle](./keyring/lifecycle.md). `Encryptor::mac` computes a `Mac<T>` under the
active MAC version and `Encryptor::mac_attached` a `WithMac<T>`. `Keyring::verify_mac` and
`verify_with_mac` verify under the version a value names, with the keyring's compromised-version
policy as `decrypt` applies it. One MAC version serves every payload type of an application.

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{JsonEncoded, SignedPayloadType, SignableType};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, MacAlgorithm,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Job {
    task: String,
    image_id: u64,
}

impl SignableType for Job {
    const PAYLOAD_TYPE: SignedPayloadType = SignedPayloadType::from_static("example.com/jobs/v1");
}

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
#     MemoryKeyringStore::new(),
#     KeyringRegistryOptions::new(),
# )?;
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("jobs".to_string())?)?;
let admin = registry
    .open_or_create(
        provider,
        KeyringId::from_static("tenant-42"),
        KeyringAlgorithms::new().with_mac(MacAlgorithm::HmacSha256),
    )
    .await?;
let keyring = admin.keyring();

let job = JsonEncoded::new(Job { task: "resize".to_string(), image_id: 7 });
let mac = keyring.encryptor().await.mac(&job).await?;
keyring.verify_mac(&job, &mac).await?;

let with_mac = keyring.encryptor().await.mac_attached(&job).await?;
let verified = keyring.verify_with_mac(&with_mac).await?.0;
# assert_eq!(verified, job.0);
# registry.shutdown(None).await;
# Ok(())
# }
```

A value under a retired version fails with `KEY_VERSION_RETIRED`, so compute a new MAC over the
payload under the active version before retiring the old one; sweeps re-encrypt `Encrypted` fields
and not MACs. Move every process to 0.31 before the first MAC version is created, since 0.30 refuses
a record with a MAC version. `Authenticator` computes and verifies MACs with a key the caller holds.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/mac.rs).

### Beacons and MACs

Both are HMACs under a keyring version, and they serve different ends, see [Beacons](./beacons.md):

| | Beacon | MAC |
|---|---|---|
| Purpose | find rows by a field's value without decrypting it | prove that bytes were not changed since a key holder computed the tag |
| Output | the first `bits` bits of HMAC-SHA256, truncated on purpose so that values collide | the full tag, 32 or 64 bytes, never truncated |
| Type | `Beacon<T>`, `T: Plaintext` | `Mac<T>` and `WithMac<T>`, `T: Signable` |
| Equality | equal beacons mean likely equal values, by design | equal tags mean an equal payload under the key, which `verify` says |

## Signing the keyring record

A keyring record decides which versions are read and which encrypts, and its integrity rests on the
store's access control, see [Keyring deployment](./security.md#keyring-deployment). A store writer
can re-activate a compromised version or point a version at another DEK, and under an asymmetric
KEK, which encrypts for anyone holding its public key, plant a DEK of its own, see
[Asymmetric KEKs](./asymmetric-kek.md). A signed record closes both: the administration signs every
record it writes, and an application refuses a record that no key it trusts has signed.

- the administration holds a `KeyringAdmin` with a record signer, a `Signer` on any signing
  provider. `KeyringRegistry::create_signed` and `open_or_create_signed` sign the record from its
  first write, and `with_record_signer` adds a signer to an admin;
- a signing admin re-signs the record on every write and refuses an unsigned record with
  `RECORD_UNSIGNED`; only `sign_record` signs an unsigned record. A `NoRecordSigner` admin refuses
  to overwrite a signed record with `RECORD_SIGNER_MISSING`;
- every registry verifies the signature of every record it reads, before any field is used and
  before any KMS call. `KeyringRegistryOptions::record_signatures` decides what an unsigned
  record means: `VerifyIfSigned(keys)`, the default, reads it, and `Required(keys)` refuses it with
  `RECORD_UNSIGNED`. A signature that does not verify fails with `RECORD_SIGNATURE_INVALID` under
  both.

The verifying keys come from the application's configuration, a JWK Set or the public key of the
KMS key, never from the store or the record:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider, LocalSigningKeyName, LocalSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm, VerifyingKeySet};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, RecordSignaturePolicy,
};

# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
let signer = Signer::<_, Ring>::new(LocalSigningProvider::<Ring>::ephemeral(
    LocalSigningKeyName::try_from("records".to_string())?,
    SigningAlgorithm::Ed25519,
)?)
.await?;
let keys = VerifyingKeySet::new([signer.verifying_key().clone()])?;

let registry = KeyringRegistry::<MemoryKeyringStore, Ring>::new(
    MemoryKeyringStore::new(),
    KeyringRegistryOptions::new().with_record_signatures(RecordSignaturePolicy::Required(keys)),
)?;
# let provider = LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("records".to_string())?)?;
let admin = registry
    .open_or_create_signed(
        provider,
        signer,
        KeyringId::from_static("tenant-42"),
        KeyringAlgorithms::new(),
    )
    .await?;
assert!(admin.keyring().record().signature().is_some());
# registry.shutdown(None).await;
# Ok(())
# }
```

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/record_signing.rs).
The signed bytes are in [Formats](./formats.md#the-signed-keyring-record).

Move an existing deployment in this order:

1. move every administrative binary to 0.31, since a 0.30 administrative write removes the
   signature;
2. give every registry the signer's public key as `VerifyIfSigned(keys)`: unsigned records still
   read, and a signed one verifies from its first write;
3. give the administration a signing admin and run `sign_record` on every keyring;
4. switch the applications and the administration to `Required`;
5. rotate the signing key by adding the new public key to every registry's set first, then
   `sign_record` on every keyring with the new signer.

Under `VerifyIfSigned`, a running process that holds a signed record refuses a later unsigned one
with `RECORD_SIGNATURE_REMOVED`, keeps the record it holds and logs an `ERROR`; a restarted process
reads whatever the store holds. A store writer who strips the signature therefore downgrades only
the processes that start after the write. Be aware that `Required` is the control for those, and
the only one for a keyring whose record was never signed. To stop signing a keyring on purpose,
switch every reader to `VerifyIfSigned`, write the record unsigned with `dangerously_unsign_record`
on a `NoRecordSigner` admin, then restart the readers.

## Limits

- whoever may sign records may write any record, and a signature proves the record was written by a
  signer, not that it is the latest: a store writer can restore an older signed record, which
  running processes refuse when it moves a version backwards;
- a signature is valid for as long as its key is in the verifier's set. There is no expiry and no
  revocation list, so put a timestamp or a recipient in the payload: nothing outside the payload
  type and the payload is authenticated;
- ECDSA signatures are malleable. Never use signature bytes as an identifier or compare them for
  equality; Ed25519 signatures are unique for a key and a message;
- a MAC is forged by every holder of its key, which is every process with KMS decrypt on the
  keyring's KEK and read access to its record;
- the library does not sign the public key set. How it reaches a verifier is the deployment's
  control;
- RSA signatures, secp256k1, P-384, P-521, ML-DSA, JWS and COSE are not supported.

The errors of signing are in [Error handling](./errors.md#codes).
