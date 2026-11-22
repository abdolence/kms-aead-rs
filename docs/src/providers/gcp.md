# Google Cloud KMS

Feature `gcp-kms-encryption`, or `gcp-kms-encryption-webpki` for the bundled WebPKI roots, see
[Cargo features](../features.md).

`GcpKmsKeyRef` names a CryptoKey by its project, location, key ring and key. The provider encrypts
under the primary version of the key, and each encrypted DEK records the version that encrypted it,
so DEKs encrypted before a rotation still decrypt afterwards.

This page specifies `GcpKmsProvider`. To compare it with the other KMS providers, read [Choose a
provider and a backend](../getting-started/choosing.md#kms-providers). For the rights the
applications and the administration need, read [Permissions: applications and
administration](../production/permissions.md). For rotating the KEK, read [Rotate keys and
re-encrypt values](../production/rotation.md).

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{GcpKmsKeyRef, GcpKmsProvider, GcpKmsProviderOptions};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# async fn example() -> kms_aead::KmsAeadResult<()> {
let kms_ref = GcpKmsKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-key".to_string(),
);

let provider = GcpKmsProvider::new(&kms_ref).await?;
let envelope = KmsAeadEnvelope::<GcpKmsProvider, AwsLc>::new(provider)?;

// Or with DEKs from the Cloud KMS generator at the HSM protection level
let envelope = KmsAeadEnvelope::<GcpKmsProvider, AwsLc>::new(
    GcpKmsProvider::with_options(
        &kms_ref,
        GcpKmsProviderOptions::new().with_use_kms_random_gen(true),
    )
    .await?,
)?;

let cipher_text = envelope
    .encrypt(b"orders/1042", &SecretValue::from("secret"))
    .await?;
# let _ = cipher_text;
# Ok(())
# }
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/gcp_kms.rs).

## Configuration, authentication and permissions

`GcpKmsProvider::new` and `with_options` build a Cloud KMS client with the application default
credentials, and fail with a `SystemError` when the client cannot be built, such as when no
credentials are found. They look for credentials in the following places, preferring the first
location found:

- A JSON file whose path is specified by the `GOOGLE_APPLICATION_CREDENTIALS` environment variable;
- A JSON file in a location known to the gcloud command-line tool using
  `gcloud auth application-default login`;
- On Google Compute Engine, Cloud Run, GKE, etc., the metadata server.

For local development don't confuse `gcloud auth login` with `gcloud auth application-default login`,
since the first one authorises only the `gcloud` tool to access the Cloud Platform.

`GcpKmsProvider::with_client` takes a client the application built itself, for other
credentials.

`GcpKmsProviderOptions` has one option, `use_kms_random_gen`, `false` by default: `true` takes DEKs
from Cloud KMS `GenerateRandomBytes` at the HSM protection level in place of the backend's CSPRNG,
at the cost of one more KMS request per DEK, see
[KMS random generators](../providers.md#kms-random-generators).

The principal needs `cloudkms.cryptoKeyVersions.useToEncrypt` and `useToDecrypt` on the key, as
in the `roles/cloudkms.cryptoKeyEncrypterDecrypter` role, and `cloudkms.locations.generateRandomBytes`
on the location when the KMS generator is on.

## Key versions and rotation

A rotation adds a version to the CryptoKey and makes it the primary version, by hand or on the
key's rotation schedule. New DEKs are encrypted under the primary version from then on, and Cloud
KMS decrypts every DEK with the version that encrypted it, for as long as that version is enabled.

To retire the old version, disable it once the sweep has reached every value, see
[Re-encrypt DEKs after a KEK rotation](../production/reencrypt-deks.md):
decryptions under it fail, and enabling it again restores them. Destroying it schedules its
destruction, 30 days later by default, and until then the version can be restored.

Changing the primary version and disabling a version are eventually consistent in Cloud KMS, see
[Cloud KMS resource consistency](https://docs.cloud.google.com/kms/docs/consistency). Until a new
primary version has propagated, `Encrypt` may still use the previous one. A disabled version
"typically remains usable for encrypting and decrypting data for up to 1 minute after it is
disabled", and for several hours in exceptional cases. So:

- start the sweep only once the new primary version has propagated. The `kek_version()` of the
  encrypted DEK an encryption returns, and the `kek_version` field of the `KMS encrypt DEK` span,
  name the version Cloud KMS encrypted with, the `N` of `cryptoKeyVersions/N`, see
  [Spans and events](../observability/spans-and-events.md). A keyring whose `reencrypt_deks` ran before the new
  primary version had propagated still lists the old version among its `kek_versions_in_use`:
  run `reencrypt_deks` again, see [Re-encrypting a keyring's DEKs](../production/rotation.md#re-encrypting-a-keyrings-deks);
- run the check only once the disable has propagated, and run it again before destroying the
  version. A check inside that window passes on DEKs that are still under the old version.

Enabling a version is strongly consistent, see
[Cloud KMS resource consistency](https://docs.cloud.google.com/kms/docs/consistency): an enabled
version is available at once, so enabling the old version again after a failed check takes effect
immediately.

### Rolling back a rotation

Make the old version the primary version again, and keep the new version enabled: every swept value
and every value written since the rotation is under the new version only, and disabling it makes
them unreadable until it is enabled again. See
[Rolling back a rotation](../production/reencrypt-deks.md#rolling-back-a-rotation).

## Asymmetric KEKs

A CryptoKey with the purpose `ASYMMETRIC_DECRYPT` and an algorithm `RSA_DECRYPT_OAEP_2048_SHA256`,
`RSA_DECRYPT_OAEP_3072_SHA256` or `RSA_DECRYPT_OAEP_4096_SHA256` is an asymmetric KEK, see
[Asymmetric KEKs](../asymmetric-kek.md). 3072 bits is the size Cloud KMS marks as recommended.
Asymmetric keys have no primary version and no automatic rotation, so a version is always named:

- `GcpKmsProvider::public_key(&version)` sends `GetPublicKey` for the CryptoKeyVersion and returns
  the public key with the version the response names as its KEK version, for the producers. It
  fails with `ASYMMETRIC_KEK_PUBLIC_KEY` for a version whose algorithm is not
  `RSA_DECRYPT_OAEP_2048_SHA256`, `RSA_DECRYPT_OAEP_3072_SHA256` or `RSA_DECRYPT_OAEP_4096_SHA256`;
- a decryption of a `0x02` encrypted DEK sends `AsymmetricDecrypt` on
  `<key>/cryptoKeyVersions/<version>`, with the RSA block as `ciphertext`. The encrypted DEK names
  the version, as a symmetric ciphertext does. The request carries no CRC32C checksum fields (CRC32C is the 32-bit
  checksum with which Cloud KMS detects corruption in transit): a corrupted DEK fails the value's
  AEAD;
- the principal of a reader needs `cloudkms.cryptoKeyVersions.useToDecrypt`, as in
  `roles/cloudkms.cryptoKeyDecrypter`, and the administration also
  `cloudkms.cryptoKeyVersions.viewPublicKey`, as in `roles/cloudkms.publicKeyViewer`. Nobody needs
  `useToEncrypt`.

An asymmetric decryption costs more of the quota than a symmetric one, see
[Keyrings under an asymmetric KEK](../asymmetric-kek.md#keyrings-under-an-asymmetric-kek).

## Signing

`GcpKmsSigningProvider` signs with one CryptoKeyVersion of a key with the purpose `ASYMMETRIC_SIGN`,
see [Signatures and MACs](../signing.md). `GcpKmsSigningKeyRef` names the key as `GcpKmsKeyRef`
does, and adds the version, the `N` of `cryptoKeyVersions/N`, and the algorithm: `Ed25519` for an
`EC_SIGN_ED25519` version and `EcdsaP256Sha256` for `EC_SIGN_P256_SHA256`. Asymmetric keys have no
primary version, so a signer always names one.

```rust,no_run
use std::num::NonZeroU32;

use kms_aead::backends::AwsLc;
use kms_aead::formats::PublicKeyFormat;
use kms_aead::providers::{GcpKmsSigningKeyRef, GcpKmsSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm};

# async fn example() -> kms_aead::KmsAeadResult<()> {
let key_ref = GcpKmsSigningKeyRef::new(
    "my-project".to_string(),
    "europe-north1".to_string(),
    "my-key-ring".to_string(),
    "my-signing-key".to_string(),
    NonZeroU32::MIN,
    SigningAlgorithm::EcdsaP256Sha256,
);

let provider = GcpKmsSigningProvider::new(&key_ref).await?;
let signer = Signer::<_, AwsLc>::new(provider).await?;

// The public key to publish for the verifiers
let jwk = signer.verifying_key().encode(PublicKeyFormat::Jwk)?;
# let _ = jwk;
# Ok(())
# }
```

The provider authenticates as `GcpKmsProvider` does, and `GcpKmsSigningProvider::with_client` takes
a client the application built itself. Creating the provider sends no request; `Signer::new` sends
the first one. Cloud KMS lists `EC_SIGN_ED25519` under the software protection level only, so a key
at the HSM protection level signs with P-256.

- `sign` sends `AsymmetricSign` with the pre-image (the exact bytes a signature covers, see [Signature and MAC formats](../formats/signatures-and-macs.md)) as `data` for Ed25519, and the SHA-256 of the
  pre-image as `digest.sha256` for P-256. Each carries its CRC32C checksum, `dataCrc32c` or
  `digestCrc32c`;
- a response fails with `SIGNATURE_ENCODING` when `verifiedDataCrc32c` or `verifiedDigestCrc32c` is
  false, when `signatureCrc32c` is missing or does not match the signature, or when the signature
  is not 64 bytes (Ed25519) or strict DER (P-256), which is converted to `r || s` (the two 32-byte integers of an ECDSA signature, one after the other). A `name` other
  than the configured version fails with `SIGNING_KEY_MISMATCH`;
- `verifying_key` sends `GetPublicKey` and parses `pem`. A key of another `algorithm` than the
  configured one fails with `SIGNING_ALGORITHM_MISMATCH`, and a `pem` that does not parse with
  `INVALID_PUBLIC_KEY`;
- the principal needs `cloudkms.cryptoKeyVersions.useToSign` and
  `cloudkms.cryptoKeyVersions.viewPublicKey`, as in `roles/cloudkms.signerVerifier`.
  `roles/cloudkms.signer` alone lacks `viewPublicKey`.

A rotation is a new CryptoKeyVersion that a new signer names, see
[Key ids and rotation](../signing.md#key-ids-and-rotation).

## Limits

- Changing the primary version and disabling a version are eventually consistent, see
  [Key versions and rotation](#key-versions-and-rotation);
- an asymmetric KEK has no primary version and no automatic rotation, and an asymmetric decryption
  costs more of the quota than a symmetric one, see [Asymmetric KEKs](#asymmetric-keks);
- Cloud KMS lists `EC_SIGN_ED25519` under the software protection level only, so a key at the HSM
  protection level signs with P-256, see [Signing](#signing).

## Errors

The code of a failed KMS call is the gRPC status code, such as `PermissionDenied` or `NotFound`.
Which codes are a `NetworkError` and which an `EncryptionError` is in
[Retries](../errors.md#retries). `GcpKmsSigningProvider` returns the same codes, with a
`SignatureError` where the encryption provider returns an `EncryptionError`.
