# HashiCorp Vault Transit

Feature `hashicorp-vault-transit-kms-encryption`, or one root store and one crypto provider
variant, see [Cargo features](../features.md).

The provider encrypts DEKs with a key of the Vault Transit secrets engine. `HcVaultTransitKeyRef`
names the key, and the mount is `transit` unless set with `with_mount`.

This page specifies `HcVaultTransitProvider`. To compare it with the other KMS providers, read
[Choose a provider and a backend](../getting-started/choosing.md#kms-providers). For the rights the
applications and the administration need, read [Permissions: applications and
administration](../production/permissions.md). For rotating the KEK, read [Rotate keys and
re-encrypt values](../production/rotation.md).

```rust,no_run
use kms_aead::backends::AwsLc;
use kms_aead::providers::{HcVaultTransitKeyRef, HcVaultTransitProvider};
use kms_aead::KmsAeadEnvelope;
use secret_vault_value::SecretValue;

# async fn example() -> kms_aead::KmsAeadResult<()> {
// VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_CACERT and VAULT_CLIENT_TIMEOUT are read by
// the provider
let key_ref = HcVaultTransitKeyRef::new("orders".to_string());

let provider = HcVaultTransitProvider::new(&key_ref)?;
let envelope = KmsAeadEnvelope::<HcVaultTransitProvider, AwsLc>::new(provider)?;

let cipher_text = envelope
    .encrypt(b"orders/1042", &SecretValue::from("secret"))
    .await?;
# let _ = cipher_text;
# Ok(())
# }
```

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/hc_vault_transit_kms.rs).

## Configuration, authentication and permissions

The provider reads the address, the token and the namespace from the variables of the Vault CLI, or
takes them as options. The token needs `update` on `<mount>/encrypt/<key>` and
`<mount>/decrypt/<key>`.

### Options

`HcVaultTransitProvider::new` reads its options from the variables the Vault CLI reads, with
`HcVaultTransitProviderOptions::from_env`: `VAULT_ADDR` (required), `VAULT_TOKEN`,
`VAULT_NAMESPACE`, `VAULT_CACERT` and `VAULT_CLIENT_TIMEOUT`. An empty variable counts as unset.
`VAULT_CLIENT_TIMEOUT` takes the formats the Vault CLI takes: whole seconds (`30`), whole days
(`2d`) or a Go duration (`30s`, `1h30m`). Zero, which the Vault CLI reads as no time limit, is
refused, as is a value in any other format.
`HcVaultTransitProvider::with_options` takes them from the application:

```rust,no_run
use kms_aead::providers::{
    HcVaultTransitKeyRef, HcVaultTransitProvider, HcVaultTransitProviderOptions,
    HcVaultTransitToken,
};
use secret_vault_value::SecretValue;
use std::time::Duration;

# fn example() -> kms_aead::KmsAeadResult<()> {
let options = HcVaultTransitProviderOptions::new("https://vault.example.com:8200".to_string())
    .with_token(HcVaultTransitToken::try_from(SecretValue::from("hvs.example"))?)
    .with_namespace("team-a".to_string())
    .with_timeout(Duration::from_secs(10));

let provider = HcVaultTransitProvider::with_options(
    &HcVaultTransitKeyRef::new("orders".to_string()).with_mount("transit-eu".to_string()),
    options,
)?;
# let _ = provider;
# Ok(())
# }
```

The options are:

- `address`: the Vault server, such as `https://vault.example.com:8200`;
- `token`: sent with every request. Without one the requests carry no token, which is what a
  Vault Agent or Vault Proxy with `use_auto_auth_token` expects;
- `namespace`: the Vault Enterprise namespace of the mount;
- `ca_certificate`: a PEM file with CA certificates for a server whose certificate comes from a
  private CA. The file adds to the root store and does not replace it, unlike `VAULT_CACERT` in
  the Vault CLI, so a server with a certificate from any public CA in the root store is trusted
  as well;
- `timeout`: the time limit for one request, from opening the connection to the last byte of the
  response, 60 seconds by default.

The provider sends no request when it is created, so a wrong token or an unreachable server
fail the first encryption or decryption. An `http` address to a host other than `localhost` or a
loopback address logs a `WARN` event at creation, since the token and the DEKs then cross the
network unencrypted.

## Key versions and rotation

The encrypted DEK is the Transit ciphertext, such as `vault:v1:...`. It names the key version, so
it still decrypts after the key is rotated. The KMS spans record that version as `kek_version`, and
so does the `kek_version()` of the encrypted DEK an encryption returns: the `N` of `vault:vN:`, as
`min_decryption_version` counts it.

The decrypt names the configured key in its URL, so Vault refuses a ciphertext of another key.

A rotation is `<mount>/keys/<key>/rotate`, and the new version encrypts every DEK after it. Once
the sweep has reached every value, see
[Re-encrypt DEKs after a KEK rotation](../production/reencrypt-deks.md),
disable the old versions by setting `min_decryption_version` in the key's configuration to the new
version: Vault then refuses to decrypt under older versions, with `VAULT_STATUS_400`, and lowering
it again restores them. Once
nothing needs them, the backups included, `min_available_version` and a trim of the key delete the
older versions for good.

### Rolling back a rotation

Vault Transit encrypts under the latest version of the key, since the provider names no version in
its request, and no older version becomes the latest again: a rotation is undone by rotating once
more and sweeping to that third version. Keep the new version enabled until then, since every swept
value and every value written since the rotation is under it only. See
[Rolling back a rotation](../production/reencrypt-deks.md#rolling-back-a-rotation).

## Asymmetric KEKs

A Transit key of the type `rsa-2048`, `rsa-3072` or `rsa-4096` is an asymmetric KEK, see
[Asymmetric KEKs](../asymmetric-kek.md):

- `HcVaultTransitProvider::public_key(None)` reads `<mount>/keys/<key>` for the latest version, and
  `public_key(Some(&version))` for one, and returns the PEM public key of that version, for the
  producers. It fails with `ASYMMETRIC_KEK_PUBLIC_KEY` for a key of another type or a version the
  key does not list;
- a decryption of a `0x02` encrypted DEK sends `<mount>/decrypt/<key>` with the ciphertext
  `vault:v<version>:` and the standard base64 of the RSA block, `padding_scheme` `oaep` and
  `hash_algorithm` `sha2-256`. Both are always set and never left to the server's defaults;
- the token of a reader needs `update` on `<mount>/decrypt/<key>`, and the administration also
  `read` on `<mount>/keys/<key>` or on `<mount>/export/public-key/<key>`. Nobody needs `update` on
  `<mount>/encrypt/<key>`.

## Signing

`HcVaultTransitSigningProvider` signs with one version of a Transit key of the type `ed25519` or
`ecdsa-p256`, see [Signatures and MACs](../signing.md). `HcVaultTransitSigningKeyRef` names the key
and the mount, `transit` unless set with `with_mount`, and adds the version and the algorithm:
`Ed25519` for an `ed25519` key and `EcdsaP256Sha256` for `ecdsa-p256`. The version is required and
never zero, so a signer never signs with the latest version.

```rust,no_run
use std::num::NonZeroU32;

use kms_aead::backends::AwsLc;
use kms_aead::formats::PublicKeyFormat;
use kms_aead::providers::{HcVaultTransitSigningKeyRef, HcVaultTransitSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm};

# async fn example() -> kms_aead::KmsAeadResult<()> {
// VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE, VAULT_CACERT and VAULT_CLIENT_TIMEOUT are read by
// the provider
let key_ref = HcVaultTransitSigningKeyRef::new(
    "invoices".to_string(),
    NonZeroU32::MIN,
    SigningAlgorithm::Ed25519,
);

let provider = HcVaultTransitSigningProvider::new(&key_ref)?;
let signer = Signer::<_, AwsLc>::new(provider).await?;

// The public key to publish for the verifiers
let jwk = signer.verifying_key().encode(PublicKeyFormat::Jwk)?;
# let _ = jwk;
# Ok(())
# }
```

`HcVaultTransitSigningProvider::with_options` takes the options of
[`HcVaultTransitProviderOptions`](#options). Creating the provider sends no request; `Signer::new`
sends the first one.

- `sign` posts to `<mount>/sign/<key>` with `input`, `key_version`, `hash_algorithm` `sha2-256` and
  `marshaling_algorithm` `jws`. The `input` is the base64 of the pre-image for Ed25519, and for
  P-256 the base64 of its SHA-256 with `prehashed` set;
- Vault answers `vault:vN:<base64url>` with the 64-byte Ed25519 signature, or `r || s` for P-256. An `N` other than the configured version
  fails with `SIGNING_KEY_MISMATCH`, and a signature that is not base64url without padding or not
  64 bytes with `SIGNATURE_ENCODING`;
- `verifying_key` reads `<mount>/keys/<key>` and takes the `public_key` of the configured version:
  base64 of the raw key for Ed25519, PEM for P-256. A key of another `type` fails with
  `SIGNING_ALGORITHM_MISMATCH`, and a version the key does not list with `INVALID_PUBLIC_KEY`;
- the token needs `update` on `<mount>/sign/<key>` and `read` on `<mount>/keys/<key>`.

A rotation is `<mount>/keys/<key>/rotate`, and a new signer names the new version, see
[Key ids and rotation](../signing.md#key-ids-and-rotation).

## Limits

- The latest version of the key always encrypts, and no older version becomes the latest again, see
  [Key versions and rotation](#key-versions-and-rotation);
- `min_decryption_version` disables every version below it at once;
- DEKs always come from the backend's CSPRNG: Vault Transit has no KMS random generator in the
  provider, see [KMS random generators](../providers.md#kms-random-generators);
- BigQuery does not read Vault Transit values, and Tink reads a keyring's keysets with Tink for Go
  only, see [Choose a provider and a backend](../getting-started/choosing.md#kms-providers).

## Errors

A response with an error status is `VAULT_STATUS_<status>`. `VAULT_HTTP` and `VAULT_TIMEOUT` are
for a request that got no complete response, and `VAULT_RESPONSE`, `VAULT_RESPONSE_TOO_LARGE` and
`VAULT_CIPHERTEXT` for a response or an encrypted DEK that cannot be read. Which codes are a
`NetworkError` and which an `EncryptionError` is in [Retries](../errors.md#retries).
`HcVaultTransitSigningProvider` returns the same codes, with a `SignatureError` where the encryption
provider returns an `EncryptionError`. Invalid options
fail at creation with `VAULT_INVALID_OPTIONS`, or `VAULT_TLS` when the TLS configuration cannot be
built. A request body that cannot be serialised fails with `VAULT_REQUEST`, a `SystemError`,
before any request is sent.
