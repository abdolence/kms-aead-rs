# HashiCorp Vault Transit

Feature `hashicorp-vault-transit-kms-encryption`, or one root store and one crypto provider
variant, see [Getting started](../getting-started.md#features).

The provider wraps DEKs with a key of the Vault Transit secrets engine. `HcVaultTransitKeyRef`
names the key, and the mount is `transit` unless set with `with_mount`.

```rust,no_run
use kms_aead::providers::{HcVaultTransitKeyRef, HcVaultTransitProvider};
use kms_aead::{AeadBackend, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# async fn example() -> kms_aead::KmsAeadResult<()> {
// VAULT_ADDR, VAULT_TOKEN, VAULT_NAMESPACE and VAULT_CACERT are read by the provider
let key_ref = HcVaultTransitKeyRef::new("orders".to_string());

let envelope = KmsAeadEnvelope::new(HcVaultTransitProvider::new(&key_ref)?, AeadBackend::AwsLc)?;

let cipher_text = envelope
    .encrypt_value(b"orders/1042", &SecretValue::from("secret"))
    .await?;
# let _ = cipher_text;
# Ok(())
# }
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/hc_vault_transit_kms.rs).

## Options

`HcVaultTransitProvider::new` reads its options from the variables the Vault CLI reads, with
`HcVaultTransitProviderOptions::from_env`: `VAULT_ADDR` (required), `VAULT_TOKEN`,
`VAULT_NAMESPACE` and `VAULT_CACERT`. An empty variable counts as unset.
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
fail the first wrap or unwrap. An `http` address to a host other than `localhost` or a loopback
address logs a `WARN` event at creation, since the token and the DEKs then cross the network
unencrypted.

The token needs `update` on `<mount>/encrypt/<key>` and `<mount>/decrypt/<key>`.

## Key versions and rotation

The wrapped DEK is the Transit ciphertext, such as `vault:v1:...`. It names the key version, so
it still unwraps after the key is rotated. That version is also recorded as the wrapped DEK's
key version, for audit only: the unwrap sends the ciphertext and never the recorded version.

The unwrap names the configured key in its URL, so Vault refuses a ciphertext of another key.

## Errors

A response with an error status is `VAULT_STATUS_<status>`: a `NetworkError` for a server error
or a rate limit, an `EncryptionError` otherwise. `VAULT_HTTP` and `VAULT_TIMEOUT` are network
errors for a request that got no complete response, and `VAULT_RESPONSE`,
`VAULT_RESPONSE_TOO_LARGE` and `VAULT_CIPHERTEXT` are encryption errors for a response or a
wrapped DEK that cannot be read. Invalid options fail at creation with `VAULT_INVALID_OPTIONS`,
or `VAULT_TLS` when the TLS configuration cannot be built.

## Binding

A `DekBinding` is sent as Transit `associated_data`, which needs Vault 1.13 or later and an AEAD
key type such as `aes256-gcm96`. A Vault that does not know the field ignores it and says so in
its warnings, and the call then fails with `VAULT_BINDING_IGNORED`, so a bound wrap never
succeeds unbound.
