# Wrap-time key binding

Each version's DEK is wrapped bound to `<keyring id>/<key id>`, such as `tenant-42/3`, through the
KMS's associated data, see [Binding a wrapped key](../providers.md#binding-a-wrapped-key). Every
unwrap names the same binding, so the KMS refuses a wrapped DEK copied into another version or
another keyring.

What it stops: a writer of the keyring store without the KMS's encrypt right copying a wrapped
DEK the KEK already accepts, such as a compromised version's, into a new active version. Without
the binding, the KMS would unwrap it under any id, and a leaked DEK would come back into use under
a new key id that carries no compromised flag.

`KeyringOptions::bind_keys`, `true` by default, turns it on, and it is fixed for the life of a
keyring: the DEKs of a bound keyring do not unwrap unbound, nor the reverse.

## Per KMS

| KMS | Binding |
|---|---|
| Google Cloud KMS | additional authenticated data, not written to audit logs |
| AWS KMS | encryption context, logged by CloudTrail in plain text |
| Vault Transit | `associated_data`, Vault 1.13 or later and an AEAD key type |
| Local KMS | part of the associated data of its wrap |
| Azure Key Vault | not supported: a keyring needs `bind_keys(false)` |

The binding is not secret: CloudTrail logs it on AWS, and a keyring id already names store
documents and objects, so it must not be sensitive.

## Azure Key Vault

Key Vault's wrapKey takes no associated data, so the Azure provider refuses a binding. A keyring
on Azure is created and opened with `bind_keys` off, otherwise every wrap and unwrap fails with
`AZURE_BINDING_UNSUPPORTED`:

```rust
use kms_aead_keyring::KeyringOptions;

let options = KeyringOptions::new().with_bind_keys(false);
# let _ = options;
```

On such a keyring a writer of the store can bring a wrapped DEK back into use under a new id, so
its record's integrity rests on the store's access control alone. A keyring opened with
`bind_keys` off logs a `WARN` saying so.

Use an AES key on Azure, from Managed HSM, where wrapping needs `keys/wrap/action`. With an RSA
key the wrap is a public-key operation: anyone who holds the public key wraps a DEK of their own,
so a wrapped DEK proves no KMS right at all.

## What the binding does not cover

- An envelope value read through `decrypt_envelope_value` is unwrapped unbound, as kms-aead's
  envelope wrapped it, see [Migrating from envelope values](../operations.md#migrating-from-envelope-values);
- two keyrings with the same id under one KEK, such as staging and production, get the same
  bindings and can exchange wrapped DEKs. Use one KEK per environment;
- a destroyed version's wrapped DEK still unwraps from a backup of the record for as long as the KEK
  version that wrapped it exists, see [Crypto-shredding](../operations.md#crypto-shredding).

The full list of limits is in [Security considerations](../security.md#keyring-limits).
