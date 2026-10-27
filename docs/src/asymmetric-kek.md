# Asymmetric KEKs

An asymmetric KEK is a KMS key pair whose public half encrypts data encryption keys and whose
private half decrypts them. A producer holding the public key encrypts DEKs in its own process,
with no KMS right and no KMS call, and encrypts values under them. A reader decrypts the DEKs
through the KMS, which checks its permission and logs the call.

Use one for producers that may encrypt and must never decrypt: a service that writes records it
does not read back, a batch job that fills a table, a process outside the KMS's reach. The library
encrypts DEKs with RSA-OAEP (RSA encryption with Optimal Asymmetric Encryption Padding, RFC 8017),
SHA-256 and an empty label, `AsymmetricKekAlgorithm::RsaOaepSha256`, on RSA keys of 3072 bits for a
new key; 2048 and 4096 are accepted, and 2048 is deprecated. Cloud KMS, AWS KMS, Azure Key Vault,
Vault Transit and the local KMS decrypt it.

## Which way the keys go

With an asymmetric KEK the public key encrypts and the private key decrypts, as in every public-key
encryption. The other direction is a signature, see [Signatures and MACs](./signing.md):

| | Signature | Asymmetric KEK | Symmetric KEK |
|---|---|---|---|
| Public key | verifies; anyone holding it checks the bytes | encrypts DEKs; producers hold it, with no KMS right | none |
| Private key | signs, inside the KMS | decrypts DEKs, inside the KMS, for the readers | the one key, inside the KMS |
| Who may produce | the holder of the private key only | anyone holding the public key | principals with the KMS encrypt right |
| Gives | origin and integrity | confidentiality | confidentiality |

Any holder of the public key can produce a value that the readers decrypt, so an asymmetric KEK
gives no origin. Data that must be both confidential and attributable is encrypted and then signed.

## Producers and readers

A deployment has three sides:

| Side | Holds | KMS right | Calls |
|---|---|---|---|
| Producer | the public key, pinned in its configuration | none | `KmsAeadEnvelope::encrypt` over a `PublicKeyKekProvider` |
| Application, or any reader | a KMS provider | asymmetric decrypt on the key | `KmsAeadEnvelope::decrypt`, or a `Keyring` |
| Administration | the public key and a KMS provider, in an `AsymmetricKekProvider` | asymmetric decrypt, and read of the public key | the `KeyringAdmin` calls and the re-encryptions |

The readers use the providers they use today. They read the new layout by its first byte, and a
provider decrypts the DEKs the KMS encrypted beside the DEKs a public key encrypted. The producer is
an envelope writer and encrypts randomised values only: a beacon and a deterministic value both need
a key's plaintext, which only a reader decrypts. A keyring never has a producer, since encrypting
under a keyring version needs the version's plaintext DEK. What an asymmetric KEK changes in a
keyring is who encrypts new versions' DEKs, the administration with the public key.

```rust
use kms_aead::backends::AwsLc;
use kms_aead::formats::Envelope;
use kms_aead::providers::{LocalAsymmetricKmsProvider, LocalKekId, PublicKeyKekProvider};
use kms_aead::{AsymmetricKekAlgorithm, AsymmetricKekPublicKey, Encrypted, KmsAeadEnvelope};
use secret_vault_value::SecretValue;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
// The reader's provider: a cloud KMS provider in production
let reader_provider = LocalAsymmetricKmsProvider::<AwsLc>::ephemeral(
    LocalKekId::try_from("orders".to_string())?,
    AsymmetricKekAlgorithm::RsaOaepSha256,
)?;

// The administration hands the public key to the producers as a JSON document
let document = reader_provider.public_key(None)?.to_json()?;

// The producer: no KMS client, and no call that decrypts
let public_key = AsymmetricKekPublicKey::try_from_json(&document)?;
let producer = KmsAeadEnvelope::<PublicKeyKekProvider<AwsLc>, AwsLc>::new(
    PublicKeyKekProvider::new(public_key)?,
)?;
let encrypted: Encrypted<SecretValue, Envelope> = producer
    .encrypt(b"orders/1042", &SecretValue::from("4111 1111 1111 1111"))
    .await?;

// The reader decrypts the DEK through its KMS
let reader =
    KmsAeadEnvelope::<LocalAsymmetricKmsProvider<AwsLc>, AwsLc>::new(reader_provider)?;
let decrypted: SecretValue = reader.decrypt(b"orders/1042", &encrypted).await?;
assert_eq!(decrypted, SecretValue::from("4111 1111 1111 1111"));
# Ok(())
# }
```

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/asymmetric_kek.rs).

The KMS rights per provider:

| KMS | Reader | Administration, in addition |
|---|---|---|
| Google Cloud KMS | `cloudkms.cryptoKeyVersions.useToDecrypt` | `cloudkms.cryptoKeyVersions.viewPublicKey`, which `roles/cloudkms.cryptoKeyDecrypter` does not carry |
| AWS KMS | `kms:Decrypt` on the key | `kms:GetPublicKey` on the key |
| Azure Key Vault | `keys/unwrap/action` | `keys/get` |
| Vault Transit | `update` on `transit/decrypt/<key>` | `read` on `transit/keys/<key>` |

No side needs a KMS encrypt right. Be aware the KMS audit log no longer shows who encrypted a DEK:
the encryption is a local operation. The decrypt log stays.

## The public key

An `AsymmetricKekPublicKey` holds the key and what a reader needs to decrypt:

- the KEK, a `KekRef`: the KMS and the key's name there, as the reader's provider names it;
- the KEK version, where the KMS decrypts with a named one: the CryptoKeyVersion number on Cloud
  KMS, the 32-character version on Key Vault, the Transit version, the local version. AWS KMS has
  no versions, and `AsymmetricKekPublicKey::new` refuses a version there, or none where one is
  needed, with `ASYMMETRIC_KEK_PUBLIC_KEY`;
- the algorithm;
- the key, in a named `PublicKeyFormat`: `SpkiDer` as AWS KMS returns it, `SpkiPem` as `openssl`,
  Cloud KMS and Transit write it, or `Jwk` as Key Vault returns it. `Raw` has no meaning for an RSA
  key.

The administration fetches it with the right of the table above, on the provider it holds:
`GcpKmsProvider::public_key(&version)`, `AwsKmsProvider::public_key()`,
`AzureKmsProvider::public_key(None)` for the latest version, `HcVaultTransitProvider::public_key(None)`
and `LocalAsymmetricKmsProvider::public_key(None)`. Each reads the version from the KMS's response,
so the key and the version belong together.

The public key reaches a producer as the rest of its configuration does. A producer that takes it
from an unauthenticated place encrypts for whoever supplied it, and the reader's KMS decrypts
nothing. Every provider that holds the key logs its fingerprint, the SHA-256 of the
SubjectPublicKeyInfo, at `INFO`, and `PublicKeyKekProvider::pinned` fails with
`ASYMMETRIC_KEK_MISMATCH` when the key has another fingerprint than the operator expects. Encrypt
one test value and decrypt it with a reader before a new producer writes anything that matters.

## What each backend does

| | `Ring` | `AwsLc` | `RustCrypto` |
|---|---|---|---|
| Encrypt with a public key | no: `UNSUPPORTED_ALGORITHM` at construction | yes | yes |
| Decrypt through a cloud KMS | yes | yes | yes |
| Local KMS private half | no | yes | yes |

ring has no RSA encryption, so a producer or a local private half on `Ring` fails at construction
with `KmsAeadError::UnsupportedAlgorithm`. A reader on `Ring` needs nothing of RSA.

The `rustcrypto` feature adds the [`rsa`](https://crates.io/crates/rsa) crate for
RSA-OAEP. Its private-key operation runs only in a `LocalAsymmetricKmsProvider` on RustCrypto.
Encrypting with the public key is a public-key operation with no private key to leak, and a cloud
reader runs no RSA. Every application that enables `rustcrypto` carries `rsa` in its lockfile. A
local KMS on RustCrypto decrypts DEKs from trusted sources only, such as its own keyring record. A
process that decrypts what others send runs its private half on `AwsLc`, or in a KMS.

## The compile-time guarantee

`PublicKeyKekProvider` implements `KmsAeadEncryptionProvider` and not `KmsAeadDecryptionProvider`.
Every call that decrypts a DEK or a value requires the second: `decrypt`, the
`*_with_encrypted_dek` calls, `beacon`, `reencrypt_dek`, `DekCache::with_dek` and every keyring. Over
a producer none of them compiles, so an encrypt-only deployment holds whatever its IAM policy says.

The guarantee covers the producer's calls into the library. A DEK that `generate_encrypted_dek`
returns is in the producer's hands, and it decrypts its own writes with it through
`AeadCipher::decrypt_bare`. Other code in the process is outside the guarantee: a type of the
application's own that implements `KmsAeadDecryptionProvider` under the producer's `KekRef` is
served from the producer's DEK cache, and whoever reads the process's memory reads the cached keys.
A process that writes and reads holds a KMS provider, and is a reader.

## Keyrings under an asymmetric KEK

The administration opens its registry with an `AsymmetricKekProvider`; the applications open theirs
with the plain KMS provider. `create`, `rotate`, `change_algorithm` and `mark_compromised` encrypt
the new version's DEK with the public key, and `reencrypt_deks` decrypts every DEK through the KMS
and encrypts it again with the public key. The record does not change.

Be aware that whoever holds the public key can encrypt a DEK of their own and file it in the record.
A store writer who does so makes every application decrypt it, and the values encrypted under that
version are the writer's to read. The control is a signed record, see [Signing the keyring
record](./signing.md#signing-the-keyring-record). Run every keyring under an asymmetric KEK with
`RecordSignaturePolicy::Required` on every application, and turn it on before the first DEK a public
key encrypts. Under any other mode a registry that loads a record holding a DEK encrypted with a
public key logs a `WARN` and decrypts it, and so does a `NoRecordSigner` admin whose provider is
asymmetric when it is built.

A keyring under an asymmetric KEK exports no BigQuery and no Tink keyset, since both readers
decrypt the keyset with their KMS client's symmetric decryption. `export_bigquery_keyset`,
`export_tink_keyset` and an `Encryptor` on a field with an `Interop` fail with `INTEROP`.

An asymmetric decryption is a heavier KMS operation than a symmetric one: quotas and prices per
request are higher for RSA on every KMS. A producer reuses DEKs, with a store-less envelope and a
`DekReusePolicy`, and a keyring holds one DEK per version.

A KEK rotation moves new encryptions to a new version, and every stored DEK keeps decrypting under
its own version. The producers hold the version they encrypt under in the public key, so a rotation
is also a configuration change of every producer. AWS KMS has no versions: a rotation is a new key,
and a keyring stays under the key it was created with.

## Migrating an Azure or Transit RSA deployment

An envelope or a keyring on an Azure Key Vault RSA key or a Transit `rsa-*` key is under an
asymmetric KEK already: Key Vault's `wrapKey` operation, which encrypts a DEK, is the RSA-OAEP
encryption its public key would make. Nothing stored has to be re-encrypted:

1. deploy 0.31 to every reader first. 0.30 reads no DEK encrypted with a public key;
2. for a keyring, turn record signing on before any DEK is encrypted with a public key: give the
   administration a record signer, run `sign_record` on every keyring, then set
   `RecordSignaturePolicy::Required` on every application;
3. fetch the public key on the administration's provider and build the `AsymmetricKekProvider`
   from it and the KMS provider. Every DEK the administration encrypts from then on is encrypted
   with the public key; `reencrypt_deks` moves the existing versions at the administration's
   choice;
4. hand the public key to the producers, which switch from a KMS provider to a
   `PublicKeyKekProvider` and drop their KMS rights;
5. take `keys/wrap/action`, or `update` on `transit/encrypt/<key>`, out of the administration's
   grant once no 0.30 administration remains.

A keyring on a Cloud KMS or AWS symmetric key cannot move to an asymmetric key: a keyring stays
under the KEK it was created with. A new asymmetric key is a new keyring, filled by a sweep.

## Threat model and limits

The threat model of [Security considerations](./security.md#threat-model) holds, with these
changes:

- a holder of the public key produces values that decrypt, and plants a DEK in a keyring record
  unless the applications require signed records;
- encrypting with the public key leaves no KMS audit log. Who encrypted which DEK is recorded
  nowhere unless the producer logs it;
- a producer with a wrong public key encrypts for someone else. Authenticate the channel the key
  arrives through, pin the fingerprint and test one value;
- anyone with the public key makes the readers pay for decryptions: a made-up encrypted DEK costs
  the reader one asymmetric KMS decryption;
- the header of the encrypted DEK is not authenticated. A change makes the decryption fail and makes
  no value decrypt;
- RSA is not quantum-safe. An encrypted DEK kept in a record, a value or a backup decrypts for
  whoever later runs a cryptographically relevant quantum computer against the public key. Data
  whose confidentiality must outlast RSA stays under a symmetric KEK until a KMS decapsulates a
  post-quantum KEM in general availability, which none does today;
- the producer's DEK cache holds plaintext DEKs, as every store-less writer's does;
- the local KMS's private half is in process memory, with no IAM, no audit log and no HSM.

The bytes of the encrypted DEK are in [Formats](./formats.md#deks-encrypted-with-a-public-key), and
the codes this chapter mentions are in [Error handling](./errors.md#codes).
