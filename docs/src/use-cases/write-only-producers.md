# Writers that can never read

A partner posts documents, a device reports readings, an upload client sends files. Each encrypts
what it sends and has no way to decrypt it again, whatever its credentials leak. An asymmetric KEK
is a KMS key pair: the public half encrypts the DEKs and is not a secret, the private half stays in
the KMS and decrypts them for the readers. See [Asymmetric KEKs](../asymmetric-kek.md).

## The three sides

| Side | Holds | Does |
|---|---|---|
| Producer | the public key and its fingerprint, in its configuration | encrypts values; no KMS client, no KMS right |
| Reader | a KMS provider, with decrypt on the key | decrypts values, as for any KEK |
| Administration | the public key's source, read right on the key | hands the public key to the producers |

1. Create an RSA key for asymmetric decryption in the KMS, 3072 bits, with the algorithm
   RSA-OAEP SHA-256. Cloud KMS, AWS KMS, Azure Key Vault and Vault Transit offer it;
2. grant the readers the decrypt right and the administration the right to read the public key,
   see [the rights per KMS](../asymmetric-kek.md#producers-and-readers);
3. the administration fetches the public key on its provider, writes `to_json()` and the key's
   fingerprint to the producers' configuration;
4. each producer builds a `PublicKeyKekProvider` from them and an envelope over it.

## The producer

The fingerprint comes from a channel other than the one that delivered the key. `pinned` refuses a
key with another fingerprint with `ASYMMETRIC_KEK_MISMATCH`, so a key taken from a wrong place does
not become a key that encrypts for whoever supplied it:

```rust
use kms_aead::backends::AwsLc;
use kms_aead::formats::Envelope;
use kms_aead::providers::PublicKeyKekProvider;
use kms_aead::{AsymmetricKekPublicKey, Encrypted, KmsAeadEnvelope, AsymmetricKekFingerprint};
use secret_vault_value::SecretValue;
# use kms_aead::providers::{LocalAsymmetricKmsProvider, LocalKekId};
# use kms_aead::AsymmetricKekAlgorithm;

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> kms_aead::KmsAeadResult<()> {
# let reader_provider = LocalAsymmetricKmsProvider::<AwsLc>::ephemeral(
#     LocalKekId::try_from("submissions".to_string())?,
#     AsymmetricKekAlgorithm::RsaOaepSha256,
# )?;
# let public_key = reader_provider.public_key(None)?;
# let public_key_json = public_key.to_json()?;
# let fingerprint_from_config = public_key.fingerprint().to_string();
let public_key = AsymmetricKekPublicKey::try_from_json(&public_key_json)?;
let fingerprint = AsymmetricKekFingerprint::try_from(fingerprint_from_config)?;
let producer = KmsAeadEnvelope::<_, AwsLc>::new(PublicKeyKekProvider::<AwsLc>::pinned(
    public_key,
    fingerprint,
)?)?;

let encrypted: Encrypted<SecretValue, Envelope> = producer
    .encrypt(b"submissions/1042", &SecretValue::from("account 1234"))
    .await?;

// The reader's side: the provider it uses today
let reader =
    KmsAeadEnvelope::<LocalAsymmetricKmsProvider<AwsLc>, AwsLc>::new(reader_provider)?;
let decrypted: SecretValue = reader.decrypt(b"submissions/1042", &encrypted).await?;
# assert_eq!(decrypted, SecretValue::from("account 1234"));
# Ok(())
# }
```

Encrypt one test value and decrypt it with a reader before a new producer writes anything that
matters. The provider logs the fingerprint at `INFO` when it is built, which an operator compares
with the administration's.

## What the compiler guarantees

`PublicKeyKekProvider` encrypts and does not decrypt. Every call that decrypts a value or a DEK,
`decrypt`, `beacon`, the stream decryptors and the `*_with_encrypted_dek` calls, requires a
decrypting provider, so over a producer none of them compiles. A producer streams as well: an
envelope over it encrypts a large file with `stream_encryptor` and decrypts none, see
[Large files](./large-files.md).

The guarantee covers the producer's calls into the library. A producer process holds the plaintext
DEKs of its cached writes, and its own code can read what it wrote in memory. A service that writes
and reads holds a KMS provider and is a reader.

## With a keyring

The administration opens its registry with an `AsymmetricKekProvider`, which encrypts each new
version's DEK with the public key, and the applications open theirs with the plain KMS provider.
Whoever holds the public key can also encrypt a DEK of their own and file it in a record they can
write, and every application then decrypts it. Run every keyring under an asymmetric KEK with signed
records, and `RecordSignaturePolicy::Required` on every application, before the first DEK a public
key encrypts, see [Protect the keyring record](./signed-records.md).

## What to watch for

- The producer encrypts randomised values only. A beacon or a deterministic value needs a key's
  plaintext, which only a reader holds;
- `Ring` has no RSA encryption: a producer on it fails at construction with
  `UNSUPPORTED_ALGORITHM`. Use `AwsLc` or `RustCrypto`;
- the encryption is local, so the KMS audit log no longer shows who encrypted a DEK. The decrypt
  log stays;
- anyone holding the public key makes a reader pay for an asymmetric KMS decryption by sending a
  made-up value. Rate-limit what readers decrypt;
- a rotation of the KEK is a new public key for every producer;
- RSA is not quantum-safe, so data that must stay confidential for decades stays under a symmetric
  KEK.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/asymmetric_kek.rs).
