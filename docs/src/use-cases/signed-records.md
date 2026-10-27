# Protect the keyring record

A keyring record decides which key versions read and which encrypt. Without a signature, its
integrity rests on the access control of the keyring store: whoever can write the record can
re-activate a compromised version, clear a flag or point a version at another DEK. Under an
asymmetric KEK, which encrypts for anyone holding its public key, a writer can also plant a DEK of
its own. A signed record closes these: the administration signs every record it writes, and every
application refuses a record that no key it trusts has signed. See
[Signing the keyring record](../signing.md#signing-the-keyring-record).

## Roll out

An existing deployment moves in this order, and each step is safe to deploy before the next:

1. **Administrative binaries on 0.31.** A 0.30 administrative write removes the signature;
2. **the signing key's public half to every registry**, as `VerifyIfSigned(keys)`. Records without a
   signature still read, and a signed one verifies from its first write;
3. **a signing administration**, and `sign_record` on every keyring;
4. **`Required` on every application and on the administration.**

The keys come from the application's configuration, a JWK Set or the public key of the signing KMS
key. They never come from the store or the record:

```rust
use kms_aead::backends::Ring;
use kms_aead::providers::{LocalKekId, LocalKmsProvider, LocalSigningKeyName, LocalSigningProvider};
use kms_aead::signing::{Signer, SigningAlgorithm, VerifyingKeySet};
use kms_aead_keyring::testing::MemoryKeyringStore;
use kms_aead_keyring::{
    KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, RecordSignaturePolicy,
};

const TENANT: KeyringId = KeyringId::from_static("tenant-42");

# fn local_kek() -> Result<LocalKmsProvider<Ring>, Box<dyn std::error::Error>> {
#     Ok(LocalKmsProvider::<Ring>::ephemeral(LocalKekId::try_from("tenants".to_string())?)?)
# }
# #[tokio::main]
# async fn main() -> Result<(), Box<dyn std::error::Error>> {
# let store = MemoryKeyringStore::new();
# let before = KeyringRegistry::<_, Ring>::new(store.clone(), KeyringRegistryOptions::new())?;
# before.create(local_kek()?, TENANT, KeyringAlgorithms::new()).await?;
// A KMS signing provider in production, see "Publish content anyone can verify"
let signer = Signer::<_, Ring>::new(LocalSigningProvider::<Ring>::ephemeral(
    LocalSigningKeyName::try_from("records".to_string())?,
    SigningAlgorithm::Ed25519,
)?)
.await?;
let keys = VerifyingKeySet::new([signer.verifying_key().clone()])?;

// Step 2: the administration's registry trusts the key and still reads unsigned records
let administration = KeyringRegistry::<_, Ring>::new(
    store.clone(),
    KeyringRegistryOptions::new()
        .with_record_signatures(RecordSignaturePolicy::VerifyIfSigned(keys.clone())),
)?;

// Step 3: sign the record as it is, with no other change
let admin = administration
    .admin(local_kek()?, TENANT)
    .await?
    .with_record_signer(signer)?;
admin.sign_record().await?;

// Step 4: an application that refuses a record no trusted key has signed
let application = KeyringRegistry::<_, Ring>::new(
    store,
    KeyringRegistryOptions::new().with_record_signatures(RecordSignaturePolicy::Required(keys)),
)?;
application.open(local_kek()?, TENANT).await?;
# before.shutdown(None).await;
# administration.shutdown(None).await;
# application.shutdown(None).await;
# Ok(())
# }
```

A new keyring is signed from its first write with `create_signed` or `open_or_create_signed`. The
administration re-signs the record on every write it makes: `rotate`, `promote`, `shred` and the
rest need the signer's KMS right, `cloudkms.cryptoKeyVersions.useToSign` on Cloud KMS.

## Rotate the signing key

Add the new public key to every registry's set first, then run `sign_record` on every keyring with
the new signer. Remove the old key from the sets once every keyring is signed by the new one. The
rotation of the key itself is that of [Publish content anyone can verify](./publish-verifiable.md#rotate-signing-keys).

## What a signature closes

- a store writer without the signing key cannot change a record that applications verify: a
  cleared compromised flag, a re-activated version or a DEK planted under an asymmetric KEK fails
  with `RECORD_SIGNATURE_INVALID`, before any field of the record is used and before any KMS call;
- under `Required`, an unsigned record fails with `RECORD_UNSIGNED`, so a keyring that was never
  signed, or whose signature a writer stripped, is not read.

## The sticky refusal and what only `Required` closes

Under `VerifyIfSigned`, a running process that holds a signed record refuses a later unsigned one
with `RECORD_SIGNATURE_REMOVED`, keeps the record it holds and logs an `ERROR`. The refusal lasts
as long as the process, and a process that starts after a writer stripped the signature has no
record to compare with and reads whatever the store holds. Only `Required` protects those
processes, and the keyring whose record was never signed. Run `Required` on every application
once step 3 is done.

A signature proves that a signer wrote the record, and not that it is the latest. A store writer
can restore an older signed record. Running processes refuse a record that moves a version
backwards with `RECORD_REGRESSED`, and a process that has just started has nothing to compare with.
Keep backups and the store's version history to compare against, see
[Keyring deployment](../security.md#keyring-deployment).

## Stop signing

Switch every reader to `VerifyIfSigned`, write the record unsigned with
`dangerously_unsign_record` on an administration without a signer, then restart the readers: the
running ones refuse the unsigned record until they do.

## What to watch for

- Whoever may sign records and write the store may write any record. Give the signing right to the
  administration only, and read its audit log;
- a keyring under an asymmetric KEK runs with `Required` on every application before the first DEK
  a public key encrypts, see [Writers that can never read](./write-only-producers.md);
- an administration without a signer is refused over a signed record with `RECORD_SIGNER_MISSING`.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/record_signing.rs).
