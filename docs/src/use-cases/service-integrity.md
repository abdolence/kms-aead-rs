# Check integrity between your own services

One service puts a job on a queue, an entry in a cache or a row in a table, and another reads it.
The reader needs to know that nobody who can write the queue, the cache or the table changed the
bytes. A MAC, a keyed hash, answers that with a key only the application's services hold, and costs
an HMAC in process. The MAC does not hide the bytes, see [Envelope encryption](../envelope-encryption.md)
for that. See [Signatures and MACs](../signing.md#macs-in-a-keyring).

## Keyring MACs

A keyring holds MAC key versions beside its other versions, encrypted by the KEK and rotated, flagged
and retired as the others are. Create the keyring with a MAC algorithm, HMAC-SHA256 or HMAC-SHA512.
A service that writes calls `mac_attached` on its `Encryptor`, and a service that reads calls
`verify_with_mac`. The type that is authenticated implements `SignableType`, whose payload type
separates one kind of message from another: a MAC over a job never verifies as a cache entry. The
calls take it as `JsonEncoded::new(job)`, which stands for the compact JSON of the value.

```rust
use kms_aead_keyring::{JsonEncoded, SignableType, SignedPayloadType, WithMac};
use serde::{Deserialize, Serialize};
# use kms_aead::backends::Ring;
# use kms_aead::providers::{LocalKekId, LocalKmsProvider};
# use kms_aead_keyring::testing::MemoryKeyringStore;
# use kms_aead_keyring::{
#     KeyringAlgorithms, KeyringId, KeyringRegistry, KeyringRegistryOptions, MacAlgorithm,
# };

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
# let admin = registry
#     .open_or_create(
#         provider,
#         KeyringId::from_static("backend"),
#         KeyringAlgorithms::new().with_mac(MacAlgorithm::HmacSha256),
#     )
#     .await?;
# let keyring = admin.keyring();
// The service that enqueues: the payload and its tag in one value
let message: Vec<u8> = keyring
    .encryptor()
    .await
    .mac_attached(&JsonEncoded::new(Job { task: "resize".to_string(), image_id: 7 }))
    .await?
    .into_value();

// The service that works: the tag is checked before the payload is decoded
let with_mac = WithMac::<JsonEncoded<Job>>::try_from(message)?;
let job = keyring.verify_with_mac(&with_mac).await?.0;
# assert_eq!(job, Job { task: "resize".to_string(), image_id: 7 });
# registry.shutdown(None).await;
# Ok(())
# }
```

A value whose bytes changed fails with `MAC_INVALID`. Where the payload already has a place of its
own, such as the columns of a row, `Encryptor::mac` computes a detached `Mac<T>` to store beside it,
and `Keyring::verify_mac` checks it against the payload as read.

Both services build a `Keyring` for the same keyring id, with decrypt on the keyring's KEK and read
access to its record, see [Applications and administration apart](./deployment.md). Every service
that holds the key can compute a valid tag, so a MAC protects the bytes from whoever writes the
store, and says nothing about which service wrote them.

## Rotation

A MAC version rotates and retires like the others, see [Rotate keys and re-encrypt
values](./rotation.md). A sweep re-encrypts `Encrypted` fields and does not touch MACs, and a value
under a retired version fails with `KEY_VERSION_RETIRED`. Authenticate the payloads that still
matter again under the active version before retiring the old one. Messages that are consumed within
minutes, such as a queue's, need no such pass: wait for them to drain.

## A signature instead

Use a signature when the party that checks should not be able to forge, or is not one of your
services:

| | MAC | Signature |
|---|---|---|
| Who can check | holders of the keyring's key: your services | anyone with the public key: a partner, a browser, an offline tool |
| Who can forge | every checker | the holder of the private key only |
| Cost | an HMAC in process | one KMS call to sign, none to verify |

A webhook your customers verify, a release, and a record whose writer must be told apart from its
readers are signatures. See [Publish content anyone can verify](./publish-verifiable.md), and
[Protect the keyring record](./signed-records.md) for the keyring's own record.

## What to watch for

- Nothing outside the payload type and the payload is authenticated. A message that must not be
  replayed carries a timestamp or a nonce, and a message for one recipient names it;
- a process on 0.30 refuses a record that holds a MAC version, so move every process to 0.31 before
  the keyring gets its first MAC version.

Full example available
[here](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/mac.rs).
