# Crypto backends

The AEAD algorithms run on a crypto library that a feature compiles in. Each backend feature adds
a type, and `AeadCipher`, `DeterministicCipher`, `KmsAeadEnvelope` and `LocalKmsProvider` take
that type as their backend type parameter `B`. A build may enable any number of backends, and
there is no default one.

| Feature | Type | Library |
|---|---|---|
| `ring` | `Ring` | [ring](https://crates.io/crates/ring) |
| `aws-lc` | `AwsLc` | [aws-lc-rs](https://crates.io/crates/aws-lc-rs) |
| `aws-lc-fips` | `AwsLc`, on the FIPS module | [aws-lc-rs](https://crates.io/crates/aws-lc-rs) |
| `rustcrypto` | `RustCrypto` | the [RustCrypto AEADs](https://github.com/RustCrypto/AEADs) |

There is no default because Cargo unifies features: a default chosen by features would change
for every crate in a build when one crate enables another backend.

## Code generic over the backend

The backend types implement `AeadBackend`, a sealed trait without methods. Its one item is the
constant `NAME`, the backend's name in spans and logs: `ring`, `aws-lc` or `rustcrypto`. Code
that works with any backend bounds its type parameter with `AeadBackend` and nothing else:

```rust
use kms_aead::providers::{LocalKekId, LocalKmsProvider};
use kms_aead::{AeadBackend, KmsAeadEnvelope, KmsAeadResult, Ring};
use secret_vault_value::SecretValue;

struct Orders<B> {
    envelope: KmsAeadEnvelope<LocalKmsProvider<B>, B>,
}

impl<B: AeadBackend> Orders<B> {
    fn new() -> KmsAeadResult<Self> {
        let provider = LocalKmsProvider::ephemeral(LocalKekId::try_from("orders".to_string())?)?;
        Ok(Self {
            envelope: KmsAeadEnvelope::new(provider)?,
        })
    }

    async fn round_trip(&self, card: &SecretValue) -> KmsAeadResult<SecretValue> {
        let sealed = self.envelope.encrypt_value(b"orders/1042", card).await?;
        self.envelope.decrypt_value(b"orders/1042", &sealed).await
    }
}

# #[tokio::main(flavor = "current_thread")]
# async fn main() -> KmsAeadResult<()> {
let orders = Orders::<Ring>::new()?;
let card = SecretValue::from("4111 1111 1111 1111");
assert_eq!(orders.round_trip(&card).await?, card);
# Ok(())
# }
```

`generate_random_bytes::<B>(len)` returns `len` bytes from the CSPRNG of the backend `B`, for
secrets the application generates itself.

## Algorithms

| Algorithm | Key | `Ring` | `AwsLc` | `RustCrypto` |
|---|---|---|---|---|
| `ChaCha20Poly1305` (RFC 8439) | 32 bytes | yes | yes | yes |
| `Aes128Gcm` | 16 bytes | yes | yes | yes |
| `Aes256Gcm`, the envelope's default | 32 bytes | yes | yes | yes |
| `Aes256GcmSiv` (RFC 8452) | 32 bytes | no | yes | yes |

Every algorithm writes `[nonce: 12][ciphertext][tag: 16]`, with a random nonce from the backend's
CSPRNG. A backend that does not implement the algorithm fails at construction, never later, with
`KmsAeadError::UnsupportedAlgorithm` and the code `UNSUPPORTED_ALGORITHM`:

```rust
use kms_aead::{errors::KmsAeadError, AeadAlgorithm, AeadCipher, Ring};

let result = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256GcmSiv);
assert!(matches!(result, Err(KmsAeadError::UnsupportedAlgorithm(_))));
```

`AeadAlgorithm` reads and writes its names with `FromStr` and `Display`: `chacha20-poly1305`,
`aes-128-gcm`, `aes-256-gcm` and `aes-256-gcm-siv`.

## AEAD without a KMS

`AeadCipher` seals and opens values with a key the application holds:

```rust
use kms_aead::{AeadAlgorithm, AeadCipher, Ring};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let cipher = AeadCipher::<Ring>::new(AeadAlgorithm::ChaCha20Poly1305)?;
let key = cipher.generate_key()?;

let aad = b"orders/1042";
let cipher_text = cipher.encrypt_value(aad, &SecretValue::from("secret"), &key)?;
let decrypted = cipher.decrypt_value(aad, &cipher_text, &key)?;

assert_eq!(decrypted, SecretValue::from("secret"));
# Ok(())
# }
```

Full example available [here](https://github.com/abdolence/kms-aead-rs/blob/master/examples/only_aead.rs).

`generate_wrapped_key` makes a key and wraps it with a provider in one call, for an application
that stores the wrapped key itself. `AeadCipher` makes no KMS call and opens no span.

## Cross-backend compatibility

Every backend writes the same bytes for the same algorithm, so a value sealed by one backend
opens with any other that implements its algorithm. A writer on `Ring` and a reader on `AwsLc`
work together, and moving an application from one backend to another needs no migration of its
data:

```rust
use kms_aead::{AeadAlgorithm, AeadCipher, Ring, RustCrypto};
use secret_vault_value::SecretValue;

# fn main() -> kms_aead::KmsAeadResult<()> {
let writer = AeadCipher::<Ring>::new(AeadAlgorithm::Aes256Gcm)?;
let reader = AeadCipher::<RustCrypto>::new(AeadAlgorithm::Aes256Gcm)?;

let key = writer.generate_key()?;
let cipher_text = writer.encrypt_value(b"aad", &SecretValue::from("secret"), &key)?;

assert_eq!(
    reader.decrypt_value(b"aad", &cipher_text, &key)?,
    SecretValue::from("secret")
);
# Ok(())
# }
```

## ring

ChaCha20-Poly1305, AES-128-GCM and AES-256-GCM. It has no AES-256-GCM-SIV. ring does not zeroize
its expanded key schedules, so they stay in freed memory after each call.

## aws-lc-rs and FIPS

`aws-lc` builds aws-lc-rs with every algorithm. It is the backend that adds no second crypto
library to a build with a cloud provider, since the providers already build aws-lc-rs for TLS.

`aws-lc-fips` runs the same backend on the AWS-LC FIPS module, and builds only the FIPS module,
so it does not need `aws-lc`. It needs CMake and Go to build. Be aware it moves every user of
aws-lc-rs in the build to the FIPS module, the rustls aws-lc-rs provider included. A build with
both features compiles both C libraries, and aws-lc-rs runs on the FIPS one. AES-256-GCM is the
algorithm for FIPS deployments. AES-SIV, the deterministic algorithm, is not FIPS-approved, see
[Deterministic encryption](./deterministic.md).

aws-lc-rs copies the key into an AEAD context that AWS-LC allocates with its own allocator, which
overwrites every allocation with zeros before freeing it. The expanded key schedule does not stay
in freed memory after a call, as long as the application leaves AWS-LC's allocator in place. The
record keys AES-256-GCM-SIV derives for each call live on the stack, and AWS-LC does not clear
them.

## RustCrypto

Every algorithm, in pure Rust, with `getrandom` as the CSPRNG. It needs no C compiler. The
feature turns on the crates' `zeroize` features, so their key objects, and the Poly1305 and
POLYVAL keys each call derives, are zeroized when dropped.
