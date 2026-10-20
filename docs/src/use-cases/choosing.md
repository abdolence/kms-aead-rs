# Choose a provider and a backend

A build makes two choices that do not constrain each other: the KMS that holds the KEK, and the
crypto backend that runs the AEAD algorithms. Both are Cargo features, see
[Cargo features](../features.md).

## KMS providers

The KMS decides who else reads the values, what a rotation takes and how a scope is
crypto-shredded:

| | Google Cloud KMS | AWS KMS | Azure Key Vault | Vault Transit | Local KMS |
|---|---|---|---|---|---|
| Tink reads envelope values | yes | yes | no | no | no |
| Tink reads keyring keysets | yes | yes, with a key named by its ARN | no | Tink for Go only | no |
| BigQuery reads | yes | no | no | no | no |
| KMS random generator | yes, at the HSM protection level | yes | no | no | no |
| KEK version on each encrypted DEK | yes | no, `None` | yes | yes | yes |
| Disabling an old KEK version | yes, eventually consistent | no, for key material AWS KMS generated | yes | yes, with `min_decryption_version` | yes, by dropping it from the list |
| Crypto-shredding a scope | destroying its KEK versions | deleting the key | deleting the key, with all its versions | deleting its key versions | destroying every copy of the KEK |

Notes on the table:

- Tink reads envelope values with `KmsEnvelopeAead` and its own KMS client, see
  [Tink's KMS envelope](../formats.md#tinks-kms-envelope), and keyring keysets with
  `KeysetHandle.read`, see [Exporting a keyset to Tink](../keyring/bigquery.md#exporting-a-keyset-to-tink);
- BigQuery's `KEYS.KEYSET_CHAIN` decrypts with Cloud KMS only, see
  [Read values in BigQuery or Tink](./bigquery-and-tink.md);
- the KEK version decides how a KEK rotation is checked before the old version is disabled, see
  [Rotate keys and re-encrypt values](./rotation.md#kek-rotation). Each provider page has its
  rotation, under "Key versions and rotation": [Google Cloud KMS](../providers/gcp.md),
  [AWS KMS](../providers/aws.md), [Azure Key Vault](../providers/azure.md),
  [Vault Transit](../providers/hc-vault-transit.md) and [Local KMS](../providers/local.md);
- with an RSA key on Azure Key Vault the encryption is a public-key operation, so whoever holds the
  public key encrypts a DEK of their own into a keyring record. Use an AES key from Managed HSM,
  with `algorithm` set to `A256Kw`, see [Azure Key Vault](../providers/azure.md#options) and
  [Keyring limits](../security.md#keyring-limits);
- the local KMS has no IAM, no audit log and no HSM, see [Local KMS](../providers/local.md#limits);
- crypto-shredding per KMS is in [A leaked key or a shredded tenant](./incidents.md#crypto-shredding).

The TLS root store and the TLS crypto provider are a feature choice for Google Cloud KMS, Azure and
Vault Transit, with the rules in [Feature rules](../features.md#feature-rules).

## Crypto backends

| | `ring` | `aws-lc` | `aws-lc-fips` | `rustcrypto` |
|---|---|---|---|---|
| AES-256-GCM-SIV | no | yes | yes | yes |
| FIPS module | no | no | yes | no |
| Needs a C toolchain | yes | yes | yes, with CMake and Go | no |
| A second crypto library beside a cloud provider | yes | no | no | yes |
| Key schedules zeroised | no | yes, by AWS-LC's allocator | yes, by AWS-LC's allocator | yes |

Every backend has ChaCha20-Poly1305, AES-128-GCM and AES-256-GCM, writes the same bytes, and opens
the values of any other, so a move from one backend to another needs no migration of the data, see
[Cross-backend compatibility](../crypto-backends.md#cross-backend-compatibility).

- **No second crypto library**: the default features of the four cloud providers already build
  aws-lc-rs for TLS, so `aws-lc` adds nothing to a provider build;
- **FIPS**: `aws-lc-fips` runs the backend on the AWS-LC FIPS module and moves every user of
  aws-lc-rs in the build to it, the rustls provider included. AES-256-GCM is the algorithm for a
  FIPS deployment. AES-SIV, the deterministic algorithm, is not FIPS-approved and runs on RustCrypto
  whatever the backend, so deterministic fields stay outside the validated boundary, see
  [aws-lc-rs and FIPS](../crypto-backends.md#aws-lc-rs-and-fips);
- **No C toolchain**: `rustcrypto` is pure Rust, with `getrandom` as the CSPRNG;
- **Zeroisation**: what each backend leaves in freed memory is in
  [Crypto backends](../crypto-backends.md#ring).

A build may enable several backends at once, and code generic over the backend bounds it with
`B: AeadBackend` and nothing else, see
[Code generic over the backend](../crypto-backends.md#code-generic-over-the-backend).
