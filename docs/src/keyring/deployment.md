# Applications and administration

A keyring has two sides, each with its own handle and its own rights:

- the application decrypts and runs sweeps on a `Keyring`, which `KeyringRegistry::open` returns
  in every build, and encrypts, computes beacons and re-encrypts on the `Encryptor` the `Keyring`
  hands out for each write;
- the administration creates keyrings, rotates, promotes, retires and destroys versions, flags
  compromised ones, re-encrypts DEKs, exports keysets and shreds keyrings, on a `KeyringAdmin`, which
  `KeyringRegistry::create`, `open_or_create` and `admin` return with the `admin` feature.

The application builds without the `admin` feature and runs under a principal with the rights of
its row only:

| Side | Handle | KMS | Keyring store |
|---|---|---|---|
| Application | `Keyring` | decrypt: GCP `roles/cloudkms.cryptoKeyDecrypter`, AWS `kms:Decrypt`, Azure Key Vault `keys/unwrap/action`, Vault Transit decrypt | read, and listen or watch: Firestore read, PostgreSQL `SELECT` and `LISTEN`, Cloud Storage object read, S3 `GetObject` |
| Administration | `KeyringAdmin` | encrypt and decrypt, or under an asymmetric KEK decrypt and read of the public key | read, write and delete: Firestore write, PostgreSQL `INSERT`, `UPDATE` and `DELETE`, which also send the `NOTIFY`, Cloud Storage and S3 object write and delete |

Sweeps run on the application's side: re-encrypting a value encrypts it under a DEK the record
already holds, and never asks the KMS to encrypt a DEK. Every call that encrypts a DEK, writes
or deletes the record is a `KeyringAdmin` call. The exact roles per KMS are in
[KMS rights](#kms-rights), and the permissions per store in
[Store rights](#store-rights).

The `admin` feature keeps the administrative calls out of the application's build, and the rights
keep them out of its reach: without the KMS encrypt right and write access to the store, those
calls fail in any build.

An application opens only keyrings that exist: `open` on a keyring the store holds no record of
fails with `KeyringError::RecordMissing`. So the administration creates each keyring before an
application opens it:

- from infrastructure: a job, a CLI or a deployment step, built with the `admin` feature and run
  with the administrative rights, calls `create` or `open_or_create`;
- or from an application that provisions lazily, such as one keyring per tenant on the tenant's
  first request. Such an application enables `admin` and is given the administrative rights
  deliberately, and is then trusted as the administration is, see
  [Keyring limits](../security.md#keyring-limits).

An application's own tests that create keyrings in `MemoryKeyringStore` enable `admin` for the
tests only:

```toml
[dependencies]
kms-aead-keyring = { version = "0.31", features = ["ring", "firestore-tls-roots"] }

[dev-dependencies]
kms-aead-keyring = { version = "0.31", features = ["ring", "firestore-tls-roots", "admin"] }
```

Be aware Cargo unifies the features of the packages one command builds: a `cargo build` of a
workspace with both the application and an administrative job gives the application `admin`
too. Build and deploy the application with `cargo build -p <application>`.

## KMS rights

A [keyring](../keyring.md) record is signed only where the administration holds a record signer, see
[Signing the keyring record](../signing.md#signing-the-keyring-record) and
[Keyring deployment](../security.md#keyring-deployment), so a deployment splits the two sides
above into two principals:

- **Application**: builds without the `admin` feature, and calls `Keyring` only: encryption,
  decryption, beacons and sweeps. It needs KMS decrypt on the KEK and read access to the keyring
  store. None of its calls asks the KMS to encrypt, so it needs nothing more;
- **Administration**: builds with the `admin` feature, and calls the registry's `create`,
  `open_or_create` and `admin`, and the `KeyringAdmin` they return: `rotate`, `promote`,
  `change_algorithm`, `mark_compromised`, `retire`, `reinstate`, `destroy`,
  `dangerously_destroy_all_versions`, `shred`, `reencrypt_deks`, `export_bigquery_keyset` and
  `export_tink_keyset`. It needs KMS encrypt and decrypt on the KEK, or under an asymmetric KEK
  decrypt and the read of the public key and no encrypt right, and where it signs records the
  right to sign with the record signer's key. It is the only principal with write access to the
  keyring store. It runs in a job or in infrastructure automation, never
  in a request handler.

| KMS | Application | Administration |
|---|---|---|
| GCP | `roles/cloudkms.cryptoKeyDecrypter` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| AWS | `kms:Decrypt` on the key | `kms:Encrypt` and `kms:Decrypt` on the key, plus `kms:GenerateRandom` with the KMS random generator |
| Azure Key Vault | a role with `keys/unwrap/action` on the key | a role with `keys/wrap/action` and `keys/unwrap/action` on the key |
| Vault Transit | `update` on `transit/decrypt/<key>` | `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` |

Under an asymmetric KEK the public key encrypts new DEKs in the administration's own process, so no
side has the KMS encrypt right: Cloud KMS `useToEncrypt`, AWS `kms:Encrypt`, Key Vault
`keys/wrap/action` and Transit `transit/encrypt` leave the administration's grant. The
administration needs the read of the public key beside the applications' decrypt:

| KMS | Application | Administration |
|---|---|---|
| GCP | `cloudkms.cryptoKeyVersions.useToDecrypt`, as in `roles/cloudkms.cryptoKeyDecrypter` | decrypt, and `cloudkms.cryptoKeyVersions.viewPublicKey`, as in `roles/cloudkms.publicKeyViewer`. `roles/cloudkms.cryptoKeyDecrypter` does not carry it |
| AWS | `kms:Decrypt` on the key | `kms:Decrypt` and `kms:GetPublicKey` on the key |
| Azure Key Vault | `keys/unwrap/action` | `keys/unwrap/action` and `keys/get`. "Key Vault Crypto Service Encryption User" carries read, `wrap` and `unwrap` and no decrypt |
| Vault Transit | `update` on `transit/decrypt/<key>` | `update` on `transit/decrypt/<key>`, and `read` on `transit/keys/<key>` or `transit/export/public-key/<key>` |

The KMS audit log no longer shows who encrypted a DEK, since the encryption is local, and anyone
holding the public key can encrypt one: a keyring under an asymmetric KEK runs with
`RecordSignaturePolicy::Required` on every application, see
[Keyrings under an asymmetric KEK](../asymmetric-kek.md#keyrings-under-an-asymmetric-kek). The
`public_key` call of each provider is in [KMS providers](../providers.md#asymmetric-keks).

The permissions of each store are below.

## Store rights

The store's access control is what the record's integrity rests on, unless the record is signed:
only the administration writes the record, and the applications read it and listen to its changes, see above:

| Store | Application | Administration |
|---|---|---|
| Firestore | read of the keyring documents, which the listener uses too, such as `roles/datastore.viewer` | read, write and delete of the keyring documents, such as `roles/datastore.user` |
| PostgreSQL | `SELECT` on the table, and `LISTEN`, which needs no grant | `SELECT`, `INSERT`, `UPDATE` and `DELETE` on the table; each write and delete also sends the `NOTIFY` |
| Cloud Storage | `storage.objects.get` | `storage.objects.get`, `storage.objects.create`, `storage.objects.delete`, since a write replaces the object, and `storage.objects.list`, which `dangerously_shred()` needs to find the object's generations |
| S3 | `s3:GetObject` | `s3:GetObject` and `s3:PutObject`, and for `dangerously_shred()` also `s3:ListBucketVersions`, `s3:DeleteObject` and `s3:DeleteObjectVersion` |

## What to alert on

Each side logs events an operator acts on, such as a refused record, a failed revalidation or a
re-encryption that failed, and records metrics with the `opentelemetry` feature. The list, with the
next step for each, is in [What to alert on](../use-cases/deployment.md#what-to-alert-on).
