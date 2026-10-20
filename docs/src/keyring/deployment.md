# Applications and administration

A keyring has two sides, each with its own handle and its own rights:

- the application decrypts and runs sweeps on a `Keyring`, which `KeyringRegistry::open` returns
  in every build, and encrypts, computes beacons and re-seals on the `Sealer` the `Keyring`
  hands out for each write;
- the administration creates keyrings, rotates, promotes, retires and destroys versions, flags
  compromised ones, re-encrypts DEKs and exports keysets, on a `KeyringAdmin`, which
  `KeyringRegistry::create`, `open_or_create` and `admin` return with the `admin` feature.

The application builds without the `admin` feature and runs under a principal with the rights of
its row only:

| Side | Handle | KMS | Keyring store |
|---|---|---|---|
| Application | `Keyring` | decrypt: GCP `roles/cloudkms.cryptoKeyDecrypter`, AWS `kms:Decrypt`, Azure Key Vault unwrap key, Vault Transit decrypt | read, and listen or watch: Firestore read, PostgreSQL `SELECT` and `LISTEN`, Cloud Storage object read, S3 `GetObject` |
| Administration | `KeyringAdmin` | encrypt and decrypt | read and write: Firestore write, PostgreSQL `INSERT` and `UPDATE`, which also send the `NOTIFY`, Cloud Storage and S3 object write |

Sweeps run on the application's side: re-sealing a value encrypts it under a DEK the record
already holds, and never asks the KMS to encrypt a DEK. Every call that encrypts a DEK or writes
the record is a `KeyringAdmin` call. The exact roles per KMS are in
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
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore"] }

[dev-dependencies]
kms-aead-keyring = { version = "0.30", features = ["ring", "firestore", "admin"] }
```

Be aware Cargo unifies the features of the packages one command builds: a `cargo build` of a
workspace with both the application and an administrative job gives the application `admin`
too. Build and deploy the application with `cargo build -p <application>`.

## KMS rights

Nothing signs a [keyring](../keyring.md) record, see
[Keyring deployment](../security.md#keyring-deployment), so a deployment splits the two sides
above into two principals:

- **Application**: builds without the `admin` feature, and calls `Keyring` only: encryption,
  decryption, beacons and sweeps. It needs KMS decrypt on the KEK and read access to the keyring
  store. None of its calls asks the KMS to encrypt, so it needs nothing more;
- **Administration**: builds with the `admin` feature, and calls the registry's `create`,
  `open_or_create` and `admin`, and the `KeyringAdmin` they return: `rotate`, `promote`,
  `change_algorithm`, `mark_compromised`, `retire`, `reinstate`, `destroy`,
  `dangerously_destroy_all_versions`, `reencrypt_deks`, `export_bigquery_keyset` and
  `export_tink_keyset`. It needs KMS encrypt and decrypt on the KEK, and is the only principal
  with write access to the keyring store. It runs in a job or in infrastructure automation, never
  in a request handler.

| KMS | Application | Administration |
|---|---|---|
| GCP | `roles/cloudkms.cryptoKeyDecrypter` | `roles/cloudkms.cryptoKeyEncrypterDecrypter` |
| AWS | `kms:Decrypt` on the key | `kms:Encrypt` and `kms:Decrypt` on the key, plus `kms:GenerateRandom` with the KMS random generator |
| Azure Key Vault | a role with `keys/unwrap/action` on the key | a role with `keys/wrap/action` and `keys/unwrap/action` on the key |
| Vault Transit | `update` on `transit/decrypt/<key>` | `update` on `transit/encrypt/<key>` and `transit/decrypt/<key>` |

The permissions of each store are below.

## Store rights

The store's access control is what the record's integrity rests on: only the administration
writes the record, and the applications read it and listen to its changes, see above:

| Store | Application | Administration |
|---|---|---|
| Firestore | read of the keyring documents, which the listener uses too, such as `roles/datastore.viewer` | read and write of the keyring documents, such as `roles/datastore.user` |
| PostgreSQL | `SELECT` on the table, and `LISTEN`, which needs no grant | `SELECT`, `INSERT` and `UPDATE` on the table; each write also sends the `NOTIFY` |
| Cloud Storage | `storage.objects.get` | `storage.objects.get`, `storage.objects.create`, and `storage.objects.delete`, since a write replaces the object |
| S3 | `s3:GetObject` | `s3:GetObject` and `s3:PutObject` |
