# Develop and test without a cloud

The local KMS, the memory store and local servers for the other stores run the same code paths as
production, with no cloud account. What each one keeps, and for how long, decides where it fits.

| Piece | For | Keeps its keys |
|---|---|---|
| `LocalKmsProvider::ephemeral` | tests | for the life of the provider |
| `LocalKmsProvider::new` with `LocalKek::from_env` or `from_file` | a development database | as long as the variable or the file |
| `MemoryKeyringStore` | tests | for the life of the process |
| a Firestore emulator, a local PostgreSQL or an S3-compatible server | a development keyring store | as long as the server's data |

## The KMS

- **Tests**: `LocalKmsProvider::ephemeral` has one random KEK that lives as long as the provider.
  Every DEK it encrypts, and so every value, is unreadable once the process exits, see
  [Tests and development](../providers/local.md#tests-and-development);
- **a development environment** whose data outlives a run keeps a KEK in a variable or a file, with
  `LocalKek::from_env` or `LocalKek::from_file`, see the same section. A value written with the
  local KMS never decrypts under a cloud KMS, so a development database starts again empty on the
  move to one.

The provider is in every build, with no feature, and logs its KEK id and where each version came
from at `INFO` when it is created.

## The keyring store

- **Tests**: `MemoryKeyringStore`, in `kms_aead_keyring::testing`, loses its records, and with them
  every DEK, when the process exits. A test that creates keyrings in it enables `admin` in
  `[dev-dependencies]` only, see [Applications and administration](../keyring/deployment.md);
- **Firestore**: the emulator of the Google Cloud CLI, `gcloud emulators firestore start`, and
  `FIRESTORE_EMULATOR_HOST` set to its address. `FirestoreDb::new` connects to the emulator while
  the variable is set, so the store needs no change. The
  [`sweep_firestore` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_firestore.rs)
  runs on it:

  ```sh
  docker run --rm -d --name kms-aead-firestore -p 8687:8687 \
    gcr.io/google.com/cloudsdktool/google-cloud-cli:emulators \
    gcloud emulators firestore start --host-port=0.0.0.0:8687
  FIRESTORE_EMULATOR_HOST=127.0.0.1:8687 PROJECT_ID=kms-aead-emulator \
    cargo run -p kms-aead-keyring --example sweep_firestore --features ring,admin,firestore-tls-roots
  ```

- **PostgreSQL**: a local server, the table of [PostgreSQL](../keyring/stores.md#postgresql), and
  a connection with `NoTls`. The
  [`sweep_postgres` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/sweep_postgres.rs)
  reads its connection string from `KMS_AEAD_KEYRING_POSTGRES_URL`;
- **S3**: an S3-compatible server such as MinIO, once it passes the store conformance suite, see
  [S3-compatible servers](../keyring/stores.md#s3-compatible-servers).

Cloud Storage has no local server in the store's tests.

## A first run

The [`local_kms` example](https://github.com/abdolence/kms-aead-rs/blob/master/kms-aead-keyring/examples/local_kms.rs)
creates a keyring on the memory store with a local KEK, rotates it and reads a value written
before the rotation: `cargo run -p kms-aead-keyring --example local_kms --features ring,admin`.
The same with kms-aead alone is in [With an envelope](../getting-started.md#with-an-envelope).

## Limits

- The local KMS has no IAM and no audit log, and the KEK in a variable stays in the process
  environment, see [Local KMS](../providers/local.md#limits);
- values encrypted under a local KEK are not exported to BigQuery, which decrypts with Cloud KMS
  only.
