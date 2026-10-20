# Applications and administration apart

A keyring deployment has two sides, which build, run and are granted differently. The concepts
and the rights tables are in [Applications and administration](../keyring/deployment.md); this
page is the checklist of each side, and what to alert on in production.

## The application

- Builds without the `admin` feature, with `cargo build -p <application>`, since Cargo unifies
  the features of every package one command builds;
- runs as a principal with KMS decrypt on the KEK and read access to the keyring store, listen
  included, see [KMS rights](../keyring/deployment.md#kms-rights) and
  [Store rights](../keyring/deployment.md#store-rights);
- calls `KeyringRegistry::open`, and on the `Keyring` it returns `sealer`, `decrypt` and the
  probes, and runs the sweeps;
- awaits `registry.shutdown()` before it exits.

## The administration

- Builds with the `admin` feature, and `bigquery-export` where it exports BigQuery keysets;
- runs in a job or in infrastructure automation, never in a request handler, as the only principal
  with KMS encrypt on the KEK and write access to the keyring store;
- calls `create` or `open_or_create` for each new keyring, and on the `KeyringAdmin` the lifecycle
  calls, `reencrypt_deks` and the keyset exports, see
  [Key versions and lifecycle](../keyring/lifecycle.md);
- logs every call it makes, since a version its log does not show is the start of
  [A version the administrative job did not create](../operations/runbook.md#a-version-the-administrative-job-did-not-create);
- opens its registry with the longest `record_ttl` in the fleet, which the promotion guard waits.

An application that creates keyrings lazily, such as one per tenant on its first request, is both
sides at once, see [A keyring per tenant](./keyring-per-tenant.md#creating-the-keyrings).

## What to alert on

The events are logged through tracing, see [Keyring events](../observability.md#keyring-events)
and [Events](../observability.md#events), and the metrics need the `opentelemetry` feature, see
[Metrics](../observability.md#metrics).

| Signal | What it means | Next step |
|---|---|---|
| `ERROR`: a refreshed record refused because it moves a version backwards | something other than the administrative job rewrote or restored the record | [A version the administrative job did not create](../operations/runbook.md#a-version-the-administrative-job-did-not-create) |
| `WARN`: "The keyring record could not be revalidated; the cached record stays in use" | the process misses every change, a promotion or a compromised flag included, until the store answers | fix the process's access to the store before the next promotion |
| `WARN`: a record the store no longer holds | the record was deleted; new processes fail at `open` with `RecordMissing` | [The keyring record was deleted or corrupted](../operations/runbook.md#the-keyring-record-was-deleted-or-corrupted) |
| `WARN`: the store's listener disconnected or did not start, or a keyring opened with no tokio runtime | changes reach the process within `record_ttl` instead of seconds | check the listener's connection and the runtime |
| `WARN`: a compromised flag written without a rotation | the KMS could not encrypt a new DEK, so `encrypt` fails with `NoActiveVersion` | `rotate` and `promote_now` once the KMS answers, see [Compromised versions](../keyring/lifecycle.md#compromised-versions) |
| `WARN`: a read of a compromised version under the `Allow` policy | values under a leaked DEK are being read | the sweep of [A plaintext DEK leaked](../operations/runbook.md#a-plaintext-dek-leaked) |
| `WARN`: a read refused because its version is retired or destroyed | a value the sweep missed | `reinstate` a retired version, and sweep again |
| `WARN`: a `KeyringRegistry` dropped with its tasks running, or a `shutdown` that aborted them | the process exits without `shutdown` | await `registry.shutdown()` before the exit |
| `WARN`: a record a sweep could not re-seal, or `SweepReport::failed` above zero | a record left under an old version | the cause in the event's `error`, see [Running a sweep](../operations/sweeps.md#running-a-sweep) |
| `error.type` on `kms_aead.operation.duration` | calls that fail, by code, such as `DECRYPT` for a value that is not authentic under its key and AAD, or `KEY_VERSION_UNKNOWN` | the code, see [Error handling](../errors.md) |
| `error.type` on `kms_aead.kms.duration` | KMS requests that fail: a denied permission, a disabled key version, a quota | [Retries](../errors.md#retries) for the codes of each KMS |
| `error.type` on `kms_aead.store.duration` | keyring store reads that fail | the store's own monitoring |
| values and bytes per keyring version | a version near the limits of its algorithm | [Alerting on volume](../operations/rotation.md#alerting-on-volume) |
| an `Encrypt` in the KMS audit log by a principal other than the administration | an IAM over-grant, or a version the job did not create. Cloud KMS logs `Encrypt` as `DATA_READ` in its Data Access audit logs, see [Cloud KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging) and [Enable Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) | [A KMS IAM over-grant](../operations/runbook.md#a-kms-iam-over-grant) |
| a `Decrypt` in the KMS audit log by a principal other than the application, the administration and the keyset readers: every `KEYS.KEYSET_CHAIN` query decrypts its keyset as the principal that runs it, and so does a Tink reader through its own KMS client, see [Queries](../keyring/bigquery.md#queries) and [Exporting a keyset to Tink](../keyring/bigquery.md#exporting-a-keyset-to-tink) | an IAM over-grant, or an encrypted DEK or a keyset opened outside the deployment. Cloud KMS logs `Decrypt` as `DATA_READ` in its Data Access audit logs, which are off by default and must be turned on, see [Cloud KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging) and [Enable Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access) | [A KMS IAM over-grant](../operations/runbook.md#a-kms-iam-over-grant) |
| `WARN`, inside the KMS span: a Cloud KMS or Vault Transit response without a key version | the KMS reported no version, so `kek_versions_in_use` lists a `None` and the check before a KEK disable never passes | [A KEK version the KMS did not report](../operations/rotation.md#a-kek-version-the-kms-did-not-report) |
| `WARN`, once per process: the first read of a layout of 0.29 or earlier | values not yet upgraded | [Upgrading stored values](../formats.md#upgrading-stored-values) |

Without a keyring, the rows of kms-aead apply: `error.type` on `kms_aead.operation.duration` and
`kms_aead.kms.duration`, the KMS audit log, and the `WARN` of old layouts.
