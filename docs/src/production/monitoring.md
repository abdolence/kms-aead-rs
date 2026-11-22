# Monitoring and alerts

The catalogue of what to alert on in production, then the alerts for the volume of values under a
key version and for the two rotations.

## What to alert on

The events are logged through tracing, see [Keyring events](../observability/spans-and-events.md#keyring-events)
and [Events](../observability/spans-and-events.md#events), and the metrics need the `opentelemetry` feature, see
[Metrics](../observability/metrics.md#metrics).

### The keyring record

| Signal | What it means | Next step |
|---|---|---|
| `ERROR`: a refreshed record refused because it moves a version backwards | something other than the administrative job rewrote or restored the record | [A version the administrative job did not create](./runbook.md#a-version-the-administrative-job-did-not-create) |
| `ERROR`: a refreshed record refused by record verification, with `RECORD_UNSIGNED`, `RECORD_SIGNATURE_INVALID` or `RECORD_SIGNATURE_REMOVED` | something other than the record signer wrote or restored the record; the process keeps the record it holds | [A version the administrative job did not create](./runbook.md#a-version-the-administrative-job-did-not-create), and the signer's KMS audit log |
| `WARN`: "The keyring record could not be revalidated; the cached record stays in use" | the process misses every change, a promotion or a compromised flag included, until the store answers | fix the process's access to the store before the next promotion |
| `WARN`: "The keyring store no longer holds the keyring record; every version is destroyed in this process" | the record was deleted or shredded, and this process destroyed every version in memory | [The keyring record was deleted or corrupted](./runbook.md#the-keyring-record-was-deleted-or-corrupted) |
| `WARN`: the store's listener disconnected or did not start, or a keyring opened with no tokio runtime | changes reach the process within `record_ttl` instead of seconds | check the listener's connection and the runtime |

After the `WARN` about a deleted record, the process's handles fail with `NoActiveVersion` and
`KeyVersionDestroyed`, and new opens fail with `RecordMissing` until a record is created. A process
that read the shred's first write logs an `INFO` instead.

### Versions and sweeps

| Signal | What it means | Next step |
|---|---|---|
| `WARN`: a compromised flag written without a rotation | the KMS could not encrypt a new DEK, so `encrypt` fails with `NoActiveVersion` | `rotate` and `promote_now` once the KMS answers, see [Compromised versions](../keyring/lifecycle.md#compromised-versions) |
| `WARN`: a read of a compromised version under the `Allow` policy | values under a leaked DEK are being read | the sweep of [A plaintext DEK leaked](./runbook.md#a-plaintext-dek-leaked) |
| `WARN`: a read refused because its version is retired or destroyed | a value the sweep missed | `reinstate` a retired version, and sweep again |
| `WARN`: a record a sweep could not re-encrypt, or `SweepReport::failed` above zero | a record left under an old version | the cause in the event's `error`, see [Running a sweep](./sweeps.md#running-a-sweep) |
| `WARN`, once per process: the first read of a layout of 0.29 or earlier | values not yet upgraded | [Upgrading stored values](../migrating-from-0.29.md#upgrading-stored-values) |

### The process and the KMS

| Signal | What it means | Next step |
|---|---|---|
| `WARN`: a `KeyringRegistry` dropped with its tasks running, or a `shutdown` that aborted them | the process exits without `shutdown` | await `registry.shutdown(None)` before the exit |
| `WARN`, inside the KMS span: a Cloud KMS or Vault Transit response without a key version | the KMS reported no version, so `kek_versions_in_use` lists a `None` and the check before a KEK disable never passes | [A KEK version the KMS did not report](./rotation.md#a-kek-version-the-kms-did-not-report) |

### Metrics

| Signal | What it means | Next step |
|---|---|---|
| `error.type` on `kms_aead.operation.duration` | calls that fail, by code, such as `DECRYPT` for a value that is not authentic under its key and AAD, or `KEY_VERSION_UNKNOWN` | the code, see [Error handling](../errors.md) |
| `error.type` on `kms_aead.kms.duration` | KMS requests that fail: a denied permission, a disabled key version, a quota | [Retries](../errors.md#retries) for the codes of each KMS |
| `error.type` on `kms_aead.store.duration` | keyring store reads that fail | the store's own monitoring |
| values and bytes per keyring version | a version near the limits of its algorithm | [Alerting on volume](./monitoring.md#alerting-on-volume) |

### The KMS audit log

| Signal | What it means | Next step |
|---|---|---|
| an `Encrypt` by a principal other than the administration | an IAM over-grant, or a version the job did not create | [A KMS IAM over-grant](./runbook.md#a-kms-iam-over-grant) |
| a `Decrypt` by a principal other than the application, the administration and the keyset readers | an IAM over-grant, or an encrypted DEK or a keyset decrypted outside the deployment | [A KMS IAM over-grant](./runbook.md#a-kms-iam-over-grant) |

Cloud KMS logs `Encrypt` and `Decrypt` as `DATA_READ` in its Data Access audit logs, which are off
by default and must be turned on, see [Cloud KMS audit logging](https://docs.cloud.google.com/kms/docs/audit-logging)
and [Enable Data Access audit logs](https://docs.cloud.google.com/logging/docs/audit/configure-data-access).
Every `KEYS.KEYSET_CHAIN` query decrypts its keyset as the principal that runs it, and so does a
Tink reader through its own KMS client, see [Queries](../keyring/bigquery.md#queries) and
[Exporting a keyset to Tink](../keyring/bigquery.md#exporting-a-keyset-to-tink).

Without a keyring, the rows of kms-aead apply: `error.type` on `kms_aead.operation.duration` and
`kms_aead.kms.duration`, the KMS audit log, and the `WARN` of old layouts.

## Alerting on volume

With the `opentelemetry` feature, the keyring records the plaintext size of each value it encrypts
under each version, see [Metrics](../observability/metrics.md#metrics): the histogram's count is the
values, and its sum their bytes. Each process records its own, and the alert sums them across the
fleet. Here at half of 2^32 values and of 2^38 bytes per version, in PromQL over the Prometheus
export, with the range covering the version's life:

```promql
sum by (kms_aead_keyring, kms_aead_key_id) (
  increase(kms_aead_plaintext_size_bytes_count{
    kms_aead_mode="keyring", kms_aead_operation="encrypt", kms_aead_purpose="randomized"
  }[90d])
) > 0.5 * 2^32

sum by (kms_aead_keyring, kms_aead_key_id) (
  increase(kms_aead_plaintext_size_bytes_sum{
    kms_aead_mode="keyring", kms_aead_operation="encrypt",
    kms_aead_algorithm=~"aes-(128|256)-gcm"
  }[90d])
) > 0.5 * 2^38
```

A histogram starts at zero in every new process, and `increase()` counts across those restarts.
The `[90d]` range needs 90 days of retention: Prometheus keeps 15 days by default, so keep the
metric in long-term storage, through remote write or in a backend with a longer retention. The bytes
alert keeps to AES-GCM versions, the only ones with a volume bound. Rotate the version the alert
names, as in [Staging a rotation](./rotation.md#rotation-cadence).

## During a DEK rotation

- "The keyring record could not be revalidated", from the rotation until the old version is retired:
  a process that logs it is one a promotion can leave behind, and one that can still encrypt under
  the old version;
- `error.type` `KEY_VERSION_UNKNOWN` on `kms_aead.operation.duration`, a read that met a version
  its process could not load, and `KEY_VERSION_RETIRED` once the old version is retired;
- `SweepReport::failed` above zero, and the sweep's `WARN` per record;
- the values and bytes per version, which say when the next rotation is due, see
  [Alerting on volume](#alerting-on-volume).

The metrics need the `opentelemetry` feature, see [Metrics](../observability/metrics.md#metrics).

## During a KEK rotation

- "The keyring record could not be revalidated", from the re-encryption until the disable: a
  process that logs it keeps the old encrypted DEKs, and its reads fail after the disable once its
  DEK cache entries expire;
- `error.type` on `kms_aead.kms.duration` with `kms_aead.operation` `decrypt_dek`, after the
  disable: a DEK the re-encryption missed, or a process that still holds old bytes;
- the rate of `kms_aead.kms.duration` with `decrypt_dek`, and `ResourceExhausted` or
  `ThrottlingException` in its `error.type`, during the burst;
- an `error_code` on the `Keyring re-encrypt DEKs` span of the administrative job.
