# Share encrypted data with other systems

The reader is not the application that wrote the value: an analyst in BigQuery, a service in
another language, or a producer that must never read its own data back.

| Pick this when | Use case |
|---|---|
| BigQuery SQL or a Tink reader in Java or Python needs an encrypted column | [Decrypt columns in BigQuery SQL or with Tink](./bigquery-and-tink.md) |
| Partners, devices or upload clients encrypt data and must not be able to decrypt it | [Accept data from partners and devices that cannot read it back](./write-only-producers.md) |
