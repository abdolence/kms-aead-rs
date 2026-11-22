# Keep sensitive data out of logs

A log line that explains a failure often needs the data that failed, and the data is the thing a
log must not keep. This use case needs no KMS and no keys.

| Pick this when | Use case |
|---|---|
| A payload that fails to parse has to be logged, and it holds emails, phone numbers or amounts | [Log a webhook payload that failed to parse](./log-json-payloads.md) |
