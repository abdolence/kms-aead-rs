# Prove where data came from

The bytes stay readable, and the reader checks who produced them and that nobody changed them on
the way. A signature answers it for anyone with a public key, and a MAC (a keyed hash) answers it
between services that share a key.

| Pick this when | Use case |
|---|---|
| A file, an export or a release is published, and anyone has to be able to verify it | [Publish a rate sheet or a release anyone can verify](./publish-verifiable.md) |
| Your own services pass jobs, cache entries or rows to each other, and the reader checks that nobody changed them | [Detect tampering with jobs and rows between your services](./service-integrity.md) |
