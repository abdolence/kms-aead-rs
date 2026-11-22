# Files and streams

The data is too large to hold in memory. It is encrypted in chunks, as it is written or sent, and
read in chunks.

| Pick this when | Use case |
|---|---|
| Uploads of any size are stored encrypted, and readers need byte ranges of them | [Store customer uploads and serve byte ranges](./large-files.md) |
| A handler sends a large export over HTTP, and the body has to leave the server encrypted | [Send a large export over HTTP, encrypted](./encrypted-http-streams.md) |
