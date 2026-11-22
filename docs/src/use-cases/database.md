# Protect data in your database

The values live in your own tables and the application reads them back. These use cases cover
encrypting the columns, the cost in KMS calls, a set of keys for each customer, lookups by an
encrypted value, and erasing a customer.

| Pick this when | Use case |
|---|---|
| Customers' emails, phone numbers or API tokens sit in your own tables | [Encrypt personal data and secrets in your database](./encrypt-fields.md) |
| Reads or writes make too many KMS calls | [Cut KMS calls with a DEK cache and DEK reuse](./fewer-kms-calls.md) |
| One customer needs its keys rotated or destroyed without touching the others | [Give each customer of a SaaS its own keys](./keyring-per-tenant.md) |
| A row has to be found by an encrypted value, such as an email | [Find a user by an encrypted email](./equality-lookups.md) |
| A customer's data has to become unreadable, backups included | [Erase one customer's data for good](./erase-a-tenant.md) |
