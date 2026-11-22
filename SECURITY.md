# Security policy

## Reporting a vulnerability

Please follow the general guidelines of the [OWASP Vulnerability Disclosure Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html).

## Security considerations and risks

### Supply chain

kms-aead and kms-aead-keyring read sensitive data, so manage them and their dependencies with the
procedures you use for commercial products. Pin versions in a lockfile, and audit the changes of an
upgrade before you take it: a broad version requirement pulls in a new release of a dependency
without that audit.

## Contacts

Email: [me@abdolence.dev](mailto:me@abdolence.dev)
