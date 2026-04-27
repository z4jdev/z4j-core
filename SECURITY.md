# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `z4j-core`,
**do not open a public GitHub issue**. Email `security@z4j.com` instead.

We follow the [disclose.io](https://disclose.io) baseline:

- Initial acknowledgement within **72 hours**.
- Coordinated disclosure timeline agreed before public release.
- Credit in the release notes (unless you prefer to remain anonymous).

PGP key and the full disclosure policy live in the
[z4j project security policy](https://github.com/z4jdev/z4j/blob/main/SECURITY.md).

## Supported versions

Only the latest minor release receives security fixes. See
[CHANGELOG.md](CHANGELOG.md) for the current version.

## Security-critical surface

`z4j-core` owns three areas where a vulnerability would have
cross-cutting impact across the z4j project:

- **Transport / HMAC v2 signing** (`z4j_core.transport`) - any
  weakness in envelope signing, replay protection, or version
  negotiation affects every agent-brain session.
- **Redaction engine** (`z4j_core.redaction`) - a bypass here could
  leak task payloads or secrets into the audit log.
- **Policy engine** (`z4j_core.policy`) - over-permissive decisions
  become RBAC vulnerabilities downstream.

These areas carry 100 % unit-test coverage and receive priority
review on every PR.
