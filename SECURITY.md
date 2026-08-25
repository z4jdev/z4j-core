# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in `z4j-core`,
**do not open a public GitHub issue**. Email `security@z4j.com` instead.

We acknowledge reports within **48 hours**, provide a preliminary assessment
within **5 business days**, and target fixes within **30 days** (**7 days** for
confirmed critical issues). Reporting timelines, safe harbor,
supported-version policy, and published advisories are maintained in the
[canonical z4j project security policy](https://github.com/z4jdev/z4j/blob/main/SECURITY.md).

## Security-critical surface

Two especially security-sensitive shared areas are:

- **Transport / HMAC v2 signing** (`z4j_core.transport`) - any
  weakness in envelope signing, replay protection, or version
  negotiation affects every agent-brain session.
- **Redaction engine** (`z4j_core.redaction`) - a bypass here could
  leak task payloads or secrets into persisted event and task data or
  downstream notification and observability surfaces.
These areas have dedicated security-focused unit tests and should be reviewed
together with their consumers in the brain and agents.

`z4j_core.policy` is a helper for direct consumers. The brain's authentication
and RBAC implementation is owned by the `z4j` package and is not delegated to
that helper.
