# z4j-core

[![PyPI version](https://img.shields.io/pypi/v/z4j-core.svg)](https://pypi.org/project/z4j-core/)
[![Python](https://img.shields.io/pypi/pyversions/z4j-core.svg)](https://pypi.org/project/z4j-core/)
[![License](https://img.shields.io/pypi/l/z4j-core.svg)](https://github.com/z4jdev/z4j-core/blob/main/LICENSE)

The z4j domain core — shared models, protocols, transport, redaction, policy.

Pure-Python dependency for every z4j package. No framework / engine /
database imports, so it can be vendored into agent processes without
dragging server runtime weight. End users do not install this package
directly; it ships as a transitive dependency of the brain or any
agent package.

## What's in here

- **Pydantic models** — `Task`, `Worker`, `Queue`, `Schedule`,
  `Event`, `Command`, `Agent`, plus the wire-frame envelope types
- **Adapter protocols** — `QueueEngineAdapter`, `SchedulerAdapter`,
  `FrameworkAdapter`. Every framework / engine / scheduler package
  implements one or more of these.
- **Wire protocol** — frame definitions and the HMAC envelope used
  by the brain ↔ agent WebSocket transport (signed v2 protocol)
- **Redaction engine** — strips secrets from logged event payloads
  (URLs, headers, kwargs, exceptions) before they hit the brain
- **Policy types** — role-based action enums (Viewer / Operator /
  Admin), used by the brain's RBAC layer
- **Error hierarchy** — shared exception classes so agents and brain
  agree on what counts as `AuthorizationError` vs `NotFoundError`
  vs `ConflictError`

## Install

```bash
pip install z4j-core
```

End users normally get this as a transitive dependency. Direct
installation is appropriate when you're building a custom adapter
against the protocols.

## Stability

The wire protocol is `v=2` and additive within the 1.x major.
Adapter protocols (`QueueEngineAdapter`, etc.) are stable contracts
within the 1.x major; new optional methods may be added.

## Documentation

Full docs at [z4j.dev/concepts/architecture/](https://z4j.dev/concepts/architecture/).

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Links

- Homepage: https://z4j.com
- Documentation: https://z4j.dev
- PyPI: https://pypi.org/project/z4j-core/
- Issues: https://github.com/z4jdev/z4j-core/issues
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: security@z4j.com (see [SECURITY.md](SECURITY.md))
