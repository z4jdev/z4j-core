# z4j-core

[![PyPI version](https://img.shields.io/pypi/v/z4j-core.svg)](https://pypi.org/project/z4j-core/)
[![Python](https://img.shields.io/pypi/pyversions/z4j-core.svg)](https://pypi.org/project/z4j-core/)
[![License](https://img.shields.io/pypi/l/z4j-core.svg)](https://github.com/z4jdev/z4j-core/blob/main/LICENSE)


**License:** Apache 2.0
**Status:** v1.0.0 - first public release.

The pure domain core of [z4j](https://z4j.com). **Imports nothing
framework- or engine-specific** - only Pydantic and the Python
standard library. This is enforced by `import-linter` in CI. Any PR
that tries to import Django, Celery, Redis, SQLAlchemy, FastAPI, etc.
from `z4j_core` will fail the build.

## Install

```bash
pip install z4j-core
```

You will rarely need to install `z4j-core` directly - every z4j agent
and the brain server depend on it and pull it in automatically.

## Why this matters

Every other package in the z4j project depends on `z4j-core`. The
brain uses its domain models and wire protocol; every adapter
implements one of its Protocols. Keeping this package free of
framework coupling is what lets us:

1. Ship v1 with Django + Celery, then add Flask / FastAPI / RQ /
   Dramatiq / Huey / arq / taskiq as peer packages without touching the core.
2. Test the entire domain layer with no database, no broker, no HTTP.
3. Evolve the protocol without rewriting the dashboard or the brain.
4. Let contributors add a new engine adapter over a weekend without
   understanding any of the rest of the system.

## What's in here

| Module | Purpose |
|---|---|
| `z4j_core.models` | Pydantic v2 domain models (Project, Agent, Task, Queue, Worker, Schedule, Command, Event, AuditEntry, User, Config, ...) |
| `z4j_core.protocols` | `QueueEngineAdapter`, `FrameworkAdapter`, `SchedulerAdapter` - the three adapter interfaces adapters implement |
| `z4j_core.errors` | Exception hierarchy (`Z4JError`, `ValidationError`, `AuthenticationError`, ...) |
| `z4j_core.redaction` | Secret redaction engine with default patterns and per-field overrides |
| `z4j_core.transport` | Wire protocol - frame shapes, version negotiation, HMAC v2 signing |
| `z4j_core.policy` | Permission engine - `can(user, action, project)` |

## Documentation

- [Architecture](https://z4j.dev/architecture) - full system architecture and Protocol signatures
- [API](https://z4j.dev/api) - REST API and WebSocket agent protocol
- [Security](https://z4j.dev/security) - threat model, redaction, HMAC
- [Adapter guide](https://z4j.dev/adapters) - how to build a third-party adapter against these Protocols

## Development

```bash
git clone https://github.com/z4jdev/z4j-core.git
cd z4j-core
uv sync --all-extras --dev
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest -xvs tests/
uv run lint-imports            # enforces core-purity contract
```

## License

Apache 2.0. See [LICENSE](LICENSE). This package is deliberately
permissively licensed so that proprietary Django / Flask / FastAPI
applications can import it without any license concerns.

## Links

- Homepage: <https://z4j.com>
- Documentation: <https://z4j.dev>
- Issues: <https://github.com/z4jdev/z4j-core/issues>
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security: `security@z4j.com` (see [SECURITY.md](SECURITY.md))
