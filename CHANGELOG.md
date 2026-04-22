# Changelog

All notable changes to `z4j-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.1] - 2026-04-21

### Changed

- Lowered minimum Python version from 3.13 to 3.11. This package now supports Python 3.11, 3.12, 3.13, and 3.14.
- Documentation polish: standardized on ASCII hyphens across README, CHANGELOG, and docstrings for consistent rendering on PyPI.


## [1.0.0] - 2026-04

### Added

- First public release.
- Pydantic v2 domain models under `z4j_core.models`: `Project`, `Agent`, `Task`, `Queue`, `Worker`, `Schedule`, `Command`, `CommandResult`, `Event`, `AuditEntry`, `User`, `Config`, `Delta`.
- The three adapter Protocols under `z4j_core.protocols`: `QueueEngineAdapter` (15 methods), `FrameworkAdapter`, `SchedulerAdapter` (7 methods).
- Exception hierarchy rooted at `Z4JError` in `z4j_core.errors`.
- Recursive secret-redaction engine under `z4j_core.redaction` with default patterns and per-field overrides.
- Wire-protocol primitives under `z4j_core.transport`: frame shapes, `PROTOCOL_VERSION = "2"`, HMAC v2 sign/verify helpers.
- Permission engine under `z4j_core.policy` (`can(user, action, project)`).
- `PROTOCOL_VERSION` constant for runtime compatibility checks between brain and agents.
- 271 unit tests.
- `py.typed` marker (PEP 561) - full static-type coverage.

### Guarantees

- No runtime dependencies beyond Pydantic and `typing-extensions`.
- No imports of Django, Celery, Flask, FastAPI, Redis, SQLAlchemy, RQ, Dramatiq, websockets, httpx, or any other framework/engine/transport library. This is enforced by `import-linter` in CI.

## Links

- Repository: <https://github.com/z4jdev/z4j-core>
- Issues: <https://github.com/z4jdev/z4j-core/issues>
- PyPI: <https://pypi.org/project/z4j-core/>

[Unreleased]: https://github.com/z4jdev/z4j-core/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/z4jdev/z4j-core/releases/tag/v1.0.0
