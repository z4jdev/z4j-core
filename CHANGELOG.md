# Changelog

All notable changes to `z4j-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.3] - 2026-04-24

### Changed

- **`Config.buffer_path` default is now per-process.** Was `~/.z4j/buffer.sqlite` (one shared file across every agent runtime in the same user). Now `~/.z4j/buffer-{pid}.sqlite` (one file per Python process). Fixes a real drift bug where two agent runtimes (e.g. Django web + Celery worker) sharing one file kept their own in-memory cached counters that drifted out of sync, producing the `cached counters drifted negative` WARNING in the worker log. SQLite WAL handled the concurrent writes correctly; only the per-process count cache was wrong. Per-process paths make the bug structurally impossible.
- The PID is captured at `Config()` instantiation time (via `Field(default_factory=...)`), not at module import. Multiple `Config()` calls in the same process resolve to the same path.

### Migration notes

If you have an existing `~/.z4j/buffer.sqlite` with un-drained events from a pre-1.0.3 install, those events stay where they are - the new default points at a different file. To recover the legacy buffer, either set `Z4J_BUFFER_PATH=~/.z4j/buffer.sqlite` for ONE process and let it drain, OR delete `~/.z4j/buffer.sqlite` if you don't care about the queued events (in practice the buffer empties within seconds whenever the brain is reachable; long-queued events are unusual).

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
