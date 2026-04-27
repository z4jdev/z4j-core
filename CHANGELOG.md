# Changelog

All notable changes to `z4j-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.6] - 2026-04-27

> Coordinated companion publish to `z4j-brain` 1.0.19 and the `z4j`
> umbrella 1.0.19 — the last fully-stable v1.0.x patch wave before
> the v1.1.0 ecosystem baseline. Pure additive: any caller built
> against `z4j-core` 1.0.4 keeps working unchanged.
>
> **Why 1.0.6 and not 1.0.5:** an earlier 1.0.5 was published to
> PyPI as a version-only bump that did NOT include the Schedule
> field additions described below. PyPI is immutable, so the actual
> additions ship as 1.0.6. Anyone targeting "the version that
> understands `catch_up` / `source` / `source_hash`" should pin
> `z4j-core>=1.0.6,<1.1`.

## [1.0.5] - 2026-04-27 (yanked / no functional changes)

> Published to PyPI as a version-only bump without the Schedule
> field additions. **Do not depend on this version.** Use 1.0.6 or
> later. Yanked from PyPI.

### Added

- **`Schedule` model gains `catch_up`, `source`, `source_hash`** to
  match the brain's SQLAlchemy schema and REST `SchedulePublic`
  payload. Without these, an external SDK consumer calling
  `GET /api/v1/projects/{slug}/schedules` against a brain that
  populates the new columns would have failed Pydantic validation
  (the `Schedule` model uses `extra="forbid"` so unknown fields
  raise). All three fields ship with defaults
  (`CatchUpPolicy.SKIP`, `"dashboard"`, `None`) so callers building
  a `Schedule` from scratch don't need to pass them.
- **`CatchUpPolicy` StrEnum** (`skip` / `fire_one_missed` /
  `fire_all_missed`) for type-safe access to the new field.
  Exported from `z4j_core.models`. Pinned by
  `tests/unit/test_models.py::TestSchedule`.

## [1.0.4] - 2026-04-24

### Added

- **`BufferStorageError` exception** in `z4j_core.errors` (subclass of `ConfigError`). Raised by the agent when the on-disk SQLite buffer directory is unwritable AND every fallback location was also unusable. Operators see a clean diagnostic line with the offending path, the running uid, and the canonical `Z4J_BUFFER_PATH` override - instead of a raw `PermissionError` traceback buried in worker logs. Required for the buffer-path fallback in z4j-bare 1.0.6.

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
