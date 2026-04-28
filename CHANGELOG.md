# Changelog

All notable changes to `z4j-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.1.0] - 2026-04-28

> Coordinated ecosystem release alongside `z4j-brain` 1.1.0,
> `z4j-scheduler` 1.1.0, and the `z4j` umbrella 1.1.0. v1.1.x is the
> ecosystem's always-works baseline - see `docs/MIGRATIONS.md` in the
> z4j repo for the additive-only compatibility contract.

### Security (round-9 audit, wire protocol)

- **Cross-session replay attack closed.** Pre-fix the wire
  protocol's HMAC envelope did not include the connection's
  `session_id`. Combined with the agent's per-session reset of
  `seq + nonce` counters, this meant an attacker who recorded a
  signed envelope from session A could replay it into session B
  (both sessions had independent counter spaces starting at the
  same low values, so the replay-guard's `seq` check passed).
  Fix in `transport/framing.py`: signer and verifier now bind the
  `session_id` into the signed payload. Verifier rejects the
  frame if the embedded session_id doesn't match the connection
  context. Wired in both the WebSocket and long-poll codepaths
  (brain side + agent side both get the protection).
- **`canonical_json` now refuses `NaN`/`Infinity`.** Pre-fix
  `json.dumps(allow_nan=True)` would accept these values on the
  signer side, but Python's `json.loads` accepts them
  asymmetrically - and `int`/`float` round-tripping produced
  divergent canonical forms across versions. The asymmetric
  acceptance was a working footgun for verification mismatches.
  Now `allow_nan=False` everywhere; non-finite floats raise at
  the signer boundary so the operator sees a clear error.

### Added

- **`Schedule` model gains `catch_up`, `source`, `source_hash`** to
  match the brain's SQLAlchemy schema. Without these, every external
  SDK consumer that called `GET /api/schedules` against a brain on
  the new schema would have failed Pydantic validation on a perfectly
  normal response (the model uses `extra="forbid"`). All three fields
  ship with defaults (`CatchUpPolicy.SKIP`, `"dashboard"`, `None`) so
  callers building a `Schedule` from scratch don't need to pass them.
- **`CatchUpPolicy` StrEnum** (`skip` / `fire_one_missed` /
  `fire_all_missed`) for type-safe access to the new field. Exported
  from `z4j_core.models`. Pinned by
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
