"""Stdlib-only logging formatters honoring ``Z4J_LOG_FORMAT``.

The agent runtime (z4j-bare) and adapter packages (z4j-celery,
z4j-django, etc.) live inside foreign host processes. They cannot
pull a heavy logging dependency (structlog, loguru) into the host's
dep closure without being a bad citizen. So the agent side gets a
small stdlib-only formatter that produces the same JSON shape the
brain emits via structlog, so SIEM pipelines see one consistent
schema regardless of which side a log line came from.

Two formats:

- ``text``: default. One human-readable line per record, suitable
  for tailing in a terminal. Matches the pre-1.5 agent output
  modulo the namespace tree introduced in Phase E.
- ``json``: one JSON object per line. Field set is stable and
  documented in ``docs/logging-output.md``. Set
  ``Z4J_LOG_FORMAT=json`` to opt in.

The brain has its own structlog-based config (richer console
output, processor pipeline) and accepts ``Z4J_LOG_FORMAT`` as an
alias for ``Z4J_LOG_JSON=true``. The agent always uses these
formatters directly.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime
from typing import Literal

__all__ = [
    "JsonFormatter",
    "TextFormatter",
    "configure_stdlib_logging",
    "resolve_log_format",
]


LogFormat = Literal["text", "json"]


# Standard LogRecord attribute names. Anything not in this set that
# appears on the record is treated as caller-supplied "extra" and
# included in JSON output. The list comes from CPython's
# logging.Logger.makeRecord docstring; we copy it verbatim because
# the upstream attribute is not exported.
_RESERVED_RECORD_FIELDS = frozenset({
    "args", "asctime", "created", "exc_info", "exc_text", "filename",
    "funcName", "levelname", "levelno", "lineno", "message", "module",
    "msecs", "msg", "name", "pathname", "process", "processName",
    "relativeCreated", "stack_info", "taskName", "thread", "threadName",
})


# Substrings in field names that mark caller-supplied ``extra=`` values
# as secret-bearing. The brain's structlog config has a ``_drop_secrets``
# processor with the same intent; this constant is the stdlib-only
# equivalent installed in :class:`JsonFormatter`. Substring (not
# whole-word) matching catches camelCase + snake_case + prefixed
# variants like ``hmac_secret``, ``auth_token``, ``user_password``.
# The list is deliberately conservative; false positives mean a
# log field gets masked, false negatives mean a secret leaks.
_SECRET_NAME_SUBSTRINGS = (
    "secret",
    "password",
    "token",
    "api_key",
    "private_key",
    "passphrase",
    "credential",
    "authorization",
    "cookie",
)


def _looks_secret(name: str) -> bool:
    """Return True if a log-record extra field name suggests a secret value."""
    lname = name.lower()
    # Specifically allow names that contain the substring as part of
    # an unrelated word (e.g. ``token_count``, ``credential_count``).
    # The pattern is "field name has the substring AND is not an
    # obvious counter/flag/timestamp."
    if lname.endswith(("_count", "_total", "_ttl", "_seconds", "_at")):
        return False
    return any(pat in lname for pat in _SECRET_NAME_SUBSTRINGS)


def resolve_log_format(env: dict[str, str] | None = None) -> LogFormat:
    """Read ``Z4J_LOG_FORMAT`` and validate.

    Returns ``"text"`` (default) or ``"json"``. Anything else logs
    a warning and falls back to ``"text"`` rather than failing - we
    don't want a typo in an env var to crash startup before logging
    is even configured.
    """
    if env is None:
        env = dict(os.environ)
    raw = (env.get("Z4J_LOG_FORMAT") or "text").strip().lower()
    if raw in ("text", "json"):
        return raw  # type: ignore[return-value]
    sys.stderr.write(
        f"z4j: unknown Z4J_LOG_FORMAT={raw!r}, falling back to 'text'. "
        f"Valid values: text, json.\n",
    )
    return "text"


class JsonFormatter(logging.Formatter):
    """Render each LogRecord as one JSON object on a single line.

    Field set:
        ts:      ISO-8601 UTC timestamp with millisecond precision
        level:   stdlib level name in lowercase ("info", "warning", ...)
        logger:  logger name (the Z4J namespace tree from Phase E)
        msg:     fully-formatted message
        exc:     stringified exception traceback if exc_info present
        process: OS PID (useful when several agent processes share a
                 log stream)
        thread:  thread name (useful for tracing async tasks)
        + any extra=... fields the caller passed
        + any contextvars Phase G has bound (agent_id, session_id, ...)

    Output is always valid JSON-per-line (newline-delimited JSON,
    NDJSON). Embedded newlines in messages are preserved as JSON
    escapes (``\\n``) so a downstream parser stays line-oriented.
    """

    def format(self, record: logging.LogRecord) -> str:
        ts = (
            datetime.fromtimestamp(record.created, tz=UTC)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        payload: dict[str, object] = {
            "ts": ts,
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack"] = record.stack_info
        if record.process is not None:
            payload["process"] = record.process
        if record.threadName and record.threadName != "MainThread":
            payload["thread"] = record.threadName
        # Caller-supplied extras (logger.info("x", extra={"k": "v"}))
        # land as attributes on the record. Anything not in the
        # stdlib reserved set is included. Field names matching the
        # secret deny-list are masked; the brain's structlog has the
        # same defense via _drop_secrets.
        for key, value in record.__dict__.items():
            if key in _RESERVED_RECORD_FIELDS:
                continue
            if key.startswith("_"):
                continue
            if _looks_secret(key):
                payload[key] = "***"
            else:
                payload[key] = _coerce_jsonable(value)
        try:
            # Ensure_ascii=True: U+2028 / U+2029 line
            # separators escape to \\u2028 / \\u2029. Otherwise some
            # NDJSON parsers (older Logstash, certain Filebeat
            # configs) treat the literal characters as record
            # boundaries and split one log entry into two.
            return json.dumps(
                payload, default=_coerce_jsonable, ensure_ascii=True,
            )
        except (TypeError, ValueError):
            # Last resort: if a custom field defied coercion, drop it
            # rather than swallow the log line. Stdlib logging treats
            # a formatter exception as fatal to the handler.
            for key in list(payload):
                if key not in ("ts", "level", "logger", "msg"):
                    payload.pop(key, None)
            return json.dumps(payload, default=str, ensure_ascii=True)


class TextFormatter(logging.Formatter):
    """Compact human-readable single-line text format.

    Layout: ``<iso-ts> <LEVEL> <logger> <message>``. Identical to
    the pre-1.5 default except the level is left-padded to a fixed
    width so columns align in a terminal.
    """

    def __init__(self, *, datefmt: str | None = None) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-7s %(name)s %(message)s",
            datefmt=datefmt or "%Y-%m-%dT%H:%M:%S",
        )


def configure_stdlib_logging(
    *,
    level: str = "INFO",
    log_format: LogFormat | None = None,
    stream: object = None,
) -> None:
    """Install a stdlib root handler honoring ``Z4J_LOG_FORMAT``.

    Idempotent: a second call replaces the previous handler. Used
    by the agent CLI; the brain has its own structlog-based setup
    in :mod:`z4j_brain.logging_config`.

    Args:
        level: stdlib level name (``DEBUG``, ``INFO``, ...).
        log_format: ``text`` | ``json``. If None (the default),
            resolved from ``Z4J_LOG_FORMAT`` via
            :func:`resolve_log_format`.
        stream: file-like object the handler writes to. Defaults to
            ``sys.stderr`` to match stdlib's ``logging.basicConfig``
            and to avoid stepping on stdout streams a host process
            may use for protocol output (e.g. a Celery worker that
            pipes results to its parent).
    """
    if log_format is None:
        log_format = resolve_log_format()
    if stream is None:
        stream = sys.stderr

    formatter: logging.Formatter
    if log_format == "json":
        formatter = JsonFormatter()
    else:
        formatter = TextFormatter()

    handler = logging.StreamHandler(stream)
    handler.setFormatter(formatter)

    root = logging.getLogger()
    # Replace any prior z4j handler we installed but leave others
    # alone (the host app may have its own handlers we don't own).
    root.handlers = [
        h for h in root.handlers
        if not getattr(h, "_z4j_managed", False)
    ]
    handler._z4j_managed = True  # type: ignore[attr-defined]
    root.addHandler(handler)
    root.setLevel(level)
    logging.getLogger("z4j").setLevel(level)

    # Install the context filter on the root so contextvars (agent_id,
    # session_id, worker_id, project_id, request_id) propagate into
    # every log record via Phase G's binding helpers.
    from z4j_core.observability.context import install_context_filter
    install_context_filter()


def _coerce_jsonable(value: object) -> object:
    """Best-effort coerce a value into something json.dumps accepts."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [_coerce_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _coerce_jsonable(v) for k, v in value.items()}
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)
