"""Contextvars carrying identity into log records automatically.

When an event is logged from inside the agent's runtime, the log
line should carry the session id, agent id, worker id, and
project id without every call site having to remember to pass
them. ``contextvars.ContextVar`` is the stdlib mechanism for
this; it propagates correctly across both threads (because each
thread has its own context) and async tasks (because asyncio
copies the context for each task at create-time).

Two pieces:

- The ContextVar declarations themselves, plus :func:`bind` /
  :func:`clear` helpers callers use at lifecycle boundaries
  (post-handshake, on disconnect, on request enter / leave).
- :class:`ContextFilter`: a stdlib logging Filter that copies
  the live contextvars onto the LogRecord just before it is
  formatted. The :class:`JsonFormatter` then includes them in
  the emitted record automatically.

Why a Filter rather than something done by the formatter
directly: filters run on the originating thread/task before
the record is queued for handlers, so they capture the binding
that was live at the moment the log call happened, not the
binding live when a background handler later flushes the buffer.
"""

from __future__ import annotations

import contextvars
import logging
from contextlib import contextmanager
from typing import Iterator

__all__ = [
    "ContextFilter",
    "agent_id_var",
    "bind",
    "clear",
    "install_context_filter",
    "project_id_var",
    "request_id_var",
    "session_id_var",
    "snapshot",
    "worker_id_var",
]


# ContextVars are scoped per task / thread so sibling agent connections
# (rare) and sibling HTTP requests (common in the brain) get isolated
# values without anyone passing context explicitly.
agent_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "z4j_agent_id", default=None,
)
session_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "z4j_session_id", default=None,
)
worker_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "z4j_worker_id", default=None,
)
project_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "z4j_project_id", default=None,
)
request_id_var: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "z4j_request_id", default=None,
)


_VAR_TO_RECORD_FIELD: dict[contextvars.ContextVar[str | None], str] = {
    agent_id_var: "agent_id",
    session_id_var: "session_id",
    worker_id_var: "worker_id",
    project_id_var: "project_id",
    request_id_var: "request_id",
}


# Maximum length of any single context-bound identifier. Mirrors the
# constraint on ``RequestIdMiddleware._normalize`` and the
# ``max_length=64`` field constraints on every id-shaped field in
# ``HelloAckPayload``. A longer value is silently truncated to keep
# the binding from failing closed (logs are observability data, not
# load-bearing) while still bounding the field size in JSON output.
_MAX_ID_LEN = 64


def _sanitize_id(value: str | None) -> str | None:
    """Reject control characters and trim length on a context id value.

    Phase G binds identity values that originated from the brain's
    ``hello_ack`` payload. The brain validates ``HelloAckPayload``
    fields with ``max_length=64`` but does NOT reject embedded
    newlines or other control characters. A malicious or compromised
    brain could emit ``agent_id="alice\\nFAKE log line"`` which would
    then split one log entry into two in the agent's text-format
    output. Filter at the bind site so log injection is impossible
    regardless of upstream validation.

    Returns the sanitized value, or ``None`` if the input was
    ``None``. Values containing control characters are rejected
    (returned as ``None``) rather than munged, so a logged "missing
    agent_id" is more debuggable than a logged-but-corrupted value.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        return None
    if len(value) > _MAX_ID_LEN:
        value = value[:_MAX_ID_LEN]
    # Reject if any control character is present (anything below
    # 0x20 except printable ASCII, plus DEL 0x7F). Newline and tab
    # are both rejected; an id that legitimately contains them is
    # not an id.
    for ch in value:
        if ord(ch) < 0x20 or ord(ch) == 0x7F:
            return None
    return value


def bind(
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    worker_id: str | None = None,
    project_id: str | None = None,
    request_id: str | None = None,
) -> dict[contextvars.ContextVar[str | None], contextvars.Token[str | None]]:
    """Set the named contextvars and return tokens for restoration.

    Caller is responsible for calling :func:`clear` with the returned
    tokens (or using :func:`bound`, the context-manager wrapper) to
    restore the previous values when the scope ends. Without
    cleanup, a long-lived task could leak a session_id into
    sibling tasks that share the same context branch.

    Values are sanitized via :func:`_sanitize_id` before binding;
    any value containing control characters is silently dropped to
    block log-injection attacks via brain-supplied identifiers.
    """
    tokens: dict[contextvars.ContextVar[str | None], contextvars.Token[str | None]] = {}
    safe_agent_id = _sanitize_id(agent_id)
    safe_session_id = _sanitize_id(session_id)
    safe_worker_id = _sanitize_id(worker_id)
    safe_project_id = _sanitize_id(project_id)
    safe_request_id = _sanitize_id(request_id)
    if safe_agent_id is not None:
        tokens[agent_id_var] = agent_id_var.set(safe_agent_id)
    if safe_session_id is not None:
        tokens[session_id_var] = session_id_var.set(safe_session_id)
    if safe_worker_id is not None:
        tokens[worker_id_var] = worker_id_var.set(safe_worker_id)
    if safe_project_id is not None:
        tokens[project_id_var] = project_id_var.set(safe_project_id)
    if safe_request_id is not None:
        tokens[request_id_var] = request_id_var.set(safe_request_id)
    return tokens


def clear(
    tokens: dict[contextvars.ContextVar[str | None], contextvars.Token[str | None]],
) -> None:
    """Restore the previous values for vars set via :func:`bind`."""
    for var, token in tokens.items():
        var.reset(token)


@contextmanager
def bound(
    *,
    agent_id: str | None = None,
    session_id: str | None = None,
    worker_id: str | None = None,
    project_id: str | None = None,
    request_id: str | None = None,
) -> Iterator[None]:
    """Context manager wrapper around :func:`bind` / :func:`clear`.

    Preferred over manual bind/clear because it survives exceptions:
    the ``finally`` clause guarantees restoration even when the
    wrapped block raises. The raw bind/clear functions exist for
    the rare callers that span coroutine boundaries (the agent's
    long-lived WebSocket session, where bind is in connect() and
    clear is in close()) where a context manager doesn't fit.
    """
    tokens = bind(
        agent_id=agent_id,
        session_id=session_id,
        worker_id=worker_id,
        project_id=project_id,
        request_id=request_id,
    )
    try:
        yield
    finally:
        clear(tokens)


def snapshot() -> dict[str, str]:
    """Return the currently-bound context vars as a plain dict.

    Filters out vars whose value is ``None`` (unset). Used by the
    logging filter to merge identity into log records.
    """
    out: dict[str, str] = {}
    for var, field in _VAR_TO_RECORD_FIELD.items():
        value = var.get()
        if value is not None:
            out[field] = value
    return out


class ContextFilter(logging.Filter):
    """Logging Filter that merges live contextvars onto each LogRecord.

    Installed via :func:`install_context_filter`. The
    :class:`z4j_core.observability.JsonFormatter` then includes any
    non-reserved attribute on the record in its output, so a log
    line emitted from inside a session automatically gains
    ``agent_id``, ``session_id``, etc. Records emitted outside a
    bound context don't gain these fields and don't break.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        for field, value in snapshot().items():
            # Don't clobber an explicit extra= passed by the caller;
            # explicit data wins over ambient context.
            if not hasattr(record, field):
                setattr(record, field, value)
        return True


def install_context_filter(
    logger: logging.Logger | str | None = None,
) -> ContextFilter:
    """Attach the :class:`ContextFilter` to a logger.

    Without this filter the ContextVars are bound but log records
    don't see them. Idempotent: a second call detects the existing
    filter and returns it rather than stacking duplicates.

    Args:
        logger: a :class:`logging.Logger` instance, a logger name,
            or None for the root logger. Defaults to the root logger
            so every z4j namespace inherits the filter.

    Returns:
        The installed filter, useful if the caller wants to remove
        it later.
    """
    if isinstance(logger, str):
        target = logging.getLogger(logger)
    elif logger is None:
        target = logging.getLogger()
    else:
        target = logger
    for existing in target.filters:
        if isinstance(existing, ContextFilter):
            return existing
    flt = ContextFilter()
    target.addFilter(flt)
    return flt
