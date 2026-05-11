"""Cross-package observability primitives: logging formatters + contextvars.

This subpackage gives every z4j package (brain, scheduler, bare, all
adapters) a single stdlib-only set of building blocks for structured
output. The brain layers structlog on top for richer console output;
the agent and adapters use these directly because they are
library-shaped code that runs inside foreign host processes (Django,
Celery, FastAPI, etc.) where pulling structlog into the host's
dependency closure would be unfriendly.

What lives here:

- :func:`configure_stdlib_logging`: install a stdlib handler whose
  format honors ``Z4J_LOG_FORMAT`` (``text`` | ``json``).
- :class:`JsonFormatter`, :class:`TextFormatter`: the formatters
  themselves, useful in isolation when integrating into a host
  framework's existing logging setup.
- :mod:`z4j_core.observability.context`: contextvars carrying
  identity (agent_id, session_id, worker_id, project_id, request_id)
  into every log record automatically.
"""

from z4j_core.observability.context import (
    ContextFilter,
    agent_id_var,
    bind,
    bound,
    clear,
    install_context_filter,
    project_id_var,
    request_id_var,
    session_id_var,
    snapshot,
    worker_id_var,
)
from z4j_core.observability.logging import (
    JsonFormatter,
    TextFormatter,
    configure_stdlib_logging,
    resolve_log_format,
)

__all__ = [
    "ContextFilter",
    "JsonFormatter",
    "TextFormatter",
    "agent_id_var",
    "bind",
    "bound",
    "clear",
    "configure_stdlib_logging",
    "install_context_filter",
    "project_id_var",
    "request_id_var",
    "resolve_log_format",
    "session_id_var",
    "snapshot",
    "worker_id_var",
]
