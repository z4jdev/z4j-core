"""Exception hierarchy for z4j-core and its consumers.

Every exception raised by z4j - in the core, the brain, or any
adapter - inherits from :class:`Z4JError`. The error middleware in the
brain maps these to HTTP status codes; adapter code wraps lower-level
exceptions with these before they cross package boundaries.

See ``docs/patterns.md §4`` for error-handling conventions.
"""

from __future__ import annotations

from typing import Any


class Z4JError(Exception):
    """Base for every exception raised anywhere in z4j.

    Attributes:
        code: Short machine-readable error code, e.g. ``"not_found"``.
              Stable across releases. Do not break consumers that
              branch on it.
        http_status: The HTTP status code the brain returns when this
              exception reaches the top-level error handler.
        details: Optional dict with additional context. Included in
              structured JSON error responses under ``details``.
    """

    code: str = "z4j_error"
    http_status: int = 500

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details: dict[str, Any] = dict(details) if details else {}

    def __repr__(self) -> str:
        return f"{type(self).__name__}(code={self.code!r}, message={self.message!r})"

    def to_dict(self) -> dict[str, Any]:
        """Serialize to the standard error response shape.

        Matches the JSON shape documented in ``docs/API.md §1.Errors``.
        """
        return {
            "error": self.code,
            "message": self.message,
            "details": self.details,
        }


# ---------------------------------------------------------------------------
# Client-facing errors (4xx)
# ---------------------------------------------------------------------------


class ValidationError(Z4JError):
    """Input failed validation.

    Raised at the boundary when a request body, query parameter, or
    wire frame does not conform to its schema.
    """

    code = "validation_error"
    http_status = 422


class AuthenticationError(Z4JError):
    """The request lacked valid credentials."""

    code = "unauthenticated"
    http_status = 401


class AuthorizationError(Z4JError):
    """The caller is authenticated but not permitted to do this."""

    code = "forbidden"
    http_status = 403


class NotFoundError(Z4JError):
    """The requested resource does not exist."""

    code = "not_found"
    http_status = 404


class ConflictError(Z4JError):
    """The requested change conflicts with current state.

    Example: creating a project whose ``slug`` is already taken.
    """

    code = "conflict"
    http_status = 409


class RateLimitExceeded(Z4JError):
    """The caller exceeded a rate-limit bucket.

    The error ``details`` should carry ``retry_after_seconds``.
    """

    code = "rate_limited"
    http_status = 429


# ---------------------------------------------------------------------------
# Protocol / wire errors
# ---------------------------------------------------------------------------


class ProtocolError(Z4JError):
    """The agent and brain speak incompatible protocol versions.

    Raised during the ``hello`` handshake in the brain when the
    agent's advertised ``protocol_version`` is outside the supported
    range.
    """

    code = "protocol_incompatible"
    http_status = 426


class InvalidFrameError(Z4JError):
    """A wire frame could not be parsed or is structurally invalid.

    This is distinct from :class:`SignatureError` - a frame can be
    structurally valid but still have a bad HMAC.
    """

    code = "invalid_frame"
    http_status = 400


class SignatureError(Z4JError):
    """HMAC verification failed on an inbound frame.

    Raised by the agent when a command frame from the brain has a
    missing or incorrect HMAC signature, and by the brain when an
    inbound agent frame fails its own signature check (when present).
    """

    code = "invalid_signature"
    http_status = 401


# ---------------------------------------------------------------------------
# Adapter and runtime errors
# ---------------------------------------------------------------------------


class AdapterError(Z4JError):
    """An adapter failed to execute a request against its underlying engine.

    Example: ``CeleryEngineAdapter.retry_task`` was called but Celery
    refused to accept the new task.
    """

    code = "adapter_error"
    http_status = 500


class AgentOfflineError(Z4JError):
    """The target agent is not currently connected to the brain.

    Commands cannot be dispatched to offline agents. The brain returns
    503 with this error code.
    """

    code = "agent_offline"
    http_status = 503


class CommandTimeoutError(Z4JError):
    """A dispatched command did not receive a result within its timeout."""

    code = "command_timeout"
    http_status = 504


# ---------------------------------------------------------------------------
# Configuration errors
# ---------------------------------------------------------------------------


class ConfigError(Z4JError):
    """A configuration value is missing or invalid.

    Raised at startup when required environment variables or settings
    entries cannot be parsed. Causes the process to exit with a clear
    error message.
    """

    code = "config_error"
    http_status = 500


class RedactionConfigError(ConfigError):
    """A redaction pattern failed to compile or validate.

    Fail-closed: rather than skipping an invalid pattern and risking
    that secrets leak through, z4j refuses to start.
    """

    code = "redaction_config_error"


__all__ = [
    "AdapterError",
    "AgentOfflineError",
    "AuthenticationError",
    "AuthorizationError",
    "CommandTimeoutError",
    "ConfigError",
    "ConflictError",
    "InvalidFrameError",
    "NotFoundError",
    "ProtocolError",
    "RateLimitExceeded",
    "RedactionConfigError",
    "SignatureError",
    "ValidationError",
    "Z4JError",
]
