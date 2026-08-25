"""Shared exception vocabulary for z4j-core and its consumers.

Public boundaries use :class:`Z4JError` subclasses for conditions that
need stable machine-readable codes. Internal code and third-party
libraries can still raise ordinary Python exceptions. The brain maps
the shared exceptions it exposes to HTTP status codes.

See ``docs/patterns.md §4`` for error-handling conventions.
"""

from __future__ import annotations

from typing import Any


class Z4JError(Exception):
    """Base for z4j's shared, machine-readable exception types.

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


class RateLimitExceeded(Z4JError):  # noqa: N818  public exported API name, renaming breaks consumers
    """The caller exceeded a rate-limit bucket.

    The error ``details`` should carry ``retry_after_seconds``.
    """

    code = "rate_limited"
    http_status = 429


# ---------------------------------------------------------------------------
# Protocol / wire errors
# ---------------------------------------------------------------------------


class ProtocolError(Z4JError):
    """The agent and brain cannot continue with the received protocol data.

    This includes incompatible versions discovered during the ``hello``
    handshake and protocol-level failures reported after connection.
    """

    code = "protocol_incompatible"
    http_status = 426


class AgentIncompatibleError(ProtocolError):
    """This agent build is one the brain will not accept, and time will not fix it.

    A subclass of :class:`ProtocolError` so existing ``except ProtocolError``
    sites still catch it, but distinguishable so a supervisor can pick a
    schedule that matches the remedy. An unsupported wire protocol or an agent
    outside the brain's supported version range is resolved by a human
    upgrading something, not by reconnecting: retrying on the transient
    schedule turns a version mismatch into a permanent reconnect storm against
    a brain that has already said no.

    Deliberately NOT fatal. The agent runs inside somebody's application, so
    stopping it for good would mean an operator who fixes the brain gets no
    agent back until they restart their app. A long backoff both stops the
    storm and lets a corrected deployment recover on its own.
    """

    # No ``code`` of its own, on purpose: this inherits ProtocolError's
    # ``protocol_incompatible``.
    #
    # ``code`` is the published, stable identifier (see Z4JError above and
    # ``docs/API.md §1.Errors``), and what this class describes IS a protocol
    # incompatibility. The subclass exists so a supervisor can select a backoff
    # schedule by exception TYPE; it is not a second name for the condition.
    # Minting a fresh code here would change the string consumers branch on
    # while every ``except ProtocolError`` kept matching, so neither side would
    # notice the break -- which is exactly how it would reach users.
    #
    # A genuinely new condition may of course have a new code. Renaming an
    # existing one may not.


class ProtocolVersionError(ProtocolError):
    """A wire frame carries a DIFFERENT protocol version than this peer.

    A subclass of :class:`ProtocolError` (so existing ``except
    ProtocolError`` sites still catch it) that is distinguishable from a
    truly-malformed / unknown-frame ``ProtocolError``. The distinction
    matters for delivery bookkeeping: a version-skew frame is AUTHENTIC
    and RECOVERABLE -- the identical bytes parse fine against a peer built
    with the matching ``PROTOCOL_VERSION`` -- so during a rolling protocol
    upgrade it must be RETRIED (it will land on an already-upgraded
    replica), not dropped-and-acked as if permanently undeliverable.
    """

    code = "protocol_version_mismatch"


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
    """The target agent is revoked, unavailable, or has no delivery path.

    The brain maps this error to HTTP 503. Some issue paths persist a
    pending command before discovering that no registry worker can
    deliver it, so this exception does not imply that no command row
    was created.
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
    entries cannot be parsed. Startup entry points normally surface it
    as a configuration failure; library callers may catch it.
    """

    code = "config_error"
    http_status = 500


class RedactionConfigError(ConfigError):
    """A redaction pattern failed to compile or validate.

    Fail-closed: rather than skipping an invalid pattern and risking
    that secrets leak through, z4j refuses to start.
    """

    code = "redaction_config_error"


class BufferStorageError(ConfigError):
    """The on-disk SQLite buffer directory is not usable.

    Raised when the agent cannot create or write to the resolved
    buffer path AND every fallback location was also unwritable.
    The exception ``message`` should name the offending path, the
    process uid, and point operators at ``Z4J_HOME`` as the
    canonical override.

    The runtime catches this at startup and refuses to start rather
    than silently buffer events into memory and lose them on the next
    restart - data integrity over uptime.
    """

    code = "buffer_storage_error"


__all__ = [
    "AdapterError",
    "AgentIncompatibleError",
    "AgentOfflineError",
    "AuthenticationError",
    "AuthorizationError",
    "BufferStorageError",
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
