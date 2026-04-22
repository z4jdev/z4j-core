"""Agent-side configuration and context models.

These types are read by the agent from the host framework at startup
and passed through to the engine and scheduler adapters. They deliberately
carry *no* framework-specific data - only the small, common shape every
framework adapter exposes to the agent core.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import AnyHttpUrl, Field, SecretStr

from z4j_core.models._base import Z4JModel


class Config(Z4JModel):
    """Resolved agent configuration.

    Built by the :class:`z4j_core.protocols.FrameworkAdapter.discover_config`
    method from a combination of environment variables, the framework's
    own settings mechanism, and sensible defaults. The agent core
    validates this once at startup and then the runtime is immutable.

    Attributes:
        brain_url: HTTPS URL of the brain the agent should connect to.
        token: Project-scoped bearer token, kept as a ``SecretStr`` so
               it never ends up in logs or tracebacks.
        project_id: Project slug the token is scoped to.
        environment: Free-form environment label attached to every event.
        tags: Per-deployment tags echoed on every event.
        transport: ``"auto"``, ``"ws"``, or ``"longpoll"``.
        engines: Names of the engine adapters the runtime should register.
        schedulers: Names of the scheduler adapters to register.
        heartbeat_seconds: How often the agent sends a heartbeat.
        buffer_path: On-disk SQLite buffer path.
        buffer_max_events: Upper bound on buffered events.
        buffer_max_bytes: Upper bound on buffer file size in bytes.
        max_payload_bytes: Per-field truncation limit.
        dev_mode: Enables the filesystem watcher and other dev-only hooks.
        log_level: Local agent log level.
        autostart: If False, the runtime is created but not started -
                   useful for test environments.
        strict_mode: If True, startup fails fast on any config problem.
                     Default False so the agent never crashes the host
                     app in production.
        redaction_extra_key_patterns: Additional key-name regex patterns.
        redaction_extra_value_patterns: Additional value regex patterns.
        redaction_defaults_enabled: If False, the built-in patterns are
                                    skipped. Intentional footgun - only
                                    set this if you know what you are doing.
        hmac_secret: Shared secret used to verify command signatures from
                     the brain. Required when ``dev_mode`` is False - the
                     runtime refuses to start without it. Kept as a
                     ``SecretStr`` so it never lands in logs.
    """

    brain_url: AnyHttpUrl
    token: SecretStr
    project_id: str = Field(min_length=1, max_length=63)
    #: Optional. Required ONLY when ``transport == "longpoll"``: the
    #: long-poll path has no handshake frame, so the agent has to
    #: advertise its own UUID up-front. WebSocket sessions discover
    #: the agent_id in ``hello_ack`` and never need this field.
    agent_id: str = Field(default="", max_length=64)
    hmac_secret: SecretStr | None = None
    environment: str = Field(default="production", max_length=40)
    tags: dict[str, str] = Field(default_factory=dict)
    transport: str = Field(default="auto", pattern=r"^(auto|ws|longpoll)$")
    engines: list[str] = Field(default_factory=list)
    schedulers: list[str] = Field(default_factory=list)
    heartbeat_seconds: int = Field(default=10, ge=1, le=300)
    buffer_path: Path = Field(default=Path.home() / ".z4j" / "buffer.sqlite")
    buffer_max_events: int = Field(default=100_000, ge=1000)
    buffer_max_bytes: int = Field(default=256 * 1024 * 1024, ge=1024 * 1024)
    max_payload_bytes: int = Field(default=8192, ge=128)
    dev_mode: bool = False
    log_level: str = Field(default="INFO", pattern=r"^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$")
    autostart: bool = True
    strict_mode: bool = False
    redaction_extra_key_patterns: list[str] = Field(default_factory=list)
    redaction_extra_value_patterns: list[str] = Field(default_factory=list)
    redaction_defaults_enabled: bool = True


class DiscoveryHints(Z4JModel):
    """Framework-specific hints to help engine adapters discover tasks.

    Returned by :class:`z4j_core.protocols.FrameworkAdapter.discovery_hints`.
    The engine adapter is free to use these - or ignore them - depending
    on its own discovery strategy.

    Attributes:
        app_paths: Filesystem paths the engine adapter may walk to find
                   ``tasks.py`` files (for Django, these are the
                   ``INSTALLED_APPS`` directories; for others, empty).
        app_names: Importable Python package names the adapter may
                   attempt to import to force discovery.
        framework_name: Name of the framework the hints came from
                        (``django``, ``flask``, ``fastapi``, ``bare``).
    """

    app_paths: list[Path] = Field(default_factory=list)
    app_names: list[str] = Field(default_factory=list)
    framework_name: str = Field(default="bare", max_length=40)


class RequestContext(Z4JModel):
    """Per-request context enrichment data.

    When the host framework is serving a request and the request
    handler triggers a task, the framework adapter can provide this
    context so the enqueued event carries user / tenant / trace info.
    All fields are optional - the adapter returns None if the current
    execution context is not a request (e.g. inside a Celery worker).

    Attributes:
        user_id: ID of the authenticated user who initiated the task.
        tenant_id: ID of the tenant or organization, for multi-tenant apps.
        request_id: The framework's request ID (used to correlate logs).
        trace_id: Distributed tracing ID (OpenTelemetry / W3C traceparent).
        extra: Free-form additional context. Must be JSON-serializable.
    """

    user_id: UUID | str | None = None
    tenant_id: UUID | str | None = None
    request_id: str | None = Field(default=None, max_length=100)
    trace_id: str | None = Field(default=None, max_length=100)
    extra: dict[str, Any] = Field(default_factory=dict)


__all__ = ["Config", "DiscoveryHints", "RequestContext"]
