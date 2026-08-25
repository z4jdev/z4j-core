"""The :class:`FrameworkAdapter` Protocol.

One implementation per host web framework. The distribution includes
``z4j-django``, ``z4j-flask``, ``z4j-fastapi``, and the framework-free
adapter in ``z4j-bare``.

A framework adapter's job is narrow:

1. Read agent configuration from the framework's native settings
2. Provide task-discovery hints (which paths to scan, which package
   names to try importing)
3. Expose the current request context if there is one
4. Hook the agent's lifecycle into the framework's startup/shutdown
5. Provide an optional extension point for an embedded admin view

Framework adapters do NOT know about queue engines. They do NOT know
about schedulers. They only know about the host framework.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable

from z4j_core.models import Config, DiscoveryHints, RequestContext, User


@runtime_checkable
class FrameworkAdapter(Protocol):
    """Adapter contract for the host web framework.

    Implementations are plain Python classes that satisfy this
    Protocol structurally - no inheritance required.
    """

    name: str
    """The framework identifier, e.g. ``"django"``, ``"flask"``,
    ``"fastapi"``, ``"bare"``. Matches the package suffix."""

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def discover_config(self) -> Config:
        """Build the agent configuration from the framework's settings.

        Implementations expose their framework-native source to the unified
        resolver, whose precedence is:

        1. Explicit installer arguments (highest priority)
        2. Environment variables
        3. Framework settings (``settings.Z4J`` for Django or
           ``app.config["Z4J"]`` for Flask)
        4. Defaults (lowest priority)

        Missing required values raise :class:`z4j_core.errors.ConfigError`.
        ``strict_mode`` is retained for configuration compatibility; the
        current resolver does not use it to make validation errors non-fatal.
        """
        ...

    def discovery_hints(self) -> DiscoveryHints:
        """Return framework-specific hints for task discovery.

        For Django this typically includes ``INSTALLED_APPS`` paths
        and names so engine adapters can find ``tasks.py`` files.
        For bare or other frameworks with no app registry, return
        empty hints - the engine adapter will fall back to its own
        strategy.
        """
        ...

    # ------------------------------------------------------------------
    # Context enrichment
    # ------------------------------------------------------------------

    def current_context(self) -> RequestContext | None:
        """Return the current request context, if any.

        Available to framework integrations that enrich an event with
        user/tenant/trace IDs. The bare agent runtime does not inject this
        context automatically. Returns None when the current execution context
        is not a request (e.g. inside a worker or at module import time).

        Implementations must never raise - return None on any error.
        """
        ...

    def current_user(self) -> User | None:
        """Return the currently authenticated user, if any.

        Used when a command is initiated from inside the framework
        itself (rare - most commands come from the dashboard). May
        return None for anonymous requests, background tasks, or
        non-request contexts.
        """
        ...

    # ------------------------------------------------------------------
    # Lifecycle hooks
    # ------------------------------------------------------------------

    def on_startup(self, hook: Callable[[], None]) -> None:
        """Register a callback to be invoked on framework startup.

        Framework integrations use this to start the agent after their own
        initialization has completed.
        """
        ...

    def on_shutdown(self, hook: Callable[[], None]) -> None:
        """Register a callback to be invoked on framework shutdown.

        Framework integrations use this to stop the agent before their workers
        finish shutting down.
        """
        ...

    # ------------------------------------------------------------------
    # Optional admin UI embed
    # ------------------------------------------------------------------

    def register_admin_view(self, view: Any) -> None:
        """Mount a read-only z4j panel inside the framework's admin UI.

        Optional extension point. Adapters without an embedded admin panel,
        including the current built-in adapters, provide a no-op.
        """
        ...


__all__ = ["FrameworkAdapter"]
