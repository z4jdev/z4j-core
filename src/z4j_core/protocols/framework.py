"""The :class:`FrameworkAdapter` Protocol.

One implementation per host web framework. v1 ships ``z4j-django``
(the primary target) and the ``bare`` adapter that lives in
``z4j-bare``. v1.1 adds ``z4j-flask`` and ``z4j-fastapi``.

A framework adapter's job is narrow:

1. Read agent configuration from the framework's native settings
2. Provide task-discovery hints (which paths to scan, which package
   names to try importing)
3. Expose the current request context if there is one
4. Hook the agent's lifecycle into the framework's startup/shutdown
5. Optionally register an admin-UI embed (Django only in v1)

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

        Implementations should combine:

        1. Environment variables (highest priority)
        2. The framework's native settings mechanism (``settings.Z4J``
           for Django, ``app.config["Z4J"]`` for Flask, the
           ``install_agent`` kwargs for FastAPI)
        3. Sensible defaults (lowest priority)

        Startup should fail fast on any missing required value - see
        :class:`z4j_core.errors.ConfigError`. The agent core's strict
        mode determines whether the failure is fatal to the host app.
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

        Called by the agent core when capturing an event, so the event
        can be enriched with user/tenant/trace IDs. Returns None when
        the current execution context is not a request (e.g. inside a
        Celery worker, or at module import time).

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

        The agent core uses this to start its background threads
        and open the transport. Implementations must run the hook
        after the framework's own initialization has completed.
        """
        ...

    def on_shutdown(self, hook: Callable[[], None]) -> None:
        """Register a callback to be invoked on framework shutdown.

        The agent core uses this to flush the buffer and close the
        transport. Implementations must run the hook before the
        framework's workers stop accepting new work.
        """
        ...

    # ------------------------------------------------------------------
    # Optional admin UI embed
    # ------------------------------------------------------------------

    def register_admin_view(self, view: Any) -> None:
        """Mount a read-only z4j panel inside the framework's admin UI.

        Implemented only for Django in v1 (as an optional embed at
        ``/admin/z4j/``). Other adapters should provide a no-op.
        """
        ...


__all__ = ["FrameworkAdapter"]
