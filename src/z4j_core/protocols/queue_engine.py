"""The :class:`QueueEngineAdapter` Protocol.

One implementation per queue engine. v1 ships ``z4j-celery``; v2 adds
``z4j-rq`` and ``z4j-dramatiq``; v3 adds ``z4j-taskiq``, ``z4j-arq``,
``z4j-huey``, ``z4j-saq``, and ``z4j-procrastinate``.

An adapter is a plain Python class that satisfies this Protocol via
structural typing - no inheritance, no ABC. See
``docs/patterns.md §2``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, Protocol, runtime_checkable

from z4j_core.models import (
    CommandResult,
    DiscoveryHints,
    Event,
    Queue,
    Task,
    TaskDefinition,
    TaskRegistryDelta,
    Worker,
)


@runtime_checkable
class QueueEngineAdapter(Protocol):
    """Adapter contract for a single task queue engine.

    An implementation must:

    1. Advertise its engine ``name`` (``"celery"``, ``"rq"``, ...).
    2. Advertise the protocol version it was built against.
    3. Discover tasks known to the engine.
    4. Stream lifecycle events.
    5. Execute the actions the brain can dispatch.
    6. Honestly report its :meth:`capabilities`.

    Any adapter method that may raise should raise a subclass of
    :class:`z4j_core.errors.Z4JError` - never let an engine-specific
    exception leak out of the adapter boundary.
    """

    name: str
    """The engine identifier, e.g. ``"celery"``. Matches the package
    suffix (``z4j-celery`` -> ``"celery"``)."""

    protocol_version: str
    """Wire-protocol version the adapter was built against. Matches
    :data:`z4j_core.version.PROTOCOL_VERSION` at build time."""

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    async def discover_tasks(
        self,
        hints: DiscoveryHints | None = None,
    ) -> list[TaskDefinition]:
        """Return every task the engine currently knows about.

        Called on agent startup (Layer 1 cold-start scan) and on
        every reconciliation tick (Layer 3). May use framework-supplied
        hints to help locate ``tasks.py`` files.

        The return value is the authoritative list at call time -
        the brain will diff it against the previous snapshot to
        compute deltas.
        """
        ...

    async def subscribe_registry_changes(
        self,
    ) -> AsyncIterator[TaskRegistryDelta]:
        """Stream task-registry changes as they happen.

        Implementations that can watch for changes (signal hooks,
        filesystem watchers, etc.) should yield deltas here. Adapters
        without a watch story return an empty async iterator.
        """
        ...

    # ------------------------------------------------------------------
    # Observation
    # ------------------------------------------------------------------

    async def subscribe_events(self) -> AsyncIterator[Event]:
        """Stream lifecycle events from the engine.

        The agent core drives this iterator in a background task,
        redacts each event, and forwards it to the brain. The adapter
        is responsible for mapping engine-native events onto the
        :class:`z4j_core.models.Event` shape.
        """
        ...

    async def list_queues(self) -> list[Queue]:
        """Return the queues the engine is currently aware of."""
        ...

    async def list_workers(self) -> list[Worker]:
        """Return the workers the engine is currently aware of."""
        ...

    async def get_task(self, task_id: str) -> Task | None:
        """Fetch the current state of one task by its engine-native ID.

        Returns None if the task is not in the engine's known state.
        Does not raise for missing tasks - that is an expected state
        for tasks that have been garbage-collected.
        """
        ...

    async def reconcile_task(self, task_id: str) -> "CommandResult":
        """Query the engine's result backend for authoritative state.

        Called by the brain's ``ReconciliationWorker`` when a task's
        z4j-captured state has been stuck in ``started`` or ``pending``
        longer than a configured threshold (missed event due to agent
        restart, buffer eviction, or broker hiccup).

        The adapter consults the engine's own result backend (Celery
        AsyncResult, RQ Job registry, Dramatiq Results middleware)
        and returns a ``CommandResult`` whose ``result`` dict carries:

            {
                "task_id": str,
                "engine_state": "pending" | "started" | "success" | "failure" | "unknown",
                "finished_at": ISO timestamp | None,
                "exception": str | None,
            }

        Returns ``status="success"`` even for "unknown" state - the
        brain uses this info to update its own snapshot and close the
        stuck-task gap. An adapter whose engine has no result-backend
        concept returns ``engine_state="unknown"`` and the brain
        leaves its own state alone.
        """
        ...

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------

    async def submit_task(
        self,
        name: str,
        *,
        args: tuple[Any, ...] = (),
        kwargs: dict[str, Any] | None = None,
        queue: str | None = None,
        eta: float | None = None,
        priority: int | None = None,
    ) -> CommandResult:
        """Enqueue a fresh task by name + args.

        This is the universal lowest-common-denominator action.
        Every task queue can enqueue a task by name + args - that's
        what makes them task queues. Brain-side polyfills for
        ``retry``, ``bulk_retry``, and ``requeue_dead_letter`` are
        all built on top of this method, eliminating per-engine
        capability gating in the dashboard.

        Returns ``CommandResult.result["task_id"]`` with the new
        task's engine-native id on success.

        Adapters MUST advertise ``"submit_task"`` in
        :meth:`capabilities` if they implement this. The brain will
        refuse to run any unified action against an agent that
        doesn't.
        """
        ...

    async def retry_task(
        self,
        task_id: str,
        *,
        override_args: tuple[Any, ...] | None = None,
        override_kwargs: dict[str, Any] | None = None,
        eta: float | None = None,
    ) -> CommandResult:
        """Re-enqueue a task, optionally with overridden args/kwargs.

        If ``override_args`` or ``override_kwargs`` is None the original
        values are used. If ``eta`` is provided, the retry is scheduled
        for that future time.

        Returns a :class:`CommandResult` with the new task ID on
        success, or an error message on failure.
        """
        ...

    async def cancel_task(self, task_id: str) -> CommandResult:
        """Cancel a task that is pending or running.

        Returns success even if the task had already completed - the
        desired state (not running) is achieved in both cases.
        """
        ...

    async def bulk_retry(
        self,
        filter: dict[str, Any],
        *,
        max: int = 1000,
    ) -> CommandResult:
        """Retry every task matching a filter, up to ``max`` tasks.

        The filter shape matches the ``/tasks`` REST endpoint query
        params (see ``docs/API.md §3.4``). Common keys: ``state``,
        ``queue``, ``task_name``, ``since``, ``until``.

        Implementations should batch retries to avoid flooding the
        broker - batches of 100 are a reasonable default.
        """
        ...

    async def purge_queue(
        self,
        queue_name: str,
        *,
        confirm_token: str | None = None,
        force: bool = False,
    ) -> CommandResult:
        """Remove all tasks from a queue.

        This is destructive and irreversible. Audit H13 requires the
        brain to include a ``confirm_token = HMAC(queue_name,
        current_depth)`` that the adapter re-derives locally and
        rejects on mismatch; ``force=True`` bypasses both that check
        and the adapter's depth-threshold refusal, and should only
        be used from scripted emergency tooling.
        """
        ...

    async def requeue_dead_letter(self, task_id: str) -> CommandResult:
        """Move a task from the dead-letter queue back to its original queue."""
        ...

    async def rate_limit(
        self,
        task_name: str,
        rate: str,
        *,
        worker_name: str | None = None,
    ) -> CommandResult:
        """Set or clear a per-task broker-side rate limit.

        ``rate`` follows Celery's grammar: ``"<n>"``, ``"<n>/s"``,
        ``"<n>/m"``, or ``"<n>/h"``; ``"0"`` removes the limit.
        ``worker_name`` targets one worker; pass ``None`` to broadcast
        the change to every worker subscribed to the broker - useful
        for an emergency global throttle, dangerous if unintended.
        """
        ...

    async def restart_worker(self, worker_id: str) -> CommandResult:
        """Restart a worker process.

        Typically implemented via the engine's control API
        (e.g. ``celery_app.control.broadcast('pool_restart', ...)``).
        """
        ...

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def capabilities(self) -> set[str]:
        """Return the set of capability tokens this adapter supports.

        Recognized tokens:

        - ``submit_task`` - :meth:`submit_task` is implemented (the
          universal primitive; should be present on every adapter
          shipping in v1.0+)
        - ``retry_task`` - :meth:`retry_task` is implemented natively;
          when absent, the brain polyfills via ``submit_task``
        - ``cancel_task`` - :meth:`cancel_task` is implemented
        - ``bulk_retry`` - native bulk implementation; when absent,
          brain loops ``submit_task`` from the stored task table
        - ``purge_queue`` - native purge; when absent, brain loops
          ``cancel_task`` over pending rows
        - ``requeue_dead_letter`` - :meth:`requeue_dead_letter` is
          implemented natively; when absent, brain polyfills
        - ``restart_worker`` - :meth:`restart_worker` is implemented
          (only celery has the remote control to do this)
        - ``rate_limit`` - native broker-side rate limit (celery only)

        The brain uses this set to enable or disable the corresponding
        UI actions. Adapters should be honest - claiming a capability
        that is not actually implemented results in runtime errors that
        surface to the user.
        """
        ...


__all__ = ["QueueEngineAdapter"]
