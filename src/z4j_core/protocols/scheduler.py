"""The :class:`SchedulerAdapter` Protocol.

One implementation per scheduler. v1 ships ``z4j-celerybeat``; v2 adds
``z4j-apscheduler`` and a crontab reader.

Scheduler adapters are a separate axis from queue-engine adapters
because scheduling and execution are not always the same component.
Celery-beat schedules Celery tasks, but it is a distinct process
with its own storage (``django_celery_beat.PeriodicTask``). APScheduler
can schedule anything. Crontab lives in the OS.

A scheduler adapter is the bridge between the z4j dashboard's
schedule-management UI and whichever scheduler the user runs.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from z4j_core.models import CommandResult, Schedule


@runtime_checkable
class SchedulerAdapter(Protocol):
    """Adapter contract for a periodic task scheduler."""

    name: str
    """Scheduler identifier, e.g. ``"celery-beat"``, ``"apscheduler"``,
    ``"crontab"``. Matches the package suffix."""

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    async def list_schedules(self) -> list[Schedule]:
        """Return every schedule this adapter currently knows about.

        Called on cold start and on every manual refresh. Implementations
        that watch their underlying storage for changes should also
        emit events (via their engine adapter or a dedicated channel)
        so the brain can update incrementally without polling.
        """
        ...

    async def get_schedule(self, schedule_id: str) -> Schedule | None:
        """Fetch a single schedule by its opaque identifier.

        Returns None if no such schedule exists. Does not raise.
        """
        ...

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    async def create_schedule(self, spec: Schedule) -> Schedule:
        """Create a new schedule from the given specification.

        Returns the created schedule with any adapter-assigned fields
        populated (``id``, ``external_id``, ``next_run_at``, etc.).

        Raises :class:`z4j_core.errors.ConflictError` if a schedule
        with the same ``(project_id, scheduler, name)`` already exists.
        """
        ...

    async def update_schedule(
        self,
        schedule_id: str,
        spec: Schedule,
    ) -> Schedule:
        """Update an existing schedule.

        ``spec`` is the desired state - fields not allowed to change
        after creation (e.g. engine, scheduler) are ignored if they
        differ from current state.

        Raises :class:`z4j_core.errors.NotFoundError` if the schedule
        does not exist.
        """
        ...

    async def delete_schedule(self, schedule_id: str) -> CommandResult:
        """Delete a schedule.

        Safe to call on an already-deleted schedule (idempotent).
        Returns success in both cases.
        """
        ...

    async def enable_schedule(self, schedule_id: str) -> CommandResult:
        """Mark a schedule as enabled.

        Re-running this on an already-enabled schedule is a no-op.
        """
        ...

    async def disable_schedule(self, schedule_id: str) -> CommandResult:
        """Mark a schedule as disabled.

        The schedule remains in storage but will not fire until
        re-enabled. Re-running on an already-disabled schedule is a no-op.
        """
        ...

    async def trigger_now(self, schedule_id: str) -> CommandResult:
        """Fire a scheduled task immediately, out of band.

        The schedule's normal firing pattern is unaffected -
        ``last_run_at`` is updated but the next fire time is computed
        from the schedule's normal cadence. Adapters whose underlying
        system does not support this operation should return a failed
        :class:`CommandResult` with a clear error message.
        """
        ...

    # ------------------------------------------------------------------
    # Capabilities
    # ------------------------------------------------------------------

    def capabilities(self) -> set[str]:
        """Return the set of capability tokens this adapter supports.

        Recognized tokens: ``list``, ``create``, ``update``, ``delete``,
        ``enable``, ``disable``, ``trigger_now``. Read-only adapters
        (e.g. a crontab reader) should return only ``list``.
        """
        ...


__all__ = ["SchedulerAdapter"]
