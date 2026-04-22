"""Schedule domain model.

A :class:`Schedule` is a periodic or one-shot trigger that fires a
task at configured times. In Celery terms: a row in
``django_celery_beat.PeriodicTask`` or an entry in
``celery_app.conf.beat_schedule``.

Schedules are managed end-to-end by z4j: the dashboard can create,
edit, enable, disable, and trigger-now a schedule. The scheduler
adapter translates these operations into the underlying system's
native API.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class ScheduleKind(StrEnum):
    """How a schedule's firing times are defined.

    - ``cron`` - standard five-field cron expression (or six-field
      with seconds, if the adapter supports it).
    - ``interval`` - repeat every N seconds.
    - ``solar`` - tied to an astronomical event (sunrise, sunset, ...).
    - ``clocked`` - fire once at a specific timestamp.
    """

    CRON = "cron"
    INTERVAL = "interval"
    SOLAR = "solar"
    CLOCKED = "clocked"


class Schedule(Z4JModel):
    """A periodic or one-shot task trigger.

    Attributes:
        id: Brain-assigned UUID.
        project_id: Project this schedule belongs to.
        engine: Engine adapter this schedule fires tasks on
                (``celery``, ``rq``, ...).
        scheduler: Scheduler adapter managing this schedule
                   (``celery-beat``, ``apscheduler``, ...).
        name: Human-readable schedule name. Unique per
              ``(project, scheduler)``.
        task_name: Fully-qualified name of the task the schedule fires.
        kind: How firing times are defined.
        expression: Engine-native schedule expression.
                    For ``cron`` this is a cron string like
                    ``"0 3 * * *"``. For ``interval`` it is an integer
                    seconds count. For ``clocked`` it is an ISO8601
                    timestamp. For ``solar`` it is the event name.
        timezone: IANA timezone the expression is evaluated in.
        queue: Queue to route fired tasks to, if overridden.
        args: Positional arguments passed to the task on each fire.
        kwargs: Keyword arguments passed to the task on each fire.
        is_enabled: If False, the schedule exists but does not fire.
        last_run_at: Timestamp of the most recent fire, if any.
        next_run_at: Predicted next-fire timestamp, if computable.
        total_runs: Lifetime count of times this schedule has fired.
        external_id: Optional pointer back to the underlying system's
                     identifier (e.g. ``django_celery_beat.PeriodicTask.id``
                     as a string). Opaque to z4j.
        metadata: Adapter-specific extension data.
        created_at: Brain-side insert time.
        updated_at: Brain-side last-modified time.
    """

    id: UUID
    project_id: UUID
    engine: str = Field(min_length=1, max_length=40)
    scheduler: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=200)
    task_name: str = Field(min_length=1, max_length=500)
    kind: ScheduleKind
    expression: str = Field(min_length=1, max_length=200)
    timezone: str = Field(default="UTC", max_length=100)
    queue: str | None = Field(default=None, max_length=200)
    args: list[Any] = Field(default_factory=list)
    kwargs: dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    last_run_at: datetime | None = None
    next_run_at: datetime | None = None
    total_runs: int = Field(default=0, ge=0)
    external_id: str | None = Field(default=None, max_length=200)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


__all__ = ["Schedule", "ScheduleKind"]
