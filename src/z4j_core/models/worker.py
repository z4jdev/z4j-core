"""Worker domain model.

A :class:`Worker` represents a running instance of the underlying
task engine - e.g. one ``celery worker`` process. Agents report
worker state to the brain via heartbeats and lifecycle events.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class WorkerState(StrEnum):
    """Lifecycle state of a worker as tracked by the brain."""

    ONLINE = "online"
    OFFLINE = "offline"
    DRAINING = "draining"
    UNKNOWN = "unknown"


class Worker(Z4JModel):
    """A running worker of a task engine.

    Attributes:
        id: Opaque UUID.
        project_id: Project this worker belongs to.
        engine: Engine adapter that reports this worker
                (``celery``, ``rq``, ...).
        name: Worker name as the engine knows it, e.g.
              ``celery@web-01``.
        hostname: Host the worker is running on, if known.
        pid: OS process ID, if known.
        concurrency: Configured concurrency level.
        queues: Queues this worker consumes from.
        state: Current lifecycle state.
        last_heartbeat: Timestamp of the most recent heartbeat event.
        load_average: Three-element 1/5/15-min load average, if available.
        memory_bytes: Resident memory footprint in bytes, if available.
        active_tasks: Number of tasks currently executing on this worker.
        metadata: Adapter-specific extension data.
        created_at: Brain-side insert time.
        updated_at: Brain-side last-modified time.
    """

    id: UUID
    project_id: UUID
    engine: str = Field(min_length=1, max_length=40)
    name: str = Field(min_length=1, max_length=200)
    hostname: str | None = Field(default=None, max_length=200)
    pid: int | None = Field(default=None, ge=0)
    concurrency: int | None = Field(default=None, ge=0)
    queues: list[str] = Field(default_factory=list)
    state: WorkerState = WorkerState.UNKNOWN
    last_heartbeat: datetime | None = None
    load_average: list[float] | None = None
    memory_bytes: int | None = Field(default=None, ge=0)
    active_tasks: int = Field(default=0, ge=0)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


__all__ = ["Worker", "WorkerState"]
