"""Task domain models.

Two distinct concepts share the word "task":

1. :class:`TaskDefinition` - a task that *exists in the codebase*.
   Discovered via the agent's five-layer discovery pipeline. Has a
   name, a module path, and (optionally) a signature. No runtime
   state. A task definition is a template.

2. :class:`Task` - a task *instance*. One row per ``.delay()`` or
   ``.apply_async()`` call. Has runtime state, args, kwargs, result,
   exception, timing, worker assignment, retry count, etc. This is
   what the dashboard's "Tasks" screen lists.

Keep them straight. They are two different tables in Postgres and
two different concepts in the UI.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class TaskState(StrEnum):
    """Lifecycle state of a task instance.

    Values map directly to Celery task states plus a few z4j-specific
    additions. Other queue engines' states are mapped to the closest
    value at the adapter boundary.
    """

    PENDING = "pending"
    RECEIVED = "received"
    STARTED = "started"
    SUCCESS = "success"
    FAILURE = "failure"
    RETRY = "retry"
    REVOKED = "revoked"
    REJECTED = "rejected"
    UNKNOWN = "unknown"


class TaskPriority(StrEnum):
    """Business-level priority classification for task instances.

    This is a z4j-side semantic layer - it does NOT control Celery
    queue routing or execution order. It controls:

    - **Notification routing**: critical failures page someone at
      3am; low-priority failures just log.
    - **Dashboard prominence**: critical tasks surface first.
    - **SLA tracking**: critical tasks get tighter expected-duration
      windows.
    - **Export/filter**: operators filter by priority to find the
      needle in the haystack.

    Assigned via ``@z4j_meta(priority="critical")`` on the task
    definition. Tasks without explicit priority default to NORMAL.
    """

    CRITICAL = "critical"
    HIGH = "high"
    NORMAL = "normal"
    LOW = "low"


class TaskDefinition(Z4JModel):
    """A task that exists in the user's codebase.

    Populated by the five-layer task discovery pipeline:

    - Runtime scan - actually loaded into the Celery registry
    - Static AST scan - declared in a ``tasks.py`` but not yet imported
    - Signal-driven - seen on the wire at least once
    - Reconciliation - periodic diff of the registry
    - Manual - user clicked "Refresh" in the dashboard

    Attributes:
        name: Fully-qualified dotted task name, e.g.
              ``myapp.tasks.send_welcome_email``.
        module: Python module the task lives in.
        engine: Which engine adapter discovered this task
                (``celery``, ``rq``, ...).
        queue: Default queue the task is routed to, if known.
        signature: Optional human-readable function signature, e.g.
                   ``(user_id: int, template: str) -> None``.
        declared_in: Relative path to the source file, e.g.
                     ``myapp/tasks.py``. Best-effort.
        loaded: True if the task was present in the runtime registry
                (Layer 1 runtime scan), False if it was only seen
                statically. Tasks with ``loaded=False`` are shown in
                the dashboard with a "declared, not yet loaded" badge.
        tags: Free-form tags attached by the user via ``@z4j_meta``.
    """

    name: str = Field(min_length=1, max_length=500)
    module: str | None = Field(default=None, max_length=500)
    engine: str = Field(min_length=1, max_length=40)
    queue: str | None = Field(default=None, max_length=200)
    signature: str | None = Field(default=None, max_length=2000)
    declared_in: str | None = Field(default=None, max_length=500)
    loaded: bool = True
    tags: list[str] = Field(default_factory=list)


class Task(Z4JModel):
    """A task instance - one row per invocation.

    Updated as events arrive for this task from the agent.

    Attributes:
        id: Brain-assigned UUID primary key.
        project_id: Project this task belongs to.
        engine: Engine name (``celery``, ``rq``, ...).
        task_id: Engine-native task ID. Unique per ``(project, engine)``.
        name: Fully-qualified task name.
        queue: Queue this task was routed to.
        state: Current lifecycle state.
        args: Redacted positional arguments.
        kwargs: Redacted keyword arguments.
        result: Redacted return value, if any.
        exception: Exception class name, if the task failed.
        traceback: Exception traceback (may be truncated).
        retry_count: Number of retries already attempted.
        eta: Scheduled start time, if the task is delayed.
        received_at: When the worker received the task.
        started_at: When execution began.
        finished_at: When execution ended (success or failure).
        runtime_ms: ``finished_at - started_at`` in milliseconds.
        worker_name: Name of the worker that executed the task.
        parent_task_id: For chains/groups/chords - the immediate parent.
        root_task_id: For chains/groups/chords - the root of the workflow.
        tags: Free-form tags.
        metadata: Adapter-specific extension payload. Must not contain
                  fields that should be on the core model.
        created_at: Brain-side insert time.
        updated_at: Brain-side last mutation time.
    """

    id: UUID
    project_id: UUID
    engine: str = Field(min_length=1, max_length=40)
    task_id: str = Field(min_length=1, max_length=200)
    name: str = Field(min_length=1, max_length=500)
    queue: str | None = Field(default=None, max_length=200)
    state: TaskState = TaskState.PENDING
    priority: TaskPriority = TaskPriority.NORMAL
    args: Any = None
    kwargs: dict[str, Any] | None = None
    result: Any = None
    exception: str | None = Field(default=None, max_length=500)
    traceback: str | None = None
    retry_count: int = Field(default=0, ge=0)
    eta: datetime | None = None
    received_at: datetime | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    runtime_ms: int | None = Field(default=None, ge=0)
    worker_name: str | None = Field(default=None, max_length=200)
    parent_task_id: str | None = Field(default=None, max_length=200)
    root_task_id: str | None = Field(default=None, max_length=200)
    tags: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


__all__ = ["Task", "TaskDefinition", "TaskPriority", "TaskState"]
