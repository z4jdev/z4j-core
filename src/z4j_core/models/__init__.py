"""Domain models for z4j.

The domain models exported here extend :class:`Z4JModel`, with
``strict=True``, ``extra="forbid"``, and ``frozen=True``. This catches
API drift at the boundary (unknown fields rejected), prevents
accidental mutation, and prevents silent type coercion. Wire-frame
models live under :mod:`z4j_core.transport` and intentionally use a
different forward-compatible configuration.

See ``docs/patterns.md §3`` for the modelling conventions.
"""

from __future__ import annotations

from z4j_core.models.agent import Agent, AgentCapabilities, AgentState
from z4j_core.models.audit import AuditEntry
from z4j_core.models.command import (
    Command,
    CommandResult,
    CommandStatus,
)
from z4j_core.models.config import Config, DiscoveryHints, RequestContext
from z4j_core.models.delta import TaskRegistryDelta
from z4j_core.models.event import Event, EventKind
from z4j_core.models.project import Project
from z4j_core.models.queue import Queue
from z4j_core.models.schedule import (
    CatchUpPolicy,
    OverlapPolicy,
    Schedule,
    ScheduleKind,
    refuse_unimplemented_overlap,
)
from z4j_core.models.task import Task, TaskDefinition, TaskState
from z4j_core.models.user import Membership, ProjectRole, User
from z4j_core.models.worker import Worker, WorkerState

__all__ = [
    "Agent",
    "AgentCapabilities",
    "AgentState",
    "AuditEntry",
    "CatchUpPolicy",
    "Command",
    "CommandResult",
    "CommandStatus",
    "Config",
    "DiscoveryHints",
    "Event",
    "EventKind",
    "Membership",
    "OverlapPolicy",
    "Project",
    "ProjectRole",
    "Queue",
    "RequestContext",
    "Schedule",
    "ScheduleKind",
    "Task",
    "TaskDefinition",
    "TaskRegistryDelta",
    "TaskState",
    "User",
    "Worker",
    "WorkerState",
    "refuse_unimplemented_overlap",
]
