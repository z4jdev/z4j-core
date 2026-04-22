"""Task registry delta.

When the agent's discovery pipeline notices that the set of known
task definitions has changed - a new task was registered, an old one
was removed, a signature changed - it emits a :class:`TaskRegistryDelta`
to the brain so the dashboard can update without requiring a full rescan.
"""

from __future__ import annotations

from pydantic import Field

from z4j_core.models._base import Z4JModel
from z4j_core.models.task import TaskDefinition


class TaskRegistryDelta(Z4JModel):
    """A partial update to the known task definitions for one engine.

    Attributes:
        engine: Engine adapter that produced the delta.
        added: Task definitions that are newly known.
        removed: Fully-qualified names of tasks that are no longer known.
        updated: Task definitions whose metadata has changed (e.g.
                 new signature, new default queue, new tags).
    """

    engine: str = Field(min_length=1, max_length=40)
    added: list[TaskDefinition] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    updated: list[TaskDefinition] = Field(default_factory=list)


__all__ = ["TaskRegistryDelta"]
