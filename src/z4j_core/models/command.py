"""Command domain model.

A :class:`Command` is an action the user wants z4j to execute against
an underlying task engine: retry a task, cancel a task, bulk retry by
filter, purge a queue, restart a worker, create/update/delete a
schedule, and so on.

The lifecycle is:

1. User clicks a button in the dashboard (or calls the REST API).
2. The brain creates a ``Command`` row with ``status=pending``.
3. The brain dispatches the command over the WebSocket to the target agent.
4. The agent executes it via the appropriate adapter and returns a
   :class:`CommandResult`.
5. The brain updates the ``Command`` row to ``status=completed`` (or
   ``failed``, ``timeout``).

Every command execution is written to the audit log. See
``docs/API.md §3.5`` for the REST API shape and
``docs/ARCHITECTURE.md §6`` for the end-to-end lifecycle.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class CommandStatus(StrEnum):
    """Lifecycle state of a command.

    - ``pending`` - persisted, not yet sent to an agent.
    - ``dispatched`` - sent to an agent, awaiting ack or result.
    - ``completed`` - agent returned a successful result.
    - ``failed`` - agent returned an error result.
    - ``timeout`` - agent did not respond within the configured
      ``timeout_at``.
    - ``cancelled`` - a user cancelled the command before it completed.
    """

    PENDING = "pending"
    DISPATCHED = "dispatched"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class CommandResult(Z4JModel):
    """The outcome of executing a command on the agent side.

    Returned by every method on :class:`z4j_core.protocols.QueueEngineAdapter`
    and :class:`z4j_core.protocols.SchedulerAdapter` that performs an
    action. Also the shape carried in the ``command_result`` wire frame.

    Attributes:
        status: ``"success"`` or ``"failed"``.
        result: Arbitrary JSON-serializable payload on success.
                For example, ``retry_task`` returns
                ``{"new_task_id": "..."}``.
        error: Human-readable error message on failure. None on success.
    """

    status: str = Field(pattern=r"^(success|failed)$")
    result: dict[str, Any] | None = None
    error: str | None = None


class Command(Z4JModel):
    """A user-initiated action to be executed by an agent.

    Attributes:
        id: Brain-assigned UUID primary key.
        project_id: Project this command is scoped to.
        issued_by: User who issued the command. None for
                   system-initiated commands.
        agent_id: Target agent, if already chosen. None until
                  dispatch.
        action: Action name - e.g. ``retry_task``, ``cancel_task``,
                ``bulk_retry``, ``purge_queue``, ``restart_worker``,
                ``schedule.enable``, ``schedule.trigger_now``.
        target_type: What kind of thing this command targets
                     (``task``, ``queue``, ``worker``, ``schedule``).
        target_id: Identifier of the target. None for actions whose
                   target is a filter (e.g. ``bulk_retry``).
        payload: Action-specific parameters. Shape varies by action.
        idempotency_key: Optional key used to deduplicate commands.
                         If the same key is used twice for the same
                         project, the second request returns the
                         first command's result.
        status: Current lifecycle state.
        result: Result returned by the agent, once available.
        error: Error message if the command failed.
        issued_at: When the brain accepted the command request.
        dispatched_at: When the brain sent the command to the agent.
        completed_at: When the brain received the result.
        timeout_at: Absolute time after which the command is considered
                    timed out. Typically ``issued_at + 60s``.
        source_ip: IP address the command was issued from (for audit).
    """

    id: UUID
    project_id: UUID
    issued_by: UUID | None = None
    agent_id: UUID | None = None
    action: str = Field(min_length=1, max_length=100)
    target_type: str = Field(min_length=1, max_length=40)
    target_id: str | None = Field(default=None, max_length=200)
    payload: dict[str, Any] = Field(default_factory=dict)
    idempotency_key: str | None = Field(default=None, max_length=200)
    status: CommandStatus = CommandStatus.PENDING
    result: CommandResult | None = None
    error: str | None = None
    issued_at: datetime
    dispatched_at: datetime | None = None
    completed_at: datetime | None = None
    timeout_at: datetime
    source_ip: IPv4Address | IPv6Address | None = None


__all__ = ["Command", "CommandResult", "CommandStatus"]
