"""Agent domain model.

An ``Agent`` represents one z4j agent runtime that has (or has ever)
connected to this brain. Each agent is project-scoped, authenticates
with a project-scoped bearer token, and advertises its capabilities
on connect via the ``hello`` wire frame.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class AgentState(StrEnum):
    """Runtime state of an agent as tracked by the brain.

    - ``online`` - WebSocket connection is active and heartbeats are
      current.
    - ``offline`` - no heartbeat within the project's offline timeout
      (default 30 seconds).
    - ``unknown`` - the agent has been registered but has never
      connected, or its last state cannot be determined.
    """

    ONLINE = "online"
    OFFLINE = "offline"
    UNKNOWN = "unknown"


class AgentCapabilities(Z4JModel):
    """Capabilities an agent advertises on connect.

    Shipped as part of the ``hello`` frame. The brain uses this to
    enable/disable UI actions per agent - for example, the "Restart
    worker" button is only shown when the agent's Celery adapter
    declares the ``restart_worker`` capability.

    Attributes:
        engines: Map of engine name to the set of capability tokens
                 that engine's adapter advertises. Example:
                 ``{"celery": {"retry", "cancel", "bulk_retry",
                 "purge", "dlq", "restart_worker"}}``.
        schedulers: Same, for scheduler adapters. Example:
                 ``{"celery-beat": {"list", "create", "update",
                 "delete", "enable", "disable", "trigger_now"}}``.
    """

    engines: dict[str, set[str]] = Field(default_factory=dict)
    schedulers: dict[str, set[str]] = Field(default_factory=dict)


class Agent(Z4JModel):
    """An agent that talks to this brain on behalf of a project.

    Attributes:
        id: Opaque UUID primary key.
        project_id: The project this agent is scoped to.
        name: Human-readable name. Typically the host's ``hostname``
              or a user-chosen label.
        token_hash: HMAC-SHA256 hash of the bearer token. The plaintext
                    token is never stored - only shown to the operator
                    once, at creation time.
        protocol_version: Wire-protocol version the agent advertised in
                          its most recent ``hello`` frame.
        framework_adapter: Name of the framework adapter the agent is
                           running under (``django``, ``flask``,
                           ``fastapi``, ``bare``).
        engine_adapters: Names of the queue engine adapters active in
                         this agent (``["celery"]``, ``["celery", "rq"]``,
                         ...).
        scheduler_adapters: Names of the scheduler adapters active
                            (``["celery-beat"]``, ...).
        capabilities: Self-advertised capabilities.
        state: Last-known runtime state.
        last_seen_at: Timestamp of the most recent heartbeat.
        last_connect_at: Timestamp of the most recent successful
                         WebSocket connect.
        metadata: Free-form map of host info - Python version, PID,
                  hostname, etc. Not used for access decisions.
        created_at: When the agent record was created in the brain.
        updated_at: When the agent record was last modified.
    """

    id: UUID
    project_id: UUID
    name: str = Field(min_length=1, max_length=200)
    token_hash: str = Field(min_length=1)
    protocol_version: str = Field(min_length=1, max_length=16)
    framework_adapter: str = Field(min_length=1, max_length=40)
    engine_adapters: list[str] = Field(default_factory=list)
    scheduler_adapters: list[str] = Field(default_factory=list)
    capabilities: AgentCapabilities = Field(default_factory=AgentCapabilities)
    state: AgentState = AgentState.UNKNOWN
    last_seen_at: datetime | None = None
    last_connect_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime


__all__ = ["Agent", "AgentCapabilities", "AgentState"]
