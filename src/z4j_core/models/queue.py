"""Queue domain model.

A :class:`Queue` represents a named task queue that z4j has observed
for a given project. Populated by the agent's discovery pipeline:
agents report the queues declared in their engine's configuration
plus any queues seen on the wire.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class Queue(Z4JModel):
    """A named task queue observed by z4j.

    Attributes:
        id: Opaque UUID.
        project_id: Project this queue belongs to.
        name: Queue name as the underlying engine knows it
              (``default``, ``emails``, ``high_priority``, ...).
        engine: Engine adapter that reported this queue
                (``celery``, ``rq``, ``dramatiq``, ...).
        broker_type: Broker backing this queue, if known
                     (``redis``, ``rabbitmq``, ``postgres``, ``sqs``).
        broker_url_hint: A sanitized host:port hint for display.
                         **Never** contains credentials. The agent
                         strips the userinfo portion before sending.
        last_seen_at: Timestamp of the most recent event referencing
                      this queue. Used to auto-hide queues that have
                      gone quiet.
        metadata: Adapter-specific extension data.
        created_at: Brain-side insert time.
    """

    id: UUID
    project_id: UUID
    name: str = Field(min_length=1, max_length=200)
    engine: str = Field(min_length=1, max_length=40)
    broker_type: str | None = Field(default=None, max_length=40)
    broker_url_hint: str | None = Field(default=None, max_length=200)
    last_seen_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime


__all__ = ["Queue"]
