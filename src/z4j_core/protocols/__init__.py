"""The three adapter Protocols - the load-bearing contracts of z4j.

z4j's extensibility model rests on three orthogonal adapter axes:

- :class:`FrameworkAdapter` - host web framework (Django, Flask,
  FastAPI, bare Python). Responsible for discovering agent config,
  supplying discovery hints, and exposing request context for event
  enrichment.

- :class:`QueueEngineAdapter` - task queue engine (Celery, RQ,
  Dramatiq, ...). Responsible for capturing task lifecycle events
  and executing actions (retry, cancel, bulk retry, purge, restart).

- :class:`SchedulerAdapter` - periodic task scheduler (Celery-beat,
  APScheduler, ...). Responsible for listing, creating, updating,
  and triggering schedules.

These three axes are orthogonal - any framework can be combined with
any engine with any scheduler. Adapter packages implement one Protocol
each, and the brain does not need to know which ones exist.

See ``docs/ARCHITECTURE.md §4`` for the full design and
``docs/CLAUDE.md §2.1`` for the modularity rules.
"""

from __future__ import annotations

from z4j_core.protocols.framework import FrameworkAdapter
from z4j_core.protocols.queue_engine import QueueEngineAdapter
from z4j_core.protocols.scheduler import SchedulerAdapter

__all__ = [
    "FrameworkAdapter",
    "QueueEngineAdapter",
    "SchedulerAdapter",
]
