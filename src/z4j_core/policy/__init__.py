"""The z4j policy engine.

Decides whether a given user may perform a given action on a given
project. The engine is a pure function over three values:

- a :class:`~z4j_core.models.User`
- an :class:`Action` token
- a :class:`~z4j_core.models.Membership` (the user's membership in the
  target project, or None if they are not a member)

It returns a :class:`Decision` - ``allow``, ``deny``, or
``denied_with_reason``. The brain turns deny decisions into HTTP 403s
and writes an audit entry.

See ``docs/SECURITY.md §3`` for the threat model and
``docs/ARCHITECTURE.md §6`` for how commands flow through the engine.
"""

from __future__ import annotations

from z4j_core.policy.engine import (
    Action,
    Decision,
    PolicyEngine,
    action_required_role,
)

__all__ = [
    "Action",
    "Decision",
    "PolicyEngine",
    "action_required_role",
]
