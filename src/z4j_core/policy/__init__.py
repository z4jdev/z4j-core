"""The z4j policy engine.

Decides whether a given user may perform a given action on a given
project. The engine is a pure function over three values:

- a :class:`~z4j_core.models.User`
- an :class:`Action` token
- a :class:`~z4j_core.models.Membership` (the user's membership in the
  target project, or None if they are not a member)

It returns a :class:`Decision` with an ``allowed`` flag and an optional
machine-readable denial reason. HTTP responses and audit writes are
outside this library module. The brain uses its own persistence-aware
policy engine for those responsibilities.

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
