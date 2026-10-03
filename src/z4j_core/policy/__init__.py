"""The z4j policy engine.

Decides whether a given user may perform a given action on a given
project. The engine is a pure function over three values:

- a :class:`~z4j_core.models.User`
- an :class:`Action` token
- a :class:`~z4j_core.models.Membership` (the user's membership in the
  target project, or None if they are not a member)

It returns a :class:`Decision` with an ``allowed`` flag and an optional
machine-readable denial reason. HTTP responses and audit writes are
outside this library module. The brain's persistence-aware engine
resolves memberships and answers HTTP; it takes the role order
(:data:`ROLE_ORDER`) and the role-to-action table
(:func:`action_required_role`) from this package, so the vocabulary is
defined once.

See ``docs/SECURITY.md §3`` for the threat model and
``docs/ARCHITECTURE.md §6`` for how commands flow through the engine.
"""

from __future__ import annotations

from z4j_core.policy.engine import (
    ACTIONS_BY_ROLE,
    ROLE_ORDER,
    ROLES_SATISFYING_TIER,
    Action,
    Decision,
    PolicyEngine,
    action_allowed,
    action_required_role,
    role_rank,
    role_satisfies,
)

__all__ = [
    "ACTIONS_BY_ROLE",
    "ROLES_SATISFYING_TIER",
    "ROLE_ORDER",
    "Action",
    "Decision",
    "PolicyEngine",
    "action_allowed",
    "action_required_role",
    "role_rank",
    "role_satisfies",
]
