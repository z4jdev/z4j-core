"""Policy engine - authorization decisions for z4j.

This module is the single source of truth for "can this user do this
action on this project?" - all permission checks anywhere in z4j go
through :class:`PolicyEngine`. It is deliberately pure (no I/O, no
async) so it is trivial to unit-test against the full (action × role)
matrix.

Role hierarchy (see ``docs/SECURITY.md §3.1``):

    viewer < operator < admin

The helper :func:`action_required_role` maps each action to the
minimum role needed. ``PolicyEngine.can`` checks the user's
membership against that requirement and returns a structured
decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from z4j_core.models import Membership, ProjectRole, User


class Action(StrEnum):
    """Taxonomy of actions the policy engine knows about.

    Every action name is stable across releases. Adding a new action
    requires updating :func:`action_required_role` in the same PR so
    the permission matrix stays complete.
    """

    # Read actions - viewer and above
    READ_PROJECT = "read_project"
    READ_TASKS = "read_tasks"
    READ_QUEUES = "read_queues"
    READ_WORKERS = "read_workers"
    READ_SCHEDULES = "read_schedules"
    READ_AUDIT = "read_audit"
    READ_AGENTS = "read_agents"

    # Write actions - operator and above
    RETRY_TASK = "retry_task"
    CANCEL_TASK = "cancel_task"
    BULK_RETRY = "bulk_retry"
    PURGE_QUEUE = "purge_queue"
    REQUEUE_DEAD_LETTER = "requeue_dead_letter"
    RESTART_WORKER = "restart_worker"
    CREATE_SCHEDULE = "create_schedule"
    UPDATE_SCHEDULE = "update_schedule"
    DELETE_SCHEDULE = "delete_schedule"
    ENABLE_SCHEDULE = "enable_schedule"
    DISABLE_SCHEDULE = "disable_schedule"
    TRIGGER_SCHEDULE = "trigger_schedule"

    # Admin actions - admin only
    MANAGE_MEMBERS = "manage_members"
    UPDATE_PROJECT = "update_project"
    DELETE_PROJECT = "delete_project"
    MINT_AGENT_TOKEN = "mint_agent_token"
    REVOKE_AGENT_TOKEN = "revoke_agent_token"
    ROTATE_PROJECT_SECRET = "rotate_project_secret"
    UPDATE_RETENTION = "update_retention"


# ---------------------------------------------------------------------------
# Per-action required role mapping
# ---------------------------------------------------------------------------

_VIEWER_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.READ_PROJECT,
        Action.READ_TASKS,
        Action.READ_QUEUES,
        Action.READ_WORKERS,
        Action.READ_SCHEDULES,
        Action.READ_AUDIT,
        Action.READ_AGENTS,
    },
)

_OPERATOR_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.RETRY_TASK,
        Action.CANCEL_TASK,
        Action.BULK_RETRY,
        Action.PURGE_QUEUE,
        Action.REQUEUE_DEAD_LETTER,
        Action.RESTART_WORKER,
        Action.CREATE_SCHEDULE,
        Action.UPDATE_SCHEDULE,
        Action.DELETE_SCHEDULE,
        Action.ENABLE_SCHEDULE,
        Action.DISABLE_SCHEDULE,
        Action.TRIGGER_SCHEDULE,
    },
)

_ADMIN_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.MANAGE_MEMBERS,
        Action.UPDATE_PROJECT,
        Action.DELETE_PROJECT,
        Action.MINT_AGENT_TOKEN,
        Action.REVOKE_AGENT_TOKEN,
        Action.ROTATE_PROJECT_SECRET,
        Action.UPDATE_RETENTION,
    },
)


def action_required_role(action: Action) -> ProjectRole:
    """Return the minimum :class:`ProjectRole` needed for ``action``.

    Raises:
        ValueError: If ``action`` is not in any role bucket. This is
                    a programmer error - every new action must be
                    assigned to a role in this function.
    """
    if action in _VIEWER_ACTIONS:
        return ProjectRole.VIEWER
    if action in _OPERATOR_ACTIONS:
        return ProjectRole.OPERATOR
    if action in _ADMIN_ACTIONS:
        return ProjectRole.ADMIN
    raise ValueError(f"action {action!r} has no required role - update policy/engine.py")


# ---------------------------------------------------------------------------
# Decision type
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Decision:
    """The outcome of a policy check.

    Attributes:
        allowed: True if the action is permitted.
        reason: Machine-readable reason code on deny. One of
                ``"inactive_user"``, ``"not_a_member"``,
                ``"insufficient_role"``. None on allow.
        required_role: The role the user would need. Populated on
                       ``insufficient_role`` denies so the UI can
                       show a helpful message.
    """

    allowed: bool
    reason: str | None = None
    required_role: ProjectRole | None = None

    @classmethod
    def allow(cls) -> "Decision":
        """Construct an allow decision."""
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: str, required_role: ProjectRole | None = None) -> "Decision":
        """Construct a deny decision with a machine-readable reason."""
        return cls(allowed=False, reason=reason, required_role=required_role)


# ---------------------------------------------------------------------------
# Ordering helper
# ---------------------------------------------------------------------------

_ROLE_ORDER: dict[ProjectRole, int] = {
    ProjectRole.VIEWER: 1,
    ProjectRole.OPERATOR: 2,
    ProjectRole.ADMIN: 3,
}


def _role_satisfies(held: ProjectRole, required: ProjectRole) -> bool:
    return _ROLE_ORDER[held] >= _ROLE_ORDER[required]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Stateless policy engine.

    Construct once and share across the process. ``can`` is safe to
    call concurrently.
    """

    def can(
        self,
        user: User,
        action: Action,
        membership: Membership | None,
    ) -> Decision:
        """Decide whether ``user`` may perform ``action`` on a project.

        Args:
            user: The authenticated user making the request.
            action: The action the user wants to perform.
            membership: The user's membership in the target project.
                        None if the user has no membership at all in
                        that project.

        Returns:
            A :class:`Decision` - ``allow`` or ``deny`` with a reason.

        Notes:
            Global admins do NOT automatically get access to every
            project. This is deliberate. A global admin must be added
            as an explicit member of a project before they can act in
            it - it prevents silent cross-tenant data access.
        """
        if not user.is_active:
            return Decision.deny(reason="inactive_user")

        if membership is None:
            return Decision.deny(reason="not_a_member")

        required = action_required_role(action)
        if not _role_satisfies(membership.role, required):
            return Decision.deny(
                reason="insufficient_role",
                required_role=required,
            )

        return Decision.allow()


__all__ = [
    "Action",
    "Decision",
    "PolicyEngine",
    "action_required_role",
]
