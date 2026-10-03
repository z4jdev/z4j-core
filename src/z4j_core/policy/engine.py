"""The project-role vocabulary and the pure policy engine built on it.

This module is the single source of truth for "which role may perform
which action on a project". The brain's persistence-aware engine
(``z4j_brain.domain.policy_engine``) resolves memberships, synthesises
the instance-admin membership and answers 404 instead of 403 to
non-members, but the role order and the role-to-action table are taken
from here; it carries no role math of its own. A contract test under
``tests/contract`` enumerates every (role, action) pair in both engines
and fails when they disagree.

Role hierarchy (see ``docs/SECURITY.md``):

    viewer < auditor < operator < admin

The order is what ``min_role`` floors compare against: an auditor meets
every viewer floor and no operator floor. Actions are stricter than
floors in one place. The audit tier is granted to ``auditor`` and
``admin`` only; ``operator`` does not inherit it even though it ranks
higher. That is the separation of duties the compliance surface rests
on: the people who review the record are not the people who produce
it, and the admin tier, which already held the audit trail, keeps it.

:func:`action_required_role` maps each action to the tier that owns it;
:func:`action_allowed` answers for a held role; ``PolicyEngine.can``
checks the user's membership through both and returns a structured
decision.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from z4j_core.models import Membership, ProjectRole, User


class Action(StrEnum):
    """Taxonomy of actions the policy engine knows about.

    Every action name is stable across releases. Adding a new action
    requires assigning it to a role bucket below in the same change so
    the permission matrix stays complete; :func:`action_required_role`
    raises for an unassigned action.
    """

    # Reads - viewer and above
    READ_PROJECT = "read_project"
    READ_TASKS = "read_tasks"
    READ_QUEUES = "read_queues"
    READ_WORKERS = "read_workers"
    READ_SCHEDULES = "read_schedules"
    READ_AGENTS = "read_agents"
    READ_COMMANDS = "read_commands"
    READ_AUTOMATION_RULES = "read_automation_rules"
    READ_NOTIFICATION_CHANNELS = "read_notification_channels"
    # Listing dead letters is a read of broker state (the ``dlq.list``
    # command); resurrecting one is REQUEUE_DEAD_LETTER below.
    LIST_DEAD_LETTERS = "list_dead_letters"
    # Personal state scoped to the caller: a member's own saved views and
    # own notification subscriptions. Writes, but to nothing shared.
    MANAGE_OWN_SAVED_VIEWS = "manage_own_saved_views"
    MANAGE_OWN_SUBSCRIPTIONS = "manage_own_subscriptions"

    # The audit trail - auditor and admin
    READ_AUDIT = "read_audit"
    EXPORT_AUDIT = "export_audit"
    VERIFY_AUDIT = "verify_audit"
    READ_AUDIT_FORWARDER_STATUS = "read_audit_forwarder_status"

    # Commands and schedule control - operator and admin
    RETRY_TASK = "retry_task"
    CANCEL_TASK = "cancel_task"
    BULK_RETRY = "bulk_retry"
    REQUEUE_DEAD_LETTER = "requeue_dead_letter"
    RESTART_WORKER = "restart_worker"
    RESIZE_POOL = "resize_pool"
    MANAGE_CONSUMERS = "manage_consumers"
    SET_RATE_LIMIT = "set_rate_limit"
    ENABLE_SCHEDULE = "enable_schedule"
    DISABLE_SCHEDULE = "disable_schedule"
    PAUSE_SCHEDULE = "pause_schedule"
    RESUME_SCHEDULE = "resume_schedule"
    TRIGGER_SCHEDULE = "trigger_schedule"
    RESOLVE_SCHEDULE_EVIDENCE = "resolve_schedule_evidence"
    MANAGE_AUTOMATION_RULES = "manage_automation_rules"

    # Definitions, destructive actions and project administration - admin only
    PURGE_QUEUE = "purge_queue"
    DELETE_TASKS = "delete_tasks"
    CREATE_SCHEDULE = "create_schedule"
    UPDATE_SCHEDULE = "update_schedule"
    DELETE_SCHEDULE = "delete_schedule"
    SYNC_SCHEDULES = "sync_schedules"
    SET_LEGACY_FIRE_GRANT = "set_legacy_fire_grant"
    MANAGE_DESTRUCTIVE_AUTOMATION_RULES = "manage_destructive_automation_rules"
    UPDATE_AUTOMATION_SETTINGS = "update_automation_settings"
    MANAGE_NOTIFICATION_CHANNELS = "manage_notification_channels"
    READ_MEMBERS = "read_members"
    MANAGE_MEMBERS = "manage_members"
    MINT_AGENT_TOKEN = "mint_agent_token"  # noqa: S105  action name enum value, not a secret
    REVOKE_AGENT_TOKEN = "revoke_agent_token"  # noqa: S105  action name enum value, not a secret
    ROTATE_PROJECT_SECRET = "rotate_project_secret"  # noqa: S105  action name enum value, not a secret
    # The brain gates project edits and archival on the instance-admin
    # tier (``is_admin``), which it represents as an admin membership on
    # every project. ``admin`` is therefore the floor, not the whole
    # requirement, for these two.
    UPDATE_PROJECT = "update_project"
    DELETE_PROJECT = "delete_project"


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
        Action.READ_AGENTS,
        Action.READ_COMMANDS,
        Action.READ_AUTOMATION_RULES,
        Action.READ_NOTIFICATION_CHANNELS,
        Action.LIST_DEAD_LETTERS,
        Action.MANAGE_OWN_SAVED_VIEWS,
        Action.MANAGE_OWN_SUBSCRIPTIONS,
    },
)

_AUDITOR_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.READ_AUDIT,
        Action.EXPORT_AUDIT,
        Action.VERIFY_AUDIT,
        Action.READ_AUDIT_FORWARDER_STATUS,
    },
)

_OPERATOR_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.RETRY_TASK,
        Action.CANCEL_TASK,
        Action.BULK_RETRY,
        Action.REQUEUE_DEAD_LETTER,
        Action.RESTART_WORKER,
        Action.RESIZE_POOL,
        Action.MANAGE_CONSUMERS,
        Action.SET_RATE_LIMIT,
        Action.ENABLE_SCHEDULE,
        Action.DISABLE_SCHEDULE,
        Action.PAUSE_SCHEDULE,
        Action.RESUME_SCHEDULE,
        Action.TRIGGER_SCHEDULE,
        Action.RESOLVE_SCHEDULE_EVIDENCE,
        Action.MANAGE_AUTOMATION_RULES,
    },
)

_ADMIN_ACTIONS: frozenset[Action] = frozenset(
    {
        Action.PURGE_QUEUE,
        Action.DELETE_TASKS,
        Action.CREATE_SCHEDULE,
        Action.UPDATE_SCHEDULE,
        Action.DELETE_SCHEDULE,
        Action.SYNC_SCHEDULES,
        Action.SET_LEGACY_FIRE_GRANT,
        Action.MANAGE_DESTRUCTIVE_AUTOMATION_RULES,
        Action.UPDATE_AUTOMATION_SETTINGS,
        Action.MANAGE_NOTIFICATION_CHANNELS,
        Action.READ_MEMBERS,
        Action.MANAGE_MEMBERS,
        Action.MINT_AGENT_TOKEN,
        Action.REVOKE_AGENT_TOKEN,
        Action.ROTATE_PROJECT_SECRET,
        Action.UPDATE_PROJECT,
        Action.DELETE_PROJECT,
    },
)

#: Every action, bucketed by the tier that owns it. Kept as one mapping
#: so a role can only ever appear once per action.
ACTIONS_BY_ROLE: dict[ProjectRole, frozenset[Action]] = {
    ProjectRole.VIEWER: _VIEWER_ACTIONS,
    ProjectRole.AUDITOR: _AUDITOR_ACTIONS,
    ProjectRole.OPERATOR: _OPERATOR_ACTIONS,
    ProjectRole.ADMIN: _ADMIN_ACTIONS,
}

#: Which held roles satisfy each tier. Every tier includes ``admin``;
#: the viewer tier includes everyone; the auditor and operator tiers
#: are siblings, neither inherits the other.
ROLES_SATISFYING_TIER: dict[ProjectRole, frozenset[ProjectRole]] = {
    ProjectRole.VIEWER: frozenset(ProjectRole),
    ProjectRole.AUDITOR: frozenset({ProjectRole.AUDITOR, ProjectRole.ADMIN}),
    ProjectRole.OPERATOR: frozenset({ProjectRole.OPERATOR, ProjectRole.ADMIN}),
    ProjectRole.ADMIN: frozenset({ProjectRole.ADMIN}),
}


def action_required_role(action: Action) -> ProjectRole:
    """Return the tier that owns ``action``, the role a denial names.

    Raises:
        ValueError: If ``action`` is not in any role bucket. This is
                    a programmer error - every new action must be
                    assigned to a role in this module.
    """
    for role, actions in ACTIONS_BY_ROLE.items():
        if action in actions:
            return role
    raise ValueError(f"action {action!r} has no required role - update policy/engine.py")


def action_allowed(held: ProjectRole, action: Action) -> bool:
    """Return True when a member holding ``held`` may perform ``action``."""
    return held in ROLES_SATISFYING_TIER[action_required_role(action)]


# ---------------------------------------------------------------------------
# Ordering helpers
# ---------------------------------------------------------------------------

#: Authority order for ``min_role`` floors. A role meets a floor when its
#: rank is at least the floor's rank. ``auditor`` outranks ``viewer`` and
#: nothing else; no floor is set at ``auditor`` (audit routes name an
#: action instead), so this order never admits an operator to the
#: audit tier.
ROLE_ORDER: dict[ProjectRole, int] = {
    ProjectRole.VIEWER: 1,
    ProjectRole.AUDITOR: 2,
    ProjectRole.OPERATOR: 3,
    ProjectRole.ADMIN: 4,
}


def role_rank(role: ProjectRole) -> int:
    """Return the comparable authority rank of ``role``."""
    return ROLE_ORDER[role]


def role_satisfies(held: ProjectRole, required: ProjectRole) -> bool:
    """Return True when a member holding ``held`` meets the floor ``required``."""
    return ROLE_ORDER[held] >= ROLE_ORDER[required]


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
    def allow(cls) -> Decision:
        """Construct an allow decision."""
        return cls(allowed=True)

    @classmethod
    def deny(cls, reason: str, required_role: ProjectRole | None = None) -> Decision:
        """Construct a deny decision with a machine-readable reason."""
        return cls(allowed=False, reason=reason, required_role=required_role)


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
            project here. This engine decides on the membership it is
            handed; the brain synthesises an admin membership for its
            instance-admin tier before asking, so that bypass is the
            brain's decision, made in one place, not this table's.
        """
        if not user.is_active:
            return Decision.deny(reason="inactive_user")

        if membership is None:
            return Decision.deny(reason="not_a_member")

        if not action_allowed(membership.role, action):
            return Decision.deny(
                reason="insufficient_role",
                required_role=action_required_role(action),
            )

        return Decision.allow()


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
