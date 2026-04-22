"""Unit tests for the z4j-core policy engine.

Target coverage: 100% line + 100% branch on every (action × role)
combination. This is the single source of truth for authorization.
"""

from __future__ import annotations

import pytest

from z4j_core.models import Membership, ProjectRole, User
from z4j_core.policy import (
    Action,
    Decision,
    PolicyEngine,
    action_required_role,
)


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


class TestActionRequiredRole:
    """Every action must be assigned to exactly one required role."""

    @pytest.mark.parametrize("action", list(Action))
    def test_every_action_has_a_required_role(self, action: Action) -> None:
        role = action_required_role(action)
        assert role in ProjectRole


class TestReadActions:
    """Viewer, operator, and admin can all read."""

    @pytest.mark.parametrize(
        "action",
        [
            Action.READ_PROJECT,
            Action.READ_TASKS,
            Action.READ_QUEUES,
            Action.READ_WORKERS,
            Action.READ_SCHEDULES,
            Action.READ_AUDIT,
            Action.READ_AGENTS,
        ],
    )
    def test_viewer_can_read(
        self,
        engine: PolicyEngine,
        viewer_user: User,
        viewer_membership: Membership,
        action: Action,
    ) -> None:
        decision = engine.can(viewer_user, action, viewer_membership)
        assert decision.allowed

    @pytest.mark.parametrize(
        "action",
        [Action.READ_TASKS, Action.READ_AUDIT],
    )
    def test_operator_can_read(
        self,
        engine: PolicyEngine,
        operator_user: User,
        operator_membership: Membership,
        action: Action,
    ) -> None:
        assert engine.can(operator_user, action, operator_membership).allowed

    @pytest.mark.parametrize(
        "action",
        [Action.READ_TASKS, Action.READ_AUDIT],
    )
    def test_admin_can_read(
        self,
        engine: PolicyEngine,
        admin_user: User,
        admin_membership: Membership,
        action: Action,
    ) -> None:
        assert engine.can(admin_user, action, admin_membership).allowed


class TestWriteActions:
    """Operator and admin can write. Viewer cannot."""

    @pytest.mark.parametrize(
        "action",
        [
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
        ],
    )
    def test_viewer_cannot_write(
        self,
        engine: PolicyEngine,
        viewer_user: User,
        viewer_membership: Membership,
        action: Action,
    ) -> None:
        decision = engine.can(viewer_user, action, viewer_membership)
        assert not decision.allowed
        assert decision.reason == "insufficient_role"
        assert decision.required_role == ProjectRole.OPERATOR

    @pytest.mark.parametrize(
        "action",
        [
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
        ],
    )
    def test_operator_can_write(
        self,
        engine: PolicyEngine,
        operator_user: User,
        operator_membership: Membership,
        action: Action,
    ) -> None:
        assert engine.can(operator_user, action, operator_membership).allowed

    @pytest.mark.parametrize(
        "action",
        [
            Action.RETRY_TASK,
            Action.PURGE_QUEUE,
        ],
    )
    def test_admin_can_write(
        self,
        engine: PolicyEngine,
        admin_user: User,
        admin_membership: Membership,
        action: Action,
    ) -> None:
        assert engine.can(admin_user, action, admin_membership).allowed


class TestAdminActions:
    """Admin-only actions are denied for viewer and operator."""

    @pytest.mark.parametrize(
        "action",
        [
            Action.MANAGE_MEMBERS,
            Action.UPDATE_PROJECT,
            Action.DELETE_PROJECT,
            Action.MINT_AGENT_TOKEN,
            Action.REVOKE_AGENT_TOKEN,
            Action.ROTATE_PROJECT_SECRET,
            Action.UPDATE_RETENTION,
        ],
    )
    def test_viewer_cannot_admin(
        self,
        engine: PolicyEngine,
        viewer_user: User,
        viewer_membership: Membership,
        action: Action,
    ) -> None:
        decision = engine.can(viewer_user, action, viewer_membership)
        assert not decision.allowed
        assert decision.required_role == ProjectRole.ADMIN

    @pytest.mark.parametrize(
        "action",
        [
            Action.MANAGE_MEMBERS,
            Action.UPDATE_PROJECT,
            Action.DELETE_PROJECT,
            Action.MINT_AGENT_TOKEN,
            Action.REVOKE_AGENT_TOKEN,
            Action.ROTATE_PROJECT_SECRET,
            Action.UPDATE_RETENTION,
        ],
    )
    def test_operator_cannot_admin(
        self,
        engine: PolicyEngine,
        operator_user: User,
        operator_membership: Membership,
        action: Action,
    ) -> None:
        decision = engine.can(operator_user, action, operator_membership)
        assert not decision.allowed
        assert decision.required_role == ProjectRole.ADMIN

    @pytest.mark.parametrize(
        "action",
        [
            Action.MANAGE_MEMBERS,
            Action.UPDATE_PROJECT,
            Action.DELETE_PROJECT,
            Action.MINT_AGENT_TOKEN,
            Action.REVOKE_AGENT_TOKEN,
            Action.ROTATE_PROJECT_SECRET,
            Action.UPDATE_RETENTION,
        ],
    )
    def test_admin_can_admin(
        self,
        engine: PolicyEngine,
        admin_user: User,
        admin_membership: Membership,
        action: Action,
    ) -> None:
        assert engine.can(admin_user, action, admin_membership).allowed


class TestInactiveUser:
    """Inactive users are denied everything, regardless of role."""

    def test_inactive_user_denied(
        self,
        engine: PolicyEngine,
        inactive_user: User,
        admin_membership: Membership,
    ) -> None:
        # Even with an admin membership (pathological case), an
        # inactive user gets nothing.
        faked = Membership(
            id=admin_membership.id,
            user_id=inactive_user.id,
            project_id=admin_membership.project_id,
            role=ProjectRole.ADMIN,
            created_at=admin_membership.created_at,
        )
        decision = engine.can(inactive_user, Action.READ_TASKS, faked)
        assert not decision.allowed
        assert decision.reason == "inactive_user"


class TestNoMembership:
    """Users with no membership cannot act on the project.

    This is the test that enforces "global admins don't get automatic
    cross-tenant access" - even an ``is_admin=True`` user must have an
    explicit membership.
    """

    def test_no_membership_denied(
        self,
        engine: PolicyEngine,
        admin_user: User,
    ) -> None:
        decision = engine.can(admin_user, Action.READ_TASKS, None)
        assert not decision.allowed
        assert decision.reason == "not_a_member"


class TestDecisionConstructors:
    def test_allow_constructor(self) -> None:
        d = Decision.allow()
        assert d.allowed
        assert d.reason is None
        assert d.required_role is None

    def test_deny_constructor(self) -> None:
        d = Decision.deny("foo", required_role=ProjectRole.ADMIN)
        assert not d.allowed
        assert d.reason == "foo"
        assert d.required_role == ProjectRole.ADMIN


class TestActionRequiredRoleUnknown:
    def test_unknown_action_raises_value_error(self) -> None:
        # Synthesize a fake action not in any of the role buckets.
        # This tests the safety net in ``action_required_role``.
        class FakeAction(str):
            pass

        with pytest.raises(ValueError, match="no required role"):
            action_required_role(FakeAction("totally_made_up"))  # type: ignore[arg-type]
