"""Unit tests for the z4j-core policy engine.

Target coverage: every (action x role) combination, plus the named
expectations the taxonomy exists to guarantee (an auditor reads the
record and changes nothing; an operator changes things and does not
read the record). This module is the single source of truth for the
role-to-action table; the brain delegates to it and a contract test
under ``tests/contract`` checks that delegation.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest
from z4j_core.models import Membership, ProjectRole, User
from z4j_core.policy import (
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

_ALL_PAIRS = [(role, action) for role in ProjectRole for action in Action]

MembershipFor = Callable[[ProjectRole], Membership]
UserFor = Callable[[ProjectRole], User]


@pytest.fixture
def engine() -> PolicyEngine:
    return PolicyEngine()


@pytest.fixture
def membership_for(
    viewer_membership: Membership,
    auditor_membership: Membership,
    operator_membership: Membership,
    admin_membership: Membership,
) -> MembershipFor:
    table = {
        ProjectRole.VIEWER: viewer_membership,
        ProjectRole.AUDITOR: auditor_membership,
        ProjectRole.OPERATOR: operator_membership,
        ProjectRole.ADMIN: admin_membership,
    }
    return table.__getitem__


@pytest.fixture
def user_for(
    viewer_user: User,
    auditor_user: User,
    operator_user: User,
    admin_user: User,
) -> UserFor:
    table = {
        ProjectRole.VIEWER: viewer_user,
        ProjectRole.AUDITOR: auditor_user,
        ProjectRole.OPERATOR: operator_user,
        ProjectRole.ADMIN: admin_user,
    }
    return table.__getitem__


class TestVocabulary:
    """The table is complete, disjoint and ordered the documented way."""

    def test_role_order_is_viewer_auditor_operator_admin(self) -> None:
        ordered = sorted(ProjectRole, key=role_rank)
        assert ordered == [
            ProjectRole.VIEWER,
            ProjectRole.AUDITOR,
            ProjectRole.OPERATOR,
            ProjectRole.ADMIN,
        ]
        assert set(ROLE_ORDER) == set(ProjectRole)
        # Enum declaration order is the authority order too.
        assert list(ProjectRole) == ordered

    @pytest.mark.parametrize("action", list(Action))
    def test_every_action_has_exactly_one_required_role(self, action: Action) -> None:
        holders = [role for role, actions in ACTIONS_BY_ROLE.items() if action in actions]
        assert holders == [action_required_role(action)]

    def test_every_role_bucket_is_non_empty_and_covers_the_enum(self) -> None:
        assert set(ACTIONS_BY_ROLE) == set(ProjectRole)
        assert all(ACTIONS_BY_ROLE[role] for role in ProjectRole)
        assert frozenset().union(*ACTIONS_BY_ROLE.values()) == frozenset(Action)

    def test_tiers_form_the_documented_lattice(self) -> None:
        # admin sits in every tier, everyone sits in the viewer tier, and
        # the auditor and operator tiers are siblings.
        assert all(ProjectRole.ADMIN in roles for roles in ROLES_SATISFYING_TIER.values())
        assert ROLES_SATISFYING_TIER[ProjectRole.VIEWER] == frozenset(ProjectRole)
        assert ROLES_SATISFYING_TIER[ProjectRole.AUDITOR] == {
            ProjectRole.AUDITOR,
            ProjectRole.ADMIN,
        }
        assert ROLES_SATISFYING_TIER[ProjectRole.OPERATOR] == {
            ProjectRole.OPERATOR,
            ProjectRole.ADMIN,
        }
        assert ROLES_SATISFYING_TIER[ProjectRole.ADMIN] == {ProjectRole.ADMIN}

    def test_retention_is_not_an_action(self) -> None:
        # ``update_retention`` was never wired to a route; it is gone
        # rather than kept as a permission nobody can exercise.
        assert "update_retention" not in {a.value for a in Action}
        assert not hasattr(Action, "UPDATE_RETENTION")

    @pytest.mark.parametrize(
        ("held", "required", "expected"),
        [
            (ProjectRole.VIEWER, ProjectRole.VIEWER, True),
            (ProjectRole.VIEWER, ProjectRole.AUDITOR, False),
            (ProjectRole.AUDITOR, ProjectRole.VIEWER, True),
            (ProjectRole.AUDITOR, ProjectRole.AUDITOR, True),
            (ProjectRole.AUDITOR, ProjectRole.OPERATOR, False),
            (ProjectRole.OPERATOR, ProjectRole.VIEWER, True),
            (ProjectRole.OPERATOR, ProjectRole.ADMIN, False),
            (ProjectRole.ADMIN, ProjectRole.AUDITOR, True),
            (ProjectRole.ADMIN, ProjectRole.ADMIN, True),
        ],
    )
    def test_role_satisfies_floor(
        self, held: ProjectRole, required: ProjectRole, expected: bool
    ) -> None:
        assert role_satisfies(held, required) is expected


class TestFullMatrix:
    """Every (role, action) pair decides exactly as the table says."""

    @pytest.mark.parametrize(("role", "action"), _ALL_PAIRS)
    def test_decision_matches_the_table(
        self,
        engine: PolicyEngine,
        user_for: UserFor,
        membership_for: MembershipFor,
        role: ProjectRole,
        action: Action,
    ) -> None:
        required = action_required_role(action)
        decision = engine.can(user_for(role), action, membership_for(role))
        if role in ROLES_SATISFYING_TIER[required]:
            assert action_allowed(role, action)
            assert decision == Decision.allow()
        else:
            assert not action_allowed(role, action)
            assert decision == Decision.deny("insufficient_role", required_role=required)

    @pytest.mark.parametrize(("role", "action"), _ALL_PAIRS)
    def test_floor_and_action_agree_except_for_the_audit_tier(
        self, role: ProjectRole, action: Action
    ) -> None:
        # The only place a rank comparison and the action table differ is
        # an operator asking for the audit tier: the floor would admit it,
        # the action table does not.
        required = action_required_role(action)
        by_floor = role_satisfies(role, required)
        by_action = action_allowed(role, action)
        if role is ProjectRole.OPERATOR and required is ProjectRole.AUDITOR:
            assert by_floor and not by_action
        else:
            assert by_floor is by_action


class TestSeparationOfDuties:
    """The named guarantees the auditor role exists for."""

    AUDIT_ACTIONS = (
        Action.READ_AUDIT,
        Action.EXPORT_AUDIT,
        Action.VERIFY_AUDIT,
        Action.READ_AUDIT_FORWARDER_STATUS,
    )

    @pytest.mark.parametrize("action", AUDIT_ACTIONS)
    def test_audit_actions_belong_to_the_auditor_tier(self, action: Action) -> None:
        assert action_required_role(action) == ProjectRole.AUDITOR

    @pytest.mark.parametrize("action", AUDIT_ACTIONS)
    def test_auditor_and_admin_read_the_trail(
        self,
        engine: PolicyEngine,
        user_for: UserFor,
        membership_for: MembershipFor,
        action: Action,
    ) -> None:
        for role in (ProjectRole.AUDITOR, ProjectRole.ADMIN):
            assert engine.can(user_for(role), action, membership_for(role)).allowed

    @pytest.mark.parametrize("action", AUDIT_ACTIONS)
    def test_viewer_and_operator_do_not_read_the_trail(
        self,
        engine: PolicyEngine,
        user_for: UserFor,
        membership_for: MembershipFor,
        action: Action,
    ) -> None:
        for role in (ProjectRole.VIEWER, ProjectRole.OPERATOR):
            decision = engine.can(user_for(role), action, membership_for(role))
            assert not decision.allowed, role
            assert decision.reason == "insufficient_role"
            assert decision.required_role == ProjectRole.AUDITOR

    def test_auditor_holds_every_viewer_action_and_no_other(self) -> None:
        auditor_can = {a for a in Action if action_allowed(ProjectRole.AUDITOR, a)}
        assert (
            auditor_can
            == ACTIONS_BY_ROLE[ProjectRole.VIEWER] | ACTIONS_BY_ROLE[ProjectRole.AUDITOR]
        )

    def test_operator_holds_every_viewer_action_and_the_operator_tier_only(self) -> None:
        operator_can = {a for a in Action if action_allowed(ProjectRole.OPERATOR, a)}
        assert (
            operator_can
            == ACTIONS_BY_ROLE[ProjectRole.VIEWER] | ACTIONS_BY_ROLE[ProjectRole.OPERATOR]
        )

    def test_admin_holds_everything(self) -> None:
        assert all(action_allowed(ProjectRole.ADMIN, a) for a in Action)

    @pytest.mark.parametrize(
        "action",
        sorted(ACTIONS_BY_ROLE[ProjectRole.OPERATOR] | ACTIONS_BY_ROLE[ProjectRole.ADMIN]),
    )
    def test_auditor_changes_nothing(
        self,
        engine: PolicyEngine,
        auditor_user: User,
        auditor_membership: Membership,
        action: Action,
    ) -> None:
        decision = engine.can(auditor_user, action, auditor_membership)
        assert not decision.allowed
        assert decision.required_role in (ProjectRole.OPERATOR, ProjectRole.ADMIN)

    @pytest.mark.parametrize(
        "action",
        [
            Action.MINT_AGENT_TOKEN,
            Action.REVOKE_AGENT_TOKEN,
            Action.ROTATE_PROJECT_SECRET,
            Action.MANAGE_MEMBERS,
            Action.READ_MEMBERS,
            Action.DELETE_PROJECT,
            Action.CREATE_SCHEDULE,
            Action.UPDATE_SCHEDULE,
            Action.DELETE_SCHEDULE,
            Action.PURGE_QUEUE,
            Action.DELETE_TASKS,
        ],
    )
    def test_admin_only_actions_stay_admin_only(self, action: Action) -> None:
        assert action_required_role(action) == ProjectRole.ADMIN

    @pytest.mark.parametrize(
        "action",
        [
            Action.RETRY_TASK,
            Action.CANCEL_TASK,
            Action.BULK_RETRY,
            Action.REQUEUE_DEAD_LETTER,
            Action.RESTART_WORKER,
            Action.ENABLE_SCHEDULE,
            Action.DISABLE_SCHEDULE,
            Action.PAUSE_SCHEDULE,
            Action.RESUME_SCHEDULE,
            Action.TRIGGER_SCHEDULE,
        ],
    )
    def test_commands_and_schedule_control_are_operator_tier(self, action: Action) -> None:
        assert action_required_role(action) == ProjectRole.OPERATOR


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
    cross-tenant access" at this layer - even an ``is_admin=True`` user
    must be handed a membership; the brain synthesises one for its
    instance-admin tier before asking.
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
