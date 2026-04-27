"""Shared fixtures for z4j-core unit tests."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest

from z4j_core.models import (
    Agent,
    AgentState,
    Membership,
    Project,
    ProjectRole,
    User,
)

_FIXED_NOW = datetime(2026, 4, 11, 12, 0, 0, tzinfo=UTC)
_FIXED_USER_ID = UUID("00000000-0000-4000-8000-000000000001")
_FIXED_PROJECT_ID = UUID("00000000-0000-4000-8000-000000000002")
_FIXED_AGENT_ID = UUID("00000000-0000-4000-8000-000000000003")
_FIXED_MEMBERSHIP_ID = UUID("00000000-0000-4000-8000-000000000004")


@pytest.fixture
def now() -> datetime:
    """A stable timestamp for use in model fixtures."""
    return _FIXED_NOW


@pytest.fixture
def project() -> Project:
    return Project(
        id=_FIXED_PROJECT_ID,
        slug="sandbox",
        name="Sandbox",
        description=None,
        environment="development",
        timezone="UTC",
        retention_days=30,
        is_active=True,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )


@pytest.fixture
def viewer_user() -> User:
    return User(
        id=_FIXED_USER_ID,
        email="viewer@example.com",
        display_name="Viewer",
        is_admin=False,
        is_active=True,
        force_password_change=False,
        timezone="UTC",
        last_login_at=None,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )


@pytest.fixture
def operator_user() -> User:
    return User(
        id=UUID("00000000-0000-4000-8000-000000000011"),
        email="operator@example.com",
        display_name="Operator",
        is_admin=False,
        is_active=True,
        force_password_change=False,
        timezone="UTC",
        last_login_at=None,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )


@pytest.fixture
def admin_user() -> User:
    return User(
        id=UUID("00000000-0000-4000-8000-000000000012"),
        email="admin@example.com",
        display_name="Admin",
        is_admin=True,
        is_active=True,
        force_password_change=False,
        timezone="UTC",
        last_login_at=None,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )


@pytest.fixture
def inactive_user() -> User:
    return User(
        id=UUID("00000000-0000-4000-8000-000000000013"),
        email="gone@example.com",
        display_name=None,
        is_admin=False,
        is_active=False,
        force_password_change=False,
        timezone="UTC",
        last_login_at=None,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )


@pytest.fixture
def viewer_membership(project: Project, viewer_user: User) -> Membership:
    return Membership(
        id=_FIXED_MEMBERSHIP_ID,
        user_id=viewer_user.id,
        project_id=project.id,
        role=ProjectRole.VIEWER,
        created_at=_FIXED_NOW,
    )


@pytest.fixture
def operator_membership(project: Project, operator_user: User) -> Membership:
    return Membership(
        id=UUID("00000000-0000-4000-8000-000000000021"),
        user_id=operator_user.id,
        project_id=project.id,
        role=ProjectRole.OPERATOR,
        created_at=_FIXED_NOW,
    )


@pytest.fixture
def admin_membership(project: Project, admin_user: User) -> Membership:
    return Membership(
        id=UUID("00000000-0000-4000-8000-000000000022"),
        user_id=admin_user.id,
        project_id=project.id,
        role=ProjectRole.ADMIN,
        created_at=_FIXED_NOW,
    )


@pytest.fixture
def agent(project: Project) -> Agent:
    return Agent(
        id=_FIXED_AGENT_ID,
        project_id=project.id,
        name="sandbox-web-01",
        token_hash="0" * 64,
        protocol_version="1",
        framework_adapter="django",
        engine_adapters=["celery"],
        scheduler_adapters=["celery-beat"],
        state=AgentState.ONLINE,
        last_seen_at=_FIXED_NOW,
        last_connect_at=_FIXED_NOW,
        created_at=_FIXED_NOW,
        updated_at=_FIXED_NOW,
    )
