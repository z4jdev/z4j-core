"""Unit tests for the z4j-core Pydantic domain models.

Focus on the boundary behavior that matters in production:

- ``extra="forbid"`` rejects unknown fields
- ``frozen=True`` rejects post-construction mutation
- ``strict=True`` rejects silent type coercion
- field validators enforce their contracts
"""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import UUID

import pytest
from pydantic import ValidationError

from z4j_core.models import (
    Agent,
    AgentState,
    Project,
    ProjectRole,
    Task,
    TaskState,
    User,
)


class TestProject:
    """Project model validation."""

    def test_valid_project_parses(self) -> None:
        now = datetime(2026, 4, 11, 12, 0, 0, tzinfo=UTC)
        p = Project(
            id=UUID("00000000-0000-4000-8000-000000000001"),
            slug="sandbox",
            name="Sandbox",
            description=None,
            environment="development",
            timezone="UTC",
            retention_days=30,
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        assert p.slug == "sandbox"

    def test_slug_rejects_uppercase(self) -> None:
        with pytest.raises(ValidationError):
            Project(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                slug="Sandbox",
                name="Sandbox",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_slug_rejects_underscore(self) -> None:
        with pytest.raises(ValidationError):
            Project(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                slug="my_project",
                name="Sandbox",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_slug_rejects_leading_hyphen(self) -> None:
        with pytest.raises(ValidationError):
            Project(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                slug="-foo",
                name="Sandbox",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_unknown_field_is_rejected(self) -> None:
        with pytest.raises(ValidationError):
            Project(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                slug="sandbox",
                name="Sandbox",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
                new_field_from_future_version="oops",  # type: ignore[call-arg]
            )

    def test_is_frozen(self, project: Project) -> None:
        with pytest.raises(ValidationError):
            project.slug = "other"  # type: ignore[misc]

    def test_retention_days_bounded(self) -> None:
        with pytest.raises(ValidationError):
            Project(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                slug="sandbox",
                name="Sandbox",
                retention_days=0,
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )


class TestTask:
    """Task model validation."""

    def test_defaults_are_sensible(self) -> None:
        now = datetime.now(UTC)
        t = Task(
            id=UUID("00000000-0000-4000-8000-000000000001"),
            project_id=UUID("00000000-0000-4000-8000-000000000002"),
            engine="celery",
            task_id="abc123",
            name="myapp.tasks.send_email",
            created_at=now,
            updated_at=now,
        )
        assert t.state == TaskState.PENDING
        assert t.retry_count == 0
        assert t.tags == []

    def test_runtime_ms_must_be_non_negative(self) -> None:
        now = datetime.now(UTC)
        with pytest.raises(ValidationError):
            Task(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                project_id=UUID("00000000-0000-4000-8000-000000000002"),
                engine="celery",
                task_id="abc123",
                name="myapp.tasks.send_email",
                runtime_ms=-1,
                created_at=now,
                updated_at=now,
            )


class TestUser:
    """User model validation."""

    def test_email_is_required(self) -> None:
        with pytest.raises(ValidationError):
            User(  # type: ignore[call-arg]
                id=UUID("00000000-0000-4000-8000-000000000001"),
                display_name="admin",
                is_admin=True,
                is_active=True,
                force_password_change=False,
                timezone="UTC",
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )

    def test_email_must_be_valid(self) -> None:
        with pytest.raises(ValidationError):
            User(
                id=UUID("00000000-0000-4000-8000-000000000001"),
                email="not-an-email",  # type: ignore[arg-type]
                created_at=datetime.now(UTC),
                updated_at=datetime.now(UTC),
            )


class TestAgent:
    """Agent model validation."""

    def test_state_defaults_to_unknown(self) -> None:
        now = datetime.now(UTC)
        a = Agent(
            id=UUID("00000000-0000-4000-8000-000000000001"),
            project_id=UUID("00000000-0000-4000-8000-000000000002"),
            name="web-01",
            token_hash="0" * 64,
            protocol_version="1",
            framework_adapter="django",
            engine_adapters=["celery"],
            scheduler_adapters=["celery-beat"],
            created_at=now,
            updated_at=now,
        )
        assert a.state == AgentState.UNKNOWN


class TestEnums:
    """Enum values are stable strings."""

    def test_task_state_values(self) -> None:
        assert TaskState.PENDING.value == "pending"
        assert TaskState.SUCCESS.value == "success"
        assert TaskState.FAILURE.value == "failure"

    def test_project_role_values(self) -> None:
        assert ProjectRole.VIEWER.value == "viewer"
        assert ProjectRole.OPERATOR.value == "operator"
        assert ProjectRole.ADMIN.value == "admin"
