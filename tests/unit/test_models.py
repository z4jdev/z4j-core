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
    CatchUpPolicy,
    Project,
    ProjectRole,
    Schedule,
    ScheduleKind,
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


class TestSchedule:
    """Schedule model parses every wire-protocol field brain emits.

    The fields ``catch_up``, ``source``, and ``source_hash`` were
    added to brain's SQLAlchemy schedules table by the z4j-scheduler
    work but were initially missing from the core Pydantic model.
    Because :class:`~z4j_core.models._base.Z4JModel` sets
    ``extra="forbid"``, the absence of these fields here would cause
    every external SDK consumer that calls ``GET /api/schedules`` to
    fail with ``ValidationError`` on a perfectly normal response.
    These tests pin the wire shape.
    """

    def _now(self) -> datetime:
        return datetime(2026, 4, 27, 12, 0, 0, tzinfo=UTC)

    def _base_kwargs(self) -> dict:
        now = self._now()
        return {
            "id": UUID("00000000-0000-4000-8000-000000000001"),
            "project_id": UUID("00000000-0000-4000-8000-000000000002"),
            "engine": "celery",
            "scheduler": "celery-beat",
            "name": "nightly-report",
            "task_name": "reports.nightly",
            "kind": ScheduleKind.CRON,
            "expression": "0 3 * * *",
            "created_at": now,
            "updated_at": now,
        }

    def test_defaults_match_brain_server_defaults(self) -> None:
        s = Schedule(**self._base_kwargs())
        # These three defaults must match the brain SQLAlchemy
        # server_default values exactly. If the defaults drift the
        # round-trip via JSON will silently change semantics.
        assert s.catch_up is CatchUpPolicy.SKIP
        assert s.source == "dashboard"
        assert s.source_hash is None

    def test_parses_full_brain_payload(self) -> None:
        s = Schedule(
            **self._base_kwargs(),
            catch_up=CatchUpPolicy.FIRE_ONE_MISSED,
            source="declarative:django",
            source_hash="a" * 64,
        )
        assert s.catch_up is CatchUpPolicy.FIRE_ONE_MISSED
        assert s.source == "declarative:django"
        assert s.source_hash == "a" * 64

    def test_catch_up_rejects_unknown_string(self) -> None:
        # CatchUpPolicy is a StrEnum - unknown strings must fail.
        # This guards against typos in declarative reconcilers.
        with pytest.raises(ValidationError):
            Schedule(**self._base_kwargs(), catch_up="fire_some_missed")

    def test_source_max_length_enforced(self) -> None:
        with pytest.raises(ValidationError):
            Schedule(**self._base_kwargs(), source="x" * 65)

    def test_source_hash_max_length_enforced(self) -> None:
        with pytest.raises(ValidationError):
            Schedule(**self._base_kwargs(), source_hash="a" * 129)

    def test_unknown_field_still_rejected(self) -> None:
        # Adding the new fields must not regress extra="forbid".
        with pytest.raises(ValidationError):
            Schedule(**self._base_kwargs(), totally_made_up=True)


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

    def test_catch_up_policy_values(self) -> None:
        # Wire vocabulary is what brain stores in the catch_up column.
        assert CatchUpPolicy.SKIP.value == "skip"
        assert CatchUpPolicy.FIRE_ONE_MISSED.value == "fire_one_missed"
        assert CatchUpPolicy.FIRE_ALL_MISSED.value == "fire_all_missed"
