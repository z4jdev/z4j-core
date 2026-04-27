"""Project domain model.

A project is a logical grouping - typically "one app in one
environment," e.g. ``acme-web-prod``. It owns agents, tasks, queues,
workers, schedules, commands, and audit entries.
"""

from __future__ import annotations

import re
from datetime import datetime
from uuid import UUID

from pydantic import Field, field_validator

from z4j_core.models._base import Z4JModel

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")


class Project(Z4JModel):
    """A project - the top-level scoping unit in z4j.

    Projects contain everything else. Agents authenticate to a single
    project. Users are granted access to projects via memberships.
    Retention policies, rate limits, and other settings live on the
    project.

    Attributes:
        id: Opaque UUID primary key.
        slug: URL-safe identifier. Lowercase, ``a-z0-9-``, 2-63 chars,
              starts with alphanum. Used in ``/projects/{slug}`` URLs.
        name: Human-readable display name.
        description: Optional long-form description.
        environment: Free-form label for the environment
                     (``development``, ``staging``, ``production``, ...).
        timezone: IANA timezone name used for schedule display.
        retention_days: Per-project override for event retention
                        (default 30 days).
        is_active: Soft-delete flag. Inactive projects are hidden from
                   the dashboard but their data is retained.
        created_at: UTC timestamp the project was created.
        updated_at: UTC timestamp of last mutation.
    """

    id: UUID
    slug: str = Field(min_length=2, max_length=63)
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    environment: str = Field(default="production", max_length=40)
    timezone: str = Field(default="UTC", max_length=100)
    retention_days: int = Field(default=30, ge=1, le=3650)
    is_active: bool = True
    created_at: datetime
    updated_at: datetime

    @field_validator("slug")
    @classmethod
    def _validate_slug(cls, value: str) -> str:
        if not _SLUG_RE.match(value):
            raise ValueError(
                "slug must match ^[a-z0-9][a-z0-9-]{1,62}$ "
                "(lowercase letters, digits, and hyphens)",
            )
        return value


__all__ = ["Project"]
