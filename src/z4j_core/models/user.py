"""User and membership domain models.

Brain dashboard users - not customer end-users. Phase 1 uses simple
email/password authentication with argon2id hashes. Phase 3+ adds
SSO (SAML/OIDC) - the user model does not need to change for that,
only the auth module gains new code paths.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import EmailStr, Field

from z4j_core.models._base import Z4JModel


class ProjectRole(StrEnum):
    """Role a user holds within a specific project.

    - ``viewer`` - read-only access to all project data.
    - ``operator`` - viewer plus the ability to issue commands
      (retry, cancel, bulk retry, schedule CRUD).
    - ``admin`` - operator plus the ability to manage memberships,
      retention, rate limits, and agent tokens.
    """

    VIEWER = "viewer"
    OPERATOR = "operator"
    ADMIN = "admin"


class User(Z4JModel):
    """A brain dashboard user.

    Attributes:
        id: Opaque UUID.
        email: Case-insensitive email. Unique across the system.
        display_name: Human-readable name. Optional.
        is_admin: Global admin flag. Grants project-creation and
                  user-management rights, but does NOT automatically
                  grant any per-project role. Global admins must still
                  be explicitly added as members of projects they want
                  to view - this is deliberate, to prevent silent
                  cross-tenant access.
        is_active: Soft-deactivation flag. Inactive users cannot log
                   in but their historical audit entries are retained.
        force_password_change: True if the user must change their
                               password on the next successful login.
                               Set by admin-created accounts.
        timezone: IANA timezone used to render timestamps in the UI.
        last_login_at: Timestamp of the most recent successful login.
        created_at: When the user was created.
        updated_at: When the user record was last modified.
    """

    id: UUID
    email: EmailStr
    display_name: str | None = Field(default=None, max_length=200)
    is_admin: bool = False
    is_active: bool = True
    force_password_change: bool = False
    timezone: str = Field(default="UTC", max_length=100)
    last_login_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class Membership(Z4JModel):
    """A user's role within a specific project.

    Memberships are the unit of access control. A user can be a
    member of many projects with different roles in each.

    Attributes:
        id: Opaque UUID.
        user_id: The user this membership applies to.
        project_id: The project the user has access to.
        role: The role granted.
        created_at: When the membership was created.
    """

    id: UUID
    user_id: UUID
    project_id: UUID
    role: ProjectRole = ProjectRole.VIEWER
    created_at: datetime


__all__ = ["Membership", "ProjectRole", "User"]
