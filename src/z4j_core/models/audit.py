"""Audit-log domain model.

An :class:`AuditEntry` represents one stored audit record. The brain's
mutating workflows write audit rows transactionally where their
contract requires it; some denial and security breadcrumbs are
best-effort, and an infrastructure failure can prevent such a record.
The model itself does not assert complete one-for-one coverage of every
security-relevant action. The Postgres
``audit_log`` table refuses UPDATE at the trigger level and admits a
DELETE only from a statement that names a recognised transition
(retention and generation reset), which is what keeps an ordinary
application code path, a downgraded adapter, or a hand-run statement
from quietly editing the trail. See ``docs/DATABASE.md §3.11``.

That session setting selects a code path, it does not identify a
caller, and any client holding write access to the table can set it
for itself. The trail's evidence value therefore ends at the database
boundary; see the threat model in ``docs/SECURITY.md``.
"""

from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import Any
from uuid import UUID

from pydantic import Field

from z4j_core.models._base import Z4JModel


class AuditEntry(Z4JModel):
    """A single audit-log entry. Frozen once constructed, like every
    model here; see the module docstring for what the stored row's
    append-only property does and does not cover.

    Attributes:
        id: Opaque UUID.
        project_id: Project the action was scoped to, if any.
                    Global actions (e.g. first-boot setup) have None.
        user_id: User who performed the action, if any. System-level
                 actions have None.
        action: Dotted action identifier. Stable across releases.
                Examples: ``command.retry_task``, ``user.login``,
                ``user.login_failed``, ``project.retention_changed``,
                ``agent.token_minted``, ``agent.token_revoked``,
                ``setup.admin_created``.
        target_type: Kind of thing the action touched (``task``,
                     ``user``, ``project``, ``agent``, ``schedule``, ...).
        target_id: Identifier of the specific target.
        result: One of ``"success"``, ``"denied"``, ``"error"``.
        metadata: Additional structured context. Should not contain
                  secrets - the redaction engine re-runs before writes.
        source_ip: Client IP address that initiated the action.
        user_agent: Client User-Agent header, if available.
        occurred_at: UTC timestamp the action happened at.
    """

    id: UUID
    project_id: UUID | None = None
    user_id: UUID | None = None
    action: str = Field(min_length=1, max_length=100)
    target_type: str = Field(min_length=1, max_length=40)
    target_id: str | None = Field(default=None, max_length=200)
    result: str = Field(pattern=r"^(success|denied|error)$")
    metadata: dict[str, Any] = Field(default_factory=dict)
    source_ip: IPv4Address | IPv6Address | None = None
    user_agent: str | None = Field(default=None, max_length=500)
    occurred_at: datetime


__all__ = ["AuditEntry"]
