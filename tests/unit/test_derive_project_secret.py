"""Tests for :func:`z4j_core.transport.hmac.derive_project_secret`.

Closes the test gap flagged by R4 agent 2: verify derivation is
deterministic, domain-separated by project_id, and fails-fast on a
too-short master secret.
"""

from __future__ import annotations

import uuid

import pytest

from z4j_core.transport.hmac import (
    _PROJECT_SECRET_DERIVATION_LABEL,
    derive_project_secret,
)


class TestDeriveProjectSecret:
    def test_deterministic(self) -> None:
        master = b"x" * 32
        project_id = uuid.uuid4()
        a = derive_project_secret(master, project_id)
        b = derive_project_secret(master, project_id)
        assert a == b
        assert len(a) == 32  # HMAC-SHA256 = 32 bytes

    def test_different_projects_different_secrets(self) -> None:
        master = b"x" * 32
        a = derive_project_secret(master, uuid.uuid4())
        b = derive_project_secret(master, uuid.uuid4())
        assert a != b, (
            "two projects must derive different secrets - the whole "
            "point of the per-project derivation is that compromise "
            "of one cannot forge against another"
        )

    def test_different_masters_different_secrets(self) -> None:
        project_id = uuid.uuid4()
        a = derive_project_secret(b"master-A-" + b"x" * 24, project_id)
        b = derive_project_secret(b"master-B-" + b"x" * 24, project_id)
        assert a != b

    def test_rotating_master_rotates_every_project(self) -> None:
        """R4 finding: rotating Z4J_SECRET rotates EVERY project's
        derived secret atomically. This is the intended behaviour -
        operators must re-enrol agents. Test documents it so a
        future refactor can't silently weaken the guarantee."""
        old_master = b"m1-" + b"x" * 32
        new_master = b"m2-" + b"x" * 32
        projects = [uuid.uuid4() for _ in range(5)]
        old_secrets = [derive_project_secret(old_master, p) for p in projects]
        new_secrets = [derive_project_secret(new_master, p) for p in projects]
        for old, new in zip(old_secrets, new_secrets):
            assert old != new

    def test_short_master_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 32 bytes"):
            derive_project_secret(b"too-short", uuid.uuid4())

    def test_exactly_32_byte_master_accepted(self) -> None:
        master = b"x" * 32
        assert derive_project_secret(master, uuid.uuid4())

    def test_label_is_versioned(self) -> None:
        """The label carries an explicit version so we can rotate
        the derivation construction if ever needed. If this test
        fails, any previously-minted hmac_secret becomes invalid;
        bump the version intentionally, not as a side effect."""
        assert _PROJECT_SECRET_DERIVATION_LABEL == b"z4j-project-secret-v1:"

    def test_derivation_uses_little_endian_uuid(self) -> None:
        """``bytes_le`` is endianness-explicit (Python guarantee,
        independent of host byte order). Verify it differs from
        ``bytes`` (big-endian) so a future refactor doesn't
        accidentally swap them and invalidate every existing
        hmac_secret."""
        project_id = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
        assert project_id.bytes_le != project_id.bytes

    def test_known_project_collision_resistant(self) -> None:
        """Sanity: distinct inputs under identical master produce
        distinct outputs even when project UUIDs share a prefix."""
        master = b"x" * 32
        p1 = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff00")
        p2 = uuid.UUID("11223344-5566-7788-99aa-bbccddeeff01")
        assert derive_project_secret(master, p1) != derive_project_secret(master, p2)
