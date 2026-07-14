"""Tests for the keyed purge confirm token (M-7).

The security property under test: the token is a *keyed* HMAC, and the
brain (which keys with ``derive_project_secret``) and the agent (which
keys with the base64-decoded ``Z4J_HMAC_SECRET``) compute the SAME token
for the same ``(queue, depth)``. A party who can only observe the depth
cannot forge or refresh it.
"""

from __future__ import annotations

import base64
import hashlib
import uuid

import pytest
from z4j_core.purge_token import (
    compute_purge_confirm_token,
    legacy_purge_confirm_token,
    verify_purge_confirm_token,
)
from z4j_core.transport.hmac import decode_agent_hmac_secret, derive_project_secret

_MASTER = b"m" * 48  # >= 32 bytes
_PID = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _brain_secret() -> bytes:
    return derive_project_secret(_MASTER, _PID)


def _agent_secret() -> bytes:
    # Exactly what the brain mints into CreateAgentResponse.hmac_secret,
    # then decoded the way the agent does.
    minted = base64.urlsafe_b64encode(_brain_secret()).decode("ascii")
    return decode_agent_hmac_secret(minted)


class TestKeyAgreement:
    def test_brain_and_agent_derive_identical_secret(self) -> None:
        assert _agent_secret() == _brain_secret()

    def test_brain_and_agent_compute_identical_token(self) -> None:
        brain = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="emails",
            queue_depth=42,
        )
        agent = compute_purge_confirm_token(
            secret=_agent_secret(),
            queue_name="emails",
            queue_depth=42,
        )
        assert brain == agent

    def test_keyed_differs_from_legacy_unkeyed(self) -> None:
        keyed = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="emails",
            queue_depth=42,
        )
        legacy = legacy_purge_confirm_token(queue_name="emails", queue_depth=42)
        assert keyed != legacy
        # Legacy is a bare sha256 that ANYONE can compute.
        assert legacy == hashlib.sha256(b"purge|emails|42").hexdigest()

    def test_token_binds_to_queue_and_depth(self) -> None:
        base = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="emails",
            queue_depth=42,
        )
        assert base != compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="emails",
            queue_depth=43,
        )
        assert base != compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="other",
            queue_depth=42,
        )

    def test_different_secret_yields_different_token(self) -> None:
        other = derive_project_secret(_MASTER, uuid.uuid4())
        a = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="q",
            queue_depth=1,
        )
        b = compute_purge_confirm_token(
            secret=other,
            queue_name="q",
            queue_depth=1,
        )
        assert a != b


class TestVerify:
    def test_keyed_token_accepted(self) -> None:
        tok = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="q",
            queue_depth=5,
        )
        assert verify_purge_confirm_token(
            provided=tok,
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
        ) == (True, False)

    def test_legacy_token_accepted_only_with_flag(self) -> None:
        legacy = legacy_purge_confirm_token(queue_name="q", queue_depth=5)
        # With the explicit opt-in, legacy is accepted during the grace
        # window even when a secret is present.
        assert verify_purge_confirm_token(
            provided=legacy,
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
            accept_legacy=True,
        ) == (True, True)
        # And when the agent has no secret, legacy is the only option.
        assert verify_purge_confirm_token(
            provided=legacy,
            queue_name="q",
            queue_depth=5,
            secret=None,
            accept_legacy=True,
        ) == (True, True)

    def test_legacy_token_rejected_by_default(self) -> None:
        # SECURE DEFAULT: the depth-observer-forgeable legacy token is
        # rejected unless the operator explicitly opts in.
        legacy = legacy_purge_confirm_token(queue_name="q", queue_depth=5)
        assert verify_purge_confirm_token(
            provided=legacy,
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
        ) == (False, False)
        assert verify_purge_confirm_token(
            provided=legacy,
            queue_name="q",
            queue_depth=5,
            secret=None,
        ) == (False, False)

    def test_wrong_token_rejected(self) -> None:
        assert verify_purge_confirm_token(
            provided="0" * 64,
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
        ) == (False, False)

    def test_empty_token_rejected(self) -> None:
        assert verify_purge_confirm_token(
            provided="",
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
        ) == (False, False)

    def test_token_from_wrong_secret_rejected(self) -> None:
        forged = compute_purge_confirm_token(
            secret=derive_project_secret(_MASTER, uuid.uuid4()),
            queue_name="q",
            queue_depth=5,
        )
        assert verify_purge_confirm_token(
            provided=forged,
            queue_name="q",
            queue_depth=5,
            secret=_agent_secret(),
        ) == (False, False)

    def test_stale_depth_rejected(self) -> None:
        tok = compute_purge_confirm_token(
            secret=_brain_secret(),
            queue_name="q",
            queue_depth=5,
        )
        # Agent re-measures a different depth -> mismatch.
        assert verify_purge_confirm_token(
            provided=tok,
            queue_name="q",
            queue_depth=6,
            secret=_agent_secret(),
        ) == (False, False)


class TestDecode:
    def test_roundtrip(self) -> None:
        raw = b"\x00\x01\x02" * 11  # 33 bytes, includes a zero byte
        enc = base64.urlsafe_b64encode(raw).decode("ascii")
        assert decode_agent_hmac_secret(enc) == raw

    def test_missing_padding_restored(self) -> None:
        raw = _brain_secret()
        enc = base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")
        assert decode_agent_hmac_secret(enc) == raw

    @pytest.mark.parametrize("bad", ["", "   ", "not!base64!"])
    def test_rejects_bad_input(self, bad: str) -> None:
        with pytest.raises(ValueError):
            decode_agent_hmac_secret(bad)
