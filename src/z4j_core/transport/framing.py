"""High-level sign / verify helpers for protocol v2 frames.

The agent and the brain both need to:

1. Build an outbound frame, stamp ``ts``, ``nonce``, ``seq``,
   inject ``agent_id`` + ``project_id`` into the signing envelope,
   HMAC it, and serialise to bytes.
2. Parse an inbound frame, check ``agent_id``/``project_id`` bind
   to this session, verify the envelope HMAC, and enforce
   replay-guard rules (freshness, seq monotonicity, nonce
   uniqueness).

This module factors both flows so the agent-side and brain-side
code paths cannot drift. Any protocol-level security bug fixed
here fixes both sides simultaneously.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from z4j_core.errors import ProtocolError, SignatureError
from z4j_core.transport.frames import (
    PROTOCOL_VERSION,
    Frame,
    _SignedFrameBase,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.hmac import (
    make_nonce,
    sign_envelope,
    verify_envelope,
)
from z4j_core.transport.replay import ReplayGuard


class FrameSigner:
    """Stateful signer for outbound frames on one direction of one session.

    Holds the per-session seq counter + the secret. Callers build a
    Pydantic frame with placeholder ``nonce`` / ``seq`` / ``hmac``
    values and call :meth:`sign_and_serialize` to finalise it.

    Not thread-safe. Each direction of each session owns its own
    :class:`FrameSigner`.
    """

    __slots__ = ("_secret", "_agent_id", "_project_id", "_next_seq")

    def __init__(
        self,
        *,
        secret: bytes,
        agent_id: str | UUID,
        project_id: str | UUID,
        initial_seq: int = 1,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("FrameSigner secret must be at least 32 bytes")
        self._secret = secret
        self._agent_id = str(agent_id)
        self._project_id = str(project_id)
        self._next_seq = int(initial_seq)

    def sign_and_serialize(self, frame: _SignedFrameBase) -> bytes:
        """Finalise a signed frame: stamp freshness/nonce/seq + HMAC + serialise.

        The frame's ``ts``, ``nonce``, ``seq``, and ``hmac`` fields
        are overwritten - the caller is expected to leave them as
        placeholders (e.g. ``nonce=""``, ``seq=0``, ``hmac=""``).
        """
        frame.ts = datetime.now(timezone.utc)
        frame.nonce = make_nonce()
        frame.seq = self._next_seq
        self._next_seq += 1
        # Inject session-binding fields into the envelope before
        # signing. They are NOT Pydantic fields on the frame (they
        # are implied by the session) but they are part of the
        # signed bytes so the receiver can verify binding.
        envelope = frame.model_dump(mode="json")
        envelope["agent_id"] = self._agent_id
        envelope["project_id"] = self._project_id
        frame.hmac = sign_envelope(self._secret, envelope)
        return serialize_frame(frame)


class FrameVerifier:
    """Stateful verifier for inbound frames on one direction of one session.

    Wraps :class:`ReplayGuard` + :func:`verify_envelope` + session-
    binding check. Call :meth:`parse_and_verify` with the raw bytes
    received off the wire; the result is a validated typed
    :class:`Frame` union.

    Raises :class:`SignatureError` on any security failure
    (signature mismatch, replayed seq/nonce, stale ts, wrong
    session binding) - the caller MUST close the session + log +
    increment a security counter on any exception.
    """

    __slots__ = ("_secret", "_agent_id", "_project_id", "_guard")

    def __init__(
        self,
        *,
        secret: bytes,
        agent_id: str | UUID,
        project_id: str | UUID,
        direction: str = "inbound",
    ) -> None:
        if len(secret) < 32:
            raise ValueError("FrameVerifier secret must be at least 32 bytes")
        self._secret = secret
        self._agent_id = str(agent_id)
        self._project_id = str(project_id)
        self._guard = ReplayGuard(direction=direction)

    def parse_and_verify(self, data: bytes | str) -> Frame:
        """Parse + authenticate + replay-check an inbound frame.

        Handshake frames (``hello`` / ``hello_ack``) are returned
        without HMAC / replay checks because the session binding
        is still being established. Every other frame MUST be an
        :class:`_SignedFrameBase` subclass with a valid envelope.
        """
        frame = parse_frame(data)
        if frame.v != PROTOCOL_VERSION:
            raise ProtocolError(
                f"unsupported frame version {frame.v!r}, "
                f"expected {PROTOCOL_VERSION}",
            )

        # Handshake frames do not carry HMAC - they establish the
        # session binding. The caller (gateway / agent-transport)
        # authenticates them via bearer token.
        if not isinstance(frame, _SignedFrameBase):
            return frame

        # Reconstitute the envelope the sender signed over.
        envelope = frame.model_dump(mode="json")
        envelope["agent_id"] = self._agent_id
        envelope["project_id"] = self._project_id

        # Order matters: check HMAC FIRST so an attacker who hasn't
        # broken the signature cannot probe our replay state.
        verify_envelope(self._secret, envelope)
        self._guard.check(envelope)
        return frame


__all__ = [
    "FrameSigner",
    "FrameVerifier",
]
