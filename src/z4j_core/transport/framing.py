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

    __slots__ = (
        "_secret", "_agent_id", "_project_id", "_session_id", "_next_seq",
    )

    def __init__(
        self,
        *,
        secret: bytes,
        agent_id: str | UUID,
        project_id: str | UUID,
        session_id: str | UUID | None = None,
        initial_seq: int = 1,
    ) -> None:
        if len(secret) < 32:
            raise ValueError("FrameSigner secret must be at least 32 bytes")
        self._secret = secret
        self._agent_id = str(agent_id)
        self._project_id = str(project_id)
        # Round-9 audit fix R9-Wire-H1+H2 (Apr 2026): bind the
        # session_id into the signed envelope. Pre-fix the seq
        # counter and nonce window were instance-scoped — they
        # reset to 0 on every reconnect — so an attacker who
        # captured a frame from session N could replay it inside
        # session N+1 (seq > 0, ts within the 60s skew window,
        # nonce never seen by the new instance). Binding session_id
        # makes the captured frame's HMAC fail against the new
        # session's verifier, since the verifier reconstitutes the
        # envelope with the NEW session_id and the bytes signed
        # under the OLD one no longer match.
        #
        # Optional for backwards compat with existing tests +
        # legacy callers that haven't been updated. Production
        # call sites in gateway.py / websocket.py supply it from
        # the HelloAck payload.
        self._session_id = str(session_id) if session_id is not None else ""
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
        # R9-Wire-H1+H2: also bind session_id so cross-session
        # replays fail at HMAC verify, not just at the per-instance
        # nonce window.
        envelope["session_id"] = self._session_id
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

    __slots__ = (
        "_secret", "_agent_id", "_project_id", "_session_id", "_guard",
    )

    def __init__(
        self,
        *,
        secret: bytes,
        agent_id: str | UUID,
        project_id: str | UUID,
        session_id: str | UUID | None = None,
        direction: str = "inbound",
    ) -> None:
        if len(secret) < 32:
            raise ValueError("FrameVerifier secret must be at least 32 bytes")
        self._secret = secret
        self._agent_id = str(agent_id)
        self._project_id = str(project_id)
        # Round-9 audit fix R9-Wire-H1+H2 (Apr 2026): see
        # FrameSigner above. Binds the verifier to one session so a
        # captured frame from a previous session fails HMAC.
        self._session_id = str(session_id) if session_id is not None else ""
        self._guard = ReplayGuard(direction=direction)

    def parse_and_verify(self, data: bytes | str) -> Frame:
        """Parse + authenticate + replay-check an inbound frame.

        Handshake frames (``hello`` / ``hello_ack``) are returned
        without HMAC / replay checks because the session binding
        is still being established. Every other frame MUST be an
        :class:`_SignedFrameBase` subclass with a valid envelope.
        """
        from z4j_core.transport.frames import (  # noqa: PLC0415
            HelloAckFrame, HelloFrame,
        )

        frame = parse_frame(data)
        if frame.v != PROTOCOL_VERSION:
            raise ProtocolError(
                f"unsupported frame version {frame.v!r}, "
                f"expected {PROTOCOL_VERSION}",
            )

        # Round-9 audit fix R9-Wire-MED (Apr 2026): explicit
        # ALLOW-LIST for unsigned frames rather than negative
        # ``not isinstance(_SignedFrameBase)``. Future frame types
        # added to the union must be either a subclass of
        # ``_SignedFrameBase`` (signed) OR explicitly listed here
        # (unsigned handshake) — anything else is rejected with a
        # ProtocolError. Closes the silent-bypass risk where a new
        # frame class accidentally inherits from neither
        # ``_SignedFrameBase`` nor the handshake set.
        _UNSIGNED_FRAME_TYPES = (HelloFrame, HelloAckFrame)
        if isinstance(frame, _UNSIGNED_FRAME_TYPES):
            return frame
        if not isinstance(frame, _SignedFrameBase):
            raise ProtocolError(
                f"frame type {type(frame).__name__} is neither a "
                "signed frame nor a known handshake frame; refusing "
                "to bypass HMAC verification",
            )

        # Reconstitute the envelope the sender signed over.
        envelope = frame.model_dump(mode="json")
        envelope["agent_id"] = self._agent_id
        envelope["project_id"] = self._project_id
        # R9-Wire-H1+H2: include session_id so a frame signed
        # under a different session's binding fails verification.
        envelope["session_id"] = self._session_id

        # Order matters: check HMAC FIRST so an attacker who hasn't
        # broken the signature cannot probe our replay state.
        verify_envelope(self._secret, envelope)
        self._guard.check(envelope)
        return frame


__all__ = [
    "FrameSigner",
    "FrameVerifier",
]
