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

import json
from datetime import UTC, datetime
from typing import Any, cast
from uuid import UUID

from pydantic import BaseModel

from z4j_core.errors import ProtocolError, ProtocolVersionError
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

# ---------------------------------------------------------------------------
# Signed-frame fast-path tables (1.5.1 leak fix)
#
# The slow path runs full Pydantic ``validate_json`` for every inbound
# frame. Under sustained 100+ t/s burst load that produces tracemalloc-
# top retention of ``EventBatchFrame`` instance graphs (~22 retained
# objects per frame * ~1000 frames/s = the leak). After HMAC verify
# the bytes are proven to come from our own agent, so Pydantic's strict
# type-coercion is redundant defense-in-depth -- we can construct the
# typed model directly via ``model_construct`` and skip the validators.
#
# Builds maps lazily at import time:
#   _SIGNED_FRAME_CLASS_BY_TYPE  - frame class for each signed type
#   _SIGNED_PAYLOAD_CLASS_BY_TYPE - payload class for each signed type
#   _DATETIME_PAYLOAD_FIELDS     - per-type list of payload field names
#                                  that are datetime-typed and need
#                                  string -> datetime coercion after
#                                  model_construct
#
# ---------------------------------------------------------------------------


def _build_signed_frame_tables() -> tuple[
    dict[str, type[_SignedFrameBase]],
    dict[str, type[BaseModel]],
    dict[str, frozenset[str]],
]:
    from z4j_core.transport.frames import (
        AgentStatusFrame,
        AgentStatusPayload,
        CommandAckFrame,
        CommandAckPayload,
        CommandFrame,
        CommandPayload,
        CommandResultFrame,
        CommandResultPayload,
        ErrorFrame,
        ErrorPayload,
        EventBatchAckFrame,
        EventBatchAckPayload,
        EventBatchFrame,
        EventBatchPayload,
        HeartbeatFrame,
        HeartbeatPayload,
        RegistryDeltaFrame,
        RegistryDeltaPayload,
    )

    frame_by_type: dict[str, type[_SignedFrameBase]] = {
        "event_batch": EventBatchFrame,
        "event_batch_ack": EventBatchAckFrame,
        "heartbeat": HeartbeatFrame,
        "command": CommandFrame,
        "command_ack": CommandAckFrame,
        "command_result": CommandResultFrame,
        "registry_delta": RegistryDeltaFrame,
        "error": ErrorFrame,
        "agent_status": AgentStatusFrame,
    }
    # Payload class per signed frame type. Every current signed frame
    # declares a typed Pydantic payload; the fast path must construct that
    # nested model explicitly because ``model_construct`` does not recurse.
    payload_by_type: dict[str, type[BaseModel]] = {
        "event_batch": EventBatchPayload,
        "event_batch_ack": EventBatchAckPayload,
        "heartbeat": HeartbeatPayload,
        "command": CommandPayload,
        "command_ack": CommandAckPayload,
        "command_result": CommandResultPayload,
        "registry_delta": RegistryDeltaPayload,
        "error": ErrorPayload,
        "agent_status": AgentStatusPayload,
    }
    # Per-type set of payload fields that are ``datetime | None``. The
    # fast path leaves these as ISO strings after model_construct;
    # this table tells us which to coerce. Audited against
    # frames.py 2026-05-11 (only 2 payload datetimes outside the
    # handshake): HeartbeatPayload.last_flush_at + AgentStatusPayload.
    # last_successful_connect_at. Frame-level ``ts`` is coerced
    # separately in every type.
    datetime_payload_fields: dict[str, frozenset[str]] = {
        "heartbeat": frozenset({"last_flush_at"}),
        "agent_status": frozenset({"last_successful_connect_at"}),
    }
    return frame_by_type, payload_by_type, datetime_payload_fields


(
    _SIGNED_FRAME_CLASS_BY_TYPE,
    _SIGNED_PAYLOAD_CLASS_BY_TYPE,
    _DATETIME_PAYLOAD_FIELDS,
) = _build_signed_frame_tables()


def _coerce_iso_datetime(value: Any) -> Any:
    """Convert an ISO-8601 string to a datetime; pass through everything else.

    Used by the signed-frame fast path to restore datetime typing on
    fields where ``model_construct`` skipped Pydantic's coercion.
    ``None`` and already-typed ``datetime`` instances pass through
    unchanged. Anything else that can't be parsed surfaces as the
    raw value (rare; agent code is ours so malformed shapes are
    contract violations, not attacks).
    """
    if value is None or isinstance(value, datetime):
        return value
    if isinstance(value, str) and value:
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    return value


_AGENT_COMMAND_RESULT_STATUSES = frozenset({"success", "failed"})


def _validate_authenticated_payload_semantics(
    frame_type: str,
    payload: dict[str, Any] | None,
) -> None:
    """Pin security-relevant Literals skipped by the signed-frame fast path.

    Full Pydantic parsing limits an agent ``command_result`` to ``success`` or
    ``failed``.  The fast path intentionally uses ``model_construct`` after
    HMAC authentication, which otherwise bypasses that Literal and would let a
    compromised or buggy agent inject brain-owned ``timeout`` state.  Keep this
    check after HMAC verification (so unsigned input cannot probe semantics)
    but before replay or application state is mutated.
    """
    if frame_type != "command_result":
        return
    status = payload.get("status") if payload is not None else None
    if type(status) is not str or status not in _AGENT_COMMAND_RESULT_STATUSES:
        raise ProtocolError(
            "command_result payload status must be 'success' or 'failed'",
        )


class FrameSigner:
    """Stateful signer for outbound frames on one direction of one session.

    Holds the per-session seq counter + the secret. Callers build a
    Pydantic frame with placeholder ``nonce`` / ``seq`` / ``hmac``
    values and call :meth:`sign_and_serialize` to finalise it.

    Not thread-safe. Each direction of each session owns its own
    :class:`FrameSigner`.
    """

    __slots__ = (
        "_agent_id",
        "_next_seq",
        "_project_id",
        "_secret",
        "_session_id",
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
        # Bind the session_id into the signed envelope. The seq
        # counter and nonce window are instance-scoped and reset
        # to 0 on every reconnect, so without session binding an
        # attacker who captured a frame from session N could replay
        # it inside session N+1 (seq > 0, ts within the 60s skew
        # window, nonce never seen by the new instance). Binding
        # session_id makes the captured frame's HMAC fail against
        # the new session's verifier, since the verifier
        # reconstitutes the envelope with the NEW session_id and
        # the bytes signed under the OLD one no longer match.
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
        frame.ts = datetime.now(UTC)
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
        # Also bind session_id so cross-session replays fail at
        # HMAC verify, not just at the per-instance nonce window.
        envelope["session_id"] = self._session_id
        frame.hmac = sign_envelope(self._secret, envelope)
        return serialize_frame(cast(Frame, frame))


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
        "_agent_id",
        "_guard",
        "_project_id",
        "_secret",
        "_session_id",
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
        # See
        # FrameSigner above. Binds the verifier to one session so a
        # captured frame from a previous session fails HMAC.
        self._session_id = str(session_id) if session_id is not None else ""
        self._guard = ReplayGuard(direction=direction)

    def parse_and_verify(self, data: bytes | str) -> Frame:
        """Parse + authenticate + replay-check an inbound frame.

        Dispatches on frame ``type``:

        - **Handshake** (``hello`` / ``hello_ack``): slow path
          (full Pydantic validation) since the session binding is
          still being established and these frames are infrequent
          (one per session).
        - **Signed frames** (every other type): fast path
          (1.5.1 leak fix). Parses minimally, HMAC-verifies on the
          raw dict, then constructs the typed Frame via
          ``model_construct`` without re-running Pydantic
          validation. After HMAC verify the bytes are proven to
          come from our agent code, so validation is redundant
          defense-in-depth -- the leak shape under sustained burst
          load made it operationally expensive.

        Both paths share identical security semantics: HMAC FIRST
        (so an attacker without the signature cannot probe replay
        state), then replay guard.
        """
        # Peek at the type discriminator without paying the full
        # validation cost. ``json.loads`` is C-implemented and
        # returns plain dicts; that's all we need to dispatch.
        if isinstance(data, (bytes, bytearray, memoryview)):
            raw_bytes_or_str: bytes | str = bytes(data)
        else:
            raw_bytes_or_str = data
        try:
            raw_dict: Any = json.loads(raw_bytes_or_str)
        except (json.JSONDecodeError, TypeError) as exc:
            raise ProtocolError(f"frame is not valid JSON: {exc}") from exc

        if not isinstance(raw_dict, dict):
            raise ProtocolError(
                f"frame must decode to a JSON object, got {type(raw_dict).__name__}",
            )
        # Version gate FIRST -- before the type dispatch -- so a frame from a
        # peer on a DIFFERENT protocol version raises the RECOVERABLE
        # ProtocolVersionError (retry against an upgraded replica) even when
        # the version bump also introduced a new frame TYPE this peer does
        # not know: without this, that frame surfaces as an unknown-type
        # ProtocolError and is drop-acked, losing a frame an upgraded replica
        # would store. ONLY an INT ``v`` that differs is a recoverable
        # skew; a wrong-TYPE ``v`` (string / bool / float) is MALFORMED
        # content -- a plain ProtocolError so it is drop-acked, not retried
        # forever as if a version bump would fix it (round-8 external
        # M-malformed-version). A missing ``v`` falls through to the type
        # checks below.
        version = raw_dict.get("v")
        if type(version) is int:
            if version != PROTOCOL_VERSION:
                raise ProtocolVersionError(
                    f"unsupported frame version {version!r}, expected {PROTOCOL_VERSION}",
                )
        elif version is not None:
            raise ProtocolError(
                f"frame ``v`` must be an integer, got {type(version).__name__}",
            )
        frame_type = raw_dict.get("type")
        if not isinstance(frame_type, str):
            raise ProtocolError("frame missing required ``type`` field")

        # Handshake frames go through the full Pydantic path. These
        # are infrequent (one HelloFrame + one HelloAckFrame per
        # session) so the validation cost is negligible.
        if frame_type in ("hello", "hello_ack"):
            return self._verify_unsigned(raw_bytes_or_str)

        # Signed frames take the fast path.
        if frame_type not in _SIGNED_FRAME_CLASS_BY_TYPE:
            raise ProtocolError(
                f"unknown frame type {frame_type!r}; refusing to process",
            )
        return self._verify_signed_fast(raw_dict, frame_type)

    def _verify_unsigned(self, data: bytes | str) -> Frame:
        """Full-Pydantic slow path for handshake frames.

        Same behaviour as the pre-1.5.1 ``parse_and_verify``: validate
        + version check + return without HMAC / replay (the session
        binding is still being negotiated, no shared secret yet).
        """
        from z4j_core.transport.frames import (
            HelloAckFrame,
            HelloFrame,
        )

        frame = parse_frame(data)
        if frame.v != PROTOCOL_VERSION:
            raise ProtocolVersionError(
                f"unsupported frame version {frame.v!r}, expected {PROTOCOL_VERSION}",
            )
        if not isinstance(frame, (HelloFrame, HelloAckFrame)):
            # Defence-in-depth: dispatcher already filtered, but if
            # a future frame class accidentally claims a handshake
            # type discriminator without subclassing the right base,
            # we refuse to bypass HMAC.
            raise ProtocolError(
                f"frame type {type(frame).__name__} claims a handshake "
                "discriminator but is not a known handshake frame; "
                "refusing to bypass HMAC verification",
            )
        return frame

    def _verify_signed_fast(
        self,
        raw_dict: dict[str, Any],
        frame_type: str,
    ) -> Frame:
        """Fast path for signed frames -- HMAC verify then model_construct.

        Saves ~22 retained Pydantic-validator objects per frame vs the
        slow path (Wave A tracemalloc baseline). Under sustained
        100+ t/s burst this is the dominant leak source addressed by
        this commit.

        Security invariants are identical to the slow path:
        - HMAC over the canonical envelope MUST verify before any
          state mutation.
        - Replay guard enforced after HMAC.
        - Protocol version must match ``PROTOCOL_VERSION``.
        - Frame type must be in the signed allow-list.

        Bypassed (intentional, with rationale):
        - Most field-level Pydantic constraints (``ge``, ``le``,
          ``max_length``) on typed envelope fields. The agent code
          is ours; after HMAC, malformed shapes are agent bugs, not
          attacks. Security-relevant control Literals are pinned by
          :func:`_validate_authenticated_payload_semantics`. The WS
          gateway's bytes cap (1 MiB per frame) remains the outer DoS
          bound.
        - Strict-mode field validation. ``model_construct`` accepts
          whatever JSON values the wire delivered, while still constructing
          the typed nested payload model required by downstream attribute
          access.
        """
        # ------------------------------------------------------------
        # Light shape sanity (the §7 safety net from the design doc).
        # Cheap checks that catch agent-code regressions FAST without
        # paying the full Pydantic price.
        # ------------------------------------------------------------
        # By here parse_and_verify's top gate has already raised a
        # ProtocolVersionError for an INT ``v`` that differs, so any ``v``
        # that still fails this equality is missing/None (a wrong TYPE was
        # rejected there too) -- i.e. MALFORMED, not a recoverable skew. Raise
        # a plain ProtocolError so it is drop-acked, not retried forever
        # (round-8 external M-malformed-version).
        if raw_dict.get("v") != PROTOCOL_VERSION:
            raise ProtocolError(
                f"frame ``v`` missing or invalid: {raw_dict.get('v')!r}, "
                f"expected {PROTOCOL_VERSION}",
            )
        payload = raw_dict.get("payload")
        if payload is not None and not isinstance(payload, dict):
            raise ProtocolError(
                f"signed frame payload must be a JSON object, got {type(payload).__name__}",
            )

        # ------------------------------------------------------------
        # HMAC verify on the raw wire dict + session binding fields.
        # ``verify_envelope`` strips the ``hmac`` key and runs
        # ``canonical_json`` -- identical to the slow path because
        # ``serialize_frame`` and ``frame.model_dump(mode="json")``
        # produce structurally identical dicts for the same frame.
        # ------------------------------------------------------------
        envelope: dict[str, Any] = {**raw_dict}
        envelope["agent_id"] = self._agent_id
        envelope["project_id"] = self._project_id
        envelope["session_id"] = self._session_id

        verify_envelope(self._secret, envelope)
        _validate_authenticated_payload_semantics(frame_type, payload)
        self._guard.check(envelope)

        # ------------------------------------------------------------
        # Construct the typed Frame instance WITHOUT validation.
        # ``model_construct`` skips field validators, type coercion,
        # and constraint checks but produces a real Pydantic
        # instance that downstream code (``frame.payload.events``,
        # ``frame.ts``, etc.) treats identically to the slow path.
        # ------------------------------------------------------------
        frame_cls = _SIGNED_FRAME_CLASS_BY_TYPE[frame_type]
        payload_cls = _SIGNED_PAYLOAD_CLASS_BY_TYPE.get(frame_type)

        # Separate the payload from the envelope so we can construct
        # the nested payload model first (model_construct does not
        # recurse).
        frame_kwargs = {k: v for k, v in raw_dict.items() if k != "payload"}

        # Coerce frame-level ``ts`` ISO string -> datetime so
        # downstream code that does ``frame.ts.timestamp()`` or
        # ``frame.ts or datetime.now(UTC)`` works identically.
        if "ts" in frame_kwargs:
            frame_kwargs["ts"] = _coerce_iso_datetime(frame_kwargs["ts"])

        if payload_cls is None:
            # Reserved for a future signed frame that deliberately declares
            # an untyped payload. Every current signed frame is registered
            # with a typed payload class above.
            constructed_payload: Any = payload if payload is not None else {}
        else:
            payload_dict = dict(payload) if payload else {}
            # Coerce known datetime fields in the payload before
            # constructing the typed model (so attribute access yields
            # datetime, not str).
            for dt_field in _DATETIME_PAYLOAD_FIELDS.get(frame_type, ()):
                if dt_field in payload_dict:
                    payload_dict[dt_field] = _coerce_iso_datetime(
                        payload_dict[dt_field],
                    )
            constructed_payload = payload_cls.model_construct(**payload_dict)

        frame_kwargs["payload"] = constructed_payload
        return cast(Frame, frame_cls.model_construct(**frame_kwargs))


__all__ = [
    "FrameSigner",
    "FrameVerifier",
]
