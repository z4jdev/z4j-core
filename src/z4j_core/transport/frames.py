"""Wire-frame Pydantic models and (de)serialization helpers.

Every message the agent and brain exchange is a single JSON object
with a mandatory ``v`` (protocol version), ``type`` (discriminator),
and ``id`` (ULID-ish string used by the peer to ack). The specific
``payload`` shape depends on the frame type.

**Protocol v2 (April 2026)**: every stateful frame in BOTH
directions carries an ``hmac`` over a canonical envelope that
binds ``(v, type, id, ts, nonce, seq, agent_id, project_id,
payload)``. The receiver's :class:`ReplayGuard` additionally
rejects frames whose ``ts`` is outside the skew window, whose
``seq`` is non-monotonic, or whose ``nonce`` has been seen
recently. The only v2 frames that do NOT carry an ``hmac`` are
the two handshake frames (``hello`` / ``hello_ack``) because the
session's agent_id + project_id is still being negotiated; the
brain authenticates those via the bearer token alone, and no
state change happens until after handshake.

v1 is not supported on the wire. See ``docs/SECURITY.md §4.3``.

This module defines one Pydantic model per frame type and a single
:class:`Frame` discriminated union so both sides can parse frames
without caring which specific type they got.

See ``docs/API.md §5`` for the complete protocol reference.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


#: Protocol version. v2 adds a per-frame HMAC envelope covering
#: ``(v, type, id, ts, nonce, seq, agent_id, project_id, payload)``
#: plus strict replay protection (``ReplayGuard``). v1 is not
#: supported on the wire any more - see ``docs/SECURITY.md §4.3``.
PROTOCOL_VERSION: int = 2


class _FrameBase(BaseModel):
    """Shared config for every wire frame.

    Notice that wire frames are NOT frozen - the agent builds them,
    stamps an ``id``, then signs/serializes. They are also not
    ``extra="forbid"`` because new protocol versions may add fields
    to existing frame shapes (additive change - see
    ``docs/API.md §7``); we ignore unknown fields to stay
    forward-compatible within a major version.
    """

    model_config = ConfigDict(
        strict=True,
        extra="ignore",
        populate_by_name=True,
    )

    v: Literal[2] = Field(default=2)
    id: str = Field(min_length=1, max_length=64)
    ts: datetime | None = None


class _SignedFrameBase(_FrameBase):
    """v2 base for every stateful frame.

    ``nonce`` / ``seq`` / ``hmac`` are populated by
    :class:`~z4j_core.transport.framing.FrameSigner` and verified by
    :class:`~z4j_core.transport.framing.FrameVerifier`. The model
    keeps them permissive at parse time (empty string / zero) so the
    outbound buffer can serialize placeholder frames that the signer
    overwrites immediately before they hit the wire; the verifier
    then rejects any incoming frame whose envelope doesn't match.
    """

    nonce: str = Field(default="", max_length=64)
    seq: int = Field(default=0, ge=0)
    hmac: str = Field(default="", max_length=128)


# ---------------------------------------------------------------------------
# 1) hello / hello_ack - handshake frames
# ---------------------------------------------------------------------------


class HelloFrame(_FrameBase):
    """First frame the agent sends on connect.

    Declares the agent's protocol version, framework, engines,
    schedulers, and host info. The brain validates compatibility
    before accepting the connection.
    """

    type: Literal["hello"] = "hello"
    payload: "HelloPayload"


class HelloPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    protocol_version: str
    agent_version: str
    framework: str
    engines: list[str] = Field(default_factory=list)
    schedulers: list[str] = Field(default_factory=list)
    capabilities: dict[str, list[str]] = Field(default_factory=dict)
    host: dict[str, Any] = Field(default_factory=dict)


class HelloAckFrame(_FrameBase):
    """Brain's response to a successful ``hello``.

    Carries the brain's version, the session id, the assigned
    ``agent_id`` and ``project_id``, and runtime tuning parameters
    (heartbeat interval, max frame size).
    """

    type: Literal["hello_ack"] = "hello_ack"
    payload: "HelloAckPayload"


class HelloAckPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    protocol_version: str
    brain_version: str
    agent_id: str
    project_id: str
    session_id: str
    heartbeat_interval_seconds: int = 10
    max_frame_size_bytes: int = 1_048_576


# ---------------------------------------------------------------------------
# 2) event_batch / event_batch_ack - ingestion
# ---------------------------------------------------------------------------


class EventBatchFrame(_SignedFrameBase):
    """A batch of lifecycle events from the agent to the brain.

    The ``payload.events`` list is the hot path - this is the
    highest-volume frame type in the whole protocol. Signed in v2
    so a stolen bearer token alone cannot be used to forge events.
    """

    type: Literal["event_batch"] = "event_batch"
    payload: "EventBatchPayload"


class EventBatchPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    events: list[dict[str, Any]] = Field(default_factory=list)


class EventBatchAckFrame(_SignedFrameBase):
    """Ack for an ``event_batch`` - records how many events the brain took."""

    type: Literal["event_batch_ack"] = "event_batch_ack"
    payload: "EventBatchAckPayload"


class EventBatchAckPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    received: int = Field(ge=0)
    accepted: int = Field(ge=0)
    rejected: int = Field(ge=0)


# ---------------------------------------------------------------------------
# 3) heartbeat
# ---------------------------------------------------------------------------


class HeartbeatFrame(_SignedFrameBase):
    """Periodic agent heartbeat carrying liveness and buffer health.

    Signed in v2 so a stolen bearer cannot spoof worker state /
    poison queue-depth metrics.
    """

    type: Literal["heartbeat"] = "heartbeat"
    payload: "HeartbeatPayload"


class HeartbeatPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    buffer_size: int = Field(default=0, ge=0)
    last_flush_at: datetime | None = None
    dropped_events: int = Field(default=0, ge=0)
    adapter_health: dict[str, str] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# 4) command / command_ack / command_result - actions
# ---------------------------------------------------------------------------


class CommandFrame(_SignedFrameBase):
    """A command the brain is asking the agent to execute.

    In v2 the HMAC covers the full envelope (including ``ts,
    nonce, seq, agent_id, project_id``), not just the payload. The
    agent's :class:`ReplayGuard` rejects captured frames replayed
    outside the 60s skew window AND frames whose seq isn't
    strictly greater than the last-seen seq for this session.
    """

    type: Literal["command"] = "command"
    payload: "CommandPayload"


class CommandPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    action: str
    target: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    issued_by: str | None = None


class CommandAckFrame(_SignedFrameBase):
    """First-stage response - "I received the command."

    Signed in v2 so the brain cannot be fooled into believing a
    destructive command was ack'd by the agent when it wasn't.
    """

    type: Literal["command_ack"] = "command_ack"
    payload: dict[str, Any] = Field(default_factory=dict)


class CommandResultFrame(_SignedFrameBase):
    """Second-stage response - the actual result of executing the command.

    Signed in v2 so a forged success-result cannot close out a
    destructive command in the audit log.
    """

    type: Literal["command_result"] = "command_result"
    payload: "CommandResultPayload"


class CommandResultPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    status: Literal["success", "failed"]
    result: dict[str, Any] | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# 5) registry_delta
# ---------------------------------------------------------------------------


class RegistryDeltaFrame(_SignedFrameBase):
    """Incremental update to the agent's known task registry."""

    type: Literal["registry_delta"] = "registry_delta"
    payload: "RegistryDeltaPayload"


class RegistryDeltaPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    engine: str
    added: list[dict[str, Any]] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    updated: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# 6) error
# ---------------------------------------------------------------------------


class ErrorFrame(_SignedFrameBase):
    """Non-fatal or fatal error report from one peer to the other."""

    type: Literal["error"] = "error"
    payload: "ErrorPayload"


class ErrorPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    code: str
    message: str
    fatal: bool = False


# ---------------------------------------------------------------------------
# Discriminated union + parse/serialize helpers
# ---------------------------------------------------------------------------


Frame = Annotated[
    HelloFrame
    | HelloAckFrame
    | EventBatchFrame
    | EventBatchAckFrame
    | HeartbeatFrame
    | CommandFrame
    | CommandAckFrame
    | CommandResultFrame
    | RegistryDeltaFrame
    | ErrorFrame,
    Field(discriminator="type"),
]
"""Discriminated union of every frame shape on the wire.

Use :func:`parse_frame` to decode from a JSON blob or dict, and
:func:`serialize_frame` to encode. Do not hand-roll - the discriminator
machinery is what makes Pydantic pick the right subtype.
"""


FRAME_TYPES: frozenset[str] = frozenset(
    {
        "hello",
        "hello_ack",
        "event_batch",
        "event_batch_ack",
        "heartbeat",
        "command",
        "command_ack",
        "command_result",
        "registry_delta",
        "error",
    },
)


_frame_adapter: TypeAdapter[Frame] = TypeAdapter(Frame)


def parse_frame(
    data: str | bytes | bytearray | memoryview | dict[str, Any],
) -> Frame:
    """Parse a wire frame from JSON (or a dict) into the typed union.

    Accepts every byte-like buffer the websocket layer might hand us:
    ``bytes``, ``bytearray`` (returned by some asyncio implementations),
    and ``memoryview`` (zero-copy buffer wrappers). Pre-decoded
    dictionaries are also accepted unchanged.

    Bytes / str input goes through Pydantic's JSON validator
    (``validate_json``) rather than ``json.loads + validate_python``
    because the frame models use ``ConfigDict(strict=True)``: in
    strict mode, ``validate_python`` would reject an ISO-8601
    datetime string for a ``datetime`` field, while ``validate_json``
    keeps the lenient JSON-mode coercion that the wire protocol
    requires (we serialize datetimes to ISO strings on send).

    Raises:
        pydantic.ValidationError: If the payload does not match any
                                  known frame shape. Callers should
                                  catch and translate to
                                  :class:`z4j_core.errors.InvalidFrameError`.
    """
    if isinstance(data, (bytes, bytearray, memoryview)):
        return _frame_adapter.validate_json(bytes(data))
    if isinstance(data, str):
        return _frame_adapter.validate_json(data)
    return _frame_adapter.validate_python(data)


def serialize_frame(frame: Frame) -> bytes:
    """Serialize a frame to UTF-8 encoded JSON bytes ready for the wire.

    The output is non-canonical (key order follows the model
    definition). For signing, use :func:`canonical_json` on the
    frame's ``payload`` instead.
    """
    return _frame_adapter.dump_json(frame)


def canonical_json(payload: Any) -> bytes:
    """Canonical JSON rendering of a value, suitable for HMAC signing.

    Canonicalization rules:

    - UTF-8 encoded
    - Sorted dict keys at every level
    - Compact separators (``","`` and ``":"``)
    - ``ensure_ascii=False`` so non-ASCII strings are not re-escaped

    These must match exactly on both sides of the wire or HMAC
    verification will fail.
    """
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=_default_serializer,
    ).encode("utf-8")


def _default_serializer(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


# Rebuild forward references after the module has loaded.
HelloFrame.model_rebuild()
HelloAckFrame.model_rebuild()
EventBatchFrame.model_rebuild()
EventBatchAckFrame.model_rebuild()
HeartbeatFrame.model_rebuild()
CommandFrame.model_rebuild()
CommandAckFrame.model_rebuild()
CommandResultFrame.model_rebuild()
RegistryDeltaFrame.model_rebuild()
ErrorFrame.model_rebuild()


__all__ = [
    "CommandAckFrame",
    "CommandFrame",
    "CommandPayload",
    "CommandResultFrame",
    "CommandResultPayload",
    "ErrorFrame",
    "ErrorPayload",
    "EventBatchAckFrame",
    "EventBatchAckPayload",
    "EventBatchFrame",
    "EventBatchPayload",
    "FRAME_TYPES",
    "Frame",
    "HeartbeatFrame",
    "HeartbeatPayload",
    "HelloAckFrame",
    "HelloAckPayload",
    "HelloFrame",
    "HelloPayload",
    "PROTOCOL_VERSION",
    "RegistryDeltaFrame",
    "RegistryDeltaPayload",
    "canonical_json",
    "parse_frame",
    "serialize_frame",
]
