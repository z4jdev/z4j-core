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

    # Round-9 audit fix R9-Wire-LOW (Apr 2026): tighten nonce cap.
    # ``make_nonce()`` returns ``secrets.token_urlsafe(16)`` = 22
    # chars; the prior 64-cap let a peer ship 64-byte nonces and
    # bloat the OrderedDict's per-entry size 3×. 32 covers any
    # reasonable encoding of 16 random bytes.
    nonce: str = Field(default="", max_length=32)
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

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): cap list/dict
    # cardinality on every wire-frame payload. Pre-fix a single
    # signed handshake could carry a 10M-element ``engines`` list
    # or ``capabilities`` dict, OOM-walking the validator before
    # the WS gateway's frame-bytes cap kicked in. The values below
    # are 100x any realistic agent (a fleet shipping 5 engines and
    # 3 schedulers with ~10 capabilities each).
    protocol_version: str = Field(max_length=40)
    agent_version: str = Field(max_length=40)
    framework: str = Field(max_length=40)
    engines: list[str] = Field(default_factory=list, max_length=64)
    schedulers: list[str] = Field(default_factory=list, max_length=64)
    capabilities: dict[str, list[str]] = Field(default_factory=dict)
    host: dict[str, Any] = Field(default_factory=dict)

    # Worker-first protocol fields (1.2.0+). All optional + additive:
    # an agent that omits these is treated as a single-connection
    # 1.1.x agent; an agent that sends them is registered as a
    # discrete worker under its agent_id, and the brain accepts
    # multiple concurrent connections sharing the same agent_id
    # (one per worker). Pre-1.2.0 agents (no worker_id) keep the
    # historical "one connection per agent_id" contract.
    #
    # ``worker_id`` is a stable identifier for THIS process. Agents
    # generate it from ``<framework>-<pid>-<start_unix_ms>`` so two
    # gunicorn workers on the same host with the same agent_token
    # never collide. The brain treats (agent_id, worker_id) as the
    # composite primary key for the worker connection.
    #
    # ``worker_role`` is one of "web" / "task" / "scheduler" /
    # "beat" / "other" / None. Each framework/engine adapter
    # declares its own role hint (django/flask/fastapi -> web;
    # celery/rq/dramatiq/huey/arq/taskiq -> task; celerybeat ->
    # beat; z4j-scheduler -> scheduler). Used by the dashboard
    # for filtering and by alert rules ("any web worker dying").
    worker_id: str | None = Field(default=None, max_length=128)
    worker_role: str | None = Field(default=None, max_length=32)
    worker_pid: int | None = Field(default=None, ge=0, le=2**31 - 1)
    worker_started_at: datetime | None = None


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

    # Round-9 audit fix R9-Wire-LOW (Apr 2026): mirror the caps
    # already on HelloPayload so a hostile/buggy peer can't ship a
    # 100MB string in any handshake field. Pre-handshake DoS
    # surface, Pydantic walks each string before HMAC check.
    protocol_version: str = Field(max_length=40)
    brain_version: str = Field(max_length=40)
    agent_id: str = Field(max_length=64)
    project_id: str = Field(max_length=64)
    session_id: str = Field(max_length=64)
    heartbeat_interval_seconds: int = Field(default=10, ge=1, le=3600)
    max_frame_size_bytes: int = Field(default=1_048_576, ge=1024, le=64 * 1024 * 1024)


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

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): hard cap on the
    # ``events`` list. The WS gateway's bytes cap and the
    # frame-router's iteration cap (R7) are both downstream of
    # Pydantic parse time, without this, the validator walks an
    # unbounded list before either kicks in. 5000 is generous
    # (500 is the agent's batcher ceiling) and far below the
    # pre-existing 1 MiB frame-bytes cap.
    events: list[dict[str, Any]] = Field(
        default_factory=list, max_length=5000,
    )


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

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): bounded counters and
    # adapter_health. ``ge=0`` is already enforced; we add a sanity
    # ``le`` cap on ints so a hostile heartbeat can't poison
    # downstream metric exporters with int64-max values.
    buffer_size: int = Field(default=0, ge=0, le=10_000_000)
    last_flush_at: datetime | None = None
    dropped_events: int = Field(default=0, ge=0, le=10_000_000)
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

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): bound the command
    # envelope. ``action`` is a known short token; ``issued_by``
    # is a UUID string; ``target`` and ``parameters`` are still
    # ``dict`` (per-command shape varies) but the WS gateway's
    # frame-bytes cap remains the outer bound.
    action: str = Field(max_length=80)
    target: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    timeout_seconds: int = Field(default=60, ge=1, le=3600)
    issued_by: str | None = Field(default=None, max_length=64)


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
    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): ``error`` is rendered
    # in the audit log + dashboard; cap to keep a hostile or buggy
    # adapter from inflating either by emitting a 100MB traceback.
    error: str | None = Field(default=None, max_length=8192)


# ---------------------------------------------------------------------------
# 5) registry_delta
# ---------------------------------------------------------------------------


class RegistryDeltaFrame(_SignedFrameBase):
    """Incremental update to the agent's known task registry."""

    type: Literal["registry_delta"] = "registry_delta"
    payload: "RegistryDeltaPayload"


class RegistryDeltaPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026): cap registry-delta
    # cardinality. A typical adapter ships 10-200 task definitions;
    # 10000 covers monorepo-scale projects with substantial headroom
    # while bounding the validator walk.
    engine: str = Field(max_length=40)
    added: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)
    removed: list[str] = Field(default_factory=list, max_length=10_000)
    updated: list[dict[str, Any]] = Field(default_factory=list, max_length=10_000)


# ---------------------------------------------------------------------------
# 6) error
# ---------------------------------------------------------------------------


class ErrorFrame(_SignedFrameBase):
    """Non-fatal or fatal error report from one peer to the other."""

    type: Literal["error"] = "error"
    payload: "ErrorPayload"


class ErrorPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    # Round-8 audit fix R8-Pyd-H1 (Apr 2026).
    code: str = Field(max_length=80)
    message: str = Field(max_length=8192)
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
    # Round-9 audit fix R9-Wire-H4 (Apr 2026): refuse to serialise
    # ``NaN`` / ``Infinity`` / ``-Infinity`` (``allow_nan=False``).
    # Pre-fix Python's ``json.dumps`` emitted them as bare literals
    # which (a) are NOT valid JSON, so any peer using strict JSON
    # parsers (Pydantic via ``validate_json``) rejects after the
    # signer signed OK, asymmetric verification failure that's
    # invisible to the signing side; and (b) any payload carrying
    # an integer value that survives a JS / msgpack round-trip and
    # comes back as a float (``1`` → ``1.0``) re-canonicalises
    # differently and breaks HMAC. Refusing NaN/Inf is a strict
    # SHOULD per RFC 7159; the round-trip int/float shape requires
    # contract discipline at the agent (we can't auto-canonicalise
    # ints from floats without losing precision).
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
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
