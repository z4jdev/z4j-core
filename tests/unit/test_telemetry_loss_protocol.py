"""Health loss counters survive the signed fast path with their bounds intact."""

import json
from typing import Any
from uuid import uuid4

import pytest
from z4j_core.errors import ProtocolError
from z4j_core.transport.frames import (
    AgentStatusFrame,
    AgentStatusPayload,
    HeartbeatFrame,
    HeartbeatPayload,
    TelemetryLossPayload,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import sign_envelope


@pytest.mark.parametrize(
    "frame_cls,payload_cls",
    [
        (HeartbeatFrame, HeartbeatPayload),
        (AgentStatusFrame, AgentStatusPayload),
    ],
)
@pytest.mark.parametrize("invalid", [None, -1, True, 2**53])
def test_signed_loss_roundtrip_and_bounds(
    frame_cls: Any, payload_cls: Any, invalid: int | None
) -> None:
    identity: dict[str, Any] = {
        "agent_id": str(uuid4()),
        "project_id": str(uuid4()),
        "session_id": str(uuid4()),
    }
    secret = b"loss-regression-secret-32-bytes!!"
    signer = FrameSigner(secret=secret, **identity)
    verifier = FrameVerifier(secret=secret, **identity)
    loss = TelemetryLossPayload(
        buffer_id="buffer", runtime_id="runtime", event_records=7, adapter_events={"rq": 3}
    )
    wire = signer.sign_and_serialize(
        frame_cls(id=str(uuid4()), payload=payload_cls(telemetry_loss=loss))
    )
    if invalid is not None:
        raw = json.loads(wire)
        raw["payload"]["telemetry_loss"]["adapter_events"]["rq"] = invalid
        raw["hmac"] = sign_envelope(secret, {**raw, **identity})
        with pytest.raises(ProtocolError, match="invalid telemetry loss"):
            verifier.parse_and_verify(json.dumps(raw).encode())
        # Invalid payload did not consume the sequence/nonce.
    parsed = verifier.parse_and_verify(wire)
    assert isinstance(parsed, (HeartbeatFrame, AgentStatusFrame))
    assert parsed.payload.telemetry_loss is not None
    assert parsed.payload.telemetry_loss == loss
    assert parsed.payload.telemetry_loss.adapter_events["rq"] == 3


def test_old_heartbeat_reports_unavailable_loss() -> None:
    identity: dict[str, Any] = {
        "agent_id": str(uuid4()),
        "project_id": str(uuid4()),
        "session_id": str(uuid4()),
    }
    secret = b"x" * 32
    signer = FrameSigner(secret=secret, **identity)
    raw = json.loads(
        signer.sign_and_serialize(HeartbeatFrame(id=str(uuid4()), payload=HeartbeatPayload()))
    )
    del raw["payload"]["telemetry_loss"]
    raw["hmac"] = sign_envelope(secret, {**raw, **identity})
    parsed = FrameVerifier(secret=secret, **identity).parse_and_verify(json.dumps(raw).encode())
    assert isinstance(parsed, HeartbeatFrame)
    assert parsed.payload.telemetry_loss is None
