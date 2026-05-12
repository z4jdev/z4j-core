"""Tests for the 1.5.1 signed-frame fast-path leak fix.

Covers ``FrameVerifier._verify_signed_fast``: HMAC verification,
replay-guard interaction, datetime coercion, and shape-sanity
defences. The slow path (handshake frames) is also exercised so
both paths produce equivalent typed frames.

See ``RELEASE-1.5.1-LEAK-FIX-DESIGN.md`` for the design rationale
and the empirical pass/fail thresholds these tests support.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from z4j_core.errors import ProtocolError, SignatureError
from z4j_core.transport.frames import (
    EventBatchFrame,
    EventBatchPayload,
    HeartbeatFrame,
    HeartbeatPayload,
    HelloFrame,
    HelloPayload,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signer_verifier_pair(
    *, secret: bytes | None = None,
) -> tuple[FrameSigner, FrameVerifier]:
    """Build a matched signer/verifier with a shared session binding."""
    secret = secret or b"x" * 32
    agent_id = str(uuid4())
    project_id = str(uuid4())
    session_id = str(uuid4())
    signer = FrameSigner(
        secret=secret,
        agent_id=agent_id,
        project_id=project_id,
        session_id=session_id,
    )
    verifier = FrameVerifier(
        secret=secret,
        agent_id=agent_id,
        project_id=project_id,
        session_id=session_id,
    )
    return signer, verifier


def _build_event_batch(n_events: int = 3) -> EventBatchFrame:
    return EventBatchFrame(
        id=str(uuid4()),
        payload=EventBatchPayload(
            events=[
                {"engine": "celery", "task_id": str(uuid4()), "kind": "started"}
                for _ in range(n_events)
            ],
        ),
    )


# ---------------------------------------------------------------------------
# Round-trip equivalence: fast path produces a usable Frame
# ---------------------------------------------------------------------------


class TestRoundTrip:
    def test_event_batch_round_trip(self) -> None:
        signer, verifier = _signer_verifier_pair()
        frame = _build_event_batch(n_events=5)
        wire = signer.sign_and_serialize(frame)

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, EventBatchFrame)
        assert parsed.id == frame.id
        assert len(parsed.payload.events) == 5
        assert parsed.payload.events[0]["engine"] == "celery"
        # Frame-level ts was set by the signer; fast path must coerce
        # the ISO string back to a datetime so downstream consumers
        # (frame_router L715: ``frame.ts or datetime.now(UTC)``) work.
        assert isinstance(parsed.ts, datetime)

    def test_heartbeat_round_trip_with_datetime_payload_field(self) -> None:
        signer, verifier = _signer_verifier_pair()
        last_flush = datetime.now(UTC) - timedelta(minutes=2)
        frame = HeartbeatFrame(
            id=str(uuid4()),
            payload=HeartbeatPayload(
                buffer_size=42,
                last_flush_at=last_flush,
                dropped_events=0,
                adapter_health={"celery": "ok"},
            ),
        )
        wire = signer.sign_and_serialize(frame)

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, HeartbeatFrame)
        # last_flush_at must be coerced ISO string -> datetime so
        # downstream attribute access keeps working.
        assert isinstance(parsed.payload.last_flush_at, datetime)
        # Compare to second precision (wire format is ISO with
        # microsecond precision; this is a wider tolerance to absorb
        # any timezone normalisation in the round trip).
        delta = abs(
            (parsed.payload.last_flush_at - last_flush).total_seconds()
        )
        assert delta < 1.0
        assert parsed.payload.buffer_size == 42
        assert parsed.payload.adapter_health == {"celery": "ok"}

    def test_empty_event_batch_round_trip(self) -> None:
        signer, verifier = _signer_verifier_pair()
        frame = _build_event_batch(n_events=0)
        wire = signer.sign_and_serialize(frame)

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, EventBatchFrame)
        assert parsed.payload.events == []


# ---------------------------------------------------------------------------
# Security: HMAC verify, replay guard, session binding
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_tampered_payload_rejected(self) -> None:
        signer, verifier = _signer_verifier_pair()
        frame = _build_event_batch()
        wire = signer.sign_and_serialize(frame)
        # Flip a byte inside the events list (the agent-controlled
        # part of the payload). HMAC over the canonical envelope
        # MUST fail.
        d = json.loads(wire)
        d["payload"]["events"][0]["kind"] = "tampered"
        tampered_wire = json.dumps(d).encode()

        with pytest.raises(SignatureError):
            verifier.parse_and_verify(tampered_wire)

    def test_tampered_hmac_rejected(self) -> None:
        signer, verifier = _signer_verifier_pair()
        frame = _build_event_batch()
        wire = signer.sign_and_serialize(frame)
        d = json.loads(wire)
        # Flip one char in the HMAC. The recompute won't match.
        original = d["hmac"]
        d["hmac"] = ("0" if original[0] != "0" else "1") + original[1:]
        tampered_wire = json.dumps(d).encode()

        with pytest.raises(SignatureError):
            verifier.parse_and_verify(tampered_wire)

    def test_cross_session_replay_rejected(self) -> None:
        # Frame signed under session A must not verify under session B.
        secret = b"y" * 32
        agent_id = str(uuid4())
        project_id = str(uuid4())
        signer_a = FrameSigner(
            secret=secret, agent_id=agent_id, project_id=project_id,
            session_id="session-A",
        )
        verifier_b = FrameVerifier(
            secret=secret, agent_id=agent_id, project_id=project_id,
            session_id="session-B",
        )
        wire = signer_a.sign_and_serialize(_build_event_batch())

        with pytest.raises(SignatureError):
            verifier_b.parse_and_verify(wire)

    def test_replay_guard_rejects_duplicate(self) -> None:
        signer, verifier = _signer_verifier_pair()
        wire = signer.sign_and_serialize(_build_event_batch())

        # First parse succeeds; the same wire bytes a second time
        # MUST be rejected by the replay guard (nonce already used +
        # seq not strictly increasing).
        verifier.parse_and_verify(wire)
        with pytest.raises(SignatureError):
            verifier.parse_and_verify(wire)


# ---------------------------------------------------------------------------
# Slow path (handshake) preserved
# ---------------------------------------------------------------------------


class TestHandshakeSlowPath:
    def test_hello_frame_takes_slow_path(self) -> None:
        # Hello is an unsigned frame -- no HMAC, no replay. The
        # dispatcher must NOT touch it with the fast path.
        secret = b"z" * 32
        verifier = FrameVerifier(
            secret=secret,
            agent_id=str(uuid4()),
            project_id=str(uuid4()),
            session_id=str(uuid4()),
        )
        hello = HelloFrame(
            id=str(uuid4()),
            payload=HelloPayload(
                protocol_version="2",
                agent_version="1.5.1",
                framework="bare",
                engines=["celery"],
                schedulers=[],
            ),
        )
        wire = serialize_frame(hello)

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, HelloFrame)
        assert parsed.payload.framework == "bare"


# ---------------------------------------------------------------------------
# Dispatcher errors: malformed input, unknown types, version mismatch
# ---------------------------------------------------------------------------


class TestDispatcherErrors:
    def test_non_json_input_rejected(self) -> None:
        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolError, match="not valid JSON"):
            verifier.parse_and_verify(b"not-json")

    def test_non_object_json_rejected(self) -> None:
        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolError, match="must decode to a JSON object"):
            verifier.parse_and_verify(b"[1, 2, 3]")

    def test_missing_type_field_rejected(self) -> None:
        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolError, match="missing required"):
            verifier.parse_and_verify(b'{"id": "x"}')

    def test_unknown_type_rejected(self) -> None:
        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolError, match="unknown frame type"):
            verifier.parse_and_verify(b'{"type": "foo", "v": 2}')

    def test_wrong_protocol_version_rejected_on_fast_path(self) -> None:
        # Build a syntactically-correct envelope claiming v=99 for a
        # signed frame type. The fast path's shape sanity check must
        # reject before touching HMAC.
        _, verifier = _signer_verifier_pair()
        bad = json.dumps({
            "v": 99,
            "type": "event_batch",
            "id": "x",
            "payload": {"events": []},
        }).encode()
        with pytest.raises(ProtocolError, match="unsupported frame version"):
            verifier.parse_and_verify(bad)

    def test_non_object_payload_rejected(self) -> None:
        # Payload claiming to be a list (rather than dict) must fail
        # the shape sanity before HMAC.
        _, verifier = _signer_verifier_pair()
        bad = json.dumps({
            "v": 2,
            "type": "event_batch",
            "id": "x",
            "payload": [1, 2, 3],
        }).encode()
        with pytest.raises(ProtocolError, match="payload must be a JSON object"):
            verifier.parse_and_verify(bad)
