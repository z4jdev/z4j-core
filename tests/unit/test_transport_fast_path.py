"""Tests for the 1.5.1 signed-frame fast-path leak fix.

Covers ``FrameVerifier._verify_signed_fast``: HMAC verification,
replay-guard interaction, datetime coercion, and shape-sanity
defences. The slow path (handshake frames) is also exercised so
both paths produce equivalent typed frames.

Pins the empirical pass/fail thresholds for the fast-path framing
leak fix.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any, cast, get_args
from uuid import uuid4

import pytest
from pydantic import BaseModel
from z4j_core.errors import ProtocolError, SignatureError
from z4j_core.transport import framing as framing_module
from z4j_core.transport.frames import (
    CommandAckFrame,
    CommandAckPayload,
    CommandResultFrame,
    CommandResultPayload,
    EventBatchFrame,
    EventBatchPayload,
    Frame,
    HeartbeatFrame,
    HeartbeatPayload,
    HelloFrame,
    HelloPayload,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.framing import FrameSigner, FrameVerifier
from z4j_core.transport.hmac import sign_envelope

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _signer_verifier_pair(
    *,
    secret: bytes | None = None,
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


def _signed_command_ack_wire(
    payload: dict[str, object],
) -> tuple[bytes, FrameVerifier]:
    """Build a real signed ACK wire while retaining additive payload fields."""
    secret = b"a" * 32
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
    wire = signer.sign_and_serialize(
        CommandAckFrame(id=str(uuid4()), payload=CommandAckPayload()),
    )
    raw = json.loads(wire)
    raw["payload"] = payload
    envelope = {
        **raw,
        "agent_id": agent_id,
        "project_id": project_id,
        "session_id": session_id,
    }
    raw["hmac"] = sign_envelope(secret, envelope)
    return json.dumps(raw).encode(), verifier


def _signed_command_result_wire(
    status: str,
    *,
    resign: bool,
) -> tuple[bytes, FrameVerifier]:
    """Build a result wire that can exercise values Pydantic rejects."""
    secret = b"r" * 32
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
    wire = signer.sign_and_serialize(
        CommandResultFrame(
            id=str(uuid4()),
            payload=CommandResultPayload(status="success"),
        ),
    )
    raw = json.loads(wire)
    raw["payload"]["status"] = status
    if resign:
        envelope = {
            **raw,
            "agent_id": agent_id,
            "project_id": project_id,
            "session_id": session_id,
        }
        raw["hmac"] = sign_envelope(secret, envelope)
    return json.dumps(raw).encode(), verifier


# ---------------------------------------------------------------------------
# Registry alignment: the fast-path tables must cover the wire-model union
# ---------------------------------------------------------------------------


class TestFastPathTableAlignment:
    def test_signed_frame_and_payload_tables_match_frame_union(self) -> None:
        expected_frames: dict[str, type[BaseModel]] = {}
        expected_payloads: dict[str, type[BaseModel]] = {}
        expected_datetime_fields: dict[str, frozenset[str]] = {}

        frame_union = get_args(Frame)[0]
        for frame_cls in get_args(frame_union):
            if "hmac" not in frame_cls.model_fields:
                continue

            frame_type = frame_cls.model_fields["type"].default
            payload_cls = frame_cls.model_fields["payload"].annotation
            assert isinstance(frame_type, str)
            assert isinstance(payload_cls, type)
            assert issubclass(payload_cls, BaseModel)

            expected_frames[frame_type] = frame_cls
            expected_payloads[frame_type] = payload_cls

            datetime_fields = frozenset(
                field_name
                for field_name, field in payload_cls.model_fields.items()
                if field.annotation is datetime or datetime in get_args(field.annotation)
            )
            if datetime_fields:
                expected_datetime_fields[frame_type] = datetime_fields

        assert expected_frames == framing_module._SIGNED_FRAME_CLASS_BY_TYPE
        assert expected_payloads == framing_module._SIGNED_PAYLOAD_CLASS_BY_TYPE
        assert expected_datetime_fields == framing_module._DATETIME_PAYLOAD_FIELDS


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
        delta = abs((parsed.payload.last_flush_at - last_flush).total_seconds())
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

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"delivery_claim_token": "11111111-1111-4111-8111-111111111111"},
            {
                "delivery_claim_token": "22222222-2222-4222-8222-222222222222",
                "future_additive_field": "ignored",
            },
        ],
    )
    def test_command_ack_fast_path_matches_typed_slow_path(
        self,
        payload: dict[str, object],
    ) -> None:
        wire, verifier = _signed_command_ack_wire(payload)

        parsed_fast = verifier.parse_and_verify(wire)
        parsed_slow = parse_frame(wire)

        assert isinstance(parsed_fast, CommandAckFrame)
        assert isinstance(parsed_fast.payload, CommandAckPayload)
        assert isinstance(parsed_slow, CommandAckFrame)
        assert parsed_fast.payload.model_dump() == parsed_slow.payload.model_dump()

    def test_missing_command_ack_mapping_reproduces_router_attribute_failure(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        wire, verifier = _signed_command_ack_wire(
            {"delivery_claim_token": "33333333-3333-4333-8333-333333333333"},
        )
        monkeypatch.delitem(
            framing_module._SIGNED_PAYLOAD_CLASS_BY_TYPE,
            "command_ack",
        )

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, CommandAckFrame)
        untyped_payload = cast(Any, parsed.payload)
        assert isinstance(untyped_payload, dict)
        attribute_name = "delivery_claim_token"
        with pytest.raises(AttributeError, match="delivery_claim_token"):
            getattr(untyped_payload, attribute_name)

    @pytest.mark.parametrize("status", ["success", "failed"])
    def test_command_result_statuses_remain_fast_path_compatible(
        self,
        status: str,
    ) -> None:
        wire, verifier = _signed_command_result_wire(status, resign=True)

        parsed = verifier.parse_and_verify(wire)

        assert isinstance(parsed, CommandResultFrame)
        assert parsed.payload.status == status


# ---------------------------------------------------------------------------
# Security: HMAC verify, replay guard, session binding
# ---------------------------------------------------------------------------


class TestSecurityInvariants:
    def test_authenticated_timeout_result_is_rejected_without_consuming_replay_state(
        self,
    ) -> None:
        wire, verifier = _signed_command_result_wire("timeout", resign=True)

        # Semantic validation runs after HMAC but before the replay guard. A
        # rejected control frame therefore cannot mutate replay/application
        # state; the same bytes fail for the same fixed semantic reason again.
        for _ in range(2):
            with pytest.raises(
                ProtocolError,
                match="status must be 'success' or 'failed'",
            ):
                verifier.parse_and_verify(wire)

    def test_command_result_hmac_is_checked_before_timeout_semantics(self) -> None:
        wire, verifier = _signed_command_result_wire("timeout", resign=False)

        with pytest.raises(SignatureError):
            verifier.parse_and_verify(wire)

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
            secret=secret,
            agent_id=agent_id,
            project_id=project_id,
            session_id="session-A",
        )
        verifier_b = FrameVerifier(
            secret=secret,
            agent_id=agent_id,
            project_id=project_id,
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
        # reject before touching HMAC, and it must raise the DISTINCT
        # ProtocolVersionError (a ProtocolError subclass) so the delivery
        # bookkeeping can treat a version-skew frame as RECOVERABLE (retry
        # against an upgraded replica) rather than a permanent drop (C5).
        from z4j_core.errors import ProtocolVersionError

        _, verifier = _signer_verifier_pair()
        bad = json.dumps(
            {
                "v": 99,
                "type": "event_batch",
                "id": "x",
                "payload": {"events": []},
            }
        ).encode()
        with pytest.raises(ProtocolVersionError, match="unsupported frame version"):
            verifier.parse_and_verify(bad)

    def test_unknown_type_is_not_a_version_error(self) -> None:
        # An unknown/malformed frame at the MATCHING version is a
        # ProtocolError but NOT a ProtocolVersionError -- it is
        # deterministically undeliverable (dropped), unlike a recoverable
        # version skew (C5).
        from z4j_core.errors import ProtocolVersionError

        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolError) as exc_info:
            verifier.parse_and_verify(b'{"type": "foo", "v": 2}')
        assert not isinstance(exc_info.value, ProtocolVersionError)

    def test_unknown_type_at_wrong_version_is_a_version_error(self) -> None:
        # A frame carrying a NEW type introduced by a version bump must
        # surface as ProtocolVersionError (retry -> lands on an upgraded
        # replica), not an unknown-type ProtocolError that gets drop-acked.
        # The version gate runs BEFORE the type dispatch.
        from z4j_core.errors import ProtocolVersionError

        _, verifier = _signer_verifier_pair()
        with pytest.raises(ProtocolVersionError):
            verifier.parse_and_verify(b'{"type": "metrics_batch", "v": 99, "id": "x"}')

    def test_non_int_version_is_a_drop_not_a_version_skew(self) -> None:
        # External round-8: only an INTEGER v that differs from the
        # protocol version is a recoverable skew (retry -> upgraded
        # replica). A v of the WRONG TYPE (string, float, bool, list,
        # object) is a malformed frame no replica will ever accept, so it
        # must raise a plain ProtocolError (deterministic DROP), never a
        # retryable ProtocolVersionError -- otherwise the agent resends a
        # structurally-broken frame forever.
        from z4j_core.errors import ProtocolVersionError

        _, verifier = _signer_verifier_pair()
        for bad_v in ("2", 2.0, True, [2], {"n": 2}):
            wire = json.dumps(
                {
                    "v": bad_v,
                    "type": "event_batch",
                    "id": "x",
                    "payload": {"events": []},
                }
            ).encode()
            with pytest.raises(ProtocolError) as exc_info:
                verifier.parse_and_verify(wire)
            assert not isinstance(exc_info.value, ProtocolVersionError), bad_v

    def test_missing_version_is_a_drop_not_a_version_skew(self) -> None:
        # A signed frame with no ``v`` at all is malformed (the field is
        # mandatory on the wire), so it drops rather than retries.
        from z4j_core.errors import ProtocolVersionError

        _, verifier = _signer_verifier_pair()
        wire = json.dumps(
            {
                "type": "event_batch",
                "id": "x",
                "payload": {"events": []},
            }
        ).encode()
        with pytest.raises(ProtocolError) as exc_info:
            verifier.parse_and_verify(wire)
        assert not isinstance(exc_info.value, ProtocolVersionError)

    def test_non_object_payload_rejected(self) -> None:
        # Payload claiming to be a list (rather than dict) must fail
        # the shape sanity before HMAC.
        _, verifier = _signer_verifier_pair()
        bad = json.dumps(
            {
                "v": 2,
                "type": "event_batch",
                "id": "x",
                "payload": [1, 2, 3],
            }
        ).encode()
        with pytest.raises(ProtocolError, match="payload must be a JSON object"):
            verifier.parse_and_verify(bad)
