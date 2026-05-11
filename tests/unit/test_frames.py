"""Unit tests for the wire frame (de)serialization and versioning."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from z4j_core.errors import ProtocolError
from z4j_core.transport import (
    FRAME_TYPES,
    MIN_SUPPORTED_PROTOCOL,
    SUPPORTED_PROTOCOLS,
    canonical_json,
    check_compatibility,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.frames import (
    CommandFrame,
    CommandPayload,
    EventBatchFrame,
    EventBatchPayload,
    HeartbeatFrame,
    HeartbeatPayload,
    HelloFrame,
    HelloPayload,
)


class TestFrameTypesSet:
    def test_all_expected_types_are_registered(self) -> None:
        expected = {
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
            "agent_status",  # Phase H (1.5)
        }
        assert expected == set(FRAME_TYPES)


class TestHelloRoundTrip:
    def test_hello_parse_and_serialize(self) -> None:
        frame = HelloFrame(
            id="01HQ",
            payload=HelloPayload(
                protocol_version="2",
                agent_version="0.1.0",
                framework="django",
                engines=["celery"],
                schedulers=["celery-beat"],
                capabilities={"celery": ["retry", "cancel"]},
                host={"hostname": "web-01", "python": "3.14.4", "pid": 1},
            ),
        )
        raw = serialize_frame(frame)
        parsed = parse_frame(raw)
        assert isinstance(parsed, HelloFrame)
        assert parsed.payload.framework == "django"

    def test_hello_parse_from_dict(self) -> None:
        as_dict = {
            "v": 2,
            "id": "01HQ",
            "type": "hello",
            "payload": {
                "protocol_version": "2",
                "agent_version": "0.1.0",
                "framework": "django",
                "engines": ["celery"],
                "schedulers": ["celery-beat"],
                "capabilities": {"celery": ["retry", "cancel"]},
                "host": {},
            },
        }
        parsed = parse_frame(as_dict)
        assert isinstance(parsed, HelloFrame)

    def test_hello_missing_payload_rejected(self) -> None:
        bad = {"v": 2, "id": "x", "type": "hello"}
        with pytest.raises(ValidationError):
            parse_frame(bad)

    def test_unknown_type_rejected(self) -> None:
        bad = {"v": 2, "id": "x", "type": "nope", "payload": {}}
        with pytest.raises(ValidationError):
            parse_frame(bad)


class TestCommandFrame:
    def test_command_hmac_defaults_to_placeholder(self) -> None:
        # v2 keeps hmac permissive at parse time (default "") so the
        # outbound buffer can hold unsigned frames that the
        # FrameSigner overwrites at send time. The FrameVerifier on
        # the receiving side is what enforces the signature.
        frame = CommandFrame(
            id="cmd_1",
            payload=CommandPayload(
                action="retry_task",
                target={"task_id": "abc"},
            ),
        )
        assert frame.hmac == ""
        assert frame.nonce == ""
        assert frame.seq == 0

    def test_command_serializes_with_hmac(self) -> None:
        frame = CommandFrame(
            id="cmd_1",
            payload=CommandPayload(
                action="retry_task",
                target={"task_id": "abc"},
            ),
            hmac="deadbeef" * 8,
        )
        raw = serialize_frame(frame)
        reparsed = parse_frame(raw)
        assert isinstance(reparsed, CommandFrame)
        assert reparsed.hmac == "deadbeef" * 8


class TestEventBatchFrame:
    def test_empty_event_batch_is_valid(self) -> None:
        frame = EventBatchFrame(id="b1", payload=EventBatchPayload(events=[]))
        raw = serialize_frame(frame)
        reparsed = parse_frame(raw)
        assert isinstance(reparsed, EventBatchFrame)
        assert reparsed.payload.events == []

    def test_event_batch_accepts_arbitrary_event_dicts(self) -> None:
        frame = EventBatchFrame(
            id="b2",
            payload=EventBatchPayload(
                events=[
                    {"kind": "task.started", "task_id": "abc", "data": {"name": "foo"}},
                ],
            ),
        )
        raw = serialize_frame(frame)
        reparsed = parse_frame(raw)
        assert isinstance(reparsed, EventBatchFrame)
        assert len(reparsed.payload.events) == 1


class TestHeartbeatFrame:
    def test_heartbeat_defaults(self) -> None:
        frame = HeartbeatFrame(
            id="hb_1",
            payload=HeartbeatPayload(),
        )
        assert frame.payload.buffer_size == 0
        assert frame.payload.dropped_events == 0
        assert frame.payload.adapter_health == {}


class TestCanonicalJSON:
    def test_produces_sorted_compact_output(self) -> None:
        raw = canonical_json({"b": 2, "a": 1})
        assert raw == b'{"a":1,"b":2}'

    def test_nested_order_independent(self) -> None:
        a = canonical_json({"outer": {"b": 2, "a": 1}, "x": 1})
        b = canonical_json({"x": 1, "outer": {"a": 1, "b": 2}})
        assert a == b

    def test_non_ascii_not_escaped(self) -> None:
        raw = canonical_json({"name": "café"})
        assert "café".encode() in raw

    def test_unserializable_raises(self) -> None:
        class NotJSON:
            pass

        with pytest.raises(TypeError):
            canonical_json({"x": NotJSON()})


class TestVersioning:
    def test_current_protocol_is_supported(self) -> None:
        check_compatibility("2")  # must not raise

    def test_unknown_protocol_is_rejected(self) -> None:
        with pytest.raises(ProtocolError) as excinfo:
            check_compatibility("99")
        details = excinfo.value.details
        assert details["advertised"] == "99"
        assert details["minimum"] == MIN_SUPPORTED_PROTOCOL

    def test_older_protocol_is_rejected(self) -> None:
        with pytest.raises(ProtocolError):
            check_compatibility("0")

    def test_supported_list_matches_min(self) -> None:
        assert MIN_SUPPORTED_PROTOCOL in SUPPORTED_PROTOCOLS

    def test_protocol_version_format_is_stable(self) -> None:
        # We currently use integer strings; if that ever changes,
        # this test signals the need to update every adapter.
        for version in SUPPORTED_PROTOCOLS:
            int(version)  # must not raise


class TestInvalidJSON:
    def test_malformed_json_raises(self) -> None:
        # parse_frame routes bytes/str through Pydantic's validate_json,
        # which raises ValidationError (with input_type=json_invalid)
        # rather than the stdlib json.JSONDecodeError.
        with pytest.raises(ValidationError):
            parse_frame("{not valid")
