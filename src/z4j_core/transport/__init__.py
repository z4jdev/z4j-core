"""Wire protocol primitives shared by the brain and the agent.

This subpackage carries ONLY the shared wire format - frame shapes,
canonicalization, HMAC signing, version negotiation. No I/O, no
network code, no async. The actual WebSocket client lives in
``z4j-bare`` (under Apache 2.0) and the WebSocket server lives in
``z4j-brain`` (under AGPL v3).

Keeping the shared types here means both sides of the protocol
validate against the exact same schema, and the brain does not need
to depend on ``z4j-bare`` just to parse agent frames.

See ``docs/API.md §5`` for the complete protocol reference and
``docs/ARCHITECTURE.md §4`` for the architectural rationale.
"""

from __future__ import annotations

from z4j_core.transport.frames import (
    FRAME_TYPES,
    CommandAckFrame,
    CommandFrame,
    CommandResultFrame,
    ErrorFrame,
    EventBatchAckFrame,
    EventBatchFrame,
    Frame,
    HeartbeatFrame,
    HelloAckFrame,
    HelloFrame,
    RegistryDeltaFrame,
    canonical_json,
    parse_frame,
    serialize_frame,
)
from z4j_core.transport.hmac import (
    HMACVerifier,
    make_signature,
    verify_signature,
)
from z4j_core.transport.versioning import (
    CURRENT_PROTOCOL,
    MIN_SUPPORTED_PROTOCOL,
    SUPPORTED_PROTOCOLS,
    check_compatibility,
)

__all__ = [
    "CURRENT_PROTOCOL",
    "CommandAckFrame",
    "CommandFrame",
    "CommandResultFrame",
    "ErrorFrame",
    "EventBatchAckFrame",
    "EventBatchFrame",
    "FRAME_TYPES",
    "Frame",
    "HMACVerifier",
    "HeartbeatFrame",
    "HelloAckFrame",
    "HelloFrame",
    "MIN_SUPPORTED_PROTOCOL",
    "RegistryDeltaFrame",
    "SUPPORTED_PROTOCOLS",
    "canonical_json",
    "check_compatibility",
    "make_signature",
    "parse_frame",
    "serialize_frame",
    "verify_signature",
]
