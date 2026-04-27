"""HMAC signing and verification for protocol v2 frames.

**Protocol v2 (April 2026) - every stateful frame is signed in
BOTH directions.**

A frame envelope is the JSON document that gets signed. It
binds every piece of replay-relevant context into the
signature:

    envelope = {
        "v": 2,
        "type": <frame type>,
        "id": <frame id>,
        "ts": <ISO 8601 UTC>,
        "nonce": <16-byte urlsafe base64>,
        "seq": <monotonic int per session per direction>,
        "agent_id": <the authenticated agent's UUID>,
        "project_id": <the project this session belongs to>,
        "payload": <the frame-specific payload>,
    }

The HMAC is `HMAC-SHA256(project_secret, canonical_json(envelope))`.
The receiver recomputes it, compares with ``hmac.compare_digest``,
and additionally verifies:

- ``ts`` is within ±60s of local time (replay window)
- ``seq`` strictly greater than the last-seen seq for this
  (agent_id, direction) pair (strict monotonicity)
- ``nonce`` has not been observed in the last 120s (belt-and-
  braces against reuse under clock-skew)
- ``agent_id`` / ``project_id`` match what the receiver thinks
  the session is bound to (confused-deputy protection)

Protocol v1 (which signed only the payload, omitted ts/nonce/seq/
agent_id, and only signed brain→agent commands) is NOT supported
by v2 parties. See ``docs/SECURITY.md §4.3`` and
``docs/API.md §5`` for the full threat model and wire format.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Any
from uuid import UUID

from z4j_core.errors import SignatureError


def make_signature(secret: bytes, canonical_payload: bytes) -> str:
    """Compute the hex HMAC-SHA256 signature of a canonical payload.

    Args:
        secret: The per-project HMAC secret. Must be at least 32
                bytes. Typically sourced from
                ``secrets.token_bytes(32)`` on the brain side and
                stored in the project row.
        canonical_payload: The payload to sign, already serialized in
                           canonical form. Callers should use
                           :func:`z4j_core.transport.frames.canonical_json`
                           to produce this.

    Returns:
        The lowercase hex-encoded SHA-256 HMAC digest.

    Raises:
        ValueError: If the secret is shorter than 32 bytes.
    """
    if len(secret) < 32:
        raise ValueError("HMAC secret must be at least 32 bytes")
    return hmac.new(secret, canonical_payload, hashlib.sha256).hexdigest()


def verify_signature(
    secret: bytes,
    canonical_payload: bytes,
    provided: str | None,
) -> None:
    """Verify that ``provided`` is the correct HMAC for the payload.

    Uses :func:`hmac.compare_digest` for a constant-time comparison -
    critical to prevent timing oracles on the signature.

    Args:
        secret: The per-project HMAC secret.
        canonical_payload: The canonical JSON payload that was signed.
        provided: The hex signature the peer sent. May be None.

    Raises:
        SignatureError: If ``provided`` is missing, malformed, or
                        does not match the expected signature.
    """
    if not provided:
        raise SignatureError("command frame missing hmac signature")

    expected = make_signature(secret, canonical_payload)

    # Constant-time comparison. ``compare_digest`` requires equal-length
    # inputs to be useful - if the peer sent a wrong-length string,
    # reject immediately.
    if len(expected) != len(provided):
        raise SignatureError("invalid hmac signature length")

    if not hmac.compare_digest(expected, provided):
        raise SignatureError("hmac signature mismatch")


#: Domain-separation prefix for :func:`derive_project_secret`.
#: Bumping the version invalidates every previously-derived
#: secret atomically - useful if the derivation construction
#: itself ever needs to change. **Do not change this casually.**
_PROJECT_SECRET_DERIVATION_LABEL = b"z4j-project-secret-v1:"


def derive_project_secret(master_secret: bytes, project_id: UUID) -> bytes:
    """HMAC-derive a per-project signing secret from the brain master.

    Returns 32 bytes deterministically derived from
    ``(master_secret, project_id)`` so the brain and the agent
    can compute the same value independently - the master never
    leaves the brain process. Compromise of one project's
    derived secret does NOT enable forgery against another
    project, because each project's secret is keyed by its own
    UUID under domain separation.

    Construction:

        derived = HMAC-SHA256(
            master_secret,
            b"z4j-project-secret-v1:" || project_id.bytes_le,
        )

    The label provides domain separation so the same master
    cannot be mis-used to derive secrets for unrelated purposes
    via a coincidence of inputs.

    Rotating ``master_secret`` (typically by changing
    ``Z4J_SECRET`` in the brain config) rotates every project's
    derived secret atomically - every agent must re-enrol to
    pick up the new value. There is no per-project rotation
    channel; that is by design (see ``docs/SECURITY.md §4``).
    """
    if len(master_secret) < 32:
        raise ValueError("master HMAC secret must be at least 32 bytes")
    return hmac.new(
        master_secret,
        _PROJECT_SECRET_DERIVATION_LABEL + project_id.bytes_le,
        hashlib.sha256,
    ).digest()


def generate_project_secret() -> bytes:
    """**Deprecated.** Random per-project secret stored in the DB.

    Superseded by :func:`derive_project_secret`, which produces
    a per-project secret deterministically from the brain master
    so nothing has to be persisted. Kept only for the duration
    of any in-tree callers; remove once those are gone.
    """
    return secrets.token_bytes(32)


class HMACVerifier:
    """Stateful convenience wrapper around a per-project secret.

    Holding the secret as an attribute keeps it out of debug
    reprs. Prefer this class over calling :func:`verify_signature`
    directly in code paths that handle many frames.
    """

    __slots__ = ("_secret",)

    def __init__(self, secret: bytes) -> None:
        if len(secret) < 32:
            raise ValueError("HMAC secret must be at least 32 bytes")
        self._secret = secret

    def sign(self, canonical_payload: bytes) -> str:
        """Sign ``canonical_payload`` with this verifier's secret."""
        return make_signature(self._secret, canonical_payload)

    def verify(self, canonical_payload: bytes, provided: str | None) -> None:
        """Verify ``provided`` matches this verifier's secret.

        Same contract as :func:`verify_signature`.
        """
        verify_signature(self._secret, canonical_payload, provided)

    def __repr__(self) -> str:
        # Never print the secret, even under repr().
        return "<HMACVerifier secret=[REDACTED]>"


#: Maximum clock skew between peers before a frame is rejected as
#: too old / too new. 60 seconds balances NTP drift tolerance with
#: replay-window tightness. The :data:`MAX_NONCE_TRACK_SECONDS`
#: below MUST be strictly larger so a frame at the max-skew edge
#: cannot dodge the nonce cache.
MAX_FRAME_TS_SKEW_SECONDS: int = 60

#: How long the receiver keeps each nonce in memory to reject
#: duplicates. Must exceed :data:`MAX_FRAME_TS_SKEW_SECONDS` on
#: both sides of the wire.
MAX_NONCE_TRACK_SECONDS: int = 180

#: Minimum seq value. Frames with seq <= 0 are malformed.
MIN_SEQ: int = 1


def make_nonce() -> str:
    """Return a fresh 16-byte urlsafe-base64 nonce.

    Callers stamp this into the frame envelope before signing. The
    receiver rejects frames whose nonce has been observed in the
    last :data:`MAX_NONCE_TRACK_SECONDS`.
    """
    return secrets.token_urlsafe(16)


def envelope_bytes(envelope: dict[str, Any]) -> bytes:
    """Canonical JSON rendering of an unsigned frame envelope.

    Drops the ``hmac`` field (if present) before serialising so the
    signer and verifier always agree on the bytes being signed. The
    import is deferred to avoid a cycle with ``frames.py`` which
    lives in the same package and imports this module.
    """
    from z4j_core.transport.frames import canonical_json

    unsigned = {k: v for k, v in envelope.items() if k != "hmac"}
    return canonical_json(unsigned)


def sign_envelope(secret: bytes, envelope: dict[str, Any]) -> str:
    """Sign a frame envelope (every field except ``hmac``).

    The envelope MUST contain at minimum: ``v``, ``type``, ``id``,
    ``ts``, ``nonce``, ``seq``, ``agent_id``, ``project_id``,
    ``payload``. Missing any of these is a programmer bug, not a
    runtime condition - the caller produces the dict - so we do
    not validate here; tests cover the shape.
    """
    return make_signature(secret, envelope_bytes(envelope))


def verify_envelope(
    secret: bytes,
    envelope: dict[str, Any],
) -> None:
    """Recompute and check the ``hmac`` field on a frame envelope.

    Only checks the signature. Timestamp-skew, seq-monotonicity,
    nonce-freshness, and agent_id/project_id binding are checked
    by the session-level receiver (see
    :class:`z4j_core.transport.replay.ReplayGuard`).
    """
    provided = envelope.get("hmac")
    verify_signature(secret, envelope_bytes(envelope), provided)


__all__ = [
    "HMACVerifier",
    "MAX_FRAME_TS_SKEW_SECONDS",
    "MAX_NONCE_TRACK_SECONDS",
    "MIN_SEQ",
    "derive_project_secret",
    "envelope_bytes",
    "generate_project_secret",
    "make_nonce",
    "make_signature",
    "sign_envelope",
    "verify_envelope",
    "verify_signature",
]
